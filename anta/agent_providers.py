"""The detection agent on AI providers other than Anthropic: OpenAI, Google Gemini, and any
server that speaks OpenAI's chat completions API (local models through Ollama, LM Studio,
llama.cpp or vLLM, and hosted services such as OpenRouter, Groq or Mistral).

Each review works as it does with Claude: the session (internal addresses pseudonymised
unless allowed), read-only lookup tools the model may call, and one verdict object back,
checked before it is trusted. Smaller models call tools less reliably, so the session's
destination, host and history lookups are sent with it up front; the tools stay available
for anything else. Requests go over the standard library's HTTP client, verified against
the operating system's certificate store, with redirects refused (a redirect must not carry
the API key to another host). The key is sent in a header and never logged or echoed.
"""
from __future__ import annotations

import asyncio
import json
import re
import ssl
import urllib.error
import urllib.request
from collections.abc import Awaitable, Callable
from urllib.parse import quote, urlsplit

from .agent import (MAX_TOOL_ROUNDS, PROVIDERS, SYSTEM_PROMPT, TOOLS, VERDICT_SCHEMA, AgentError, AgentSettings,
                    clean_verdict)

OPENAI_URL = "https://api.openai.com/v1"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta"
MAX_RESPONSE = 8 << 20
REVIEW_TIMEOUT = 120.0
LIST_TIMEOUT = 20.0

# Without a schema the provider enforces, the model is told the verdict's shape.
ANSWER_FORMAT = ("\n\nWhen you have decided, answer with only a JSON object (no other text) with these fields: "
                 + json.dumps(VERDICT_SCHEMA["properties"]) + ". confidence is a number from 0 to 1.")
ASK_AGAIN = "Answer with only the JSON verdict object, nothing else."


# ------------------------------------------------------------------ HTTP

class ProviderHTTPError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class ProviderUnreachable(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # (the response is then reported as the error it is)


_CONTEXT: ssl.SSLContext | None = None


def _ssl_context() -> ssl.SSLContext:
    """The operating system's trusted certificates (truststore), as the Anthropic SDK uses;
    else Python's defaults."""
    global _CONTEXT
    if _CONTEXT is None:
        try:
            import truststore
            _CONTEXT = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except ImportError:
            _CONTEXT = ssl.create_default_context()
    return _CONTEXT


def _error_text(raw: bytes) -> str:
    """The provider's own error message, short and printable."""
    try:
        data = json.loads(raw)
    except ValueError:
        text = raw.decode(errors="replace")
    else:
        err = data.get("error") if isinstance(data, dict) else None
        text = err.get("message") if isinstance(err, dict) else err if isinstance(err, str) else ""
        text = text or (data.get("message") if isinstance(data, dict) else "") or ""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).strip()
    return text[:200]


def _http(method: str, url: str, headers: dict, body: dict | None, timeout: float) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={**headers, "Content-Type": "application/json", "Accept": "application/json",
                                          "User-Agent": "ANTA detection agent"})
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_ssl_context()))
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            raw = exc.read(64 * 1024)
        except OSError:
            raw = b""
        if 300 <= status < 400:
            raise ProviderHTTPError(status, "the server redirected the request elsewhere (not followed)") from None
        raise ProviderHTTPError(status, _error_text(raw)) from None
    except (urllib.error.URLError, OSError) as exc:  # (TimeoutError is an OSError)
        reason = getattr(exc, "reason", exc)
        raise ProviderUnreachable(str(reason)[:200] or exc.__class__.__name__) from None
    if len(raw) > MAX_RESPONSE:
        raise ProviderUnreachable("the server's answer was too large")
    try:
        out = json.loads(raw)
    except ValueError:
        raise ProviderUnreachable("the server's answer wasn't JSON") from None
    if not isinstance(out, dict):
        raise ProviderUnreachable("the server's answer wasn't a JSON object")
    return out


async def _call(method: str, url: str, headers: dict, body: dict | None = None, timeout: float = REVIEW_TIMEOUT) -> dict:
    return await asyncio.to_thread(_http, method, url, headers, body, timeout)


def _who(provider: str, base_url: str = "") -> str:
    if provider == "compatible":
        return f"the server at {urlsplit(base_url).netloc}" if base_url else "the server"
    return f"the {PROVIDERS[provider]['company']} API"


def _explain(exc: Exception, provider: str, base_url: str = "") -> str:
    who = _who(provider, base_url)
    if isinstance(exc, ProviderUnreachable):
        return f"couldn't reach {who} ({exc})"
    if not isinstance(exc, ProviderHTTPError):
        return f"the review failed: {str(exc)[:200]}"
    s, m = exc.status, exc.message
    if s == 401 or (provider == "gemini" and s == 400 and "api key" in m.lower()):
        return f"{who} refused the API key"
    if s == 403:
        return f"{who} won't let this API key use that model" + (f" ({m})" if m else "")
    if s == 404:
        return "unknown model" + (" (or the server address is wrong)" if provider == "compatible" else "") + \
            (f": {m}" if m else "")
    if s == 429:
        return f"rate limited by {who}; reviews resume later"
    return f"{who} returned an error ({s})" + (f": {m}" if m else "")


# ------------------------------------------------------------------ answers

def parse_verdict_text(text: str) -> dict:
    """The verdict object in a model's text answer: on its own, in a ```json block, or
    after reasoning a model printed first."""
    t = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", t, re.S)
    if fence:
        t = fence.group(1)
    else:
        a, b = t.find("{"), t.rfind("}")
        if a < 0 or b <= a:
            raise ValueError("there is no JSON object in it")
        t = t[a:b + 1]
    return clean_verdict(json.loads(t))


async def _context(request: dict, call_tool: Callable[[str, dict], Awaitable[dict]]) -> dict:
    """The session's own lookups, sent with it."""
    s = request["session"]
    return {**request, "context": {
        "destination": await call_tool("destination_profile", {"address": s["server"]}),
        "host": await call_tool("host_profile", {"host": s["client"]}),
        "history": await call_tool("conversation_history", {"host": s["client"], "destination": s["server"],
                                                             "port": s["server_port"]})}}


async def _run_tool(call_tool, name: str, args) -> dict:
    if not isinstance(args, dict):
        return {"error": "the arguments weren't a JSON object"}
    try:
        return await call_tool(name, args)
    except Exception as exc:  # noqa: BLE001 - a failed lookup is reported to the model
        return {"error": f"lookup failed: {exc}"}


# ------------------------------------------------------------------ OpenAI and compatible servers

class ChatBackend:
    """OpenAI's chat completions API: OpenAI itself, or a compatible server at the address
    the user gave. OpenAI enforces the verdict's schema; other servers are asked for it."""

    def __init__(self, settings: AgentSettings, provider: str = "openai"):
        self.settings = settings
        self.provider = provider

    @property
    def base_url(self) -> str:
        return OPENAI_URL if self.provider == "openai" else self.settings.values["base_url"]

    @property
    def name(self) -> str:
        model = self.settings.model(self.provider)
        if self.provider == "openai":
            return f"OpenAI ({model})"
        return f"{model} at {urlsplit(self.base_url).netloc}"

    def headers(self) -> dict:
        key = self.settings.api_key(self.provider) or self.settings.env_key(self.provider)
        if not key and self.provider == "openai":
            raise AgentError("there's no OpenAI API key: save one under Detection…")
        return {"Authorization": f"Bearer {key}"} if key else {}  # (a local server may need none)

    def tools(self) -> list[dict]:
        out = []
        for t in TOOLS:
            fn = {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}
            if self.provider == "openai":
                fn["strict"] = True
            out.append({"type": "function", "function": fn})
        return out

    async def review(self, request: dict, call_tool: Callable[[str, dict], Awaitable[dict]]) -> dict:
        if not self.base_url:
            raise AgentError("no server address is set for the OpenAI-compatible server")
        model = self.settings.model(self.provider)
        if not model:
            raise AgentError("no model is chosen")
        headers = self.headers()
        request = await _context(request, call_tool)
        messages = [{"role": "system", "content": SYSTEM_PROMPT + ANSWER_FORMAT},
                    {"role": "user", "content": "Review this session:\n" + json.dumps(request, indent=1)}]
        body = {"model": model, "tools": self.tools()}
        if self.provider == "openai":
            body["response_format"] = {"type": "json_schema",
                                       "json_schema": {"name": "verdict", "strict": True, "schema": VERDICT_SCHEMA}}
        usage = {"input_tokens": 0, "output_tokens": 0, "tool_calls": 0}
        asked_again = False
        for _ in range(MAX_TOOL_ROUNDS + 2):
            try:
                out = await _call("POST", self.base_url + "/chat/completions", headers, {**body, "messages": messages})
            except (ProviderHTTPError, ProviderUnreachable) as exc:
                raise AgentError(_explain(exc, self.provider, self.base_url)) from None
            u = out.get("usage") if isinstance(out.get("usage"), dict) else {}
            usage["input_tokens"] += int(u.get("prompt_tokens") or 0)
            usage["output_tokens"] += int(u.get("completion_tokens") or 0)
            choices = out.get("choices") if isinstance(out.get("choices"), list) else []
            choice = choices[0] if choices and isinstance(choices[0], dict) else {}
            msg = choice.get("message") if isinstance(choice.get("message"), dict) else {}
            finish = choice.get("finish_reason")
            if msg.get("refusal") or finish == "content_filter":
                raise AgentError("the model declined to review this session")
            calls = msg.get("tool_calls") if isinstance(msg.get("tool_calls"), list) else []
            if calls:
                messages.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
                for call in calls:
                    fn = call.get("function") if isinstance(call, dict) else None
                    if not isinstance(fn, dict):
                        continue
                    usage["tool_calls"] += 1
                    try:
                        args = json.loads(fn.get("arguments") or "{}")
                    except ValueError:
                        args = None
                    result = await _run_tool(call_tool, str(fn.get("name") or ""), args)
                    messages.append({"role": "tool", "tool_call_id": call.get("id") or "", "content": json.dumps(result)})
                continue
            if finish == "length":
                raise AgentError("the review ran out of output tokens")
            text = msg.get("content") if isinstance(msg.get("content"), str) else ""
            try:
                verdict = parse_verdict_text(text)
            except ValueError as exc:
                if asked_again:
                    raise AgentError(f"the model's answer wasn't a verdict: {exc}") from None
                asked_again = True  # once: smaller models sometimes answer in prose first
                messages += [{"role": "assistant", "content": text}, {"role": "user", "content": ASK_AGAIN}]
                continue
            return {**verdict, "usage": usage, "model": str(out.get("model") or model)}
        raise AgentError("the review took too many lookups")


# ------------------------------------------------------------------ Gemini

def _gemini_schema(schema):
    """JSON Schema as Gemini's function declarations take it (no additionalProperties)."""
    if isinstance(schema, dict):
        return {k: _gemini_schema(v) for k, v in schema.items() if k not in ("additionalProperties", "strict")}
    if isinstance(schema, list):
        return [_gemini_schema(v) for v in schema]
    return schema


GEMINI_DECLINED = {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY"}


class GeminiBackend:
    """Google's Gemini API (generateContent), with function calling for the lookups."""

    def __init__(self, settings: AgentSettings):
        self.settings = settings

    @property
    def name(self) -> str:
        return f"Gemini ({self.settings.model('gemini')})"

    async def review(self, request: dict, call_tool: Callable[[str, dict], Awaitable[dict]]) -> dict:
        key = self.settings.api_key("gemini") or self.settings.env_key("gemini")
        if not key:
            raise AgentError("there's no Gemini API key: save one under Detection…")
        model = self.settings.model("gemini")
        if not model:
            raise AgentError("no model is chosen")
        url = f"{GEMINI_URL}/models/{quote(model, safe='')}:generateContent"
        headers = {"x-goog-api-key": key}
        request = await _context(request, call_tool)
        contents = [{"role": "user", "parts": [{"text": "Review this session:\n" + json.dumps(request, indent=1)}]}]
        body = {"systemInstruction": {"parts": [{"text": SYSTEM_PROMPT + ANSWER_FORMAT}]},
                "tools": [{"functionDeclarations": [{"name": t["name"], "description": t["description"],
                                                     "parameters": _gemini_schema(t["input_schema"])} for t in TOOLS]}]}
        usage = {"input_tokens": 0, "output_tokens": 0, "tool_calls": 0}
        asked_again = False
        for _ in range(MAX_TOOL_ROUNDS + 2):
            try:
                out = await _call("POST", url, headers, {**body, "contents": contents})
            except (ProviderHTTPError, ProviderUnreachable) as exc:
                raise AgentError(_explain(exc, "gemini")) from None
            u = out.get("usageMetadata") if isinstance(out.get("usageMetadata"), dict) else {}
            usage["input_tokens"] += int(u.get("promptTokenCount") or 0)
            usage["output_tokens"] += int(u.get("candidatesTokenCount") or 0) + int(u.get("thoughtsTokenCount") or 0)
            candidates = out.get("candidates") if isinstance(out.get("candidates"), list) else []
            if not candidates:
                feedback = out.get("promptFeedback") if isinstance(out.get("promptFeedback"), dict) else {}
                raise AgentError("the model declined to review this session" if feedback.get("blockReason")
                                 else "the model gave no answer")
            cand = candidates[0] if isinstance(candidates[0], dict) else {}
            finish = cand.get("finishReason")
            if finish in GEMINI_DECLINED:
                raise AgentError("the model declined to review this session")
            content = cand.get("content") if isinstance(cand.get("content"), dict) else {}
            parts = [p for p in content.get("parts") or [] if isinstance(p, dict)]
            calls = [p["functionCall"] for p in parts if isinstance(p.get("functionCall"), dict)]
            if calls:
                contents.append({"role": "model", "parts": parts})  # as given (thought signatures included)
                answers = []
                for call in calls:
                    usage["tool_calls"] += 1
                    name = str(call.get("name") or "")
                    result = await _run_tool(call_tool, name, call.get("args") if "args" in call else {})
                    response = {"name": name, "response": result}
                    if call.get("id"):
                        response["id"] = call["id"]
                    answers.append({"functionResponse": response})
                contents.append({"role": "user", "parts": answers})
                continue
            if finish == "MAX_TOKENS":
                raise AgentError("the review ran out of output tokens")
            text = "".join(str(p.get("text") or "") for p in parts if not p.get("thought"))
            try:
                verdict = parse_verdict_text(text)
            except ValueError as exc:
                if asked_again:
                    raise AgentError(f"the model's answer wasn't a verdict: {exc}") from None
                asked_again = True
                contents += [{"role": "model", "parts": parts or [{"text": text}]},
                             {"role": "user", "parts": [{"text": ASK_AGAIN}]}]
                continue
            return {**verdict, "usage": usage, "model": str(out.get("modelVersion") or model)}
        raise AgentError("the review took too many lookups")


# ------------------------------------------------------------------ one question, one JSON answer

async def ask_json(settings: AgentSettings, provider: str, system: str, question: str, schema: dict) -> dict:
    """One question, one JSON object back (Ask the capture's translation): no tools, the
    schema enforced where the provider can, else asked for and parsed out of the text."""
    model = settings.model(provider)
    if not model:
        raise AgentError("no model is chosen")
    instruction = system + "\n\nAnswer with only a JSON object with these fields: " + json.dumps(schema["properties"])
    try:
        if provider == "gemini":
            key = settings.api_key("gemini") or settings.env_key("gemini")
            if not key:
                raise AgentError("there's no Gemini API key: save one under Detection…")
            out = await _call("POST", f"{GEMINI_URL}/models/{quote(model, safe='')}:generateContent", {"x-goog-api-key": key},
                              {"systemInstruction": {"parts": [{"text": instruction}]},
                               "contents": [{"role": "user", "parts": [{"text": question}]}],
                               "generationConfig": {"responseMimeType": "application/json"}})
            cands = out.get("candidates") if isinstance(out.get("candidates"), list) else []
            cand = cands[0] if cands and isinstance(cands[0], dict) else {}
            if not cands or cand.get("finishReason") in GEMINI_DECLINED:
                raise AgentError("the model declined to answer")
            content = cand.get("content") if isinstance(cand.get("content"), dict) else {}
            text = "".join(str(p.get("text") or "") for p in content.get("parts") or []
                           if isinstance(p, dict) and not p.get("thought"))
        else:
            chat = ChatBackend(settings, provider)
            if not chat.base_url:
                raise AgentError("no server address is set for the OpenAI-compatible server")
            body = {"model": model, "messages": [{"role": "system", "content": instruction},
                                                 {"role": "user", "content": question}]}
            if provider == "openai":
                body["response_format"] = {"type": "json_schema",
                                           "json_schema": {"name": "answer", "strict": True, "schema": schema}}
            out = await _call("POST", chat.base_url + "/chat/completions", chat.headers(), body)
            choices = out.get("choices") if isinstance(out.get("choices"), list) else []
            choice = choices[0] if choices and isinstance(choices[0], dict) else {}
            msg = choice.get("message") if isinstance(choice.get("message"), dict) else {}
            if msg.get("refusal") or choice.get("finish_reason") == "content_filter":
                raise AgentError("the model declined to answer")
            text = msg.get("content") if isinstance(msg.get("content"), str) else ""
    except (ProviderHTTPError, ProviderUnreachable) as exc:
        raise AgentError(_explain(exc, provider, settings.values.get("base_url", ""))) from None
    t = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S)
    a, b = t.find("{"), t.rfind("}")
    if a < 0 or b <= a:
        raise AgentError("the model's answer wasn't JSON")
    try:
        data = json.loads(t[a:b + 1])
    except ValueError:
        raise AgentError("the model's answer wasn't JSON") from None
    if not isinstance(data, dict):
        raise AgentError("the model's answer wasn't a JSON object")
    return data


async def ask_model_json(settings: AgentSettings, system: str, text: str, schema: dict, effort: str = "low",
                         max_tokens: int = 8000) -> dict:
    """One request to the AI model set up under Detection… (Claude, OpenAI, Gemini or an
    OpenAI-compatible server), one JSON object back. The caller decides what `text` holds
    (and pseudonymises it); this only sends it."""
    provider = settings.values["provider"]
    if provider not in PROVIDERS:
        raise AgentError("your own agent program reviews sessions only; choose an AI model under Detection…")
    if not settings.consented(provider) or not settings.model(provider):
        raise AgentError("set up an AI model under Detection… (and agree to send it data) to use it here")
    if provider != "claude":
        return await ask_json(settings, provider, system, text, schema)
    from .agent import ClaudeBackend, _api_error
    client = ClaudeBackend(settings).client()
    try:
        import anthropic
    except ImportError:
        anthropic = None
    try:
        response = await client.messages.create(
            model=settings.model("claude"), max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": text}],
            output_config={"effort": effort, "format": {"type": "json_schema", "schema": schema}})
    except Exception as exc:  # noqa: BLE001 - mapped to a plain message
        raise AgentError(_api_error(anthropic, exc)) from None
    if response.stop_reason == "refusal":
        raise AgentError("the model declined to answer")
    if response.stop_reason == "max_tokens":
        raise AgentError("the model ran out of output tokens")
    out = next((b.text for b in response.content if getattr(b, "type", "") == "text"), "")
    try:
        data = json.loads(out)
    except ValueError:
        raise AgentError("the model's answer wasn't JSON") from None
    if not isinstance(data, dict):
        raise AgentError("the model's answer wasn't a JSON object")
    return data


# ------------------------------------------------------------------ model lists

# OpenAI lists every model the key may use; these families can't hold a conversation.
_NOT_CHAT = re.compile(r"embedding|whisper|tts|dall-e|davinci|babbage|moderation|transcribe|image|audio|realtime|"
                       r"search|sora|computer-use", re.I)


async def list_models(settings: AgentSettings, provider: str) -> list[dict]:
    """The models the saved key (or the server) offers: [{id, name}], for choosing one."""
    if provider == "claude":
        try:
            import anthropic
        except ImportError:
            raise AgentError("the Anthropic SDK isn't installed (pip install anthropic)") from None
        key = settings.api_key("claude")
        client = anthropic.AsyncAnthropic(api_key=key, timeout=LIST_TIMEOUT) if key else \
            anthropic.AsyncAnthropic(timeout=LIST_TIMEOUT)
        try:
            return [{"id": m.id, "name": m.display_name or m.id} async for m in client.models.list(limit=100)]
        except Exception as exc:  # noqa: BLE001 - reported as a plain message
            from .agent import _api_error
            raise AgentError(_api_error(anthropic, exc)) from None
    try:
        if provider == "gemini":
            key = settings.api_key("gemini") or settings.env_key("gemini")
            if not key:
                raise AgentError("save your Gemini API key first")
            out = await _call("GET", f"{GEMINI_URL}/models?pageSize=1000", {"x-goog-api-key": key}, timeout=LIST_TIMEOUT)
            models = []
            for m in out.get("models") or []:
                if isinstance(m, dict) and "generateContent" in (m.get("supportedGenerationMethods") or []):
                    mid = str(m.get("name") or "").removeprefix("models/")
                    if AgentSettings._model_ok("gemini", mid):
                        models.append({"id": mid, "name": str(m.get("displayName") or mid)})
            return sorted(models, key=lambda m: m["id"])
        backend = ChatBackend(settings, provider)
        if not backend.base_url:
            raise AgentError("enter the server's address first")
        out = await _call("GET", backend.base_url + "/models", backend.headers(), timeout=LIST_TIMEOUT)
        ids = [str(m.get("id")) for m in out.get("data") or [] if isinstance(m, dict) and m.get("id")]
        if provider == "openai":
            ids = [i for i in ids if not _NOT_CHAT.search(i)]
        return [{"id": i, "name": i} for i in sorted(set(ids)) if AgentSettings._model_ok(provider, i)]
    except (ProviderHTTPError, ProviderUnreachable) as exc:
        raise AgentError(_explain(exc, provider, settings.values["base_url"])) from None
