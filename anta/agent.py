"""A detection agent in place of a session model.

Sessions the rule-based detectors didn't flag, to destinations few hosts use, go to an
agent that can look up what ANTA already knows — who else talks to the destination, the
names it answers to, where it is, threat-intel hits, the history of the conversation — and
gives a verdict: malicious, suspicious or benign, with its reasons. Two kinds:

  * An AI model through its provider's API, with the user's own key: Claude (Anthropic),
    OpenAI, Google Gemini, or any server speaking OpenAI's chat completions API (local
    models through Ollama, LM Studio, llama.cpp or vLLM, or hosted ones; see
    agent_providers.py). Opt-in per provider: the session details leave ANTA, so internal
    addresses are replaced with pseudonyms unless the user allows them, query strings are
    never sent, and an hourly limit caps how many sessions are reviewed (each review may
    be a paid request).
  * The user's own program: a command named in the local config file (`agent_command`
    in anta.toml) — never settable from the dashboard — given one JSON request on stdin
    (the session and the same context) and answering one JSON verdict on stdout.

The agent only reads; nothing it says acts on the network.
"""
from __future__ import annotations

import asyncio
import collections
import contextlib
import ipaddress
import json
import os
import re
import tempfile
import time
from collections.abc import Awaitable, Callable

from urllib.parse import urlsplit, urlunsplit

from . import devices, paths

DEFAULT_MODEL = "claude-opus-5-5"
# The AI providers an agent can use, and the environment variables a key may come from.
# Only Claude has a default model: the others' models are listed from the provider, or typed.
PROVIDERS = {
    "claude": {"label": "Claude", "company": "Anthropic", "key_env": ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")},
    "openai": {"label": "OpenAI", "company": "OpenAI", "key_env": ("OPENAI_API_KEY",)},
    "gemini": {"label": "Gemini", "company": "Google", "key_env": ("GEMINI_API_KEY", "GOOGLE_API_KEY")},
    "compatible": {"label": "OpenAI-compatible server", "company": "", "key_env": ()},
}
EFFORTS = ("low", "medium", "high")
# Models whose requests take server-side refusal fallbacks ("default": Anthropic routes a
# declined request to the right fallback model by its category).
FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}
MAX_TOOL_ROUNDS = 6
VERDICTS = ("malicious", "suspicious", "benign")

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": list(VERDICTS)},
        "confidence": {"type": "number", "description": "0 to 1: how sure you are of the verdict"},
        "headline": {"type": "string", "description": "one sentence an analyst reads first"},
        "reasons": {"type": "array", "items": {"type": "string"}, "description": "the evidence, most important first"},
        "next_steps": {"type": "array", "items": {"type": "string"},
                       "description": "what an analyst should check or do next (observation, not attack)"},
    },
    "required": ["verdict", "confidence", "headline", "reasons", "next_steps"],
    "additionalProperties": False,
}

TOOLS = [
    {"name": "destination_profile", "strict": True,
     "description": "What ANTA knows about a remote address or domain: how many internal hosts talk to it, "
                    "the DNS names it answered to, its country and network owner, threat-intelligence matches, "
                    "and alerts that mention it.",
     "input_schema": {"type": "object", "properties": {"address": {"type": "string",
                      "description": "an IP address or domain name from the session"}},
                      "required": ["address"], "additionalProperties": False}},
    {"name": "host_profile", "strict": True,
     "description": "What ANTA knows about a host on the monitored network: the applications it uses and "
                    "serves, and its alerts. Internal hosts may be pseudonyms like internal-host-1.",
     "input_schema": {"type": "object", "properties": {"host": {"type": "string"}},
                      "required": ["host"], "additionalProperties": False}},
    {"name": "conversation_history", "strict": True,
     "description": "Earlier sessions between a host and a destination port: their times, sizes and durations, "
                    "and whether they recur on a regular schedule (beaconing).",
     "input_schema": {"type": "object", "properties": {"host": {"type": "string"},
                                                       "destination": {"type": "string"},
                                                       "port": {"type": "integer"}},
                      "required": ["host", "destination", "port"], "additionalProperties": False}},
]

SYSTEM_PROMPT = """You are the detection agent inside ANTA, a passive network monitor that observes a \
network its owner runs. Each request is one network session that ANTA's rule-based detectors did not flag, \
to a destination few hosts on the network use. Decide whether it is malicious (for example command-and-control, \
data exfiltration, a malware download, lateral movement), suspicious (worth an analyst's look), or benign.

Look up context with the tools when it could change your answer: who else talks to the destination, what \
names it answers to, where it is, threat-intelligence matches, and whether the conversation recurs on a schedule. \
Be calibrated: most unusual sessions are benign (software updates, telemetry, cloud services, peer-to-peer \
apps), so say malicious only on real evidence, and prefer suspicious when the evidence is thin. ANTA only \
observes: recommend checks and defensive steps an analyst can take, never actions against other systems.

Answer with the verdict object. Write the headline and reasons for an analyst, in plain words, naming the \
evidence."""


# ------------------------------------------------------------------ settings

def _private_write(path: str, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class AgentSettings:
    """What the agent is and how much it may do. Each provider keeps its own model, its own
    agreement to send it sessions, and its own API key; the keys are kept apart, owner-only,
    and never handed back to the page."""

    DEFAULTS = {"provider": "claude", "effort": "medium", "reviews_per_hour": 30, "share_internal": False,
                "base_url": ""}

    def __init__(self, directory: str | None = None, command: list | None = None):
        self.dir = directory or paths.app_data_dir()
        self.path = os.path.join(self.dir, "agent.json")
        self.key_path = os.path.join(self.dir, "agent.key")  # Claude's (where it has always been)
        self.command = [str(c) for c in (command or [])]  # from the local config file only
        self.values = self.validate({})
        with contextlib.suppress(OSError, ValueError, TypeError):
            with open(self.path, encoding="utf-8") as fh:
                self.values = self.validate(json.load(fh))

    @staticmethod
    def _model_ok(provider: str, model) -> bool:
        if not isinstance(model, str):
            return False
        if provider == "claude":
            return bool(re.fullmatch(r"[a-z0-9][a-z0-9.\-]{2,63}", model))
        if provider == "gemini":  # (it goes in the request's path)
            return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,127}", model))
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,127}", model))  # gpt-…, llama3.1:8b, org/model

    def validate(self, v: dict) -> dict:
        out = dict(self.DEFAULTS)
        if v.get("provider") in (*PROVIDERS, "command"):
            out["provider"] = v["provider"]
        models = v.get("models") if isinstance(v.get("models"), dict) else {}
        consents = v.get("consents") if isinstance(v.get("consents"), dict) else {}
        # (Settings saved before there were other providers: their model and consent were Claude's.)
        if "claude" not in models and "model" in v:
            models = {**models, "claude": v["model"]}
        if "claude" not in consents and "consent" in v:
            consents = {**consents, "claude": v["consent"]}
        out["models"] = {}
        for p in PROVIDERS:
            m = str(models.get(p) or "").strip()
            if p == "gemini":
                m = m.removeprefix("models/")
            out["models"][p] = m if self._model_ok(p, m) else (DEFAULT_MODEL if p == "claude" else "")
        out["consents"] = {p: bool(consents.get(p, False)) for p in PROVIDERS}
        if v.get("effort") in EFFORTS:
            out["effort"] = v["effort"]
        with contextlib.suppress(TypeError, ValueError):
            out["reviews_per_hour"] = int(min(max(int(v.get("reviews_per_hour", 30)), 1), 1000))
        out["share_internal"] = bool(v.get("share_internal", False))
        with contextlib.suppress(ValueError):
            out["base_url"] = clean_base_url(v.get("base_url") or "") if v.get("base_url") else ""
        return out

    def update(self, changes: dict) -> dict:
        """`model` and `consent` are for the provider named in the changes, else the current one."""
        if "base_url" in changes and changes["base_url"]:
            clean_base_url(changes["base_url"])  # (raises ValueError with the reason)
        target = changes.get("provider") if changes.get("provider") in PROVIDERS else self.values["provider"]
        values = {**self.values, **{k: v for k, v in changes.items() if k not in ("model", "consent")}}
        if "model" in changes and target in PROVIDERS:
            model = str(changes["model"] or "").strip()
            if target == "gemini":
                model = model.removeprefix("models/")  # (how Gemini's own model list names them)
            if model and not self._model_ok(target, model):
                raise ValueError("that isn't a model name this provider uses")
            values["models"] = {**self.values["models"], target: model}
        if "consent" in changes and target in PROVIDERS:
            values["consents"] = {**self.values["consents"], target: bool(changes["consent"])}
        self.values = self.validate(values)
        _private_write(self.path, json.dumps(self.values, indent=1).encode())
        return self.public()

    def model(self, provider: str | None = None) -> str:
        return self.values["models"].get(provider or self.values["provider"], "")

    def consented(self, provider: str | None = None) -> bool:
        return self.values["consents"].get(provider or self.values["provider"], False)

    def _key_path(self, provider: str) -> str:
        return self.key_path if provider == "claude" else os.path.join(self.dir, f"agent-{provider}.key")

    def api_key(self, provider: str | None = None) -> str | None:
        provider = provider or self.values["provider"]
        if provider not in PROVIDERS:
            return None
        with contextlib.suppress(OSError):
            with open(self._key_path(provider), encoding="utf-8") as fh:
                return fh.read().strip() or None
        return None

    def env_key(self, provider: str | None = None) -> str | None:
        """A key from the provider's usual environment variable (an OpenAI-compatible server
        gets none: another provider's key mustn't go to whatever server is named)."""
        for name in PROVIDERS.get(provider or self.values["provider"], {}).get("key_env", ()):
            if os.environ.get(name):
                return os.environ[name]
        return None

    def set_api_key(self, key: str | None, provider: str | None = None) -> None:
        provider = provider or self.values["provider"]
        if provider not in PROVIDERS:
            raise ValueError("the agent program doesn't take an API key")
        if not key:
            with contextlib.suppress(OSError):
                os.unlink(self._key_path(provider))
            return
        key = key.strip()
        if provider == "claude" and not re.fullmatch(r"[A-Za-z0-9_\-]{20,300}", key):
            raise ValueError("that doesn't look like an Anthropic API key")
        if not re.fullmatch(r"[\x21-\x7e]{8,500}", key):
            raise ValueError("that doesn't look like an API key")
        _private_write(self._key_path(provider), key.encode())

    def public(self) -> dict:
        provider = self.values["provider"]
        current = provider if provider in PROVIDERS else "claude"
        return {**self.values, "model": self.model(current), "consent": self.consented(current),
                "key_saved": bool(self.api_key(current)), "key_from_environment": bool(self.env_key(current)),
                "keys_saved": {p: bool(self.api_key(p)) for p in PROVIDERS},
                "keys_from_environment": {p: bool(self.env_key(p)) for p in PROVIDERS},
                "providers": {p: {"label": m["label"], "company": m["company"]} for p, m in PROVIDERS.items()},
                "server": server_name(self.values["base_url"]),
                "command": self.command, "command_configured": bool(self.command),
                "command_name": command_name(self.command)}


def _local_host(host: str) -> bool:
    """A host on this computer or the local network (plain http is allowed there)."""
    host = host.strip("[]").lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".lan", ".home.arpa")) or "." not in host and ":" not in host:
        return True
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(host)
        return devices.address_kind(host) in INTERNAL_KINDS
    return False


def clean_base_url(url: str) -> str:
    """An OpenAI-compatible server's address, like http://localhost:11434/v1. Plain http only
    to this computer or the local network: elsewhere the key and sessions need https."""
    u = urlsplit(str(url).strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("the server address must start with http:// or https://")
    if u.username or u.password or u.query or u.fragment:
        raise ValueError("the server address can't hold a name, password, query or fragment")
    if u.scheme == "http" and not _local_host(u.hostname):
        raise ValueError("use https:// for a server that isn't on this computer or your local network")
    return urlunsplit((u.scheme, u.netloc, u.path.rstrip("/"), "", ""))


def server_name(base_url: str) -> str:
    return urlsplit(base_url).netloc if base_url else ""


# ------------------------------------------------------------------ pseudonyms

INTERNAL_KINDS = {"private", "link-local", "loopback", "shared"}


def _internal(address: str) -> bool:
    # (ANTA's own address kinds: Python's is_private also covers the documentation ranges)
    return devices.address_kind(address) in INTERNAL_KINDS


class Pseudonyms:
    """Internal addresses as internal-host-N for one review, and back for the tools."""

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.to_alias: dict[str, str] = {}
        self.to_real: dict[str, str] = {}
        self.hosts = 0
        self.macs = 0

    def alias(self, address: str) -> str:
        if not self.enabled or not _internal(address):
            return address
        if address not in self.to_alias:
            self.hosts += 1
            name = f"internal-host-{self.hosts}"
            self.to_alias[address], self.to_real[name] = name, address
        return self.to_alias[address]

    def real(self, name: str) -> str:
        return self.to_real.get(name, name)

    def mac(self, address: str) -> str:
        """A hardware address as mac-N (it names one device as surely as an IP does)."""
        if not self.enabled:
            return address
        key = address.lower().replace("-", ":")
        if key in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return address
        if key not in self.to_alias:
            self.macs += 1
            name = f"mac-{self.macs}"
            self.to_alias[key], self.to_real[name] = name, address
        return self.to_alias[key]

    # (an IPv4 address may have a :port after it; an IPv6 one with a port is written [addr]:port)
    IP_TOKEN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)|"
                          r"(?<![\w:.])[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?![\w:]|\.\w)")
    MAC_TOKEN = re.compile(r"(?<![\w:-])[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}(?![\w:-])")

    def scrub_text(self, text: str) -> str:
        """Free text with its internal addresses (IPv4 and IPv6) and hardware addresses
        replaced by pseudonyms."""
        if not self.enabled:
            return text
        text = self.MAC_TOKEN.sub(lambda m: self.mac(m.group(0)), text)

        def ip(m):
            with contextlib.suppress(ValueError):
                ipaddress.ip_address(m.group(0))
                return self.alias(m.group(0))
            return m.group(0)
        return self.IP_TOKEN.sub(ip, text)

    def restore(self, text: str) -> str:
        """The agent's own words with the pseudonyms it used turned back into addresses."""
        return re.sub(r"\b(?:internal-host|mac)-\d+\b", lambda m: self.to_real.get(m.group(0), m.group(0)), text)

    def scrub(self, value):
        """Every internal address inside a JSON-able value, pseudonymised."""
        if isinstance(value, str):
            if not self.enabled:
                return value
            with contextlib.suppress(ValueError):  # an address on its own (IPv4 or IPv6)
                ipaddress.ip_address(value)
                return self.alias(value)
            return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lambda m: self.alias(m.group(0)), value)
        if isinstance(value, dict):
            return {self.scrub(k) if isinstance(k, str) else k: self.scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub(v) for v in value]
        return value


# ------------------------------------------------------------------ backends

def clean_verdict(data: dict) -> dict:
    if not isinstance(data, dict) or data.get("verdict") not in VERDICTS:
        raise ValueError("the agent's answer has no verdict")
    try:
        confidence = float(data.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    strings = lambda v, n: [str(x)[:500] for x in v][:n] if isinstance(v, list) else []  # noqa: E731
    return {"verdict": data["verdict"], "confidence": min(max(confidence, 0.0), 1.0),
            "headline": str(data.get("headline") or "")[:400], "reasons": strings(data.get("reasons"), 10),
            "next_steps": strings(data.get("next_steps"), 8)}


class AgentError(Exception):
    pass


class ClaudeBackend:
    """Claude through the Anthropic API, with read-only lookup tools and a schema-checked verdict."""

    def __init__(self, settings: AgentSettings, client=None):
        self.settings = settings
        self._client = client

    @property
    def name(self) -> str:
        return f"Claude ({self.settings.model('claude')})"

    def client(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError:
                raise AgentError("the Anthropic SDK isn't installed (pip install anthropic)") from None
            key = self.settings.api_key("claude")
            self._client = anthropic.AsyncAnthropic(api_key=key, timeout=120.0) if key else \
                anthropic.AsyncAnthropic(timeout=120.0)  # ANTHROPIC_API_KEY or an `ant auth login` profile
        return self._client

    async def review(self, request: dict, call_tool: Callable[[str, dict], Awaitable[dict]]) -> dict:
        v = self.settings.values
        model = self.settings.model("claude")
        params = {"model": model, "max_tokens": 16000, "system": SYSTEM_PROMPT, "tools": TOOLS,
                  "output_config": {"effort": v["effort"], "format": {"type": "json_schema", "schema": VERDICT_SCHEMA}}}
        if model in FALLBACK_MODELS:  # a declined request is retried on Anthropic's fallback model
            params.update(betas=["server-side-fallback-2026-07-01"], fallbacks="default")
        messages = [{"role": "user", "content": "Review this session:\n" + json.dumps(request, indent=1)}]
        usage = {"input_tokens": 0, "output_tokens": 0, "tool_calls": 0}
        client = self.client()
        try:
            import anthropic
        except ImportError:
            anthropic = None
        for _ in range(MAX_TOOL_ROUNDS + 1):
            try:
                response = await client.beta.messages.create(messages=messages, **params)
            except Exception as exc:  # noqa: BLE001 - mapped to a plain message below
                raise AgentError(_api_error(anthropic, exc)) from None
            if getattr(response, "usage", None):
                usage["input_tokens"] += int(getattr(response.usage, "input_tokens", 0) or 0)
                usage["output_tokens"] += int(getattr(response.usage, "output_tokens", 0) or 0)
            if response.stop_reason == "refusal":
                raise AgentError("the model declined to review this session")
            if response.stop_reason == "max_tokens":
                raise AgentError("the review ran out of output tokens")
            if response.stop_reason == "tool_use":
                results = []
                for block in response.content:
                    if getattr(block, "type", "") != "tool_use":
                        continue
                    usage["tool_calls"] += 1
                    try:
                        out = await call_tool(block.name, dict(block.input or {}))
                        results.append({"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(out)})
                    except Exception as exc:  # noqa: BLE001 - a tool failing is reported to the model
                        results.append({"type": "tool_result", "tool_use_id": block.id, "is_error": True,
                                        "content": f"lookup failed: {exc}"})
                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user", "content": results})
                continue
            text = next((b.text for b in response.content if getattr(b, "type", "") == "text"), "")
            try:
                verdict = clean_verdict(json.loads(text))
            except ValueError as exc:
                raise AgentError(f"the model's answer wasn't a verdict: {exc}") from None
            return {**verdict, "usage": usage, "model": getattr(response, "model", model)}
        raise AgentError("the review took too many lookups")


def _api_error(anthropic, exc: Exception) -> str:
    if anthropic is not None:
        if isinstance(exc, anthropic.AuthenticationError):
            return "the Anthropic API key was refused"
        if isinstance(exc, anthropic.PermissionDeniedError):
            return "the API key may not use that model"
        if isinstance(exc, anthropic.NotFoundError):
            return "unknown model"
        if isinstance(exc, anthropic.RateLimitError):
            return "rate limited by the Anthropic API; reviews resume later"
        if isinstance(exc, anthropic.APIStatusError):
            return f"the Anthropic API returned an error ({exc.status_code})"
        if isinstance(exc, anthropic.APIConnectionError):
            return "couldn't reach the Anthropic API"
    return f"the review failed: {str(exc)[:200]}"


def command_name(argv: list[str]) -> str:
    """How the user's agent program is named in the dashboard: the script, when an
    interpreter runs it."""
    if not argv:
        return "your agent"
    prog = os.path.basename(argv[0])
    if len(argv) > 1 and re.fullmatch(r"(python|node|ruby|perl|bash|sh|deno|bun|pwsh)[\d.]*(\.exe)?", prog, re.IGNORECASE):
        prog = os.path.basename(argv[1])
    return f"your agent ({prog})"


class CommandBackend:
    """The user's own agent program: one JSON request on stdin, one JSON verdict on stdout."""

    def __init__(self, argv: list[str], timeout: float = 60.0):
        self.argv = list(argv)
        self.timeout = timeout

    @property
    def name(self) -> str:
        return command_name(self.argv)

    async def review(self, request: dict, call_tool: Callable[[str, dict], Awaitable[dict]]) -> dict:
        if not self.argv:
            raise AgentError("no agent_command is set in the config file")
        # The program gets the context up front (it can't call back into ANTA).
        s = request["session"]
        request = {**request, "context": {
            "destination": await call_tool("destination_profile", {"address": s["server"]}),
            "host": await call_tool("host_profile", {"host": s["client"]}),
            "history": await call_tool("conversation_history", {"host": s["client"], "destination": s["server"],
                                                                 "port": s["server_port"]})},
            "verdict_schema": VERDICT_SCHEMA}
        try:
            proc = await asyncio.create_subprocess_exec(
                *self.argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL)
        except OSError as exc:
            raise AgentError(f"couldn't start the agent program: {exc}") from None
        try:
            out, _ = await asyncio.wait_for(proc.communicate((json.dumps(request) + "\n").encode()), self.timeout)
        except TimeoutError:
            proc.kill()
            raise AgentError("the agent program took too long") from None
        line = out[: 256 * 1024].decode(errors="replace").strip().splitlines()
        try:
            return {**clean_verdict(json.loads(line[-1] if line else "")), "model": self.name}
        except ValueError as exc:
            raise AgentError(f"the agent program's answer wasn't a verdict: {exc}") from None


# ------------------------------------------------------------------ the review queue

class Reviewer:
    """Queues candidate sessions and reviews them one at a time, within the hourly limit.
    A host/destination pair reviewed in the last hour isn't reviewed again."""

    def __init__(self, settings: AgentSettings, context, on_verdict: Callable[[dict, dict], None],
                 backend=None):
        self.settings = settings
        self.context = context    # .session_summary(rec), .destination_profile(..), .host_profile(..), .history(..)
        self.on_verdict = on_verdict
        self._backend = backend   # a fixed backend (tests); otherwise built from the settings
        self._built = None        # (settings it was built for, backend)
        self.queue: asyncio.Queue | None = None
        self.task: asyncio.Task | None = None
        self.recent: dict[tuple, float] = {}
        self.window: collections.deque = collections.deque()
        self.stats = collections.Counter()
        self.last_error = ""

    def backend(self):
        if self._backend is not None:
            return self._backend
        v = self.settings.values
        provider = v["provider"]
        config = (provider, self.settings.model(), v["base_url"], self.settings.api_key(), tuple(self.settings.command))
        if self._built is None or self._built[0] != config:  # one client until the settings change
            if provider == "command":
                backend = CommandBackend(self.settings.command)
            elif provider == "claude":
                backend = ClaudeBackend(self.settings)
            else:
                from .agent_providers import ChatBackend, GeminiBackend
                backend = GeminiBackend(self.settings) if provider == "gemini" else ChatBackend(self.settings, provider)
            self._built = (config, backend)
        return self._built[1]

    def forget_backend(self) -> None:
        """A new API key: the next review builds a new client."""
        self._built = None

    def status(self) -> dict:
        return {"queued": self.queue.qsize() if self.queue else 0, "reviewed": self.stats["reviewed"],
                "flagged": self.stats["flagged"], "benign": self.stats["benign"], "errors": self.stats["errors"],
                "skipped": self.stats["skipped"], "input_tokens": self.stats["input_tokens"],
                "output_tokens": self.stats["output_tokens"], "last_error": self.last_error,
                "reviews_last_hour": len(self.window), "limit_per_hour": self.settings.values["reviews_per_hour"]}

    def ready(self) -> bool:
        """Whether reviews can run: a configured program, or an AI provider the user agreed to
        send sessions to, with a model (and, for an OpenAI-compatible server, its address)."""
        p = self.settings.values["provider"]
        if p == "command":
            return bool(self.settings.command)
        return self.settings.consented(p) and bool(self.settings.model(p)) and \
            (p != "compatible" or bool(self.settings.values["base_url"]))

    def submit(self, rec: dict) -> bool:
        """From the analyzer (on the event loop): queue a session if there's room."""
        if not self.ready():
            return False
        key = (rec["src_ip"], rec["dst_ip"], rec["dst_port"])
        now = time.time()
        if now - self.recent.get(key, 0) < 3600:
            return False
        if self.queue is None:
            self.queue = asyncio.Queue(maxsize=200)
        if self.task is None or self.task.done():
            self.task = asyncio.get_running_loop().create_task(self._run())
        try:
            self.queue.put_nowait(rec)
        except asyncio.QueueFull:
            self.stats["skipped"] += 1
            return False
        self.recent[key] = now
        if len(self.recent) > 50_000:
            for k in [k for k, t in self.recent.items() if now - t >= 3600]:
                del self.recent[k]
        return True

    async def _run(self) -> None:
        while True:
            rec = await self.queue.get()
            await self._wait_for_budget()
            try:
                verdict = await self.review(rec)
            except AgentError:
                continue
            self.on_verdict(rec, verdict)

    async def _wait_for_budget(self) -> None:
        while True:
            now = time.time()
            while self.window and now - self.window[0] >= 3600:
                self.window.popleft()
            if len(self.window) < self.settings.values["reviews_per_hour"]:
                return
            await asyncio.sleep(min(60.0, 3600 - (now - self.window[0]) + 0.1))

    async def review(self, rec: dict) -> dict:
        """One review now (also used for an analyst asking about an alert, or a test)."""
        self.window.append(time.time())
        names = Pseudonyms(not self.settings.values["share_internal"])
        request = {"session": names.scrub(self.context.session_summary(rec))}

        async def call_tool(name: str, args: dict) -> dict:
            if name == "destination_profile":
                out = self.context.destination_profile(names.real(str(args.get("address", ""))))
            elif name == "host_profile":
                out = self.context.host_profile(names.real(str(args.get("host", ""))))
            elif name == "conversation_history":
                out = self.context.history(names.real(str(args.get("host", ""))),
                                           names.real(str(args.get("destination", ""))), int(args.get("port") or 0))
            else:
                raise ValueError(f"no tool called {name}")
            return names.scrub(out)

        backend = self.backend()
        try:
            verdict = await backend.review(request, call_tool)
        except AgentError as exc:
            self.stats["errors"] += 1
            self.last_error = str(exc)
            raise
        verdict["headline"] = names.restore(verdict["headline"])
        for k in ("reasons", "next_steps"):
            verdict[k] = [names.restore(t) for t in verdict[k]]
        self.last_error = ""
        self.stats["reviewed"] += 1
        self.stats["flagged" if verdict["verdict"] != "benign" else "benign"] += 1
        for k in ("input_tokens", "output_tokens"):
            self.stats[k] += int((verdict.get("usage") or {}).get(k, 0))
        verdict["reviewer"] = backend.name
        verdict["shared_internal_addresses"] = not names.enabled
        verdict["reviewed_at"] = time.time()
        return verdict
