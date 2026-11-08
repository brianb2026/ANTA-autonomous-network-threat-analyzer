"""The detection agent on other AI providers: OpenAI, Google Gemini, and servers speaking
OpenAI's chat completions API (local models through Ollama, LM Studio and the like).

Each provider is a local stand-in server speaking its API, so no request leaves the
machine. They check what ANTA sends (the key in its header and nowhere else, the tools,
pseudonyms for internal addresses, the lookups' results going back) and how it reads the
answers: tool calls, a verdict in prose or a ```json block, refusals, errors, redirects.
"""
import asyncio
import json
import os
import stat

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from anta import agent_providers
from anta.agent import AgentError, AgentSettings, Reviewer, clean_base_url
from anta.agent_providers import list_models, parse_verdict_text

VERDICT = {"verdict": "suspicious", "confidence": 0.6, "headline": "Check-ins to a host nobody else uses",
           "reasons": ["Only one internal host talks to it"], "next_steps": ["See which program opens it"]}
REC = {"src_ip": "10.0.0.50", "src_port": 5000, "dst_ip": "203.0.113.77", "dst_port": 8443}


class Context:
    def __init__(self):
        self.asked = []

    def session_summary(self, rec):
        return {"client": rec["src_ip"], "server": rec["dst_ip"], "server_port": rec["dst_port"]}

    def destination_profile(self, address):
        self.asked.append(("destination", address))
        return {"address": address, "internal_hosts": ["10.0.0.50"]}

    def host_profile(self, host):
        self.asked.append(("host", host))
        return {"host": host}

    def history(self, host, destination, port):
        self.asked.append(("history", host, destination, port))
        return {"sessions_seen": 12}


class Stub:
    """A provider's API on localhost, answering POSTs from a script and recording them."""

    def __init__(self, script, path):
        self.script, self.requests, self.path = list(script), [], path
        self.app = web.Application()
        self.app.router.add_route("*", "/{tail:.*}", self.handle)

    async def handle(self, request):
        body = await request.json() if request.can_read_body else None
        self.requests.append({"path": request.path, "query": request.query_string,
                              "headers": {k.lower(): v for k, v in request.headers.items()},
                              "body": body})
        status, answer = self.script.pop(0)
        if status in (302, 307):
            return web.Response(status=status, headers={"Location": answer})
        return web.json_response(answer, status=status)

    async def __aenter__(self):
        self.server = TestServer(self.app, host="127.0.0.1")
        await self.server.start_server()
        self.url = f"http://127.0.0.1:{self.server.port}"
        return self

    async def __aexit__(self, *exc):
        await self.server.close()


def settings(tmp_path, **values):
    s = AgentSettings(directory=str(tmp_path))
    s.update(values)
    return s


def chat_answer(message, finish="stop", model="stub-model"):
    return {"id": "c1", "model": model, "choices": [{"index": 0, "message": {"role": "assistant", **message},
                                                     "finish_reason": finish}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20}}


def tool_call(cid, name, args):
    return {"id": cid, "type": "function", "function": {"name": name, "arguments": args}}


# ------------------------------------------------------------------ settings

def test_each_provider_keeps_its_own_model_consent_and_key(tmp_path):
    with open(tmp_path / "agent.json", "w") as fh:  # saved before there were other providers
        json.dump({"provider": "claude", "model": "claude-sonnet-5-5", "consent": True, "effort": "low"}, fh)
    s = AgentSettings(directory=str(tmp_path))
    assert s.model("claude") == "claude-sonnet-5-5" and s.consented("claude") and s.values["effort"] == "low"
    assert not s.consented("openai") and s.model("openai") == ""
    s.update({"provider": "openai", "model": "gpt-test-mini", "consent": True})
    assert s.model("openai") == "gpt-test-mini" and s.model("claude") == "claude-sonnet-5-5"
    s.update({"provider": "compatible", "model": "llama3.1:8b", "base_url": "http://localhost:11434/v1/"})
    assert s.values["base_url"] == "http://localhost:11434/v1" and not s.consented("compatible")
    s.update({"provider": "gemini", "model": "models/gemini-test"})
    assert s.model("gemini") == "gemini-test"  # (the API's own "models/" prefix dropped)
    with pytest.raises(ValueError):
        s.update({"model": "gemini test; rm -rf"})
    # Keys: one file each, owner-only, never handed back.
    s.set_api_key("sk-openai-test-key-0123456789", "openai")
    s.set_api_key("AIza-gemini-test-key-0123", "gemini")
    assert s.api_key("openai") != s.api_key("gemini") and s.api_key("claude") is None
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(tmp_path / "agent-openai.key").st_mode) == 0o600
    pub = json.dumps(s.public())
    assert "sk-openai" not in pub and "AIza" not in pub and s.public()["keys_saved"]["openai"]
    with pytest.raises(ValueError):
        s.set_api_key("has a space in it", "openai")
    with pytest.raises(ValueError):
        s.set_api_key("anything-0123456789", "command")


def test_server_addresses(monkeypatch):
    assert clean_base_url("http://localhost:1234/v1") == "http://localhost:1234/v1"
    assert clean_base_url("http://192.168.1.20:11434/v1") == "http://192.168.1.20:11434/v1"
    assert clean_base_url("http://gpu-box:8000/v1") == "http://gpu-box:8000/v1"  # (a name on the LAN)
    assert clean_base_url("https://openrouter.ai/api/v1") == "https://openrouter.ai/api/v1"
    for bad in ("http://example.com/v1", "http://8.8.8.8/v1", "ftp://localhost/v1", "https://user:pw@host/v1",
                "https://host/v1?x=1", "localhost:11434"):
        with pytest.raises(ValueError):
            clean_base_url(bad)
    # An OpenAI-compatible server never gets another provider's key from the environment.
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env-0123456789")
    s = AgentSettings(directory=None)
    assert s.env_key("openai") and s.env_key("compatible") is None


def test_ready_needs_consent_a_model_and_for_a_server_its_address(tmp_path):
    s = settings(tmp_path, provider="openai")
    r = Reviewer(s, Context(), lambda rec, v: None)
    assert not r.ready()
    s.update({"model": "gpt-test", "consent": True})
    assert r.ready()
    s.update({"provider": "compatible", "model": "llama3", "consent": True})
    assert not r.ready()  # no address yet
    s.update({"base_url": "http://localhost:11434/v1"})
    assert r.ready() and r.backend().name == "llama3 at localhost:11434"


# ------------------------------------------------------------------ OpenAI and compatible servers

def test_openai_reviews_with_lookups_pseudonyms_and_its_schema(tmp_path, monkeypatch):
    async def go():
        script = [
            (200, chat_answer({"content": None, "tool_calls": [
                tool_call("t1", "destination_profile", json.dumps({"address": "203.0.113.77"})),
                tool_call("t2", "host_profile", "{not json")]}, finish="tool_calls")),
            (200, chat_answer({"content": json.dumps(VERDICT)}, model="gpt-test-2026")),
        ]
        async with Stub(script, "/v1/chat/completions") as stub:
            monkeypatch.setattr(agent_providers, "OPENAI_URL", stub.url + "/v1")
            s = settings(tmp_path, provider="openai", model="gpt-test", consent=True)
            s.set_api_key("sk-test-openai-0123456789", "openai")
            ctx = Context()
            verdict = await Reviewer(s, ctx, lambda rec, v: None).review(REC)
        assert verdict["verdict"] == "suspicious" and verdict["model"] == "gpt-test-2026"
        assert verdict["reviewer"] == "OpenAI (gpt-test)"
        assert verdict["usage"] == {"input_tokens": 200, "output_tokens": 40, "tool_calls": 2}
        first, second = stub.requests
        assert first["path"] == "/v1/chat/completions"
        assert first["headers"]["authorization"] == "Bearer sk-test-openai-0123456789"
        body = first["body"]
        assert body["model"] == "gpt-test" and all(t["function"]["strict"] for t in body["tools"])
        assert body["response_format"]["json_schema"]["schema"]["required"][0] == "verdict"
        # The session's lookups went with it; the internal address only as a pseudonym.
        sent = json.dumps([r["body"] for r in stub.requests])
        assert "10.0.0.50" not in sent and "internal-host-1" in sent and "sk-test" not in sent
        assert ("history", "10.0.0.50", "203.0.113.77", 8443) in ctx.asked
        tool_results = [m for m in second["body"]["messages"] if m["role"] == "tool"]
        assert [m["tool_call_id"] for m in tool_results] == ["t1", "t2"]
        assert "arguments weren't a JSON object" in tool_results[1]["content"]
    asyncio.run(go())


def test_a_local_server_without_a_key_and_a_verdict_in_prose(tmp_path):
    async def go():
        script = [
            (200, chat_answer({"content": "<think>hmm</think>Looking at this session, it seems unusual."})),
            (200, chat_answer({"content": "Here it is:\n```json\n" + json.dumps(VERDICT) + "\n```"})),
        ]
        async with Stub(script, "/v1/chat/completions") as stub:
            s = settings(tmp_path, provider="compatible", model="qwen2.5:14b", consent=True, base_url=stub.url + "/v1")
            verdict = await Reviewer(s, Context(), lambda rec, v: None).review(REC)
        assert verdict["verdict"] == "suspicious" and verdict["reviewer"].startswith("qwen2.5:14b at 127.0.0.1:")
        first = stub.requests[0]
        assert "authorization" not in first["headers"]  # no key saved: none sent
        assert "response_format" not in first["body"] and not any("strict" in t["function"] for t in first["body"]["tools"])
        assert stub.requests[1]["body"]["messages"][-1] == {"role": "user", "content": agent_providers.ASK_AGAIN}
    asyncio.run(go())


@pytest.mark.parametrize("status,answer,expect", [
    (401, {"error": {"message": "Incorrect API key"}}, "refused the API key"),
    (404, {"error": {"message": "model 'nope' not found"}}, "unknown model (or the server address is wrong): model 'nope' not found"),
    (429, {"error": {"message": "slow down"}}, "rate limited by the server at"),
    (500, {"error": "boom"}, "returned an error (500): boom"),
    (200, chat_answer({"content": "", "refusal": "I can't help with that"}), "declined"),
    (200, chat_answer({"content": "{\"verdict\": \"malic"}, finish="length"), "ran out of output tokens"),
])
def test_errors_are_reported_not_trusted(tmp_path, status, answer, expect):
    async def go():
        async with Stub([(status, answer)], "/v1/chat/completions") as stub:
            s = settings(tmp_path, provider="compatible", model="m", consent=True, base_url=stub.url + "/v1")
            s.set_api_key("local-test-key-123", "compatible")
            r = Reviewer(s, Context(), lambda rec, v: None)
            with pytest.raises(AgentError) as err:
                await r.review(REC)
        assert expect in str(err.value) and "local-test-key" not in str(err.value)
    asyncio.run(go())


def test_redirects_are_not_followed(tmp_path):
    """A redirect could carry the key to another host: it is refused, and the other host
    never hears from ANTA."""
    async def go():
        async with Stub([], "/") as other:
            async with Stub([(307, other.url + "/v1/chat/completions")], "/v1/chat/completions") as stub:
                s = settings(tmp_path, provider="compatible", model="m", consent=True, base_url=stub.url + "/v1")
                s.set_api_key("secret-key-0123456789", "compatible")
                with pytest.raises(AgentError) as err:
                    await Reviewer(s, Context(), lambda rec, v: None).review(REC)
        assert "redirected" in str(err.value) and other.requests == []
    asyncio.run(go())


def test_an_unreachable_server(tmp_path):
    s = settings(tmp_path, provider="compatible", model="m", consent=True, base_url="http://127.0.0.1:9/v1")
    with pytest.raises(AgentError) as err:
        asyncio.run(Reviewer(s, Context(), lambda rec, v: None).review(REC))
    assert "couldn't reach the server at 127.0.0.1:9" in str(err.value)


# ------------------------------------------------------------------ Gemini

def test_gemini_reviews_with_function_calls(tmp_path, monkeypatch):
    async def go():
        call = {"functionCall": {"name": "conversation_history", "id": "fc-1",
                                 "args": {"host": "internal-host-1", "destination": "203.0.113.77", "port": 8443}},
                "thoughtSignature": "sig-abc"}
        script = [
            (200, {"candidates": [{"content": {"role": "model", "parts": [call]}, "finishReason": "STOP"}],
                   "usageMetadata": {"promptTokenCount": 300, "candidatesTokenCount": 10, "thoughtsTokenCount": 5}}),
            (200, {"candidates": [{"content": {"role": "model", "parts": [
                {"text": "reasoning", "thought": True}, {"text": json.dumps(VERDICT)}]}, "finishReason": "STOP"}],
                   "usageMetadata": {"promptTokenCount": 400, "candidatesTokenCount": 30}, "modelVersion": "gemini-test-001"}),
        ]
        async with Stub(script, "/") as stub:
            monkeypatch.setattr(agent_providers, "GEMINI_URL", stub.url + "/v1beta")
            s = settings(tmp_path, provider="gemini", model="gemini-test", consent=True)
            s.set_api_key("AIza-test-gemini-key-01234", "gemini")
            ctx = Context()
            verdict = await Reviewer(s, ctx, lambda rec, v: None).review(REC)
        assert verdict["verdict"] == "suspicious" and verdict["model"] == "gemini-test-001"
        assert verdict["usage"] == {"input_tokens": 700, "output_tokens": 45, "tool_calls": 1}
        first, second = stub.requests
        assert first["path"] == "/v1beta/models/gemini-test:generateContent"
        assert first["headers"]["x-goog-api-key"] == "AIza-test-gemini-key-01234" and "key=" not in first["query"]
        decls = first["body"]["tools"][0]["functionDeclarations"]
        assert {d["name"] for d in decls} == {"destination_profile", "host_profile", "conversation_history"}
        assert "additionalProperties" not in json.dumps(decls)
        # The model's turn goes back as it came (its thought signature too), then the lookup's result.
        model_turn, answer = second["body"]["contents"][-2:]
        assert model_turn == {"role": "model", "parts": [call]}
        response = answer["parts"][0]["functionResponse"]
        assert response["id"] == "fc-1" and response["name"] == "conversation_history"
        assert ("history", "10.0.0.50", "203.0.113.77", 8443) in ctx.asked
        assert "10.0.0.50" not in json.dumps([r["body"] for r in stub.requests])
    asyncio.run(go())


def test_gemini_refusals_and_bad_keys(tmp_path, monkeypatch):
    async def go(script):
        async with Stub(script, "/") as stub:
            monkeypatch.setattr(agent_providers, "GEMINI_URL", stub.url + "/v1beta")
            s = settings(tmp_path, provider="gemini", model="gemini-test", consent=True)
            s.set_api_key("AIza-test-gemini-key-01234", "gemini")
            with pytest.raises(AgentError) as err:
                await Reviewer(s, Context(), lambda rec, v: None).review(REC)
            return str(err.value)
    assert "declined" in asyncio.run(go([(200, {"promptFeedback": {"blockReason": "SAFETY"}})]))
    assert "declined" in asyncio.run(go([(200, {"candidates": [{"finishReason": "SAFETY"}]})]))
    assert "refused the API key" in asyncio.run(go([(400, {"error": {"message": "API key not valid. Please pass a valid API key."}})]))


# ------------------------------------------------------------------ model lists

def test_model_lists(tmp_path, monkeypatch):
    async def go():
        script = [
            (200, {"data": [{"id": "gpt-test"}, {"id": "text-embedding-3-small"}, {"id": "whisper-1"}, {"id": "o-test-mini"}]}),
            (200, {"models": [{"name": "models/gemini-test", "displayName": "Gemini Test",
                               "supportedGenerationMethods": ["generateContent", "countTokens"]},
                              {"name": "models/embedding-test", "supportedGenerationMethods": ["embedContent"]}]}),
            (200, {"object": "list", "data": [{"id": "llama3.1:8b"}, {"id": "qwen2.5:14b"}]}),
        ]
        async with Stub(script, "/") as stub:
            monkeypatch.setattr(agent_providers, "OPENAI_URL", stub.url + "/v1")
            monkeypatch.setattr(agent_providers, "GEMINI_URL", stub.url + "/v1beta")
            s = settings(tmp_path, base_url=stub.url + "/v1")
            s.set_api_key("sk-test-openai-0123456789", "openai")
            s.set_api_key("AIza-test-gemini-key-01234", "gemini")
            openai = await list_models(s, "openai")
            gemini = await list_models(s, "gemini")
            local = await list_models(s, "compatible")
        assert [m["id"] for m in openai] == ["gpt-test", "o-test-mini"]
        assert gemini == [{"id": "gemini-test", "name": "Gemini Test"}]
        assert [m["id"] for m in local] == ["llama3.1:8b", "qwen2.5:14b"]
        assert [r["path"] for r in stub.requests] == ["/v1/models", "/v1beta/models", "/v1/models"]
    asyncio.run(go())


def test_verdict_text():
    assert parse_verdict_text(json.dumps(VERDICT))["verdict"] == "suspicious"
    assert parse_verdict_text("Sure.\n" + json.dumps(VERDICT) + "\nHope that helps")["confidence"] == 0.6
    for bad in ("no json here", '{"verdict": "probably fine"}'):
        with pytest.raises(ValueError):
            parse_verdict_text(bad)


def test_providers_over_the_api(monkeypatch):
    from test_server import AUTH, make_client

    async def go():
        dash, c = await make_client()
        try:
            r = await (await c.post("/api/agent/settings", headers=AUTH, json={"provider": "claude"})).json()
            # A key saved for another provider doesn't switch to it.
            r = await (await c.post("/api/agent/settings", headers=AUTH, json={
                "key_provider": "openai", "api_key": "sk-test-openai-0123456789"})).json()
            assert r["agent"]["provider"] == "claude" and r["agent"]["keys_saved"]["openai"]
            assert "sk-test" not in json.dumps(r)
            bad = await c.post("/api/agent/settings", headers=AUTH, json={"provider": "compatible",
                                                                          "base_url": "http://example.com/v1"})
            assert bad.status == 400 and "https://" in (await bad.json())["error"]
            async with Stub([(200, {"data": [{"id": "llama3.1:8b"}]})], "/") as stub:
                r = await (await c.post("/api/agent/settings", headers=AUTH, json={
                    "provider": "compatible", "base_url": stub.url + "/v1", "model": "llama3.1:8b", "consent": True})).json()
                assert r["agent_ready"] and r["agent"]["server"] == stub.url[len("http://"):]
                listed = await (await c.post("/api/agent/models", headers=AUTH, json={"provider": "compatible"})).json()
                assert listed["models"] == [{"id": "llama3.1:8b", "name": "llama3.1:8b"}]
            down = await c.post("/api/agent/models", headers=AUTH, json={"provider": "compatible"})
            assert down.status == 502 and "couldn't reach" in (await down.json())["error"]
        finally:
            await c.post("/api/agent/settings", headers=AUTH, json={"provider": "claude", "key_provider": "openai",
                                                                     "api_key": None})
            await c.close()
    asyncio.run(go())
