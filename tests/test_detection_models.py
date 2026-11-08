"""Choosing the detection model: the built-in Isolation Forest, an ONNX model the user
adds (checked, then calibrated on benign sessions), or a detection agent in the model's
place — Claude through the Anthropic API (tested here with a stand-in client: no request
leaves the machine) or the user's own program."""
import asyncio
import base64
import json
import os
import stat
import sys

import numpy as np
import pytest

from anta.agent import AgentError, AgentSettings, ClaudeBackend, CommandBackend, Pseudonyms, Reviewer
from anta.agent_context import AgentContext
from anta.analyzer import Analyzer, Config
from anta.modelstore import ModelError, ModelStore, calibration_set
from conftest import run_engine

skl2onnx = pytest.importorskip("skl2onnx")


def _onnx(model, n=10, name="input"):
    from skl2onnx.common.data_types import FloatTensorType
    return skl2onnx.convert_sklearn(model, initial_types=[(name, FloatTensorType([None, n]))],
                                    target_opset={"": 17, "ai.onnx.ml": 3}).SerializeToString()


@pytest.fixture(scope="module")
def builtin():
    from anta import paths
    from anta.model import AnomalyModel
    return AnomalyModel(paths.models_dir())  # (300 trees: seconds to load, so once)


@pytest.fixture(scope="module")
def models():
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    benign, attack = calibration_set()
    iso = _onnx(IsolationForest(n_estimators=60, random_state=0).fit(benign))
    x = np.vstack([benign[:2000], attack[:120]])
    y = np.r_[np.zeros(2000), np.ones(120)]
    rf = _onnx(RandomForestClassifier(n_estimators=30, random_state=0).fit(x, y), name="float_input")
    narrow = _onnx(IsolationForest(n_estimators=5, random_state=0).fit(benign[:, :4]), n=4)
    return {"iso": iso, "rf": rf, "narrow": narrow}


def test_added_models_are_checked_and_calibrated(tmp_path, models, builtin):
    store = ModelStore(root=str(tmp_path / "custom"), builtin_model=builtin)
    assert store.list()[0]["attack_catch_rate"] < 0.05  # the built-in model, measured the same way (see below)
    iso = store.add_onnx("My forest", models["iso"], filename="forest.onnx")
    assert iso["direction"] == "lower" and iso["output"] == "scores"       # an Isolation Forest's convention
    assert 0.003 <= iso["benign_alert_rate"] <= 0.008                       # calibrated to the 0.5% target
    rf = store.add_onnx("Classifier", models["rf"])
    assert rf["direction"] == "higher" and rf["output"] == "output_probability"  # P(malicious), read from the map
    assert rf["attack_catch_rate"] > 0.9
    for data, words in ((models["narrow"], "[N, 10]"), (b"not onnx", "ONNX Runtime can load")):
        with pytest.raises(ModelError, match=words.replace("[", r"\[")):
            store.add_onnx("bad", data)
    with pytest.raises(ModelError, match="alert rate"):
        store.add_onnx("bad", models["iso"], fp_rate=0.9)
    store.set_active(rf["id"])
    m = store.load()
    benign, attack = calibration_set()
    assert m.name == "Classifier" and all(m.is_anomaly(s) for s in m.scores(attack[:5]))
    assert np.mean([m.is_anomaly(s) for s in m.scores(benign)]) < 0.01
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(os.path.join(store.root, rf["id"], "model.onnx")).st_mode) == 0o600
    store.remove(rf["id"])
    assert store.active() == "builtin" and rf["id"] not in {e["id"] for e in store.list()}


# ------------------------------------------------------------------ a stand-in Anthropic client

class Block:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class Response:
    def __init__(self, stop_reason, content, model="claude-opus-5-5"):
        self.stop_reason, self.content, self.model = stop_reason, content, model
        self.usage = Block(input_tokens=1000, output_tokens=200)


class FakeClient:
    """client.beta.messages.create(...) answering from a script, recording each request."""

    def __init__(self, script):
        self.script, self.requests = list(script), []
        self.beta = Block(messages=Block(create=self._create))

    async def _create(self, **params):
        self.requests.append(json.loads(json.dumps(params, default=lambda o: o.__dict__)))
        return self.script.pop(0)


VERDICT = {"verdict": "malicious", "confidence": 0.85, "headline": "Regular check-ins to a host nobody else uses",
           "reasons": ["Only one internal host talks to it", "Fixed 60-second schedule"],
           "next_steps": ["Check which process on the host opens the connection"]}


class Context:
    """The lookups the agent can make, recording what they were asked."""

    def __init__(self):
        self.asked = []

    def session_summary(self, rec):
        return {"client": rec["src_ip"], "server": rec["dst_ip"], "server_port": rec["dst_port"],
                "note": f"seen from {rec['src_ip']}"}

    def destination_profile(self, address):
        self.asked.append(("destination", address))
        return {"address": address, "internal_hosts": ["10.0.0.50"], "internal_host_count": 1}

    def host_profile(self, host):
        self.asked.append(("host", host))
        return {"host": host}

    def history(self, host, destination, port):
        self.asked.append(("history", host, destination, port))
        return {"sessions_seen": 12, "seconds_between_sessions": [60.0, 60.1, 59.9]}


REC = {"src_ip": "10.0.0.50", "src_port": 5000, "dst_ip": "203.0.113.77", "dst_port": 8443}


def test_claude_reviews_with_lookups_and_pseudonyms(tmp_path):
    settings = AgentSettings(directory=str(tmp_path))
    settings.update({"consent": True, "effort": "low"})
    client = FakeClient([
        Response("tool_use", [Block(type="text", text="Checking the destination."),
                              Block(type="tool_use", id="t1", name="destination_profile", input={"address": "203.0.113.77"}),
                              Block(type="tool_use", id="t2", name="conversation_history",
                                    input={"host": "internal-host-1", "destination": "203.0.113.77", "port": 8443})]),
        Response("end_turn", [Block(type="text", text=json.dumps(VERDICT))]),
    ])
    ctx = Context()
    reviewer = Reviewer(settings, ctx, lambda rec, v: None, backend=ClaudeBackend(settings, client=client))
    verdict = asyncio.run(reviewer.review(REC))
    assert verdict["verdict"] == "malicious" and verdict["reasons"][1] == "Fixed 60-second schedule"
    assert verdict["usage"] == {"input_tokens": 2000, "output_tokens": 400, "tool_calls": 2}
    first = client.requests[0]
    assert first["model"] == "claude-opus-5-5" and first["output_config"]["effort"] == "low"
    assert first["output_config"]["format"]["schema"]["required"][0] == "verdict"
    assert first["fallbacks"] == "default" and first["betas"] == ["server-side-fallback-2026-07-01"]
    assert all(t["strict"] for t in first["tools"])
    # The internal address left the machine only as a pseudonym; the tools got the real one.
    sent = json.dumps(client.requests)
    assert "10.0.0.50" not in sent and "internal-host-1" in sent and "203.0.113.77" in sent
    assert ("history", "10.0.0.50", "203.0.113.77", 8443) in ctx.asked
    # Allowed to share internal addresses, they go as they are.
    settings.update({"share_internal": True})
    client2 = FakeClient([Response("end_turn", [Block(type="text", text=json.dumps(VERDICT))])])
    asyncio.run(Reviewer(settings, ctx, lambda r, v: None, backend=ClaudeBackend(settings, client=client2)).review(REC))
    assert "10.0.0.50" in json.dumps(client2.requests)


def test_pseudonyms():
    names = Pseudonyms(True)
    scrubbed = names.scrub({"a": "10.1.2.3", "b": "seen from 192.168.0.9 and 10.1.2.3", "c": "100.64.0.1",
                            "d": "203.0.113.77", "e": "fe80::1", "f": "8.8.8.8"})
    assert scrubbed == {"a": "internal-host-1", "b": "seen from internal-host-2 and internal-host-1",
                        "c": "internal-host-3", "d": "203.0.113.77", "e": "internal-host-4", "f": "8.8.8.8"}
    assert names.restore("internal-host-2 beacons; internal-host-12 unknown") == "192.168.0.9 beacons; internal-host-12 unknown"
    assert Pseudonyms(False).scrub("10.1.2.3") == "10.1.2.3"


def test_refusals_and_bad_answers_are_reported_not_trusted(tmp_path):
    settings = AgentSettings(directory=str(tmp_path))
    settings.update({"consent": True, "model": "claude-haiku-5-5"})
    for script, words in (([Response("refusal", [])], "declined"),
                          ([Response("end_turn", [Block(type="text", text='{"verdict": "maybe"}')])], "wasn't a verdict"),
                          ([Response("max_tokens", [])], "ran out")):
        client = FakeClient(script)
        reviewer = Reviewer(settings, Context(), lambda r, v: None, backend=ClaudeBackend(settings, client=client))
        with pytest.raises(AgentError, match=words):
            asyncio.run(reviewer.review(REC))
        assert reviewer.status()["errors"] == 1 and words.split()[0] in reviewer.status()["last_error"]
        assert "fallbacks" not in client.requests[0]  # (no server-side fallback for this model)


def test_your_own_agent_program(tmp_path):
    prog = tmp_path / "my_agent.py"
    prog.write_text("import json, sys\nreq = json.loads(sys.stdin.readline())\n"
                    "ctx = req['context']\nhosts = ctx['destination']['internal_host_count']\n"
                    "print(json.dumps({'verdict': 'suspicious' if hosts <= 1 else 'benign', 'confidence': 0.6,"
                    " 'headline': 'rare destination seen from ' + req['session']['client'],"
                    " 'reasons': ['saw ' + req['session']['client'].upper()], 'next_steps': []}))\n")
    settings = AgentSettings(directory=str(tmp_path), command=[sys.executable, str(prog)])
    settings.update({"provider": "command"})
    reviewer = Reviewer(settings, Context(), lambda r, v: None)
    assert isinstance(reviewer.backend(), CommandBackend) and reviewer.ready()
    verdict = asyncio.run(reviewer.review(REC))
    assert verdict["verdict"] == "suspicious"
    # The program saw a pseudonym (upper-cased here so it isn't translated back); its answer
    # comes back with the real address.
    assert verdict["reasons"] == ["saw INTERNAL-HOST-1"]
    assert verdict["headline"] == "rare destination seen from 10.0.0.50"


class FakeBackend:
    name = "test agent"

    def __init__(self):
        self.seen = []

    async def review(self, request, call_tool):
        self.seen.append(request["session"])
        return dict(VERDICT)


def test_the_agent_replaces_the_model_in_the_analyzer(engine, tmp_path, data_dir):
    """With the agent chosen, sessions no detector flagged (to destinations few hosts use) are
    reviewed within the hourly limit, a pair at most once an hour, and its verdicts are alerts."""
    a = Analyzer(model=None, config=Config(agent_min_bytes=500))
    settings = AgentSettings(directory=str(tmp_path))
    settings.update({"consent": True, "reviews_per_hour": 5})
    backend = FakeBackend()
    verdicts, reviewed = [], []

    def on_verdict(rec, v):
        reviewed.append((rec["src_ip"], rec["dst_ip"], rec["dst_port"]))
        verdicts.append(a.agent_alert(rec, v))

    async def go():
        reviewer = Reviewer(settings, AgentContext(lambda: a), on_verdict, backend=backend)
        a.agent_submit = reviewer.submit
        for rec in run_engine(engine, "-r", os.path.join(data_dir, "mixed_demo.pcap")):
            a.ingest(rec)
        for _ in range(200):
            await asyncio.sleep(0.01)
            if reviewer.status()["reviewed"] >= 5 or reviewer.queue.empty():
                break
        return reviewer

    reviewer = asyncio.run(go())
    assert reviewer.status()["reviewed"] == 5 and reviewer.status()["reviews_last_hour"] == 5  # the hourly limit
    assert len(reviewed) == 5 and len(set(reviewed)) == 5                  # each pair once
    # Each verdict is an alert of its own, or (on a pair a detector already alerts on) joins that alert.
    assert all(v is not None and (v["kind"] == "agent" and v["severity"] == "high" or v.get("agent_review"))
               for v in verdicts)
    assert all("10." not in s["client"] and "192.168." not in s["client"] for s in backend.seen)  # pseudonyms
    alert = next(v for v in verdicts if v["kind"] == "agent")
    assert alert["agent"]["reasons"] == VERDICT["reasons"] and "Test agent judged" in alert["headline"]
    assert "(85% confident)" in alert["headline"]


def test_detection_settings_over_the_api(engine, models, builtin, tmp_path):
    from test_inventory import AUTH, make_client, run

    async def go():
        dash, c = await make_client(Analyzer(model=builtin))
        try:
            r = await (await c.get("/api/models", headers=AUTH)).json()
            assert r["active"] == "builtin" and [m["kind"] for m in r["models"]][-1] == "agent"
            assert r["calibration"]["benign"] > 1000 and r["calibration"]["attack"] > 100 and len(r["features"]) == 10
            up = await c.post("/api/models/upload", headers=AUTH, json={
                "name": "Team model", "filename": "team.onnx", "content": base64.b64encode(models["rf"]).decode()})
            body = await up.json()
            assert up.status == 200 and body["added"]["direction"] == "higher"
            r = await (await c.post("/api/models/active", headers=AUTH, json={"id": body["added"]["id"]})).json()
            assert r["active"] == body["added"]["id"] and dash.analyzer.model.name == "Team model"
            bad = await c.post("/api/models/upload", headers=AUTH, json={"name": "x", "content": base64.b64encode(
                models["narrow"]).decode()})
            assert bad.status == 400 and "[N, 10]" in (await bad.json())["error"]
            # The agent: the key is write-only; the program can't be set from the dashboard.
            r = await (await c.post("/api/agent/settings", headers=AUTH, json={
                "api_key": "sk-ant-test-0123456789abcdefghij", "consent": True, "command": ["/bin/sh", "-c", "id"],
                "model": "claude-sonnet-5-5"})).json()
            assert r["agent"]["key_saved"] and "sk-ant" not in json.dumps(r) and r["agent"]["command"] == []
            assert r["agent"]["model"] == "claude-sonnet-5-5"
            r = await (await c.post("/api/models/active", headers=AUTH, json={"id": "agent"})).json()
            assert r["active"] == "agent" and dash.analyzer.model is None and dash.analyzer.agent_submit is not None
            dash.reset()  # a new capture keeps the choice
            assert dash.analyzer.agent_submit is not None
            r = await (await c.post("/api/models/remove", headers=AUTH, json={"id": body["added"]["id"]})).json()
            assert all(m["id"] != body["added"]["id"] for m in r["models"])
            if os.name != "nt":
                assert stat.S_IMODE(os.stat(dash.agent_settings.key_path).st_mode) == 0o600
            await c.post("/api/agent/settings", headers=AUTH, json={"api_key": None})
            assert not dash.agent_settings.api_key()
        finally:
            await c.close()
    run(go())


def test_agent_verdicts_join_the_detectors_alerts(engine, data_dir):
    """The agent and a detector on the same pair make one alert, whichever spoke first."""
    a = Analyzer(model=None, config=Config(agent_min_bytes=0))
    beacon = ("10.0.0.23", "192.168.1.105", 443)
    answered = []

    def submit(rec):  # an agent that answers at once: before the beacon has built up
        if (rec["src_ip"], rec["dst_ip"], rec["dst_port"]) == beacon and not answered:
            answered.append(a.agent_alert(rec, {**VERDICT, "reviewer": "test agent"}))

    a.agent_submit = submit
    retracted = set()
    for rec in run_engine(engine, "-r", os.path.join(data_dir, "mixed_demo.pcap")):
        retracted |= {x["id"] for x in a.ingest(rec) if x.get("retracted")}
    assert answered and answered[0]["kind"] == "agent"           # first: the agent's own alert
    assert answered[0]["id"] in retracted                          # then folded into the beacon alert
    pair = [x for x in a.alerts.values() if (x["src_ip"], x["dst_ip"], x["dst_port"]) == beacon]
    assert [x["kind"] for x in pair] == ["beacon"]
    assert pair[0]["agent_review"]["headline"] == VERDICT["headline"]
    # After: a later verdict (benign, here) goes on the detector's alert, and survives its updates.
    rec = {"src_ip": beacon[0], "dst_ip": beacon[1], "dst_port": beacon[2]}
    again = a.agent_alert(rec, {**VERDICT, "verdict": "benign", "headline": "Looks like a monitoring agent"})
    assert again is pair[0] and again["agent_review"]["verdict"] == "benign"
    assert all(x["kind"] != "agent" for x in a.alerts.values() if (x["src_ip"], x["dst_ip"], x["dst_port"]) == beacon)


def test_the_agents_lookups(engine, data_dir):
    a = Analyzer(model=None)
    recs = []
    for rec in run_engine(engine, "-r", os.path.join(data_dir, "mixed_demo.pcap")):
        a.ingest(rec)
        if rec.get("type") == "session" and (rec["src_ip"], rec["dst_ip"], rec["dst_port"]) == \
                ("10.0.0.23", "192.168.1.105", 443):
            recs.append(rec)
    ctx = AgentContext(lambda: a)
    s = ctx.session_summary(recs[-1])
    assert s["client"] == "10.0.0.23" and s["server_port"] == 443 and s["internal_hosts_using_destination"] == 1
    assert "?" not in json.dumps(s.get("http_requests") or [])     # no query strings
    d = ctx.destination_profile("192.168.1.105")
    assert d["internal_hosts"] == ["10.0.0.23"] and 443 in d["ports_used"]
    assert any(x["title"] == "C2 Beaconing" for x in d["alerts"])
    assert ctx.host_profile("10.0.0.23")["is_internal"] and not ctx.host_profile("203.0.113.9")["is_internal"]
    h = ctx.history("10.0.0.23", "192.168.1.105", 443)
    assert h["sessions_seen"] > 100 and h["transport"] == "tcp"
    assert abs(h["regularity"]["period"] - 4.2) < 0.1                # the beacon's schedule
    assert all(isinstance(v, (int, float, str, bool)) for v in h["regularity"].values())
    json.dumps([s, d, h])                                            # all of it can go in a request
    assert ctx.history("10.0.0.23", "192.0.2.1", 1)["sessions_seen"] == 0


def test_claude_through_the_real_sdk(tmp_path):
    """The Anthropic SDK itself, talking to a stand-in for the API (no key, nothing leaves
    the machine): the request it serialises and the replies it parses."""
    anthropic = pytest.importorskip("anthropic")
    httpx2 = pytest.importorskip("httpx2")
    sent = []

    def api(request):
        body = json.loads(request.content)
        sent.append((request.headers.get("anthropic-beta"), body))
        if len(sent) == 1:
            content = [{"type": "tool_use", "id": "toolu_1", "name": "destination_profile",
                        "input": {"address": "203.0.113.77"}}]
            stop = "tool_use"
        else:
            content = [{"type": "text", "text": json.dumps(VERDICT)}]
            stop = "end_turn"
        return httpx2.Response(200, json={"id": "msg_1", "type": "message", "role": "assistant", "model": body["model"],
                                          "content": content, "stop_reason": stop, "stop_sequence": None,
                                          "usage": {"input_tokens": 500, "output_tokens": 80}})

    client = anthropic.AsyncAnthropic(api_key="sk-ant-test",
                                      http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(api)))
    settings = AgentSettings(directory=str(tmp_path))
    settings.update({"consent": True})
    ctx = Context()
    verdict = asyncio.run(Reviewer(settings, ctx, lambda r, v: None,
                                   backend=ClaudeBackend(settings, client=client)).review(REC))
    assert verdict["verdict"] == "malicious" and verdict["usage"]["tool_calls"] == 1
    beta, first = sent[0]
    assert beta == "server-side-fallback-2026-07-01" and first["fallbacks"] == "default"
    assert first["output_config"]["format"]["type"] == "json_schema" and first["model"] == "claude-opus-5-5"
    assert [m["role"] for m in sent[1][1]["messages"]] == ["user", "assistant", "user"]
    assert ("destination", "203.0.113.77") in ctx.asked
