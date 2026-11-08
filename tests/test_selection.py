"""Selections and focus: packets selected in the list become a scope every analysis tool can
be limited to (as one display filter, read from a file when long), and Explain with AI over
them sends evidence with secrets and internal addresses taken out."""
import asyncio
import base64
import os
import random
import subprocess

import pytest

from anta import explain_ai, scopes
from anta.agent import AgentSettings, Pseudonyms
from anta.analyzer import Analyzer
from anta.tools import samples
from conftest import run_engine
from test_server import AUTH, make_client

SECRET = "Sup3rS3cret!"  # noqa: S105 - the login lab's made-up password


def count(engine, path, *args):
    return run_engine(engine, "--packets", "-r", path, "--count", "--limit", "1", *args)[-1]["matched_total"]


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------- the engine

def test_frame_sets_match_one_by_one_and_bound_the_parser(engine, data_dir, tmp_path):
    demo = os.path.join(data_dir, "http_download.pcap")
    rng = random.Random(3)
    picks = sorted(rng.sample(range(1, 2151), 300))
    ranges = ", ".join(f"{a}..{a + 2}" if i % 3 == 0 else str(a) for i, a in enumerate(picks))
    want = set()
    for i, a in enumerate(picks):
        want.update(range(a, a + 3) if i % 3 == 0 else [a])
    want = {n for n in want if n <= 2150}
    path = tmp_path / "sel.flt"
    path.write_text(f"frame.number in {{{ranges}}}\n")
    got = run_engine(engine, "--packets", "-r", demo, "--display-filter-file", str(path), "--limit", "5000")
    assert {r["n"] for r in got if r.get("type") == "packet"} == want
    # Ports in a set (numbers, the fast path) and a set with an empty range.
    assert count(engine, demo, "-Y", "tcp.port in {80, 8000..8100}") == count(engine, demo, "-Y", "tcp.port == 80 || (tcp.port >= 8000 && tcp.port <= 8100)")
    assert count(engine, demo, "-Y", "frame.number in {9..3, 5}") == 1
    deep = subprocess.run([engine, "--check-filter", "(" * 300 + "tcp" + ")" * 300], capture_output=True, text=True).stdout
    assert "nested too deeply" in deep
    many = tmp_path / "many.flt"
    many.write_text(" || ".join(["tcp"] * 5000))
    r = subprocess.run([engine, "--packets", "-r", demo, "--display-filter-file", str(many)], capture_output=True, text=True)
    assert r.returncode == 2 and "too many terms" in r.stderr


# ---------------------------------------------------------------- the scope module

def test_frames_and_parts_become_one_filter():
    assert scopes.parse_frames("40-,1-20,21,35") == [(1, 21), (35, 35), (40, None)]
    assert scopes.frames_clause(scopes.parse_frames("1-20,35,40-")) == "(frame.number in {1..20, 35} || frame.number >= 40)"
    assert scopes.frames_count([(1, 20), (35, 35)]) == 21
    for bad in ("", "3-1", "0", "1-2-3", "a"):
        with pytest.raises(scopes.ScopeError):
            scopes.parse_frames(bad)
    flt = scopes.build_filter([{"filter": "dns", "frames": "1-9"}, {"filter": "ip.addr == 10.0.0.5"}], lambda a: "x")
    assert flt == "((dns) && frame.number in {1..9}) || ((ip.addr == 10.0.0.5))"
    with pytest.raises(scopes.ScopeError):
        scopes.build_filter([], lambda a: "x")
    with pytest.raises(scopes.ScopeError):
        scopes.build_filter([{"filter": "tcp\nudp"}], lambda a: "x")


def test_pseudonyms_cover_ports_brackets_and_macs():
    n = Pseudonyms(True)
    text = "TCP 10.0.0.12:51018 ↔ 3.92.181.98:443; [fd00::a]:5353; ARP 02:00:00:00:00:01 is at 10.0.0.1, 10.0.0.12."
    out = n.scrub_text(text)
    for real in ("10.0.0.12", "fd00::a", "02:00:00:00:00:01", "10.0.0.1,"):
        assert real not in out
    assert "3.92.181.98:443" in out and "internal-host-1:51018" in out and "mac-1" in out
    assert n.restore(out) == text
    assert Pseudonyms(False).scrub_text(text) == text  # (the user allowed sharing them)


def test_secrets_never_reach_the_evidence(engine, tmp_path):
    lab = str(tmp_path / "logins.pcap")
    samples.write_pcap(lab, samples.login_lab(SECRET))
    rows = [r for r in run_engine(engine, "--packets", "-r", lab, "--limit", "1000") if r.get("type") == "packet"]
    text = explain_ai.evidence("the lab", rows, len(rows), rows[0]["ts"], None, None, [])
    for secret in (SECRET, base64.b64encode(SECRET.encode()).decode(), base64.b64encode(f"\0erin\0{SECRET}".encode()).decode(),
                   "guest@example.com"):
        assert secret not in text
    assert "PASS [hidden]" in text and "C: [hidden]" in text
    assert explain_ai.redact("GET /a?user=x&password=y HTTP/1.1") == "GET /a?[query removed] HTTP/1.1"
    assert explain_ai.redact("Standard query 0x1 A aGVsbG8gd29ybGQgdGhpcyBpcyBsb25n.exfil.net").endswith("exfil.net")


def test_a_models_answer_is_checked_and_its_names_restored():
    n = Pseudonyms(True)
    n.scrub_text("10.0.0.5 talked")
    a = explain_ai.clean({"summary": "internal-host-1 beacons", "assessment": "made up", "confidence": 3,
                          "observations": [{"text": "see internal-host-1", "frames": [3, 1, 1, True, -2, "x"]}, "junk"],
                          "next_steps": ["block it", ""]}, n)
    assert a["summary"] == "10.0.0.5 beacons" and a["assessment"] == "unclear" and a["confidence"] == 1.0
    assert a["observations"] == [{"text": "see 10.0.0.5", "frames": [1, 3]}] and a["next_steps"] == ["block it"]


# ---------------------------------------------------------------- the server

@pytest.fixture(scope="module")
def lab_pcap(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("selection") / "samples.pcap")
    samples.write_pcap(path, samples.all_samples())
    return path


def test_every_tool_follows_a_selection(engine, lab_pcap):
    async def go():
        analyzer = Analyzer()
        for rec in run_engine(engine, "-r", lab_pcap):
            analyzer.ingest(rec)
        dash, c = await make_client(analyzer)
        dash.packets.reset(lab_pcap)
        post = lambda path, body: c.post(path, json=body, headers=AUTH)  # noqa: E731
        get = lambda path: c.get(path, headers=AUTH)  # noqa: E731
        try:
            # Explicit frames, within the list's display filter.
            r = await (await post("/api/scope", {"parts": [{"filter": "tcp", "frames": "1-400"}]})).json()
            assert r["count"] == count(engine, lab_pcap, "-Y", "tcp && frame.number <= 400") and r["label"] == "selected packets"
            sid = r["id"]
            page = await (await get(f"/api/packets?scope={sid}&count=1&limit=1000")).json()
            assert page["matched_total"] == r["count"] and all(p["n"] <= 400 for p in page["packets"])
            st = await (await get(f"/api/stats?scope={sid}")).json()
            assert st["stats"]["properties"]["frames"] == r["count"]
            # A second selection within it narrows it.
            inner = await (await post("/api/scope", {"parts": [{"filter": "tcp.flags.syn == 1"}], "within": sid,
                                                     "label": "connection attempts"})).json()
            assert inner["parent"] == sid and inner["label"] == "connection attempts"
            assert inner["count"] == count(engine, lab_pcap, "-Y", "tcp && frame.number <= 400 && tcp.flags.syn == 1")
            # Session tools: only the selection's connections.
            objects = (await (await get("/api/objects")).json())["objects"]
            exe = next(o for o in objects if o["name"] == "payload.exe")
            conv = await (await post("/api/scope", {"parts": [{"filter": f"ip.addr == {exe['client']} && ip.addr == {exe['server']}"}]})).json()
            scoped = (await (await get(f"/api/objects?scope={conv['id']}")).json())["objects"]
            assert {o["name"] for o in scoped} >= {"payload.exe"} and len(scoped) < len(objects)
            alerts = (await (await get(f"/api/scope/{conv['id']}/alerts")).json())["alerts"]
            assert alerts and all(analyzer.alerts[a]["dst_ip"] in (exe["client"], exe["server"]) or
                                  analyzer.alerts[a]["src_ip"] in (exe["client"], exe["server"]) for a in alerts)
            story = await (await get(f"/api/storyline?scope={conv['id']}")).json()
            assert all(s["device"] in (exe["client"], exe["server"]) for s in story["stories"])
            for path in ("/api/rhythm", "/api/logins", "/api/fingerprints", "/api/eta", "/api/assets"):
                assert (await get(f"{path}?scope={conv['id']}")).status == 200, path
            ex = await (await get(f"/api/explain?scope={conv['id']}")).json()
            assert ex["conversations"] and all(exe["client"] in (x["client"].rsplit(":", 1)[0], x["server"].rsplit(":", 1)[0])
                                               for x in ex["conversations"])
            # Save just the selection.
            saved = await (await post("/api/save/packets", {"scope": "all", "selection": sid})).json()
            assert saved["packets"] == r["count"] and saved["name"] == "samples_selection.pcap"
            # A long selection (thousands of separate packets) goes to the engine in a file.
            frames = ",".join(str(n) for n in range(1, 4001, 2))
            big = await (await post("/api/scope", {"parts": [{"frames": frames}]})).json()
            assert big["count"] == count(engine, lab_pcap, "-Y", "frame.number <= 4000 && frame.number & 1") and big["filter_length"] > 8000
            # Stale or foreign ids, and bad selections.
            gone = await get("/api/packets?scope=nope")
            assert gone.status == 410 and (await gone.json())["scope_gone"] is True
            assert (await post("/api/scope", {"parts": [{"frames": "5-1"}]})).status == 400
            assert (await post("/api/scope", {"parts": [{"filter": "ip.addr == 192.0.2.250"}]})).status == 409
            assert (await c.post("/api/scope", json={"parts": [{"frames": "1"}]})).status == 401
            dash.reset()  # a new capture: the old selections are gone
            dash.packets.reset(lab_pcap)
            assert (await get(f"/api/stats?scope={sid}")).status == 410
        finally:
            await c.close()
    run(go())


def test_explain_with_ai_sends_only_evidence(engine, tmp_path, monkeypatch):
    lab = str(tmp_path / "logins.pcap")
    samples.write_pcap(lab, samples.login_lab(SECRET))

    async def go():
        dash, c = await make_client()
        dash.packets.reset(lab)
        # Settings of its own: other tests set up providers in the shared test data folder.
        dash.agent_settings = AgentSettings(directory=str(tmp_path))
        dash.reviewer.settings = dash.agent_settings
        dash.reviewer.forget_backend()
        post = lambda path, body: c.post(path, json=body, headers=AUTH)  # noqa: E731
        try:
            s = await (await post("/api/scope", {"parts": [{"filter": "tcp"}]})).json()
            p = await (await post("/api/explain/ai", {"scope": s["id"], "preview": True})).json()
            assert p["ready"] is False and p["model"] is None and p["packets"] == s["count"]
            text = p["preview"]
            assert SECRET not in text and "10.20.0.5" not in text and "internal-host-" in text and "PASS [hidden]" in text
            assert (await post("/api/explain/ai", {"scope": s["id"]})).status == 409  # no model set up
            # With a model (here a stand-in for the provider call): the same text goes out, the answer comes back real.
            dash.agent_settings.update({"provider": "openai", "model": "gpt-test", "consent": True})
            dash.agent_settings.set_api_key("sk-test-not-real", "openai")
            sent = {}

            async def fake(settings, system, text, schema, effort="low", max_tokens=8000):
                sent["text"], sent["system"] = text, system
                host = text.split("internal-host-")[1].split()[0].rstrip(":,")
                return {"summary": f"internal-host-{host} logs in to many services in clear text", "assessment": "worth a look",
                        "observations": [{"text": "FTP login", "frames": [1, 4]}], "next_steps": ["Use SFTP"], "confidence": 0.8}
            import anta.agent_providers as ap
            monkeypatch.setattr(ap, "ask_model_json", fake)
            a = await (await post("/api/explain/ai", {"scope": s["id"]})).json()
            assert sent["text"] == text and "analyst's assistant" in sent["system"]
            assert a["summary"].startswith("10.20.0.") and a["assessment"] == "worth a look" and a["observations"][0]["frames"] == [1, 4]
            stream = await (await post("/api/explain/ai", {"stream": "tcp:0", "preview": True})).json()
            assert stream["packets"] > 0 and SECRET not in stream["preview"]
            assert (await post("/api/explain/ai", {})).status == 400
        finally:
            await c.close()
    run(go())
