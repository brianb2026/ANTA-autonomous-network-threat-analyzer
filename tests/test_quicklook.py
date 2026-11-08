"""Quick look, behind the right-click menus: what ANTA already knows about an address, a
domain, a MAC address, a hash, a TLS fingerprint, a URL or a file name, as short lines of
plain text, from the analysis already done (nothing is looked up outside the computer)."""
import json
import os

import pytest

from anta import netmap
from anta.agent_context import AgentContext
from anta.analyzer import Analyzer
from anta.objects import list_objects
from anta.quicklook import alerts_involving, classify, lookup
from conftest import run_engine


@pytest.mark.parametrize("q,kind", [
    ("10.0.0.23", "ip"), ("2001:db8::1", "ip"), ("AA:BB:CC:00:11:22", "mac"), ("aa-bb-cc-00-11-22", "mac"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"), ("d" * 40, "sha1"),
    ("a" * 32, "md5"),
    ("t13d1516h2_8daaf6152771_02713d6af862", "ja4"), ("t130200_1301_234ea6891581", "ja4s"),
    ("https://evil.example/drop.exe", "url"), ("update.cdn-telemetry.net", "domain"), ("invoice.pdf.exe", "filename"),
    ("hello world", "text"), ("999.1.1.1", "text"),
])
def test_what_kind_of_thing(q, kind):
    assert classify(q) == kind


@pytest.fixture(scope="module")
def demo(engine, data_dir):
    a = Analyzer(model=None)
    for rec in run_engine(engine, "-r", os.path.join(data_dir, "mixed_demo.pcap")):
        a.ingest(rec)
    sessions = [r for r in run_engine(engine, "--index", "-r", os.path.join(data_dir, "mixed_demo.pcap"))
                if r.get("type") == "session"]
    stats = next(r for r in run_engine(engine, "--stats", "-r", os.path.join(data_dir, "mixed_demo.pcap"))
                 if r.get("type") == "stats")
    return a, AgentContext(lambda: a), sessions, netmap.build(stats)["nodes"]


def test_an_address(demo):
    a, ctx, sessions, nodes = demo
    fast = lookup("192.168.1.105", ctx, a)  # (the menu's first answer: the analyzer alone)
    assert fast["kind"] == "ip" and fast["alerts"][0]["title"] == "C2 Beaconing"
    assert any("used by 1 of your hosts" in x.lower() for x in fast["lines"])
    full = lookup("192.168.1.105", ctx, a, nodes, sessions, list_objects(sessions))
    assert "update.cdn-telemetry.net" in full["lines"][0]  # the name it answers to, from the map
    assert full["lines"][-1].startswith("1 alert (1 critical): C2 Beaconing")
    assert all(isinstance(x, str) and "\n" not in x for x in full["lines"])
    json.dumps(full)


def test_a_domain_a_file_and_unknowns(demo):
    a, ctx, sessions, nodes = demo
    d = lookup("cdn.jsdelivr.net", ctx, a, nodes, sessions)
    assert d["kind"] == "domain" and any(x.startswith("Resolved to ") for x in d["lines"])
    assert any("Named in" in x for x in d["lines"]) and any(x == "Part of jsdelivr.net" for x in d["lines"])
    files = list_objects(sessions)
    f = next(o for o in files if o.get("sha256"))
    h = lookup(f["sha256"], ctx, a, nodes, sessions, files)
    assert h["kind"] == "sha256" and h["lines"][0].startswith(f"File {f['name']} ")
    assert lookup("203.0.113.250", ctx, a)["lines"][0] == "A documentation address (not routed on the internet)"
    assert lookup("nothing.example", ctx, a)["lines"] == ["Nothing else is known about it in this capture"]
    hosts = [{"addr": "10.0.0.7", "name": "printer-2", "vendor": "Brother", "macs": ["00:1b:a9:12:34:56"]}]
    assert lookup("00-1B-A9-12-34-56", ctx, a, hosts)["lines"][0] == "10.0.0.7 · printer-2 · Brother"
    assert lookup("00:1b:a9:00:00:01", ctx, a, hosts)["lines"][0] == "No address in this capture uses it"


def test_alerts_involving(demo):
    a = demo[0]
    hits = alerts_involving(a, "10.0.0.23")
    assert hits and hits[0]["severity"] == "critical" and all({"id", "title", "severity"} == set(h) for h in hits)
    assert alerts_involving(a, "198.18.0.99") == []


def test_the_lookup_endpoint():
    from test_server import AUTH, make_client, run

    async def go():
        dash, c = await make_client()
        try:
            r = await (await c.get("/api/lookup", params={"q": "10.0.0.5"}, headers=AUTH)).json()
            assert r["kind"] == "ip" and r["lines"] and r["alerts"] == []
            assert (await c.get("/api/lookup", params={"q": ""}, headers=AUTH)).status == 400
            assert (await c.get("/api/lookup", params={"q": "10.0.0.5"})).status == 401
        finally:
            await c.close()
    run(go())
