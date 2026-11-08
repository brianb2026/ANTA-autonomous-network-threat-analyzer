"""Ignored alert sources: alerts from an address, a network or a MAC the analyst chose to ignore
(of every kind, or of one kind) are set aside, not deleted: every view loses them at once, and
taking the rule off brings them back with their verdicts. Alerts *to* that address still show."""
import asyncio
import json
import os

import pytest

from anta import ignore
from anta.analyzer import TITLES, Analyzer
from anta.tools import samples
from conftest import run_engine
from test_server import AUTH, make_client

SCANNER = "10.50.0.9"              # samples.scan_lab: an internal host scanning ports and hosts
SPOOFER = "02:00:00:00:07:66"      # samples.arp_spoof_lab: the MAC claiming the gateway's address


@pytest.mark.parametrize("text, canon", [
    ("10.0.0.1", "10.0.0.1"), (" 10.0.0.1 ", "10.0.0.1"), ("10.0.0.7/24", "10.0.0.0/24"), ("10.0.0.1/32", "10.0.0.1"),
    ("FD00::0001", "fd00::1"), ("fd00::/64", "fd00::/64"), ("02-00-00-00-07-66", SPOOFER), ("02:00:00:00:07:66", SPOOFER),
])
def test_sources_are_written_one_way(text, canon):
    assert ignore.canonical(text) == canon


@pytest.mark.parametrize("text", ["", "router", "10.0.0.300", "10.0.0.0/33", "02:00:00:00:07", "10.0.0.1; rm -rf"])
def test_what_isnt_a_source_says_so(text):
    with pytest.raises(ignore.IgnoreError):
        ignore.canonical(text)


def test_rules_are_cleaned_and_saved_owner_only(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTA_DATA_DIR", str(tmp_path))
    rules = ["10.0.0.1", {"source": "10.0.0.1"}, {"source": "10.0.0.1 ", "kind": "beacon", "note": "the router\x00polls"}]
    saved = ignore.save(rules, TITLES)
    assert saved == [{"source": "10.0.0.1", "kind": "", "note": ""},
                     {"source": "10.0.0.1", "kind": "beacon", "note": "the router polls"}]  # (the repeat is dropped)
    assert ignore.load(TITLES) == saved
    if os.name != "nt":
        assert os.stat(ignore.path()).st_mode & 0o777 == 0o600
    for bad in ([{"source": "10.0.0.1", "kind": "nonsense"}], "10.0.0.1", [{"source": "the router"}]):
        with pytest.raises(ignore.IgnoreError):
            ignore.save(bad, TITLES)
    with open(ignore.path(), "w", encoding="utf-8") as fh:  # (a hand-edited file: a bad line drops only itself)
        json.dump({"rules": [{"source": "nonsense"}, {"source": "10.0.0.2"}]}, fh)
    assert ignore.load(TITLES) == [{"source": "10.0.0.2", "kind": "", "note": ""}]


def test_what_a_rule_matches():
    m = ignore.Matcher([{"source": "10.0.0.0/24", "kind": "beacon", "note": ""}, {"source": SPOOFER, "kind": "", "note": ""},
                        {"source": "fd00::1", "kind": "", "note": ""}])
    assert m.match({"kind": "beacon", "src_ip": "10.0.0.9"}) == 0
    assert m.match({"kind": "scan", "src_ip": "10.0.0.9"}) is None                       # another kind
    assert m.match({"kind": "beacon", "src_ip": "192.168.1.5", "dst_ip": "10.0.0.9"}) is None  # to it, not from it
    assert m.match({"kind": "arp_spoof", "src_ip": "192.168.7.1", "offender": SPOOFER}) == 1   # the device it blames
    assert m.match({"kind": "beacon", "src_ip": "fd00::1"}) == 2
    assert m.match({"kind": "shared", "src_ip": "12 hosts"}) is None
    assert not ignore.Matcher([]) and ignore.Matcher([]).match({"src_ip": "10.0.0.9"}) is None


@pytest.fixture(scope="module")
def lab_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("ignore") / "lab.pcap"
    samples.write_pcap(str(path), sorted(samples.scan_lab() + samples.arp_spoof_lab(t0=300.0), key=lambda f: f[0]))
    return str(path)


def analyze(engine, path, rules=None):
    a = Analyzer()
    if rules:
        a.set_ignored(rules)
    out = []
    for rec in run_engine(engine, "-r", path):
        out += a.ingest(rec)
    return a, out


def test_ignored_alerts_are_set_aside_and_come_back(engine, lab_pcap):
    a, _ = analyze(engine, lab_pcap)
    scans = sorted(x["id"] for x in a.alerts.values() if x["kind"] == "scan")
    spoofs = sorted(x["id"] for x in a.alerts.values() if x["kind"] == "arp_spoof")
    assert scans and spoofs and all(a.alerts[i]["src_ip"] == SCANNER for i in scans)
    total = len(a.alerts)
    a.set_triage(scans[0], "investigating", "checking the switch port")

    changes = a.set_ignored([{"source": SCANNER, "kind": "", "note": ""}])
    assert sorted(c["id"] for c in changes if c.get("retracted")) == scans
    assert not set(scans) & set(a.alerts) and sorted(a.ignored) == scans and len(a.alerts) == total - len(scans)
    assert a.ignored_counts() == [len(scans)]
    assert a.summary()["ignored"] == len(scans) and a.summary()["alerts"] == total - len(scans)

    # By the device an alert blames (a MAC), and only of one kind.
    a.set_ignored([{"source": SCANNER, "kind": "", "note": ""}, {"source": SPOOFER, "kind": "arp_spoof", "note": ""}])
    assert not [x for x in a.alerts.values() if x["kind"] in ("scan", "arp_spoof")]
    assert a.ignored_counts() == [len(scans), len(spoofs)]
    a.set_ignored([{"source": SPOOFER, "kind": "dga", "note": ""}])  # (another kind: the ARP alerts come back, and the scans)
    assert len(a.alerts) == total and not a.ignored

    back = a.alerts[scans[0]]
    assert back["triage"]["status"] == "investigating" and back["triage"]["note"] == "checking the switch port"


def test_a_source_ignored_from_the_start_never_shows(engine, lab_pcap):
    plain, _ = analyze(engine, lab_pcap)
    a, out = analyze(engine, lab_pcap, [{"source": "10.50.0.0/24", "kind": "scan", "note": ""}])
    assert not [x for x in a.alerts.values() if x["kind"] == "scan"]
    assert not [x for x in out if not x.get("retracted") and x.get("kind") == "scan"]  # (never sent to the browser)
    assert sorted(a.alerts) == sorted(i for i, x in plain.alerts.items() if x["kind"] != "scan")
    a.set_ignored([])
    assert sorted(a.alerts) == sorted(plain.alerts)


def test_the_ignored_endpoints(engine, lab_pcap, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTA_DATA_DIR", str(tmp_path))
    analyzer, _ = analyze(engine, lab_pcap)
    scans = {x["id"] for x in analyzer.alerts.values() if x["kind"] == "scan"}

    async def go():
        dash, c = await make_client(analyzer)
        try:
            r = await c.put("/api/ignored", json={"rules": [{"source": SCANNER, "note": "the lab's scanner"}]}, headers=AUTH)
            d = await r.json()
            assert r.status == 200
            assert d["rules"] == [{"source": SCANNER, "kind": "", "note": "the lab's scanner", "count": len(scans)}]
            assert d["ignored"] == len(scans) and {"kind": "scan", "title": TITLES["scan"]} in d["kinds"]
            assert scans <= dash.retracted  # (every open window drops them on the next flush)
            listed = {x["id"] for x in await (await c.get("/api/alerts", headers=AUTH)).json()}
            assert listed and not listed & scans
            assert json.load(open(os.path.join(str(tmp_path), "ignored-sources.json")))["rules"][0]["source"] == SCANNER
            assert (await (await c.get("/api/ignored", headers=AUTH)).json())["ignored"] == len(scans)
            d = await (await c.put("/api/ignored", json={"rules": []}, headers=AUTH)).json()
            assert d == {**d, "rules": [], "ignored": 0} and scans <= set(dash.pending) and not scans & dash.retracted
            assert (await c.put("/api/ignored", json={"rules": [{"source": "the router"}]}, headers=AUTH)).status == 400
            assert (await c.get("/api/ignored")).status == 401
        finally:
            await c.close()
    asyncio.run(go())


def test_saved_rules_apply_to_the_next_capture(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTA_DATA_DIR", str(tmp_path))
    ignore.save([{"source": SCANNER}], TITLES)

    async def go():
        dash, c = await make_client()
        try:
            assert dash.analyzer.ignoring.rules[0]["source"] == SCANNER  # (read when the app starts)
            dash.reset()
            assert dash.analyzer.ignoring.rules[0]["source"] == SCANNER  # (and kept for a new capture)
        finally:
            await c.close()
    asyncio.run(go())
