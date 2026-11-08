"""The analyst's workflow around the alerts: the host panel's data, what to look at first, and
the investigation (notes, pinned answers, verdicts and focus, saved to a file and opened
again; a file from elsewhere is checked, never trusted)."""
import asyncio
import json
import os

import pytest

from anta import casefile, triage
from test_server import AUTH, make_client


def test_what_to_look_at_first_ranks_and_explains():
    stories = [{"device": "10.0.0.23", "name": "DESKTOP-1", "severity": "critical", "summary": "It called home.",
                "steps": [{"id": "A1", "severity": "critical", "title": "C2 Beaconing", "first_seen": 1, "headline": "h"}]},
               {"device": "10.0.0.9", "name": "", "severity": "low", "summary": "",
                "steps": [{"id": "A2", "severity": "low", "title": "Shared Periodic Traffic", "first_seen": 2}]}]
    logins = {"total": 3, "accounts": 2, "services": ["FTP", "Telnet"],
              "logins": [{"service": "FTP", "anonymous": False, "accepted": 1, "user": "bob"},
                         {"service": "Telnet", "anonymous": False, "accepted": 0, "user": "eve"}]}
    files = [{"name": "payload.exe", "program": True, "client": "10.0.0.23"}, {"name": "a.png", "program": False}]
    stats = {"conversations": {"ipv4": {"rows": [
        ["10.0.0.44", None, "203.0.113.50", None, 4000, 6_000_000, 2000, 100_000, 0, 5, None, {}],  # an upload
        ["10.0.0.5", None, "198.51.100.9", None, 10, 2_000_000, 10, 10, 0, 5, None, {}],          # one alerted already
    ]}}}
    alerts = [{"src_ip": "10.0.0.5", "dst_ip": "198.51.100.9"}]
    items = triage.build(stories, logins, files, stats, alerts, {"203.0.113.50": "backup-sync.io"})
    assert [i["severity"] for i in items] == ["critical", "high", "high", "info"]  # (the low story is left out)
    first = items[0]
    assert first["title"] == "10.0.0.23: C2 Beaconing" and first["actions"][0] == {"label": "Open the alert", "do": "alert", "id": "A1"}
    assert "2 accounts" in items[1]["title"] and "1 of the logins worked" in items[1]["why"]
    assert "bob" not in json.dumps(items)  # (account names stay in the logins view; the list never needs them)
    assert items[2]["title"].startswith("1 program or script downloaded: payload.exe")
    assert items[3]["title"] == "Largest upload to the internet: 10.0.0.44 → 203.0.113.50 (backup-sync.io), 5.7 MB"
    assert triage.build([], None, [], None, []) == []


def test_an_investigation_file_is_checked_not_trusted(tmp_path):
    pin = casefile.pin({"question": "who?\x00", "summary": "s" * 900, "lines": ["a\x1b[31m"] * 40, "kind": "evil",
                        "table": {"columns": ["Host"], "rows": [{"cells": ["x"] * 20, "filter": "ip.addr == 1.2.3.4"}] * 40}})
    assert pin["kind"] == "ask" and pin["question"] == "who?" and len(pin["summary"]) == 300 and len(pin["lines"]) == 12
    assert "\x1b" not in pin["lines"][0] and len(pin["table"]["rows"]) == 25 and len(pin["table"]["rows"][0]["cells"]) == 8
    with pytest.raises(casefile.CaseError):
        casefile.pin({"lines": []})
    for bad in ("", "not json", json.dumps({"format": "other"}), json.dumps({"format": casefile.FORMAT, "version": 99}),
                "x" * (6 * 1024 * 1024)):
        with pytest.raises(casefile.CaseError):
            casefile.load(bad)
    cap = tmp_path / "t.pcap"
    cap.write_bytes(b"\xd4\xc3\xb2\xa1")
    doc = casefile.load(json.dumps({
        "format": casefile.FORMAT, "version": 1, "notes": "line 1\nline 2\x07",
        "capture": {"name": "t.pcap", "path": str(cap), "size": 4},
        "pins": [{"question": "q"}, "junk", {"lines": ["only lines"]}],
        "verdicts": [{"kind": "exfil", "src_ip": "10.0.0.44", "dst_ip": "1.2.3.4", "status": "confirmed", "note": "yes"},
                     {"kind": "exfil", "status": "pwned"}],
        "focus": [{"label": "f", "filter": "ip.addr == 10.0.0.44"}, {"filter": "a\nb"}],
    }))
    assert doc["notes"] == "line 1\nline 2" and len(doc["pins"]) == 2 and len(doc["verdicts"]) == 1 and len(doc["focus"]) == 1
    assert casefile.openable(doc["capture"]["path"]) and not casefile.openable(str(tmp_path / "notes.txt"))
    assert not casefile.openable("relative.pcap")
    assert casefile.same_capture(doc["capture"], {"name": "t.pcap", "size": 4})
    assert not casefile.same_capture(doc["capture"], {"name": "t.pcap", "size": 5})


def test_the_host_panel_and_the_investigation_endpoints(engine, data_dir):
    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(os.path.join(data_dir, "mixed_demo.pcap"))
            # The host panel: profile, peers, alerts, files.
            r = await c.get("/api/host?addr=10.0.0.21&tz=0", headers=AUTH)
            host = await r.json()
            assert r.status == 200 and host["ip"] == "10.0.0.21" and host["kind"] == "private"
            assert host["lines"][0].startswith("10.0.0.21: Computer") and host["peer_count"] == 22
            assert host["peers"]["rows"][0]["host"] == "142.250.72.14" and host["filter"] == "ip.addr == 10.0.0.21"
            assert (await c.get("/api/host?addr=nope", headers=AUTH)).status == 400
            assert (await c.get("/api/host?addr=10.0.0.21")).status == 401
            r = await c.get("/api/triage", headers=AUTH)
            assert r.status == 200 and isinstance((await r.json())["items"], list)

            # Notes and pins, saved with a verdict, then opened again.
            dash.analyzer.alerts["A00001"] = {"id": "A00001", "kind": "exfil", "src_ip": "10.0.0.44", "dst_ip": "203.0.113.50",
                                              "severity": "high", "title": "Data Exfiltration", "triage": None}
            dash.analyzer.set_triage("A00001", "confirmed", "the backup host")
            assert (await c.put("/api/case/notes", json={"notes": "looking at 10.0.0.44"}, headers=AUTH)).status == 200
            r = await c.post("/api/case/pins", json={"pin": {"question": "who did 10.0.0.44 talk to?", "lines": ["2 hosts"]}},
                             headers=AUTH)
            assert r.status == 200 and len((await r.json())["pins"]) == 1
            assert (await c.post("/api/case/pins", json={"pin": {}}, headers=AUTH)).status == 400
            r = await c.post("/api/case/save", json={"focus": [{"label": "host", "filter": "ip.addr == 10.0.0.44"}]}, headers=AUTH)
            saved = await r.json()
            assert saved["name"] == "mixed_demo.anta-investigation.json"
            content = await (await c.get(saved["download"], headers=AUTH)).text()
            doc = json.loads(content)
            assert doc["notes"] == "looking at 10.0.0.44" and doc["verdicts"][0]["status"] == "confirmed"
            assert doc["focus"] == [{"label": "host", "filter": "ip.addr == 10.0.0.44"}] and "packets" not in doc["pins"][0]

            dash.case = {"notes": "", "pins": []}
            dash.analyzer.set_triage("A00001", "new", "")
            r = await c.post("/api/case/open", json={"content": content}, headers=AUTH)
            opened = await r.json()
            assert opened["applied"] and opened["same"] and opened["matched"] == 1
            assert dash.case["notes"] == "looking at 10.0.0.44" and len(dash.case["pins"]) == 1
            assert dash.analyzer.alerts["A00001"]["triage"]["status"] == "confirmed"

            # Made on another capture: nothing is applied until the user says so.
            other = json.loads(content)
            other["capture"] = {"name": "elsewhere.pcap", "path": "/nonexistent/elsewhere.pcap", "size": 1}
            other["notes"] = "other notes"
            r = await c.post("/api/case/open", json={"content": json.dumps(other)}, headers=AUTH)
            o = await r.json()
            assert not o["applied"] and not o["same"] and not o["can_open"] and o["path"] == ""
            assert dash.case["notes"] == "looking at 10.0.0.44"
            r = await c.post("/api/case/open", json={"content": json.dumps(other), "apply": True}, headers=AUTH)
            assert (await r.json())["applied"] and dash.case["notes"] == "other notes"
            assert (await c.post("/api/case/open", json={"content": "{}"}, headers=AUTH)).status == 400
        finally:
            await c.close()
    asyncio.run(go())
