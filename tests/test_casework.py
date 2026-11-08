"""Casework tools: saving packets (all, displayed, marked), Export Objects (every file
a capture carries, written out byte for byte), the indicator sweep, analyst triage,
and the server endpoints behind them."""
import asyncio
import hashlib
import json
import socket
import subprocess

import pytest

from anta import hunt
from anta.analyzer import Analyzer
from anta.objects import list_objects, safe_name
from anta.security import validate_session
from anta.tools import samples
from conftest import run_engine
from test_server import AUTH, make_client


@pytest.fixture(scope="module")
def all_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("casework") / "samples.pcap"
    samples.write_pcap(path, samples.all_samples())
    return str(path)


def index(engine, path):
    return [validate_session(r) for r in run_engine(engine, "--index", "-r", path) if r["type"] == "session"]


def count(engine, path, *args):
    return run_engine(engine, "--packets", "-r", path, "--count", "--limit", "1", *args)[-1]["matched_total"]


# ---------------------------------------------------------------- the engine

def test_save_writes_exactly_the_selected_packets(engine, all_pcap, tmp_path):
    out = str(tmp_path / "out.pcap")
    for selection in (["-Y", "ftp || ftp-data"], ["-Y", "tcp.flags == 0"], ["-f", "udp port 53"],
                      ["--frames", "1-10,20"], ["-Y", "dns", "--frames", "1-400"]):
        saved = run_engine(engine, "--packets", "-r", all_pcap, "--save", out, *selection)[-1]
        expected = count(engine, all_pcap, *[a for a in selection if a != "--frames"]) if "--frames" not in selection \
            else None
        if selection == ["--frames", "1-10,20"]:
            expected = 11
        if expected is not None:
            assert saved["packets"] == expected, selection
        assert count(engine, out) == saved["packets"]  # the copy reads back, every frame of it
    # Nothing matched: nothing is written.
    saved = run_engine(engine, "--packets", "-r", all_pcap, "--save", str(tmp_path / "none.pcap"), "-Y", "ip.addr == 192.0.2.250")
    assert saved[-1]["packets"] == 0 and not (tmp_path / "none.pcap").exists()


def test_bad_frame_lists_are_refused(engine, all_pcap, tmp_path):
    for bad in ("0-3", "5-2", "x", "1,,2"):
        p = subprocess.run([engine, "--packets", "-r", all_pcap, "--save", str(tmp_path / "o.pcap"), "--frames", bad],
                           capture_output=True, text=True)
        assert p.returncode == 2 and "frames" in p.stderr


def test_the_index_is_compact(engine, all_pcap):
    records = run_engine(engine, "--index", "-r", all_pcap)
    sessions = [r for r in records if r["type"] == "session"]
    assert sessions and all(r["final"] and "events" not in r and "rate" not in r for r in sessions)
    assert records[-1] == {"type": "index_done", "packets": records[-1]["packets"], "sessions": len(sessions)}


def test_every_listed_file_is_written_out_byte_for_byte(engine, all_pcap, tmp_path):
    objects = list_objects(index(engine, all_pcap))
    assert {o["proto"] for o in objects} == {"HTTP", "SMB", "FTP"} and len(objects) >= 7
    for o in objects:
        out = tmp_path / "obj.bin"
        rec = run_engine(engine, "--object", o["id"], "--object-out", str(out), "-r", all_pcap)[-1]
        assert rec["found"] and rec["written"] == o["size"]
        assert hashlib.sha256(out.read_bytes()).hexdigest() == o["sha256"], o["name"]
    gw3 = next(o for o in objects if o["name"] == "gw3_backup.config")
    assert gw3["direction"] == "upload" and gw3["client"] == "10.9.5.1" and gw3["type"] == "text"
    exe = next(o for o in objects if o["name"] == "payload.exe")
    assert exe["program"] and exe["type"] == "Windows executable (PE)"
    report = next(o for o in objects if o["name"] == "report.bin")  # chunked and gzip: written decoded
    assert report["size"] == 9000


def test_an_unknown_object_is_not_found(engine, all_pcap, tmp_path):
    p = subprocess.run([engine, "--object", "999999:h:0", "--object-out", str(tmp_path / "x"), "-r", all_pcap],
                       capture_output=True, text=True)
    assert p.returncode == 1 and json.loads(p.stdout.splitlines()[-1])["found"] is False


def test_safe_names():
    assert safe_name("../../etc/passwd") == "passwd"
    assert safe_name("C:\\Windows\\evil.exe") == "evil.exe"
    assert safe_name("CON.txt") == "_CON.txt"
    assert safe_name("a\x00b<c>.exe") == "a_b_c_.exe"
    assert safe_name("", "file.bin") == "file.bin"


# ---------------------------------------------------------------- indicator sweep

def test_indicators_are_read_as_reports_print_them():
    found, rejected = hunt.parse("""
        203.0.113[.]108          # a C2
        hxxps://evil[.]example/drop/x.exe
        10.0.0.0/8, 192.168.5.1:4444
        2001:db8::1
        *.bad-domain.example
        365B1BE160D155F006E3D7734DF2162D13B82039B89931A756C4642CF22446CC
        e7d705a3286e19ea42f587b344ee6865
        t13d1516h2_8daaf6152771_02713d6af862
        file:svc.exe
        da39a3ee5e6b4b0d3255bfef95601890afd80709
        what?
    """)
    kinds = {(i["kind"], i["value"], i.get("port")) for i in found}
    assert ("ip", "203.0.113.108", None) in kinds and ("ip", "192.168.5.1", 4444) in kinds
    assert ("net", "10.0.0.0/8", None) in kinds and ("ip", "2001:db8::1", None) in kinds
    assert ("domain", "bad-domain.example", None) in kinds
    assert ("sha256", "365b1be160d155f006e3d7734df2162d13b82039b89931a756c4642cf22446cc", None) in kinds
    assert ("ja3", "e7d705a3286e19ea42f587b344ee6865", None) in kinds
    assert ("ja4", "t13d1516h2_8daaf6152771_02713d6af862", None) in kinds
    assert ("file", "svc.exe", None) in kinds
    url = next(i for i in found if i["kind"] == "url")
    assert url["host"] == "evil.example" and url["path"] == "/drop/x.exe"
    reasons = {r["raw"]: r["reason"] for r in rejected}
    assert "SHA-1" in reasons["da39a3ee5e6b4b0d3255bfef95601890afd80709"] and "what?" in reasons


def test_the_sweep_finds_where_each_indicator_turned_up(engine, all_pcap):
    sessions = index(engine, all_pcap)
    gw3_sha = hashlib.sha256(samples.GW3_CONFIG.encode()).hexdigest()
    result = hunt.sweep(f"{samples.FALSE_ADDR}\n{samples.MIRROR}\n10.9.5.0/28\n{gw3_sha}\nfile:payload.exe\n"
                        "nothing-here.example\n198.51.100.66:443", sessions,
                        [{"id": "A1", "title": "Poisoned DNS Answers", "src_ip": samples.GW3,
                          "dns": {"name": samples.MIRROR, "answers": [samples.FALSE_ADDR]}}])
    by = {r["indicator"]: r for r in result["results"]}
    false = by[samples.FALSE_ADDR]
    # The DNS answer that pointed there, and the hand-built TCP that followed.
    assert any("DNS answer" in r["where"] for r in false["rows"]) and any("destination" in r["where"] for r in false["rows"])
    assert false["alerts"] == [{"id": "A1", "title": "Poisoned DNS Answers"}]
    assert by[samples.MIRROR]["hits"] == 3  # all three resolvers were asked
    assert by["10.9.5.0/28"]["hits"] >= 2   # gw3's uplink: its FTP control and data connections
    assert "FTP upload" in by[gw3_sha]["rows"][0]["where"]
    assert "HTTP download" in by["file:payload.exe"]["rows"][0]["where"]
    assert by["198.51.100.66:443"]["hits"] == 1
    assert by["nothing-here.example"]["hits"] == 0
    assert result["matched"] == len(result["results"]) - 1
    # Every "show packets" filter is one the packet list accepts.
    checks = run_engine(engine, *[a for r in result["results"] if r["filter"] for a in ("--check-filter", r["filter"])])
    assert all(c["ok"] for c in checks)


# ---------------------------------------------------------------- triage

def test_a_verdict_survives_the_alert_being_updated(engine, all_pcap):
    analyzer = Analyzer()
    records = run_engine(engine, "-r", all_pcap)
    for rec in records:
        analyzer.ingest(rec)
    alert = next(iter(analyzer.alerts.values()))
    analyzer.set_triage(alert["id"], "confirmed", "  checked the hash  ")
    for rec in records:  # the same evidence again: every alert is rebuilt
        analyzer.ingest(rec)
    again = analyzer.alerts[alert["id"]]
    assert again["triage"]["status"] == "confirmed" and again["triage"]["note"] == "checked the hash"
    with pytest.raises(ValueError):
        analyzer.set_triage(alert["id"], "pwned", "")


# ---------------------------------------------------------------- the endpoints

def run(coro):
    return asyncio.run(coro)


def test_saving_through_the_server(engine, all_pcap):
    async def go():
        dash, c = await make_client()
        dash.packets.reset(all_pcap)
        try:
            post = lambda path, body: c.post(path, json=body, headers=AUTH)  # noqa: E731
            r = await post("/api/save/packets", {"scope": "displayed", "dfilter": "ftp-data"})
            saved = await r.json()
            assert r.status == 200 and saved["packets"] == count(engine, all_pcap, "-Y", "ftp-data")
            assert saved["name"] == "samples_displayed.pcap"
            d = await c.get(saved["download"], headers=AUTH)
            body = await d.read()
            assert d.status == 200 and body[:4] == b"\xd4\xc3\xb2\xa1" and len(body) == saved["size"]
            assert 'filename="samples_displayed.pcap"' in d.headers["Content-Disposition"]
            assert (await c.get(saved["download"])).status == 401  # still needs the session
            marked = await (await post("/api/save/packets", {"scope": "marked", "frames": "1-3,7"})).json()
            assert marked["packets"] == 4
            none = await post("/api/save/packets", {"scope": "displayed", "dfilter": "ip.addr == 192.0.2.250"})
            assert none.status == 409
            assert (await post("/api/save/packets", {"scope": "marked", "frames": "1;rm -rf /"})).status == 400
            assert (await post("/api/save/packets", {"scope": "everything"})).status == 400

            # A share-safe copy: the pcap and, separately, its address key.
            safe = await (await post("/api/save/packets", {"scope": "all", "safe": {"shift_time": True}})).json()
            assert safe["name"] == "samples_share-safe.pcap" and safe["sanitized"]["shift_time"] is True
            assert safe["sanitized"]["ipv4"] > 0 and safe["sanitized"]["bytes_cut"] > 0
            key = await (await c.get(safe["key"]["download"], headers=AUTH)).text()
            assert safe["key"]["name"] == "samples_share-safe_address-key.csv" and key.startswith("kind,real,stand_in\n")
            # (documentation addresses, RFC 5737, keep their /24 by design: another host's stand-in may be one)
            real = [line.split(",")[1] for line in key.splitlines()[1:] if line.startswith("ipv4,") and
                    not line.split(",")[1].startswith(("192.0.2.", "198.51.100.", "203.0.113."))]
            copy = await (await c.get(safe["download"], headers=AUTH)).read()
            packets, off = [], 24  # (each packet on its own: bytes across two records could spell anything)
            while off + 16 <= len(copy):
                caplen = int.from_bytes(copy[off + 8:off + 12], "little")
                packets.append(copy[off + 16:off + 16 + caplen])
                off += 16 + caplen
            assert real and packets and not any(socket.inet_aton(ip) in p for ip in real for p in packets)
            assert (await post("/api/save/packets", {"scope": "all", "safe": "yes"})).status == 400

            objects = (await (await c.get("/api/objects", headers=AUTH)).json())["objects"]
            exe = next(o for o in objects if o["name"] == "payload.exe")
            got = await (await post("/api/save/object", {"id": exe["id"]})).json()
            assert got["verified"] and got["name"] == "payload.exe"
            data = await (await c.get(got["download"], headers=AUTH)).read()
            assert hashlib.sha256(data).hexdigest() == exe["sha256"]
            assert (await post("/api/save/object", {"id": "../../etc/passwd"})).status == 400
            assert (await post("/api/save/object", {"id": "999999:h:0"})).status == 404

            text = await (await post("/api/save/text", {"name": "../../x/report", "type": "txt", "content": "hello"})).json()
            assert text["name"] == "report.txt"
            assert await (await c.get(text["download"], headers=AUTH)).text() == "hello"
            assert (await post("/api/save/text", {"name": "x", "type": "exe", "content": "MZ"})).status == 400
            assert (await c.get("/api/download/not-a-token", headers=AUTH)).status == 404

            sweep = await (await post("/api/hunt", {"text": f"{samples.FALSE_ADDR}\nbogus!"})).json()
            assert sweep["results"][0]["hits"] >= 2 and sweep["rejected"][0]["raw"] == "bogus!"
        finally:
            await c.close()
    run(go())


def test_triage_through_the_server(engine, all_pcap):
    async def go():
        analyzer = Analyzer()
        for rec in run_engine(engine, "-r", all_pcap):
            analyzer.ingest(rec)
        alert_id = next(iter(analyzer.alerts))
        _, c = await make_client(analyzer)
        try:
            r = await c.put(f"/api/alerts/{alert_id}/triage", json={"status": "false_positive", "note": "lab traffic"},
                            headers=AUTH)
            assert r.status == 200 and (await r.json())["triage"]["status"] == "false_positive"
            listed = await (await c.get("/api/alerts", headers=AUTH)).json()
            row = next(a for a in (listed["alerts"] if isinstance(listed, dict) else listed) if a["id"] == alert_id)
            assert row["triage"]["note"] == "lab traffic"
            bad = await c.put(f"/api/alerts/{alert_id}/triage", json={"status": "nope"}, headers=AUTH)
            assert bad.status == 400
            missing = await c.put("/api/alerts/A99999/triage", json={"status": "new"}, headers=AUTH)
            assert missing.status == 404
            # A form post from another site can't set a verdict.
            forged = await c.put(f"/api/alerts/{alert_id}/triage", data="status=new", headers={
                **AUTH, "Content-Type": "application/x-www-form-urlencoded"})
            assert forged.status == 403
        finally:
            await c.close()
    run(go())


def test_saving_needs_a_capture():
    async def go():
        _, c = await make_client()
        try:
            r = await c.post("/api/save/packets", json={"scope": "all"}, headers=AUTH)
            assert r.status == 409
            assert (await c.get("/api/objects", headers=AUTH)).status == 409
        finally:
            await c.close()
    run(go())
