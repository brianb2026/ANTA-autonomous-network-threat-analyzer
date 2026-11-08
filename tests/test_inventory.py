"""Inventory and intelligence: offline GeoIP, threat-intel feeds (parsing, matching,
alerts), encrypted traffic analytics, per-host baselines, the passive asset
inventory, flow logs, settings, and the server endpoints behind them."""
import asyncio
import datetime
import json
import os
import stat

import pytest

from anta import baseline, eta, flowlog, geoip, settings
from anta.analyzer import Analyzer
from anta.intel import IntelStore, parse
from anta.tools import samples
from anta.tools.samples import tcp_session
from conftest import run_engine
from test_protocols import fingerprint_lab
from test_server import AUTH, make_client

FEODO = """#####
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)
#####
"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
"2026-09-30 10:00:00","198.51.100.66","443","online","2026-10-01","QakBot"
"""
SSLBL = """# abuse.ch SSLBL JA3 Fingerprint Blacklist (CSV)
# ja3_md5,Firstseen,Lastseen,Listingreason
b386946a5a44d1ddcc843bc75336dfce,2019-01-01 00:00:00,2021-01-01 00:00:00,Dridex
"""
URLHAUS = """################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)
################################################################
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-10-01 10:00:00","http://bad.example.net/drop/payload.exe","online","2026-10-01","malware_download","exe","https://urlhaus.abuse.ch/url/1/","x"
"""
THREATFOX = """################################################################
# ThreatFox IOCs: CSV export
################################################################
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","reference","tags","anonymous","reporter"
"2026-10-01 10:00:00", "1", "c2.example.org", "domain", "botnet_cc", "win.x", "", "XWorm", "", "100", "", "", "0", "x"
"2026-10-01 10:00:00", "2", "203.0.113.77:8443", "ip:port", "botnet_cc", "win.x", "", "XWorm", "", "100", "", "", "0", "x"
"""
BAZAAR = """################################################################
# MalwareBazaar recent malware samples (SHA256 hashes)
################################################################
""" + "a" * 64 + "\n"


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------- GeoIP

def test_geoip_offline_lookup():
    db = geoip.GeoDB()
    assert db.wait(60), db.error
    g = db.lookup("8.8.8.8")
    assert g["country"] == "US" and g["asn"] == 15169 and g["country_name"] == "United States"
    assert db.lookup("2001:4860:4860::8888")["asn"] == 15169
    assert db.lookup("10.1.2.3") is None and db.lookup("not an ip") is None
    assert db.info()["loaded"] and db.info()["rows"] > 100_000


# ------------------------------------------------------------- intel feeds

def test_each_feed_format_is_parsed():
    feodo = parse("feodo", FEODO)
    assert "QakBot" in feodo["ip_port"]["198.51.100.66:443"][0]["reason"] and feodo["ip"]["198.51.100.66"]
    assert parse("sslbl_ja3", SSLBL)["ja3"]["b386946a5a44d1ddcc843bc75336dfce"][0]["reason"] == "Dridex"
    assert parse("urlhaus", URLHAUS)["url"]["bad.example.net/drop/payload.exe"]
    tf = parse("threatfox", THREATFOX)
    assert tf["domain"]["c2.example.org"] and tf["ip_port"]["203.0.113.77:8443"]
    assert parse("bazaar", BAZAAR)["sha256"]["a" * 64]
    plain = parse("custom", "# my list\n203.0.113.5\nevil.example\nhxxp://x[.]example/a\n")  # a plain indicator list
    assert plain["ip"]["203.0.113.5"] and plain["domain"]["evil.example"]


def session(src="10.0.0.5", dst="198.51.100.66", dport=443, **extra):
    rec = {"type": "session", "final": True, "flow_id": 1, "proto": "tcp", "src_ip": src, "src_port": 50000,
           "dst_ip": dst, "dst_port": dport, "start": 1_790_000_000.0, "end": 1_790_000_010.0,
           "c2s": {"packets": 10, "bytes": 2000, "payload_bytes": 1500},
           "s2c": {"packets": 10, "bytes": 9000, "payload_bytes": 8000}}
    rec.update(extra)
    return rec


def test_store_matches_sessions_and_stays_private(tmp_path):
    store = IntelStore(str(tmp_path / "intel"))
    for name, text in (("feodo", FEODO), ("threatfox", THREATFOX), ("bazaar", BAZAAR), ("sslbl", SSLBL)):
        store.import_text(name, text)
    assert store.size() >= 6
    kinds = {m["kind"] for m in store.match_session(session())}
    assert kinds == {"ip_port"}  # the exact C2 address and port, not also the bare address
    m = store.match_session(session(dst="192.0.2.1", tls={"sni": "api.c2.example.org", "ja3": "b386946a5a44d1ddcc843bc75336dfce"}))
    assert {x["kind"] for x in m} == {"domain", "ja3"}  # a subdomain of a listed domain
    m = store.match_session(session(dst="192.0.2.1", http_files=[{"sha256": "A" * 64, "filename": "x.exe"}]))
    assert m and m[0]["kind"] == "sha256"
    assert not store.match_session(session(dst="192.0.2.1"))
    fid = next(f["id"] for f in store.feeds() if f["name"] == "feodo")
    store.set_enabled(fid, False)
    assert not store.match_session(session())
    store.remove(fid)
    assert fid not in {f["id"] for f in store.feeds()}
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(tmp_path / "intel").st_mode) == 0o700
        for p in (tmp_path / "intel").iterdir():
            assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_listed_c2_raises_a_critical_alert(tmp_path):
    store = IntelStore(str(tmp_path / "intel"))
    store.import_text("feodo", FEODO)
    analyzer = Analyzer(intel=store)
    alerts = analyzer.ingest(session())
    hit = next(a for a in alerts if a["kind"] == "intel_match")
    assert hit["severity"] == "critical" and "QakBot" in hit["headline"] + " ".join(hit["details"])
    again = analyzer.recheck_intel([session()])
    assert [a["id"] for a in again] == [hit["id"]]  # the same alert, updated


# ------------------------------------------------- encrypted traffic analytics

def shaped(up, down, dur, events, proto="tcp"):
    return session(proto=proto, app="tls", start=0.0, end=float(dur), events=events,
                   c2s={"packets": 50, "bytes": up + 2000, "payload_bytes": up},
                   s2c={"packets": 50, "bytes": down + 2000, "payload_bytes": down})


def test_encrypted_sessions_are_classified_by_shape():
    assert eta.classify(shaped(600, 900, 1, [[0, 300], [5, -900]]))["class"] == "handshake"
    assert eta.classify(shaped(50_000_000, 200_000, 300, []))["class"] == "upload"
    assert eta.classify(shaped(100_000, 30_000_000, 40, []))["class"] == "download"
    beats = [[i * 30_000, 120 if i % 2 == 0 else -80] for i in range(20)]
    assert eta.classify(shaped(1200, 800, 600, beats))["class"] == "heartbeat"
    keys = [[t, 60 if i % 2 == 0 else -90] for i, t in enumerate([0, 80, 900, 950, 2400, 2500, 2600, 6000, 6100, 6150, 9000,
                                                                 9050, 12000, 12100, 15500, 15600, 15700, 21000, 21100, 25000, 25050, 25200])]
    verdict = eta.classify(shaped(5000, 7000, 30, keys))
    assert verdict["class"] == "interactive" and verdict["why"]
    assert eta.is_encrypted(session(app="ssh")) and not eta.is_encrypted(session(app="http"))


# ------------------------------------------------------------- baselines

def test_a_host_is_judged_against_its_own_history():
    b = baseline.Baselines(bucket_s=30, min_history=12)
    t = 1_790_000_000.0
    for i in range(30):  # 15 minutes of a laptop's usual traffic
        b.observe(session(start=t + i * 30, end=t + i * 30 + 5, dst=f"203.0.113.{i % 3}", app="tls",
                          c2s={"packets": 5, "bytes": 20_000, "payload_bytes": 18_000}))
    for i in range(40):  # then one minute of contacting 40 hosts and uploading 40 MB, with SMB never used before
        b.observe(session(start=t + 900 + i, end=t + 901 + i, dst=f"10.9.{i}.1", dport=445, app="smb",
                          c2s={"packets": 900, "bytes": 1_000_000, "payload_bytes": 1_000_000}))
    found = b.judge(t + 2000, final=True)
    metrics = {d["metric"] for d in found if d["ip"] == "10.0.0.5"}
    assert {"bytes_out", "dst_hosts", "new_app"} <= metrics
    assert all(d["history"] >= 12 for d in found)
    quiet = baseline.Baselines()
    for i in range(30):
        quiet.observe(session(start=t + i * 30, end=t + i * 30 + 5))
    assert not quiet.judge(t + 2000, final=True)


# --------------------------------------------------------- flow logs, settings

def test_flow_log_writes_private_daily_files_and_prunes(tmp_path):
    log = flowlog.FlowLog(str(tmp_path / "flows"), days=2, max_mb=1)
    old = session(start=datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc).timestamp())
    new = session(start=datetime.datetime(2026, 10, 9, tzinfo=datetime.timezone.utc).timestamp(),
                  tcp={"handshake": True, "closed": True}, app="tls", tls={"sni": "x.example", "ja4": "t13d"})
    log.write(old)
    log.write(new)
    log.close()
    names = [f["name"] for f in log.files()]
    assert names == ["flows-2026-10-01.jsonl", "flows-2026-10-09.jsonl"]
    line = json.loads((tmp_path / "flows" / names[1]).read_text())
    assert (line["service"], line["conn_state"], line["tls"]["sni"], line["orig_bytes"]) == ("tls", "SF", "x.example", 1500)
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(tmp_path / "flows" / names[1]).st_mode) == 0o600
    assert log.prune(today=datetime.date(2026, 10, 9)) == ["flows-2026-10-01.jsonl"]
    assert flowlog.FlowLog(str(tmp_path / "missing")).files() == []


def test_settings_are_clamped_and_saved_privately():
    v = settings.validate({"ring_segments": 10**9, "ring_segment_mb": 1, "flowlog_live": 0, "bogus": 1, "flowlog_days": "x"})
    assert v["ring_segments"] == 1000 and v["ring_segment_mb"] == 16 and v["flowlog_live"] is False
    assert v["flowlog_days"] == settings.DEFAULTS["flowlog_days"] and "bogus" not in v
    saved = settings.save({"ring_segments": 3})
    assert settings.load() == saved and saved["ring_segments"] == 3
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(settings.path()).st_mode) == 0o600
    settings.save(settings.DEFAULTS)


# ------------------------------------------------------------ the endpoints

@pytest.fixture(scope="module")
def fp_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("assets") / "fp.pcap"
    frames = fingerprint_lab()
    frames += [(t + 2, f) for t, f in samples.http_download("10.40.0.10", "8.8.8.8", 80, "/a.bin", b"x" * 300)]
    samples.write_pcap(path, frames)
    return str(path)


def test_asset_inventory_endpoint(fp_pcap):
    async def go():
        dash, c = await make_client()
        try:
            dash.geo.wait(60)
            dash.packets.reset(fp_pcap)
            rows = {r["ip"]: r for r in (await (await c.get("/api/assets", headers=AUTH)).json())["assets"]}
            win = rows["10.40.0.10"]
            assert win["os_family"] == "Windows" and win["device"] == "Computer"
            assert any("DHCP parameter request list" in e for e in win["os_evidence"])
            assert any("TCP SYN is Windows'" in e for e in win["os_evidence"])
            assert win["dhcp_prl"].startswith("1,3,6,15") and win["syn"]["ttl"] == 128 and "http" in win["apps_used"]
            cast = rows["10.40.0.20"]
            assert cast["iot"] and cast["device"] == "IoT / smart device" and "_googlecast._tcp" in cast["mdns_services"]
            google = rows["8.8.8.8"]
            assert google["scope"] == "public" and google["asn"] == 15169 and google["country"] == "US"
            stats = await (await c.get("/api/stats", headers=AUTH)).json()
            assert stats["geo"]["countries"][0]["country"] == "US"
            assert next(n for n in stats["map"]["nodes"] if n["addr"] == "8.8.8.8")["geo"]["asn"] == 15169
        finally:
            await c.close()
    run(go())


def test_intel_endpoints_and_recheck(engine, tmp_path):
    frames = tcp_session("10.0.0.5", 50000, "198.51.100.66", 443, [(True, b"\x16\x03\x01" + bytes(60)), (False, bytes(100))])
    path = tmp_path / "c2.pcap"
    samples.write_pcap(path, frames)

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(str(path))
            post = lambda p, b: c.post(p, json=b, headers=AUTH)  # noqa: E731
            r = await (await post("/api/intel/import", {"name": "Partner list", "content": FEODO})).json()
            fid = r["imported"]["id"] if "id" in r["imported"] else next(f["id"] for f in r["feeds"] if f["name"] == "Partner list")
            assert r["indicators"] >= 2
            listed = await (await c.get("/api/intel", headers=AUTH)).json()
            assert {f["id"] for f in listed["feeds"]} >= {"feodo", "threatfox", fid} and listed["geo"]["source_url"]
            check = await (await post("/api/intel/recheck", {})).json()
            assert check == {"sessions": 1, "matches": 1}
            assert any(a["kind"] == "intel_match" for a in dash.pending.values())
            assert (await post("/api/intel/change", {"id": fid, "enabled": False})).status == 200
            assert (await (await post("/api/intel/recheck", {})).json())["matches"] == 0
            assert (await post("/api/intel/change", {"id": "nope", "remove": True})).status == 404
            assert (await post("/api/intel/update", {"id": "not-a-feed"})).status == 400
            assert (await post("/api/intel/import", {"name": 3})).status == 400
            r = await (await post("/api/intel/change", {"id": fid, "remove": True})).json()
            assert fid not in {f["id"] for f in r["feeds"]}
        finally:
            await c.close()
    run(go())


def test_fingerprint_and_eta_endpoints(engine, data_dir):
    demo = os.path.join(data_dir, "mixed_demo.pcap")

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(demo)
            for rec in run_engine(engine, "-r", demo):
                dash.analyzer.ingest(rec)
            fp = await (await c.get("/api/fingerprints", headers=AUTH)).json()
            assert fp["clients"] and fp["servers"]
            assert all(c_["ja4"] or c_["ja3"] for c_ in fp["clients"])
            assert sum(c_["sessions"] for c_ in fp["clients"]) >= sum(1 for _ in fp["clients"])
            e = await (await c.get("/api/eta", headers=AUTH)).json()
            assert e["total"] > 100 and sum(e["classes"].values()) == e["total"]
            assert {"class", "label", "why", "confidence"} <= set(e["sessions"][0])
            # Rhythm: the demo's C2 beacon (every 4.2 s) is a steady timer with its alert.
            rh = await (await c.get("/api/rhythm", headers=AUTH)).json()
            c2 = next(r for r in rh["rows"] if r["dst"] == "192.168.1.105")
            assert c2["rhythm"] == "steady" and abs(c2["period"] - 4.2) < 0.2 and c2["alert"]["severity"] == "critical"
            assert (await c.get("/api/rhythm")).status == 401
            lg = await (await c.get("/api/logins", headers=AUTH)).json()
            assert {"logins", "total", "accounts", "accepted"} <= set(lg)
        finally:
            await c.close()
    run(go())


def test_settings_recordings_and_flow_export(engine, tmp_path):
    async def go():
        dash, c = await make_client()
        try:
            r = await (await c.put("/api/settings", json={"settings": {"ring_segments": 5000, "flowlog_days": 7}},
                                   headers=AUTH)).json()
            assert r["settings"]["ring_segments"] == 1000 and r["settings"]["flowlog_days"] == 7
            assert dash.flowlog.days == 7
            folder = r["captures_dir"]
            for name in ("live-20261009-101500.pcap", "live-20261009-101500.pcap.1", "live-20261009-101500.pcap.2",
                         "other.pcap"):
                with open(os.path.join(folder, name), "wb") as fh:
                    fh.write(b"\xd4\xc3\xb2\xa1" + bytes(20))
            recs = (await (await c.get("/api/recordings", headers=AUTH)).json())["recordings"]
            rec = next(x for x in recs if x["name"] == "live-20261009-101500.pcap")
            assert [s["generation"] for s in rec["segments"]] == [2, 1, 0]  # oldest first
            assert "other.pcap" not in {x["name"] for x in recs}
            dash.packets.reset(os.path.join(folder, "live-20261009-101500.pcap.1"))  # open in ANTA
            r = await c.post("/api/recordings/delete", json={"name": rec["name"]}, headers=AUTH)
            assert r.status == 409
            dash.packets.reset(None)
            r = await (await c.post("/api/recordings/delete", json={"name": rec["name"]}, headers=AUTH)).json()
            assert r["removed"] == 3 and os.path.exists(os.path.join(folder, "other.pcap"))
            assert (await c.post("/api/recordings/delete", json={"name": "../x"}, headers=AUTH)).status == 404
            settings.save(settings.DEFAULTS)

            flows = tmp_path / "flows.pcap"
            samples.write_pcap(flows, samples.database_lab())
            dash.packets.reset(str(flows))
            saved = await (await c.post("/api/save/flows", json={}, headers=AUTH)).json()
            assert saved["flows"] == 3
            lines = (await (await c.get(saved["download"], headers=AUTH)).text()).splitlines()
            assert {json.loads(x)["service"] for x in lines} == {"mysql", "postgresql", "mssql"}
        finally:
            await c.close()
    run(go())


def test_keylog_endpoint_decrypts_in_the_packet_view(engine, tmp_path):
    from test_protocols import _tls13_capture
    pcap, keys = _tls13_capture(tmp_path)
    keytext = open(keys).read()

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(pcap)
            # No keys yet: application data stays encrypted.
            rows = (await (await c.get("/api/packets?from=1&limit=50", headers=AUTH)).json())["packets"]
            info = {p["n"]: p["info"] for p in rows}
            assert info[8] == "Application Data"
            assert (await (await c.get("/api/keylog", headers=AUTH)).json()) == \
                {"loaded": False, "secrets": 0, "scan": None}
            assert [o["proto"] for o in (await (await c.get("/api/objects", headers=AUTH)).json())["objects"]] == []
            # A non-key-log file is refused.
            assert (await c.post("/api/keylog", json={"content": "just some text\n"}, headers=AUTH)).status == 400
            # Load the key log: it reports the secret count and now decrypts.
            r = await (await c.post("/api/keylog", json={"content": keytext}, headers=AUTH)).json()
            assert r["loaded"] and r["secrets"] == 2 and r["added"] == 2
            kept = dash.packets.keylog
            assert kept and os.path.exists(kept) and stat.S_IMODE(os.stat(kept).st_mode) == 0o600
            rows = (await (await c.get("/api/packets?from=1&limit=50", headers=AUTH)).json())["packets"]
            info = {p["n"]: p["info"] for p in rows}
            assert info[8] == "GET /secret.html HTTP/1.1 " and info[10] == "HTTP/1.1 200 OK  (text/html)"
            # The capture is re-read with the keys: the HTTPS session and the file in it.
            for _ in range(100):
                status = await (await c.get("/api/keylog", headers=AUTH)).json()
                if status["scan"]["state"] != "running":
                    break
                await asyncio.sleep(0.1)
            assert status["scan"] == {"state": "done", "sessions": 1, "files": 1, "alerts": 0}
            objects = (await (await c.get("/api/objects", headers=AUTH)).json())["objects"]
            assert [(o["proto"], o["location"], o["size"]) for o in objects] == \
                [("HTTPS", "https://decrypt.example/secret.html", 11)]
            # Clearing removes the stored key file and re-encrypts the view.
            assert (await (await c.post("/api/keylog/clear", json={}, headers=AUTH)).json()) == \
                {"loaded": False, "secrets": 0, "scan": None}
            assert not os.path.exists(kept)
            rows = (await (await c.get("/api/packets?from=1&limit=50", headers=AUTH)).json())["packets"]
            assert {p["n"]: p["info"] for p in rows}[8] == "Application Data"
            assert (await (await c.get("/api/objects", headers=AUTH)).json())["objects"] == []
        finally:
            await c.close()
    run(go())


@pytest.mark.skipif(os.name == "nt", reason="process probing is POSIX-only")
def test_a_key_log_left_by_a_dead_app_is_removed_at_start():
    import subprocess
    import sys
    from anta.security import runtime_dir
    from anta.server import purge_stale_exports
    dead = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"], capture_output=True, text=True)
    rdir = runtime_dir()
    mine = os.path.join(rdir, f"anta_keylog_{os.getpid()}_live.keys")       # this app's: kept
    orphan = os.path.join(rdir, f"anta_keylog_{dead.stdout.strip()}_x.keys")  # its app was killed: removed
    legacy = os.path.join(rdir, "anta_keylog_abc123.keys")                      # unnamed owner: removed
    for p in (mine, orphan, legacy):
        with open(p, "w") as fh:
            fh.write("CLIENT_RANDOM 00 00\n")
    purge_stale_exports()
    assert os.path.exists(mine) and not os.path.exists(orphan) and not os.path.exists(legacy)
    os.unlink(mine)
