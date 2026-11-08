"""Detections that solve a malware-traffic exercise end to end: executable downloads
(with the file's SHA-256), custom protocols on TLS ports, and who the victim is
(host name, MAC, user account, domain) from Kerberos and Windows browser traffic.

Frame decoding is checked against what Wireshark 4.6 shows for the same packets."""
import gzip
import hashlib
import json
import os
import subprocess

import pytest

from anta import netmap
from anta.analyzer import Analyzer
from anta.security import InvalidRecord, validate_session
from anta.tools import samples
from anta.tools.pcapgen import BROWSER_CIPHERS, BROWSER_EXTS, tls_client_hello
from conftest import run_engine

CLIENT, DC, WEB, C2 = "10.0.0.5", "10.0.0.10", "203.0.113.80", "198.51.100.66"


@pytest.fixture(scope="module")
def sample_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("samples") / "samples.pcap"
    samples.write_pcap(path, samples.all_samples())
    return str(path)


def sessions(engine, path):
    return [r for r in run_engine(engine, "-r", path) if r["type"] == "session" and r["final"]]


def analyze(engine, path):
    analyzer = Analyzer()
    for rec in run_engine(engine, "-r", path):
        analyzer.ingest(rec)
    return list(analyzer.alerts.values())


# --------------------------------------------------------- downloaded files

def test_engine_hashes_downloaded_files(engine, sample_pcap):
    files = {f["uri"]: (s, f) for s in sessions(engine, sample_pcap) for f in s.get("http_files", [])}
    _, exe = files["/drop/payload.exe"]
    body = samples.windows_exe()
    assert exe["sha256"] == hashlib.sha256(body).hexdigest() and exe["size"] == len(body)
    assert exe["magic"].startswith("4d5a") and exe["complete"] and exe["user_agent"] == "curl/8.21.0"
    # Chunked and gzip-compressed: the hash is of the file itself, as Wireshark exports it.
    _, packed = files["/files/report.bin"]
    body = samples.windows_exe(9000, seed=3)
    assert packed["sha256"] == hashlib.sha256(body).hexdigest() and packed["size"] == len(body)
    assert packed["encoded_size"] == len(gzip.compress(body, mtime=0)) and packed["complete"]


def test_cut_short_download_is_marked_incomplete(engine, tmp_path):
    frames = samples.http_download(CLIENT, WEB, 80, "/a.exe", samples.windows_exe())
    path = tmp_path / "cut.pcap"
    samples.write_pcap(path, frames[:-12])  # the capture ends before the file does
    f = next(f for s in sessions(engine, str(path)) for f in s.get("http_files", []))
    assert not f["complete"] and 0 < f["size"] < 20_000


def test_download_alert_says_how_and_carries_the_hash(engine, sample_pcap):
    alerts = [a for a in analyze(engine, sample_pcap) if a["kind"] == "download"]
    exe = next(a for a in alerts if a["file"]["name"] == "payload.exe")
    assert exe["severity"] == "critical" and exe["src_ip"] == CLIENT
    assert exe["file"]["sha256"] == hashlib.sha256(samples.windows_exe()).hexdigest()
    assert exe["file"]["url"] == f"http://{WEB}:9000/drop/payload.exe"
    text = exe["headline"]
    assert "bare IP address" in text and "port 9000" in text and "command-line tool" in text
    # A .bin that is really a Windows program: the name hides what it is.
    packed = next(a for a in alerts if a["file"]["name"] == "report.bin")
    assert "hides that it is a Windows executable" in packed["headline"]


def test_ordinary_downloads_do_not_alert(engine, tmp_path):
    frames = []
    for i, (host, uri, body, agent, ctype) in enumerate([
            ("cdn.example.com", "/app.js", b"function x(){}" * 50, "Mozilla/5.0", "text/javascript"),  # page script
            ("download.windowsupdate.com", "/u/kb.exe", samples.windows_exe(), "Microsoft BITS/7.8",
             "application/octet-stream"),                                                         # vendor update
            ("files.example.com", "/data.bin", os.urandom(5000), "curl/8.0", "application/octet-stream")]):
        more = samples.http_download(CLIENT, WEB, 80, uri, body, host=host, agent=agent, content_type=ctype,
                                     cport=51000 + i, t0=i * 10)
        frames += more
    path = tmp_path / "benign.pcap"
    samples.write_pcap(path, frames)
    assert not [a for a in analyze(engine, str(path)) if a["kind"] == "download"]


# --------------------------------------------------------- TLS ports

def test_custom_protocol_on_443_alerts_and_tls_does_not(engine, sample_pcap, tmp_path):
    alert = next(a for a in analyze(engine, sample_pcap) if a["kind"] == "tls_port")
    assert alert["target"] == f"{C2}:443" and alert["severity"] == "high"
    assert "74 9c 90 db" in alert["details"][0] and "not a TLS record" in alert["details"][0]
    # Real TLS on 443 is quiet.
    hello = tls_client_hello("example.com", BROWSER_CIPHERS, BROWSER_EXTS)
    frames = samples.tcp_session(CLIENT, 52000, WEB, 443, [(True, hello), (False, b"\x16\x03\x03\x00\x31" + bytes(49))])
    path = tmp_path / "tls.pcap"
    samples.write_pcap(path, frames)
    assert not [a for a in analyze(engine, str(path)) if a["kind"] == "tls_port"]


def test_remote_control_on_443_is_critical(engine, tmp_path):
    # Half an hour of two-way traffic in a custom protocol: what a RAT looks like.
    exchanges = [(i % 3 != 0, bytes([0x74, 0x9C, i % 256]) * 400) for i in range(60)]
    frames = samples.tcp_session(CLIENT, 52001, C2, 443, exchanges, step=15.0)
    path = tmp_path / "rat.pcap"
    samples.write_pcap(path, frames)
    alert = next(a for a in analyze(engine, str(path)) if a["kind"] == "tls_port")
    assert alert["severity"] == "critical" and "Remote-Access Trojan" in alert["title"]
    assert "no DNS lookup" in " ".join(alert["details"]).replace("No DNS", "no DNS")


def test_new_record_fields_are_validated():
    base = {"type": "session", "proto": "tcp", "src_ip": CLIENT, "dst_ip": WEB, "src_port": 1, "dst_port": 2,
            "start": 1.0, "end": 2.0}
    ok = validate_session({**base, "http_files": [{"sha256": "a" * 64, "magic": "4d5a", "size": 3}],
                           "stream_head": {"c2s": "749c", "s2c": "", "first": "client", "c2s_from_start": True}})
    assert ok["http_files"][0]["size"] == 3 and ok["stream_head"]["first"] == "client"
    for bad in ({"http_files": [{"sha256": "<script>", "magic": ""}]}, {"stream_head": {"c2s": "zz"}}):
        with pytest.raises(InvalidRecord):
            validate_session({**base, **bad})


# --------------------------------------------------------- who the victim is

def test_kerberos_and_browser_frames_read_like_wireshark(engine, sample_pcap):
    rows = {r["n"]: (r["proto"], r["info"]) for r in run_engine(engine, "--packets", "-r", sample_pcap, "--limit",
                                                                "1000") if r["type"] == "packet"}
    infos = [v for v in rows.values() if v[0] in ("KRB5", "BROWSER")]
    assert ("KRB5", "AS-REQ") in infos and ("KRB5", "KRB Error: KRB5KDC_ERR_PREAUTH_REQUIRED") in infos
    assert ("KRB5", "TGS-REQ") in infos and ("KRB5", "TGS-REP") in infos  # over TCP, reassembled
    assert ("BROWSER", "Host Announcement HOST-A, Workstation, Server, NT Workstation") in infos
    assert ("BROWSER", "Local Master Announcement DC-1, Workstation, Server, Domain Controller, "
                       "NT Workstation") in infos
    users = run_engine(engine, "--packets", "-r", sample_pcap, "-Y",
                       'kerberos.CNameString and !(kerberos.CNameString contains "$")')
    assert {r["n"] for r in users if r["type"] == "packet"}  # the exercise's own filter works


def test_host_identity_and_domain_controller(engine, sample_pcap):
    stats = next(r for r in run_engine(engine, "--stats", "-r", sample_pcap) if r["type"] == "stats")
    nodes = {n["addr"]: n for n in netmap.build(stats)["nodes"]}
    victim = nodes[CLIENT]
    assert victim["users"] == ["bdiaz"] and "EXAMPLE.COM" in victim["domains"]
    assert victim["name"] == "HOST-A" and victim["os"].startswith("Windows 10")
    assert nodes[DC]["role"] == "Domain controller"
    assert any("Kerberos" in r for r in nodes[DC]["reasons"])


def test_fuzz_seed_tool_writes_a_capture(tmp_path):
    out = tmp_path / "seeds.pcap"
    subprocess.run([os.environ.get("PYTHON", "python3"), "-m", "anta.tools.samples", str(out)], check=True,
                   cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   env={**os.environ, "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(__file__)))})
    assert out.stat().st_size > 10_000
    json.dumps(samples.all_samples()[0][0])  # timestamps are plain numbers
