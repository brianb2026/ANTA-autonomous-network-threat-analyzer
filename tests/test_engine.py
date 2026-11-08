"""C++ engine: dissection, reassembly, fingerprints, BPF, export, transports, limits."""
import hashlib
import json
import os
import subprocess
import tempfile
import threading

import pytest

from anta.tools.pcapgen import BROWSER_CIPHERS, BROWSER_EXTS, MALWARE_CIPHERS, MALWARE_EXTS
from conftest import C2_FIXED, EXFIL_DST, run_engine, sessions


def read(path):
    with open(path, "rb") as fh:
        return fh.read()


def test_reassembles_http_download_byte_exact(engine, data_dir, tmp_path):
    """Phase 2 acceptance: rebuild a 2 MB file from reordered, retransmitted segments."""
    recs = run_engine(engine, "-r", os.path.join(data_dir, "http_download.pcap"), "--dump-streams", str(tmp_path))
    (s,) = sessions(recs)
    assert s["tcp"]["out_of_order"] > 0 and s["tcp"]["retransmissions"] > 0
    assert s["tcp"]["zero_window"] > 0
    assert s["tcp"]["gap_bytes"] == 0
    stream = (tmp_path / f"flow{s['flow_id']}_s2c.bin").read_bytes()
    body = stream[stream.index(b"\r\n\r\n") + 4:]
    assert hashlib.sha256(body).digest() == hashlib.sha256(read(os.path.join(data_dir, "http_download.body"))).digest()
    assert s["http"][0]["method"] == "GET" and s["http"][0]["host"] == "files.lab"
    assert s["http_response"]["status"] == 200


def test_edge_cases(engine, data_dir, tmp_path):
    recs = run_engine(engine, "-r", os.path.join(data_dir, "edge_cases.pcap"), "--dump-streams", str(tmp_path))
    stats = next(r for r in recs if r["type"] == "stats")
    assert (stats["non_ip"], stats["truncated"], stats["fragments"]) == (1, 1, 2)  # ARP, cut header, 2 frags
    by_port = {(s["src_ip"], s["dst_port"]): s for s in sessions(recs)}

    assert by_port[("10.2.0.5", 80)]["http"][0]["host"] == "vlan.lab"          # 802.1Q
    assert by_port[("10.2.0.6", 443)]["tls"]["sni"] == "qinq.lab"              # 802.1ad + 802.1Q
    assert by_port[("fd00::5", 443)]["tls"]["sni"] == "v6.lab"                 # IPv6 + hop-by-hop header
    dns = by_port[("fd00::5", 53)]["dns"][0]
    assert dns["qname"] == "v6dns.lab" and dns["answers"] == ["2001:db8::53"]  # canonical IPv6 text

    wrap = by_port[("10.2.0.10", 80)]                                           # seq numbers wrap past 2**32
    stream = (tmp_path / f"flow{wrap['flow_id']}_s2c.bin").read_bytes()
    assert stream.endswith(read(os.path.join(data_dir, "edge_wrap.body"))) and wrap["tcp"]["gap_bytes"] == 0
    overlap = by_port[("10.2.0.11", 9000)]                                      # partially overlapping retransmit
    dumped = (tmp_path / f"flow{overlap['flow_id']}_c2s.bin").read_bytes()
    assert dumped == read(os.path.join(data_dir, "edge_overlap.body"))
    assert overlap["tcp"]["retransmissions"] == 1


def test_rate_histogram_accounts_for_every_byte(demo_records):
    for s in sessions(demo_records):
        if s["proto"] == "tcp":
            assert sum(s["rate"]["out"]) == s["c2s"]["payload_bytes"]


def _ja4(ciphers, exts, version, alpn, sig_algs):
    """Independent JA4 implementation (FoxIO spec) to cross-check the C++ one."""
    def hexs(values):
        return ",".join(f"{x:04x}" for x in values)
    a = f"t{version}d{len(ciphers):02d}{len(exts):02d}{alpn[0] + alpn[-1] if alpn else '00'}"
    b = hashlib.sha256(hexs(sorted(ciphers)).encode()).hexdigest()[:12]
    c_in = hexs(sorted(e for e in exts if e not in (0x0000, 0x0010))) + "_" + hexs(sig_algs)
    return f"{a}_{b}_{hashlib.sha256(c_in.encode()).hexdigest()[:12]}"


SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def test_tls_fingerprints_match_reference(demo_records):
    beacon = [s for s in sessions(demo_records) if s["dst_ip"] == C2_FIXED]
    assert len(beacon) > 100
    tls = beacon[0]["tls"]
    assert tls["sni"] == "update.cdn-telemetry.net"
    expected_ja3 = "771," + "-".join(map(str, MALWARE_CIPHERS)) + "," + "-".join(map(str, MALWARE_EXTS)) + ",29-23-24,0"
    assert tls["ja3_string"] == expected_ja3
    assert tls["ja3"] == hashlib.md5(expected_ja3.encode(), usedforsecurity=False).hexdigest()
    assert tls["ja4"] == _ja4(MALWARE_CIPHERS, MALWARE_EXTS, "12", "", SIG_ALGS)
    assert len({s["tls"]["ja3"] for s in beacon}) == 1

    browsers = [s for s in sessions(demo_records) if (s.get("tls") or {}).get("sni") == "github.com"]
    # GREASE must not leak into fingerprints: every browser session hashes identically.
    assert len({s["tls"]["ja3"] for s in browsers}) == 1
    assert browsers[0]["tls"]["ja4"] == _ja4(BROWSER_CIPHERS, BROWSER_EXTS, "13", "h2", SIG_ALGS)


def test_dns_metadata(demo_records):
    dns = [q for s in sessions(demo_records) for q in s.get("dns", [])]
    tunnel = [q for q in dns if q["qname"].endswith("exfil-cdn.net")]
    assert len(tunnel) >= 200
    assert all(q["qtype"] == 16 and q["answered"] and q["txt_bytes"] > 0 for q in tunnel)
    c2 = [q for q in dns if q["qname"] == "update.cdn-telemetry.net"]
    assert c2 and c2[0]["answers"] == [C2_FIXED]


def test_bpf_filter_restricts_ingestion(engine, data_dir):
    recs = run_engine(engine, "-r", os.path.join(data_dir, "mixed_demo.pcap"), "-f", "udp port 53")
    s = sessions(recs)
    assert s and all(r["proto"] == "udp" and 53 in (r["dst_port"], r["src_port"]) for r in s)


def test_extract_writes_only_requested_flow(engine, data_dir, tmp_path):
    out = tmp_path / "one.pcap"
    demo = os.path.join(data_dir, "mixed_demo.pcap")
    target = next(s for s in sessions(run_engine(engine, "-r", demo)) if s["dst_ip"] == EXFIL_DST)
    spec = f"6,{target['src_ip']},{target['src_port']},{target['dst_ip']},{target['dst_port']}"
    run_engine(engine, "-r", demo, "--extract", spec, "-w", str(out))
    (only,) = sessions(run_engine(engine, "-r", str(out)))
    assert (only["src_ip"], only["src_port"], only["dst_ip"]) == (target["src_ip"], target["src_port"], EXFIL_DST)
    assert only["c2s"]["payload_bytes"] == target["c2s"]["payload_bytes"]
    assert (os.stat(out).st_mode & 0o077) == 0, "exports hold packet payloads and must be owner-only"


def test_extract_reads_multiple_inputs(engine, data_dir, tmp_path):
    """Rotated recordings: an export spans PATH.1 and PATH."""
    out = tmp_path / "both.pcap"
    args = ["-r", os.path.join(data_dir, "http_download.pcap"), "-r", os.path.join(data_dir, "edge_cases.pcap"),
            "-w", str(out), "--extract", "6,10.1.0.5,51515,10.1.0.80,80", "--extract", "6,10.2.0.5,40001,10.2.0.80,80"]
    run_engine(engine, *args)
    assert {s["dst_ip"] for s in sessions(run_engine(engine, "-r", str(out)))} == {"10.1.0.80", "10.2.0.80"}


def test_recording_rotates_and_is_owner_only(engine, data_dir, tmp_path):
    rec = tmp_path / "rec.pcap"
    run_engine(engine, "-r", os.path.join(data_dir, "mixed_demo.pcap"), "-w", str(rec), "--write-max-mb", "20")
    rotated = tmp_path / "rec.pcap.1"
    assert rotated.exists() and rec.exists()
    assert os.path.getsize(rotated) < 21 << 20 and os.path.getsize(rec) < 21 << 20
    for path in (rec, rotated):
        assert (os.stat(path).st_mode & 0o077) == 0, "recordings hold packet payloads and must be owner-only"


def test_memory_budget_evicts_instead_of_growing(engine, data_dir):
    demo = os.path.join(data_dir, "mixed_demo.pcap")
    unbounded = next(r for r in run_engine(engine, "-r", demo) if r["type"] == "stats")
    budget = unbounded["peak_flow_memory"] / 4
    recs = run_engine(engine, "-r", demo, "--max-memory-mb", f"{budget / 1048576:.4f}")
    stats = next(r for r in recs if r["type"] == "stats" and r["final"])
    assert stats["evicted_flows"] > 0
    assert stats["peak_flow_memory"] < budget * 1.5  # one packet's worth of overshoot at most
    assert len(sessions(recs)) >= 2000  # evicted flows are still reported, just earlier
    assert any(s.get("evicted") for s in sessions(recs))


def _pull(zmq, endpoint, start_engine_first, engine, pcap):
    ctx = zmq.Context()
    sock = ctx.socket(zmq.PULL)
    sock.setsockopt(zmq.RCVTIMEO, 15000)
    proc = None
    if start_engine_first:
        proc = subprocess.Popen([engine, "-r", pcap, "-u", "zmq+" + endpoint], stderr=subprocess.DEVNULL)
        threading.Event().wait(1.0)  # analyzer comes up late
    sock.bind(endpoint)
    if proc is None:
        proc = subprocess.Popen([engine, "-r", pcap, "-u", "zmq+" + endpoint], stderr=subprocess.DEVNULL)
    records = []
    try:
        while not records or records[-1]["type"] != "stats":
            records.append(json.loads(sock.recv()))
        proc.wait(timeout=15)
    finally:
        sock.close(0)
        ctx.term()
    return proc.returncode, records


def test_zeromq_transport_interoperates_with_libzmq(engine, data_dir):
    zmq = pytest.importorskip("zmq")
    with tempfile.TemporaryDirectory(dir="/tmp") as d:  # short path: sun_path is ~104 bytes
        code, records = _pull(zmq, f"ipc://{d}/t.ipc", False, engine, os.path.join(data_dir, "edge_cases.pcap"))
    assert code == 0 and records[0]["type"] == "hello" and len(sessions(records)) == 6


def test_offline_mode_waits_for_analyzer_instead_of_dropping(engine, data_dir):
    zmq = pytest.importorskip("zmq")
    with tempfile.TemporaryDirectory(dir="/tmp") as d:
        code, records = _pull(zmq, f"ipc://{d}/late.ipc", True, engine, os.path.join(data_dir, "edge_cases.pcap"))
    assert code == 0 and records[-1]["ipc_dropped"] == 0 and len(sessions(records)) == 6


def test_closed_stdout_stops_engine(engine, data_dir):
    """`engine | head` must terminate promptly instead of running on."""
    p = subprocess.Popen(f"'{engine}' -r '{os.path.join(data_dir, 'mixed_demo.pcap')}' | head -1", shell=True,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    out, _ = p.communicate(timeout=30)
    assert out.startswith(b'{"type":"hello"')


def test_rejects_bad_arguments(engine):
    for args in (["-r", "x.pcap", "--max-memory-mb", "-5"], ["-r", "x.pcap", "-u", "gopher://x"],
                 ["--extract", "6,1.2.3.4,1,5.6.7.8", "-r", "a", "-w", "b"]):
        assert subprocess.run([engine, *args], capture_output=True).returncode != 0
