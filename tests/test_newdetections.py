"""Detectors added for LAN and reconnaissance threats that behaviour-based analysis
missed before: ARP cache poisoning (a man-in-the-middle on the local network), port
and host scanning, and DGA-style NXDOMAIN storms (malware locating its C2). Each is
driven by a synthetic capture built to look like the real attack, and checked for
low false positives against benign traffic.
"""
import os

from anta.analyzer import Analyzer
from anta.tools import samples
from conftest import run_engine


def analyze(engine, path):
    a = Analyzer()
    for rec in run_engine(engine, "-r", path):
        a.ingest(rec)
    return a, list(a.alerts.values())


def write(tmp_path, name, frames):
    path = str(tmp_path / name)
    samples.write_pcap(path, frames)
    return path


# ------------------------------------------------------------ ARP spoofing

def test_arp_poisoning_is_flagged_and_the_spoofer_named(engine, tmp_path):
    path = write(tmp_path, "arp.pcap", samples.arp_spoof_lab())
    _, alerts = analyze(engine, path)
    spoof = [a for a in alerts if a["kind"] == "arp_spoof"]
    assert {a["src_ip"] for a in spoof} == {"192.168.7.1", "192.168.7.50"}  # gateway and host A, not the VRRP IP
    assert all(a["severity"] == "critical" for a in spoof)
    assert all(a["offender"] == "02:00:00:00:07:66" for a in spoof)        # the MAC claiming both
    assert all(a["confidence"] >= 0.9 for a in spoof)
    gw = next(a for a in spoof if a["src_ip"] == "192.168.7.1")
    assert "default gateway" in " ".join(gw["details"])
    assert "192.168.7.2" not in {a["src_ip"] for a in spoof}               # VRRP virtual MAC: legitimate sharing


def test_a_single_owner_per_ip_raises_nothing(engine, tmp_path):
    # Every IP answered for by exactly one MAC: ordinary ARP, no alert.
    frames = [(0.1, samples.arp("02:00:00:00:08:01", "192.168.8.1")),
              (0.2, samples.arp("02:00:00:00:08:50", "192.168.8.50")),
              (0.3, samples.arp("02:00:00:00:08:01", "192.168.8.1"))]  # the gateway re-announcing is fine
    path = write(tmp_path, "clean.pcap", frames)
    _, alerts = analyze(engine, path)
    assert not [a for a in alerts if a["kind"] == "arp_spoof"]


# ------------------------------------------------------------ scanning

def test_vertical_and_horizontal_scans_are_flagged(engine, tmp_path):
    path = write(tmp_path, "scan.pcap", samples.scan_lab())
    _, alerts = analyze(engine, path)
    scans = [a for a in alerts if a["kind"] == "scan"]
    kinds = {a["metrics"]["kind"] for a in scans}
    assert kinds == {"vertical", "horizontal"}
    for a in scans:
        assert a["severity"] == "high" and a["offender"] == "10.50.0.9"   # an internal host scanning = lateral
        assert a["metrics"]["count"] >= 20
    horiz = next(a for a in scans if a["metrics"]["kind"] == "horizontal")
    assert "445" in horiz["headline"] and "local network" in " ".join(horiz["details"])


def test_scan_needs_both_many_targets_and_failures(engine, tmp_path):
    # One host opening many connections that all SUCCEED (a busy proxy) is not a scan.
    frames = []
    t = 0.0
    for i in range(40):
        host, sport = f"10.70.0.{10 + i}", 40000 + i
        frames += [(t2 + t, f) for t2, f in samples.tcp_session("10.70.0.9", sport, host, 443,
                                                               [(True, b"hi"), (False, b"ok")])]
        t += 0.5
    path = write(tmp_path, "busy.pcap", frames)
    _, alerts = analyze(engine, path)
    assert not [a for a in alerts if a["kind"] == "scan"]   # handshakes completed → not a scan


# ------------------------------------------------------------ DGA

def test_dga_nxdomain_storm_is_flagged(engine, tmp_path):
    path = write(tmp_path, "dga.pcap", samples.dga_lab())
    _, alerts = analyze(engine, path)
    dga = [a for a in alerts if a["kind"] == "dga"]
    assert len(dga) == 1
    a = dga[0]
    assert a["severity"] == "high" and a["offender"] == "10.60.0.15"
    assert a["metrics"]["count"] >= 30 and a["metrics"]["entropy"] >= 3.2


def test_many_real_domains_not_found_is_not_dga(engine, tmp_path):
    # A host that mistypes ordinary, low-entropy names many times must not trip the DGA rule.
    from anta.tools.pcapgen import dns_query
    names = [f"mail{i}.example.com" for i in range(40)]   # dictionary-ish, one registered domain
    frames, t = [], 0.0
    for i, name in enumerate(names):
        frames.append((t, samples.udp("10.80.0.5", "10.80.0.1", 50000 + i, 53, dns_query(0x6000 + i, name, 1))))
        frames.append((t + 0.01, samples.udp("10.80.0.1", "10.80.0.5", 53, 50000 + i, samples._dns_reply(0x6000 + i, name, 3))))
        t += 0.05
    path = write(tmp_path, "typos.pcap", frames)
    _, alerts = analyze(engine, path)
    assert not [a for a in alerts if a["kind"] == "dga"]   # all under one domain, low entropy


def test_new_detectors_are_quiet_on_benign_traffic(engine, data_dir):
    _, alerts = analyze(engine, os.path.join(data_dir, "benign_val.pcap"))
    assert not [a for a in alerts if a["kind"] in ("scan", "dga", "arp_spoof")]
