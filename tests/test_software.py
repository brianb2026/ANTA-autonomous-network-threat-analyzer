"""Installed software read from the outside: programs and versions from User-Agents, update
checks, Server headers and greetings, judged against the end-of-support table; and a client's
first line (an FTP USER) is never kept."""
import asyncio
import datetime as dt
import json

import pytest

from anta import software as sw
from anta.tools import samples
from conftest import run_engine, sessions
from test_server import AUTH, make_client

TODAY = dt.date(2026, 11, 8)


@pytest.mark.parametrize("ua, expect", [
    ("Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
     {("Chrome", "109.0.0.0"), ("Windows 7", "6.1")}),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
     {("Microsoft Edge", "141.0.0.0"), ("Windows 10 or 11", "10.0")}),   # (not Chrome or Safari too)
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
     {("Safari", "17.4"), ("macOS", "")}),                                # (the frozen 10_15_7 is no version)
    ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
     {("Chrome", "140.0.0.0"), ("Android", "")}),                         # (Chrome's reduced "Android 10; K")
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 "
     "Safari/604.1", {("Safari", "26.0"), ("iOS / iPadOS", "26")}),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Slack/4.36.140 Chrome/120.0.6099.56 "
     "Electron/28.1.0 Safari/537.36", {("Slack", "4.36.140"), ("Electron (app framework)", "28.1.0"), ("Windows 10 or 11", "10.0")}),
    ("Debian APT-HTTP/1.3 (2.4.11)", {("APT (Debian/Ubuntu package manager)", "2.4.11")}),
    ('pip/23.3.1 {"python":"3.8.10","system":{"name":"Linux"}}', {("pip (Python packages)", "23.3.1"), ("Python", "3.8.10")}),
    ("Roku/DVP-14.0 (14.0.0.4119-46)", {("Roku OS", "14.0")}),
    ("SomeCamera/2.1.7", {("SomeCamera", "2.1.7")}),
])
def test_user_agents(ua, expect):
    assert {(n, v) for n, v, _, _ in sw.from_user_agent(ua)} == expect


def test_greetings_and_server_headers():
    got = sw.from_greeting("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10")
    assert [(n, v) for n, v, _, _ in got] == [("OpenSSH", "8.9p1"), ("Ubuntu", "22.04")]
    assert [(n, v) for n, v, _, _ in sw.from_greeting("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3")] == [("OpenSSH", "9.2p1"), ("Debian", "12")]
    assert sw.from_greeting("220 (vsFTPd 2.3.4)")[0][:2] == ("vsftpd", "2.3.4")
    got = {(n, v) for n, v, _, _ in sw.from_server_header("Apache/2.2.15 (CentOS) OpenSSL/1.0.1e-fips PHP/5.3.3")}
    assert got == {("Apache HTTP Server", "2.2.15"), ("OpenSSL", "1.0.1e"), ("PHP", "5.3.3"), ("CentOS", "")}
    assert [(n, v) for n, v, _, _ in sw.from_uri("archive.ubuntu.com", "/ubuntu/dists/jammy-security/InRelease")] == [("Ubuntu", "22.04")]
    assert sw.vtuple("8.9p1") == (8, 9, 0, 1) and sw.vtuple("1.0.1f") == (1, 0, 1, 6)


@pytest.mark.parametrize("name, version, kw, status", [
    ("OpenSSH", "9.6", {"role": "serves"}, "vulnerable"),           # regreSSHion
    ("OpenSSH", "8.9p1", {"role": "serves", "backports": True}, "check"),  # (Ubuntu patches it)
    ("OpenSSH", "9.6", {"role": "runs"}, "ok"),                     # (the flaw is in the server only)
    ("OpenSSH", "9.8p1", {"role": "serves"}, "ok"),
    ("Apache HTTP Server", "2.4.49", {}, "vulnerable"),
    ("Apache HTTP Server", "2.2.15", {}, "unsupported"),
    ("OpenSSL", "1.0.1e", {}, "vulnerable"),                        # Heartbleed
    ("OpenSSL", "1.0.1g", {}, "unsupported"),
    ("OpenSSL", "3.5.1", {}, "ok"),
    ("vsftpd", "2.3.4", {}, "vulnerable"),
    ("PHP", "7.4.3", {}, "unsupported"),
    ("PHP", "8.2.10", {}, "ending"),                                # (ends December 31, 2026)
    ("Ubuntu", "20.04", {}, "unsupported"),
    ("Ubuntu", "24.04", {}, "ok"),
    ("Debian", "12", {}, "ok"),
    ("Windows 7", "6.1", {}, "unsupported"),
    ("Windows 10 or 11", "10.0", {}, "check"),
    ("Python", "3.8.10", {}, "unsupported"),
    ("Microsoft IIS", "6.0", {}, "vulnerable"),
    ("Microsoft IIS", "8.5", {}, "unsupported"),
    ("Android", "11", {}, "unsupported"),
    ("Node.js", "18.17.0", {}, "unsupported"),
    ("Something", "1.0", {}, "unknown"),
])
def test_judging(name, version, kw, status):
    assert sw.judge(name, version, TODAY, **kw)[0] == status


def test_browsers_against_the_time_of_the_capture():
    then = dt.date(2023, 11, 14)  # (Chrome 119 was current)
    assert sw.judge("Chrome", "119.0", TODAY, then)[0] == "ok"
    assert sw.judge("Chrome", "109.0", TODAY, then)[0] == "unsupported"
    assert sw.judge("Chrome", "115.0", TODAY, then)[0] == "old"
    assert sw.judge("Chrome", "117.0", TODAY, then, {"Chrome": 121})[0] == "old"  # (a neighbour's newer version counts)
    assert sw.judge("Chrome", "116.0", TODAY, then, {"Chrome": 124})[0] == "unsupported"
    assert sw.judge("Firefox", "115.0", TODAY, dt.date(2024, 11, 1))[0] == "check"  # (may be ESR)


@pytest.fixture(scope="module")
def lab(engine, tmp_path_factory):
    path = tmp_path_factory.mktemp("software") / "office.pcap"
    samples.write_pcap(str(path), samples.software_lab())
    return path, list(sessions(run_engine(engine, "-r", str(path))))


def test_the_office(lab):
    path, ss = lab
    banners = [s.get("banner") for s in ss if s.get("banner")]
    assert {"server": "220 (vsFTPd 2.3.4)"} in banners
    assert not any("USER" in json.dumps(b) or "alice" in json.dumps(b) for b in banners)  # (who logs in is never kept)
    inv = sw.inventory(ss, today=TODAY)
    by = {(h["ip"], r["name"]): r for h in inv["hosts"] for r in h["software"]}
    assert by[("192.168.50.20", "Apache HTTP Server")]["status"] == "vulnerable"
    assert by[("192.168.50.20", "PHP")]["status"] == "unsupported" and by[("192.168.50.20", "PHP")]["role"] == "serves"
    assert by[("192.168.50.22", "vsftpd")]["status"] == "vulnerable"
    assert by[("192.168.50.10", "Windows 7")]["status"] == "unsupported"
    assert by[("192.168.50.10", "OpenSSH")]["status"] == "ok"            # (its SSH client)
    assert by[("192.168.50.21", "OpenSSH")]["status"] == "check"         # (Ubuntu's, backported)
    assert by[("192.168.50.21", "Ubuntu")]["version"] == "22.04"
    assert by[("192.168.50.11", "Ubuntu")]["version"] == "20.04" and by[("192.168.50.11", "Ubuntu")]["status"] == "unsupported"
    assert by[("192.168.50.12", "Python")]["version"] == "3.8.10"
    assert by[("192.168.50.30", "Chrome")]["status"] == "ok"
    internet = next(h for h in inv["hosts"] if h["ip"] == "93.184.216.34")
    assert not internet["local"] and inv["local_hosts"] == 7
    assert inv["hosts"][0]["worst"] == "vulnerable"
    assert inv["totals"]["vulnerable"] == 2  # (Apache and vsftpd; local devices only)


def test_every_filter_finds_its_packets(lab, engine):
    path, ss = lab
    for h in sw.inventory(ss, today=TODAY)["hosts"]:
        for r in h["software"]:
            out = run_engine(engine, "--packets", "-r", str(path), "-Y", r["filter"])
            assert any(rec.get("type") == "packet" for rec in out), r["filter"]


def test_the_endpoint_and_host_panel(lab):
    path, _ = lab

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(str(path))
            d = await (await c.get("/api/software", headers=AUTH)).json()
            assert d["local_hosts"] == 7 and d["hosts"][0]["worst"] == "vulnerable" and d["notes"]
            h = await (await c.get("/api/host?addr=192.168.50.20", headers=AUTH)).json()
            assert {r["name"] for r in h["software"]} >= {"Apache HTTP Server", "PHP"}
        finally:
            await c.close()
    asyncio.run(go())
