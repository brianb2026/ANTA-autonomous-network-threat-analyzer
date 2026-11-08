"""Network policy tests: rules in plain words, read back plainly, checked against a capture's
sessions; a failure lists the connections that broke the rule with a filter for each."""
import asyncio
import json
import os

import pytest

from anta import policy
from test_server import AUTH, make_client


@pytest.mark.parametrize("text, kind, reads", [
    ("only 10.0.0.1 answers DNS", "only_servers", "Only 10.0.0.1 may answer DNS"),
    ("Only 10.0.0.1 and fd00::1 answer DNS queries.", "only_servers", "Only 10.0.0.1, fd00::1 may answer DNS"),
    ("DNS only goes to 10.0.0.1", "only_servers", "Only 10.0.0.1 may answer DNS"),
    ("the only DHCP server is 10.0.0.1", "only_servers", "Only 10.0.0.1 may answer DHCP"),
    ("nothing uses Telnet", "no_service", "No one uses Telnet"),
    ("no FTP", "no_service", "No one uses FTP"),
    ("Telnet is not allowed", "no_service", "No one uses Telnet"),
    ("nobody uses port 23", "no_service", "No one uses port 23"),
    ("make sure nothing uses rdp", "no_service", "No one uses Remote Desktop"),
    ("all web traffic is encrypted", "no_service", "No one uses HTTP (it isn't encrypted)"),
    ("no passwords in clear text", "no_cleartext_logins", "No login sends its password unencrypted"),
    ("printers only talk to 10.0.0.0/24", "only_destinations", "Printers may only connect to 10.0.0.0/24"),
    ("IoT devices only talk to the internet over HTTPS", "only_destinations",
     "IoT devices may only connect to the internet, and only over HTTPS"),
    ("10.0.0.50 only connects to example.com and 10.0.0.1", "only_destinations",
     "10.0.0.50 may only connect to example.com, 10.0.0.1"),
    ("no host connects to the internet over SMB", "no_destinations", "No host connects to the internet over SMB file sharing"),
    ("nothing talks to 203.0.113.0/24", "no_destinations", "No host talks with 203.0.113.0/24 (in either direction)"),
    ("10.0.0.5 cannot talk to 10.0.0.9", "no_destinations", "10.0.0.5 must not talk with 10.0.0.9 (in either direction)"),
    ("no traffic between 10.0.0.5 and 10.0.0.9", "no_between", "No traffic between 10.0.0.5 and 10.0.0.9 (in either direction)"),
    ("only 10.0.0.0/24 may use SSH", "only_clients", "Only 10.0.0.0/24 may use SSH"),
    ("no traffic between 22:00 and 06:00", "quiet_hours", "Nothing is active between 22:00 and 06:00 (in your computer's time zone)"),
    ("no device connects to North Korea", "no_destinations", "No host connects to North Korea"),
    ("10.0.0.44 never talks to the internet", "no_destinations", "10.0.0.44 must not talk with the internet (in either direction)"),
    ("no host uploads more than 50 MB to the internet", "upload_limit", "Every host sends at most 50.0 MB to the internet"),
])
def test_rules_in_plain_words(text, kind, reads):
    rule = policy.parse(text)
    assert rule["kind"] == kind and rule["reads"] == reads


@pytest.mark.parametrize("text", ["telnet is allowed", "the sky is blue", "no blah", "cameras only talk to their vendor",
                                  "only everyone answers DNS", "x" * 400, ""])
def test_rules_it_cant_read_say_why(text):
    with pytest.raises(policy.PolicyError):
        policy.parse(text)


def S(src, dst, dport, app="", proto="tcp", up=100, down=100, dns=None, sni=None, start=1.0):
    return {"proto": proto, "src_ip": src, "dst_ip": dst, "src_port": 50000, "dst_port": dport, "app": app,
            "c2s": {"payload_bytes": up}, "s2c": {"payload_bytes": down}, "start": start, "end": start + 1,
            "dns": dns or [], "tls": {"sni": sni} if sni else {}}


def test_rules_checked_against_sessions():
    sessions = [
        S("10.0.0.5", "10.0.0.1", 53, "dns", "udp", dns=[{"qname": "example.com", "answers": ["93.184.216.34"]}]),
        S("10.0.0.6", "10.0.0.9", 53, "dns", "udp"),                      # a second DNS server
        S("10.0.0.6", "10.0.0.20", 23, "telnet"),
        S("10.0.0.50", "93.184.216.34", 443, "tls", sni="example.com"),   # allowed by name
        S("10.0.0.50", "198.51.100.7", 443, "tls"),                        # not allowed
        S("10.0.0.7", "203.0.113.5", 445, "smb2", up=80_000_000),          # SMB to the internet, 80 MB up
    ]
    ctx = policy.Context(sessions, logins={"logins": [], "total": 0})
    r = {x["rule"]: x for x in policy.run([
        "only 10.0.0.1 answers DNS", "nothing uses Telnet", "no FTP", "10.0.0.50 only connects to example.com",
        "no host connects to the internet over SMB", "no host uploads more than 50 MB to the internet",
        "no passwords in clear text", "the sky is blue"], ctx)}
    dns = r["only 10.0.0.1 answers DNS"]
    assert dns["status"] == "fail" and dns["groups"][0]["what"] == "10.0.0.9 answered DNS"
    assert dns["groups"][0]["filter"] == "ip.addr == 10.0.0.9 && (tcp.port == 53 || udp.port == 53)"
    assert r["nothing uses Telnet"]["status"] == "fail" and r["no FTP"]["status"] == "pass"
    only = r["10.0.0.50 only connects to example.com"]
    assert only["status"] == "fail" and [g["what"] for g in only["groups"]] == ["10.0.0.50 → 198.51.100.7"]
    assert r["no host connects to the internet over SMB"]["violations"] == 1
    up = r["no host uploads more than 50 MB to the internet"]
    assert up["status"] == "fail" and up["groups"][0]["what"].startswith("10.0.0.7 sent 76.3 MB")
    assert r["no passwords in clear text"]["status"] == "pass"
    assert r["the sky is blue"]["understood"] is False and r["the sky is blue"]["error"]
    assert "(ip.addr == 10.0.0.9" in dns["filter"]


def test_saved_rules_are_cleaned(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTA_DATA_DIR", str(tmp_path))
    saved = policy.save(["nothing uses Telnet", "# a note", "  ", "nothing uses Telnet", "no FTP\x00", 5])
    assert saved == ["nothing uses Telnet", "no FTP"] and policy.load() == saved
    if os.name != "nt":
        assert os.stat(policy.path()).st_mode & 0o777 == 0o600
    with pytest.raises(policy.PolicyError):
        policy.save("not a list")


def test_the_policy_endpoints(engine, data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTA_DATA_DIR", str(tmp_path))

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(os.path.join(data_dir, "mixed_demo.pcap"))
            r = await c.put("/api/policy", json={"rules": ["only 10.0.0.1 answers DNS", "nothing uses Telnet",
                                                            "no host uploads more than 5 MB to the internet"]}, headers=AUTH)
            d = await r.json()
            assert r.status == 200 and len(d["rules"]) == 3
            by = {x["rule"]: x for x in d["results"]}
            assert by["only 10.0.0.1 answers DNS"]["groups"][0]["what"] == "fd00::1 answered DNS"
            assert by["nothing uses Telnet"]["status"] == "pass"
            assert by["no host uploads more than 5 MB to the internet"]["groups"][0]["what"].startswith("10.0.0.44 sent")
            assert json.load(open(os.path.join(str(tmp_path), "policy.json")))["rules"][1] == "nothing uses Telnet"
            r = await c.post("/api/policy/check", json={"rules": ["no FTP"]}, headers=AUTH)
            assert (await r.json())["results"][0]["status"] == "pass"
            assert len((await (await c.get("/api/policy", headers=AUTH)).json())["rules"]) == 3  # (a check doesn't save)
            assert (await c.put("/api/policy", json={"rules": "x"}, headers=AUTH)).status == 400
            assert (await c.get("/api/policy")).status == 401
        finally:
            await c.close()
    asyncio.run(go())


def test_more_rules_checked_against_sessions():
    # 2026-10-06 14:00 UTC is a Tuesday; 2026-10-10 is a Saturday.
    tue_2pm, tue_11pm, sat_noon = 1791295200.0, 1791327600.0, 1791633600.0
    sessions = [
        S("10.0.0.5", "10.0.0.9", 445, "smb2", start=tue_2pm),             # 5 starts it
        S("10.0.0.9", "10.0.0.5", 3389, "rdp", start=tue_2pm),             # 9 starts it
        S("10.0.0.7", "10.0.5.10", 22, "ssh", start=tue_2pm),              # SSH from outside the allowed network
        S("10.0.1.4", "10.0.5.10", 22, "ssh", start=tue_2pm),
        S("10.0.0.50", "10.0.5.50", 9100, "", start=tue_2pm),
        S("10.0.0.50", "10.0.0.1", 53, "dns", "udp", start=tue_2pm),       # a printer that also looks up names
        S("10.0.0.8", "198.51.100.7", 443, "tls", down=3_000_000_000, start=tue_11pm),
        S("10.0.0.8", "198.51.100.8", 443, "tls", start=sat_noon),
    ]
    ctx = policy.Context(sessions, tz_min=0)
    r = {x["rule"]: x for x in policy.run([
        "10.0.0.5 cannot talk to 10.0.0.9", "10.0.0.5 cannot connect to 10.0.0.9", "no traffic between 10.0.0.5 and 10.0.0.9",
        "only 10.0.1.0/24 may use SSH", "10.0.0.50 may only use port 9100", "no host downloads more than 2 GB",
        "no host talks to more than 1 host", "no traffic between 22:00 and 06:00", "nothing talks on weekends",
        "no unknown devices"], ctx)}
    either = r["10.0.0.5 cannot talk to 10.0.0.9"]
    assert either["violations"] == 2 and {g["what"] for g in either["groups"]} == {"10.0.0.5 → 10.0.0.9", "10.0.0.9 → 10.0.0.5"}
    assert r["10.0.0.5 cannot connect to 10.0.0.9"]["violations"] == 1  # (only what 10.0.0.5 starts)
    assert r["no traffic between 10.0.0.5 and 10.0.0.9"]["violations"] == 2
    ssh = r["only 10.0.1.0/24 may use SSH"]
    assert ssh["violations"] == 1 and ssh["groups"][0]["what"] == "10.0.0.7 used SSH on 10.0.5.10:22"
    printer = r["10.0.0.50 may only use port 9100"]
    assert printer["violations"] == 1 and printer["groups"][0]["filter"] == "ip.addr == 10.0.0.50 && udp.port == 53"
    assert r["no host downloads more than 2 GB"]["groups"][0]["what"].startswith("10.0.0.8 received 2.8 GB")
    assert {g["what"] for g in r["no host talks to more than 1 host"]["groups"]} == {"10.0.0.8 talked to 2 hosts",
                                                                                      "10.0.0.50 talked to 2 hosts"}
    night = r["no traffic between 22:00 and 06:00"]
    assert night["violations"] == 1 and night["groups"][0]["what"] == "10.0.0.8 → 198.51.100.7 at Tue 23:00"
    assert "frame.time_epoch >= 1791327600" in night["groups"][0]["filter"]
    assert r["nothing talks on weekends"]["groups"][0]["what"].startswith("10.0.0.8 → 198.51.100.8 at Sat")
    assert r["no unknown devices"]["status"] == "unknown"  # (nothing remembered as normal yet)
    # Seen from a time zone 3 hours behind UTC, 23:00 UTC is 20:00: not night any more.
    late = policy.run(["no traffic between 22:00 and 06:00"], policy.Context(sessions, tz_min=180))[0]
    assert late["status"] == "pass"
    known = {"devices": {"ip:10.0.0.5": {"ip": "10.0.0.5"}}}
    unknown = policy.run(["no unknown devices"], policy.Context(sessions, remembered=known))[0]
    assert unknown["status"] == "fail" and "10.0.0.5" not in {g["what"].split()[0] for g in unknown["groups"]}
