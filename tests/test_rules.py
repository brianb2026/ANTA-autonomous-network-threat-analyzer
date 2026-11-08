"""Network rules: the policy tests and the firewall in one list. Plain words ("block 10.0.0.5",
"no ubuntu hosts on the network", "don't let router configs be uploaded") and firewall lines,
each a test and a firewall rule; lines that can't be read get suggestions."""
import asyncio
import os

import pytest

from anta import hostkinds, netmap, policy, rules, transfers
from anta.tools import samples
from conftest import run_engine, sessions
from test_server import AUTH, make_client


@pytest.mark.parametrize("text, kind, reads", [
    ("block 10.0.0.5", "no_destinations", "Block all traffic with 10.0.0.5 (in either direction)"),
    ("block telnet", "no_service", "Block Telnet"),
    ("block port 4444", "no_service", "Block port 4444"),
    ("block smb to the internet", "no_destinations", "Block SMB file sharing to the internet"),
    ("block 10.0.0.5 from the internet", "no_destinations", "Block 10.0.0.5 from the internet (in either direction)"),
    ("block printers from the internet", "no_destinations", "Block printers from the internet (in either direction)"),
    ("block ubuntu hosts", "no_hosts", "Block Ubuntu hosts: none may be on the network"),
    ("block example.com", "no_destinations", "Block all traffic with example.com (in either direction)"),
    ("please block 10.0.0.0/24", "no_destinations", "Block all traffic with 10.0.0.0/24 (in either direction)"),
    ("block uploads of router configs", "no_transfer", "No router configurations are uploaded"),
    ("don't let router configs be uploaded", "no_transfer", "No router configurations are uploaded"),
    ("dont let router configs be uploaded", "no_transfer", "No router configurations are uploaded"),
    ("no programs downloaded from the internet", "no_transfer", "No programs are downloaded from the internet"),
    ("no file uploads over ftp", "no_transfer", "No files are uploaded over FTP"),
    ("no database dumps uploaded", "no_transfer", "No database dumps are uploaded"),
    ("dont let ubuntu hosts on the network", "no_hosts", "No Ubuntu hosts on the network"),
    ("no ubuntu hosts", "no_hosts", "No Ubuntu hosts on the network"),
    ("windows xp machines are not allowed", "no_hosts", "No Windows XP hosts on the network"),
    ("keep kali hosts off the network", "no_hosts", "No Kali Linux hosts on the network"),
    ("no raspberry pi devices", "no_hosts", "No Raspberry Pi devices on the network"),
    ("no iot devices on the network", "no_hosts", "No IoT devices on the network"),
    ("ubuntu hosts cannot talk to the internet", "no_destinations", "Ubuntu hosts must not talk with the internet (in either direction)"),
    ("printers shouldnt talk to the internet", "no_destinations", "Printers must not talk with the internet (in either direction)"),
    ("no ftp", "no_service", "No one uses FTP"),          # (still a service, not a kind of host)
    ("telnet is not allowed", "no_service", "No one uses Telnet"),
])
def test_new_ways_to_say_a_rule(text, kind, reads):
    rule = policy.parse(text)
    assert rule["kind"] == kind and rule["reads"] == reads


def test_what_cant_be_read_gets_help():
    with pytest.raises(policy.PolicyError, match="Which one"):
        policy.parse("block this ip")
    assert rules.suggest("blok telnet")[0] == "block telnet"
    assert rules.suggest("blok 10.9.9.9")[0] == "block 10.9.9.9"  # (its own address put in)
    assert rules.classify("iptables -A INPUT -j MYCHAIN")[0] == "error" and "MYCHAIN" in rules.classify("iptables -A INPUT -j MYCHAIN")[1]
    assert rules.classify("block in tcp to any port 23")[0] == "firewall" and rules.classify("block 10.0.0.5")[0] == "words"
    assert rules.classify("# a note")[0] == "note"
    ref = rules.reference()
    assert {g["group"] for g in ref} >= {"Block things", "Keep devices off the network", "Files", "Firewall lines"}
    for g in ref:  # (every example in the guide can be read)
        for x in g["examples"]:
            assert rules.classify(x["text"])[0] in ("words", "firewall"), x["text"]


def test_what_a_host_is():
    ss = [{"src_ip": "10.0.0.5", "dst_ip": "91.189.91.83", "proto": "tcp", "http": [{"host": "archive.ubuntu.com", "user_agent": "Debian APT-HTTP/1.3"}]},
          {"src_ip": "10.0.0.6", "dst_ip": "1.1.1.1", "proto": "tcp", "http": [{"host": "x", "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)"}]},
          {"src_ip": "10.0.0.7", "dst_ip": "1.1.1.1", "proto": "tcp", "http": [{"host": "x", "user_agent": "Mozilla/5.0 (Linux; Android 14)"}]},
          {"src_ip": "1.2.3.4", "dst_ip": "10.0.0.8", "proto": "tcp", "http_response": {"server": "Apache/2.4.52 (Ubuntu)"}},
          {"src_ip": "10.0.0.9", "dst_ip": "1.1.1.1", "proto": "tcp", "http": [{"host": "ubuntu.com", "user_agent": "Mozilla/5.0 (Windows NT 10.0)"}]}]
    assets = [{"ip": "10.0.0.10", "vendor": "Raspberry Pi Trading Ltd", "names": ["raspberrypi.local"]},
              {"ip": "10.0.0.11", "names": ["archive.ubuntu.com"]}]
    t = hostkinds.Traits(ss, assets, netmap.scope_of)
    ubuntu, linux = hostkinds.resolve("ubuntu hosts"), hostkinds.resolve("linux machines")
    assert "archive.ubuntu.com" in t.evidence(ubuntu, "10.0.0.5") and "User-Agent" in t.evidence(ubuntu, "10.0.0.6")
    assert "Server header" in t.evidence(ubuntu, "10.0.0.8")
    assert t.evidence(ubuntu, "10.0.0.9") is None    # (browsing ubuntu.com proves nothing)
    assert t.evidence(ubuntu, "10.0.0.11") is None   # (a website's address isn't a device's name)
    assert t.evidence(linux, "10.0.0.5") and t.evidence(linux, "10.0.0.7") is None  # (Android says Linux too)
    assert "Raspberry Pi" in t.evidence(hostkinds.resolve("raspberry pi devices"), "10.0.0.10")
    assert hostkinds.resolve("toasters") is None


@pytest.fixture(scope="module")
def router_lab(engine, tmp_path_factory):
    path = tmp_path_factory.mktemp("rules") / "router.pcap"
    samples.write_pcap(str(path), samples.router_lab())
    return [s for s in sessions(run_engine(engine, "-r", str(path)))]


def test_router_configs_found_by_reading_them(router_lab):
    found = [(s["src_ip"], f) for s in router_lab for f in transfers.files(s) if "config" in f["kinds"]]
    assert found and all(f["up"] and f["proto"] == "FTP" for _, f in found)
    assert any("configuration" in f["why"] for _, f in found)
    r = policy.run(["don't let router configs be uploaded"], policy.Context(router_lab))[0]
    assert r["status"] == "fail" and r["violations"] == len(found) and "uploaded" in r["groups"][0]["what"]
    assert policy.run(["no router configs downloaded"], policy.Context(router_lab))[0]["status"] == "pass"


def S(src, dst, dport, proto="tcp"):
    return {"proto": proto, "src_ip": src, "dst_ip": dst, "src_port": 50000, "dst_port": dport,
            "c2s": {"payload_bytes": 100}, "s2c": {"payload_bytes": 100}}


def test_tests_and_firewall_lines_together():
    ss = [S("10.0.0.5", "8.8.8.8", 443), S("10.0.0.5", "8.8.4.4", 23), S("10.0.0.5", "10.0.0.9", 445), S("203.0.113.9", "10.0.0.7", 22)]
    alerts = [{"id": "A1", "title": "C2", "severity": "critical", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dst_port": 443}]
    lines = ["block 8.8.8.8", "block in tcp to any port 22", "nothing uses smb", "no host uploads more than 1 byte", "blok telnet"]
    res, enf = rules.evaluate(lines, policy.Context(ss), alerts, "border")
    by = {r["line"]: r for r in res}
    assert by[1]["kind"] == "no_destinations" and by[1]["status"] == "fail" and by[1]["enforce"]["blocks"] == 1
    assert by[2]["kind"] == "firewall" and by[2]["status"] == "fail" and by[2]["enforce"] == {"blocks": 1}
    assert by[3]["status"] == "fail" and by[3]["enforce"]["blocks"] == 0 and by[3]["enforce"]["inside"] == 1  # (inside: unseen)
    assert "test only" in by[4]["enforce"]["test_only"]
    assert not by[5]["understood"] and by[5]["suggestions"][0] == "block telnet"
    assert enf["totals"]["blocked"] == 2 and [a["id"] for a in enf["alerts"]["stopped"]] == ["A1"]
    # On every device, the connection inside the network is blocked too.
    res, enf = rules.evaluate(lines, policy.Context(ss), alerts, "host")
    assert enf["totals"]["blocked"] == 3 and {r["line"]: r for r in res}[3]["enforce"]["blocks"] == 1


def test_the_rules_endpoints(engine, data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTA_DATA_DIR", str(tmp_path))

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(os.path.join(data_dir, "mixed_demo.pcap"))
            d = await (await c.get("/api/policy?reference=1", headers=AUTH)).json()
            assert d["rules"] == [] and d["placement"] == "border" and d["reference"]
            body = {"rules": ["block 203.0.113.0/24", "iptables -A FORWARD -p udp --dport 53 -j DROP"], "placement": "host"}
            d = await (await c.put("/api/policy", json=body, headers=AUTH)).json()
            assert d["placement"] == "host" and policy.load_placement() == "host"
            assert d["results"][0]["enforce"]["blocks"] >= 1 and d["results"][1]["kind"] == "firewall"
            assert d["enforce"]["totals"]["blocked"] > 0 and d["enforce"]["breaks"]
            d = await (await c.post("/api/policy/check", json={"rules": ["block 203.0.113.0/24"], "placement": "border"},
                                    headers=AUTH)).json()
            assert d["placement"] == "border" and policy.load_placement() == "host"  # (a check saves nothing)
            assert (await c.post("/api/firewall", json={"rules": "x"}, headers=AUTH)).status in (404, 405)  # (one window now)
        finally:
            await c.close()
    asyncio.run(go())
