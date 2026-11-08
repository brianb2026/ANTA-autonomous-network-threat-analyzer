"""A compromised router, found the way a network-forensics exercise expects: router
configurations backed up over FTP name every address each router has, and the one
whose resolver answers a well-known name with a documentation address is the
attacker's. The packet-list text is what Wireshark 4.6 shows for these packets
(built by anta.tools.samples.router_lab)."""
import hashlib
import json
import time

import pytest

from anta import devices, netmap
from anta.analyzer import Analyzer
from anta.security import InvalidRecord, validate_session
from anta.tools import samples
from conftest import run_engine, sessions


@pytest.fixture(scope="module")
def lab_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("lab") / "lab.pcap"
    samples.write_pcap(path, samples.router_lab())
    return str(path)


def analyze(engine, path):
    analyzer = Analyzer()
    for rec in run_engine(engine, "-r", path):
        if rec["type"] == "session":
            rec = validate_session(rec)
        analyzer.ingest(rec)
    return analyzer


def by_kind(analyzer, kind):
    return [a for a in analyzer.alerts.values() if a["kind"] == kind]


# ------------------------------------------------------------------ the engine

def test_ftp_transfers_are_followed(engine, lab_pcap):
    data = {s["ftp_data"]["name"]: s for s in sessions(run_engine(engine, "-r", lab_pcap)) if s.get("ftp_data")}
    gw1 = data["backups/gw1_backup.config"]["ftp_data"]
    assert gw1["command"] == "STOR" and gw1["upload"] and not gw1["active"] and gw1["complete"]
    assert gw1["sha256"] == hashlib.sha256(samples.GW1_CONFIG.encode()).hexdigest()
    assert gw1["text"] == samples.GW1_CONFIG and gw1["user"] == "anonymous" and gw1["tls_refused"]
    # The server is behind NAT: its 227 names 172.16.90.5, the data goes to 172.16.9.5.
    gw3 = data["backups/gw3_backup.config"]
    assert gw3["dst_ip"] == samples.FTP_SERVER and gw3["ftp_data"]["text"] == samples.GW3_CONFIG
    assert gw3["ftp_data"]["control"] == f"10.9.5.1:51100 -> {samples.FTP_SERVER}:21"
    assert data["backups/test.txt"]["ftp_data"]["size"] == 0
    listing = next(s for s in data.values() if s["ftp_data"]["command"] == "LIST")
    assert listing["ftp_data"]["active"] and not listing["ftp_data"]["upload"]  # PORT: the server connects back
    assert listing["src_ip"] == samples.FTP_SERVER and listing["src_port"] == 20
    assert listing["ftp_data"]["text"] == samples.LISTING
    control = next(s for s in sessions(run_engine(engine, "-r", lab_pcap))
                   if s.get("ftp") and s["src_ip"] == "10.9.5.1")
    assert control["ftp"]["tls_refused"] and "PASS ***" in control["ftp"]["commands"]
    assert "STOR backups/gw3_backup.config" in control["ftp"]["commands"]


def test_redaction_leaves_file_contents_out(engine, lab_pcap):
    files = [s["ftp_data"] for s in sessions(run_engine(engine, "--redact", "-r", lab_pcap)) if s.get("ftp_data")]
    assert files and all("text" not in f for f in files) and all(f["sha256"] or not f["size"] for f in files)


def test_ftp_reads_like_wireshark(engine, lab_pcap):
    rows = [(r["proto"], r["info"]) for r in run_engine(engine, "--packets", "-r", lab_pcap, "--limit", "1000")
            if r["type"] == "packet"]
    for row in [("FTP", "Response: 227 Entering Passive Mode (172,16,9,5,176,44)."),
                ("FTP", "Request: STOR backups/gw1_backup.config"),
                ("FTP-DATA", "FTP Data: 258 bytes (PASV) (STOR backups/gw1_backup.config)"),
                ("FTP", "Request: PORT 192,168,10,20,176,44"),
                ("FTP-DATA", "FTP Data: 165 bytes (PORT) (LIST)"),
                ("TCP", "52000 → 14159 [<None>] Seq=1 Win=65535 Len=122")]:
        assert row in rows
    # Wireshark follows a data connection only to the address the 227 names (and from the
    # control connection's other end), so the transfer behind NAT stays plain TCP.
    assert ("TCP", "51101 → 45100 [PSH, ACK] Seq=1 Ack=1 Win=65535 Len=522") in rows
    assert not [r for r in rows if "gw3_backup" in r[1] and r[0] == "FTP-DATA"]


# ------------------------------------------------------------ the analysis

def test_the_poisoning_router_and_all_its_addresses(engine, lab_pcap):
    analyzer = analyze(engine, lab_pcap)
    [poison] = by_kind(analyzer, "dns_poison")
    assert poison["severity"] == "critical" and poison["offender"] == samples.GW3
    assert poison["dns"]["name"] == samples.MIRROR and poison["dns"]["answers"] == [samples.FALSE_ADDR]
    assert set(poison["dns"]["others"]) == {samples.GW1, samples.GW2}
    assert poison["victims"] == ["192.168.30.40"]
    device = poison["device"]
    assert device["name"] == "gw3" and device["kind"] == "OpenWrt router"
    assert sorted(device["addresses"]) == sorted(samples.GW3_ADDRESSES)
    assert device["dhcp_interfaces"] == ["wan"]
    assert "one of its own addresses" in device["evidence"]
    assert any(f"192.168.30.40 -> {samples.FALSE_ADDR}:14159" in d for d in poison["details"])


def test_one_alert_names_the_device_and_every_address(engine, lab_pcap):
    # What an analyst submits: the device, and all its addresses, including the
    # loopback that never appears on the wire.
    analyzer = analyze(engine, lab_pcap)
    [device] = by_kind(analyzer, "compromised_device")
    assert device["severity"] == "critical" and device["offender"] == samples.GW3
    assert device["addresses"] == ["192.168.30.254", "10.9.5.1", "127.9.9.3"]  # where it acted first, loopback last
    assert device["target"] == "gw3" and device["device"]["kind"] == "OpenWrt router"
    [poison] = by_kind(analyzer, "dns_poison")
    assert device["causes"] == [poison["id"]]
    assert "never seen on the network" in " ".join(device["details"])
    from anta.analyzer import alert_summary
    assert alert_summary(device)["addresses"] == device["addresses"]  # the alert table shows them all
    # A file that merely uploads its own configuration implicates nobody.
    assert all(a["kind"] != "compromised_device" or a["offender"] == samples.GW3 for a in analyzer.alerts.values())


def test_hand_built_tcp_to_the_false_address_is_critical(engine, lab_pcap):
    [crafted] = by_kind(analyze(engine, lab_pcap), "crafted_tcp")
    # It ended before the false answer was judged, and was raised again once it was.
    assert crafted["severity"] == "critical" and crafted["dst_ip"] == samples.FALSE_ADDR
    assert crafted["metrics"]["segments"] == 3 and crafted["metrics"]["poisoned"] is True
    assert any(samples.MIRROR in d for d in crafted["details"])


def test_router_configurations_over_ftp(engine, lab_pcap):
    alerts = {a["file"]["name"]: a for a in by_kind(analyze(engine, lab_pcap), "ftp_file")}
    assert set(alerts) == {"gw1_backup.config", "gw3_backup.config"}  # not the empty test.txt, not the listing
    gw3 = alerts["gw3_backup.config"]
    assert gw3["severity"] == "medium" and gw3["src_ip"] == "10.9.5.1" and gw3["dst_ip"] == samples.FTP_SERVER
    assert gw3["file"]["url"] == f"ftp://{samples.FTP_SERVER}/backups/gw3_backup.config"
    assert gw3["device"]["name"] == "gw3"
    assert any("AUTH TLS" in d for d in gw3["details"])


def test_the_map_shows_the_router(engine, lab_pcap):
    analyzer = analyze(engine, lab_pcap)
    stats = next(r for r in run_engine(engine, "--stats", "-r", lab_pcap) if r["type"] == "stats")
    graph = netmap.annotate_devices(netmap.build(stats), [e["device"] for e in analyzer.devices.values()])
    node = next(n for n in graph["nodes"] if n["addr"] == samples.GW3)
    assert node["role"] == "Router / gateway" and node["name"] == "gw3"
    assert sorted(node["device"]["addresses"]) == sorted(samples.GW3_ADDRESSES)
    assert any("describes OpenWrt router gw3" in r for r in node["reasons"])


def resolver_alerts(engine, tmp_path, lookups):
    path = tmp_path / "dns.pcap"
    samples.write_pcap(path, samples.dns_lookups(lookups))
    return by_kind(analyze(engine, str(path)), "dns_poison")


def test_how_much_a_disagreement_matters(engine, tmp_path):
    good = ["151.101.2.132"]
    # An internal address where others give a public one: split DNS or redirection.
    [a] = resolver_alerts(engine, tmp_path, [("10.1.0.5", "10.1.0.1", "updates.example.com", good),
                                             ("10.2.0.5", "10.2.0.1", "updates.example.com", ["10.66.0.9"])])
    assert a["severity"] == "medium" and a["offender"] == "10.2.0.1"
    # 0.0.0.0 where others resolve it: a filtering resolver.
    [a] = resolver_alerts(engine, tmp_path, [("10.1.0.5", "10.1.0.1", "ads.example.com", good),
                                             ("10.2.0.5", "10.2.0.1", "ads.example.com", ["0.0.0.0"])])
    assert a["severity"] == "low"
    # A lab resolver that answers everything with documentation addresses: nothing to compare, no alert.
    assert not resolver_alerts(engine, tmp_path, [("10.1.0.5", "10.1.0.1", f"h{i}.lab.example", [f"192.0.2.{i}"])
                                                  for i in range(1, 6)])
    # Names that never leave the network aren't judged at all.
    assert not resolver_alerts(engine, tmp_path, [("10.1.0.5", "10.1.0.1", "printer.home.arpa", ["192.0.2.7"]),
                                                  ("10.2.0.5", "10.2.0.1", "printer.home.arpa", good)])


# ------------------------------------------------------------ device configurations

def test_address_kinds():
    assert devices.address_kind("203.0.113.9") == "documentation"
    assert devices.address_kind("198.18.0.1") == "benchmarking"
    assert devices.address_kind("127.3.6.3") == "loopback"
    assert devices.address_kind("0.0.0.0") == "unspecified"
    assert devices.address_kind("10.0.0.1") == "private"
    assert devices.address_kind("2001:db8::1") == "documentation"
    assert devices.address_kind("151.101.2.132") == "public"
    assert {"documentation", "benchmarking"} <= devices.NEVER_VALID


def addrs(dev):
    return [(i.name, i.text()) for i in dev.interfaces]


def test_openwrt():
    dev = devices.parse(samples.GW3_CONFIG, "backups/gw3_backup.config")
    assert dev.kind == "OpenWrt router" and dev.name == "gw3"
    assert addrs(dev) == [("loopback", "127.9.9.3/8"), ("lan", "192.168.30.254/24"), ("uplink", "10.9.5.1/28")]
    assert dev.dhcp_interfaces == ["wan"]
    dev = devices.parse(samples.GW1_CONFIG + "\nconfig domain\n\toption name 'nas.example.com'\n\toption ip '192.0.2.4'\n"
                        "config dnsmasq\n\tlist address '/update.example.org/198.51.100.3'\n", "gw1.cfg")
    assert dev.hostname == "gw1" and dev.name == "gw1"
    assert dev.dns_overrides == [("nas.example.com", "192.0.2.4"), ("update.example.org", "198.51.100.3")]


def test_cisco_juniper_mikrotik():
    dev = devices.parse("hostname edge-1\n!\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.252\n"
                        "interface Loopback0\n ip address 10.255.0.1 255.255.255.255\n ipv6 address 2001:db8::1/64\n"
                        "!\nip host portal.example.com 192.0.2.80\n", "edge-1-running.cfg")
    assert dev.kind == "Cisco IOS device" and dev.name == "edge-1"
    assert addrs(dev) == [("Gi0/0", "10.0.0.1/30"), ("Loopback0", "10.255.0.1/32"), ("Loopback0", "2001:db8::1/64")]
    assert dev.dns_overrides == [("portal.example.com", "192.0.2.80")]
    dev = devices.parse("set system host-name core-2\nset interfaces ge-0/0/0 unit 0 family inet address 10.1.1.1/24\n",
                        "core.conf")
    assert dev.kind == "Juniper device" and dev.hostname == "core-2" and addrs(dev) == [("ge-0/0/0.0", "10.1.1.1/24")]
    dev = devices.parse("/ip address\nadd address=192.168.88.1/24 interface=bridge network=192.168.88.0\n"
                        "/ip dns static\nadd address=192.0.2.66 name=login.example.com\n"
                        "/system identity\nset name=mt-home\n", "export.rsc")
    assert dev.kind == "MikroTik router" and dev.hostname == "mt-home"
    assert addrs(dev) == [("bridge", "192.168.88.1/24")] and dev.dns_overrides == [("login.example.com", "192.0.2.66")]


def test_hosts():
    ip_addr = ("1: lo: <LOOPBACK,UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
               "2: eth0@if7: <BROADCAST,UP> mtu 1500\n    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n")
    assert addrs(devices.parse(ip_addr, "ip-addr.txt")) == [("lo", "127.0.0.1/8"), ("eth0", "10.0.0.5/24")]
    ifupdown = "auto eth0\niface eth0 inet static\n    address 10.0.0.6\n    netmask 255.255.255.0\niface eth1 inet dhcp\n"
    dev = devices.parse(ifupdown, "interfaces")
    assert addrs(dev) == [("eth0", "10.0.0.6/24")] and dev.dhcp_interfaces == ["eth1"]
    ifconfig = "en0: flags=8863<UP,BROADCAST> mtu 1500\n\tinet 10.0.0.7 netmask 0xffffff00 broadcast 10.0.0.255\n"
    assert addrs(devices.parse(ifconfig, "ifconfig.txt")) == [("en0", "10.0.0.7/24")]
    netplan = "network:\n  ethernets:\n    ens3:\n      addresses:\n        - 10.0.0.8/24\n    ens4:\n      addresses: [10.9.0.1/16]\n"
    assert addrs(devices.parse(netplan, "01-netcfg.yaml")) == [("ens3", "10.0.0.8/24"), ("ens4", "10.9.0.1/16")]
    ipconfig = ("Windows IP Configuration\n\n   Host Name . . . . . . . . . . . . : WS-12\n\n"
                "Ethernet adapter Ethernet0:\n\n   IPv4 Address. . . . . . . . . . . : 10.0.0.9(Preferred)\n")
    dev = devices.parse(ipconfig, "ipconfig.txt")
    assert dev.kind == "Windows host" and dev.hostname == "WS-12" and addrs(dev) == [("Ethernet0", "10.0.0.9")]
    dev = devices.parse("# local overrides\naddress=/bank.example.com/192.0.2.99\n", "dnsmasq.conf")
    assert dev.kind == "DNS resolver (dnsmasq)" and dev.dns_overrides == [("bank.example.com", "192.0.2.99")]


def test_not_a_configuration():
    for text in ("", "hello world\n", samples.LISTING, "config\n", "interface\n", "/ip address\n", "x" * 600_000):
        assert devices.parse(text, "f.txt") is None


@pytest.mark.parametrize("text", [
    "/ip address\n" + "add address=1.2.3.4 " * 30000,
    "interface x\n" + "\n" * 500000,
    "\n" * 500000,
    "IPv4 Address\n" + "xadapter " * 60000,
    "hostname" + " \t" * 200000 + "x y",
    "config interface 'a'\n" + "\toption ipaddr '" * 40000,
])
def test_hostile_text_parses_in_linear_time(text):
    # Files come off the wire: no pattern may backtrack its way to minutes.
    start = time.perf_counter()
    devices.parse(text[:512 * 1024], "x.config")
    assert time.perf_counter() - start < 2


# ------------------------------------------------------------ validation

def test_ftp_records_are_validated(engine, lab_pcap):
    rec = next(s for s in sessions(run_engine(engine, "-r", lab_pcap)) if s.get("ftp_data"))
    big = json.loads(json.dumps(rec))
    big["ftp_data"]["text"] = "a" * 100_000
    assert len(validate_session(big)["ftp_data"]["text"]) == 64 * 1024
    for field, value in (("sha256", "zz"), ("text", 5), ("magic", "not hex")):
        bad = json.loads(json.dumps(rec))
        bad["ftp_data"][field] = value
        with pytest.raises(InvalidRecord):
            validate_session(bad)
    bad = json.loads(json.dumps(rec))
    bad["tcp"]["null_flags"] = -1
    with pytest.raises(InvalidRecord):
        validate_session(bad)
