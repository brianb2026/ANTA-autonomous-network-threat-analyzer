"""Analysis tools: display filters, expert information, statistics, the network map,
Follow Stream, coloring rules, and the API behind them.

The expected values come from Wireshark 4.6 (tshark -2) on the same packets."""
import asyncio
import json
import os
import socket
import stat
import struct

import pytest
from aiohttp.test_utils import TestClient, TestServer

from anta import netmap
from anta.analyzer import Analyzer
from anta.server import Dashboard, allowed_hosts_for
from anta.tools.pcapgen import dns_query, dns_response
from anta.tools.samples import ACK, FIN, PSH, SACK_PERM, SYN, icmp, mss_option, tcp, udp, write_pcap
from conftest import ENGINE, run_engine

TOKEN = "analysis-test-token-0123456789"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
JSON = {**AUTH, "Content-Type": "application/json"}

# ----------------------------------------------------------- a capture builder

def _udp(src, dst, sport, dport, payload, ttl=64):
    return udp(src, dst, sport, dport, payload, ttl)


_tcp, _icmp, _mss = tcp, icmp, mss_option


def expert_capture(path):
    C, S = "10.1.0.1", "10.1.0.2"
    f = [
        # A connection where the client's data is acknowledged in part, then resent
        (0.00, _tcp(C, S, 40000, 80, 1000, 0, SYN, opts=_mss(1460) + SACK_PERM)),
        (0.01, _tcp(S, C, 80, 40000, 5000, 1001, SYN | ACK, opts=_mss(600) + SACK_PERM)),
        (0.02, _tcp(C, S, 40000, 80, 1001, 5001, ACK)),
        (0.03, _tcp(C, S, 40000, 80, 1001, 5001, PSH | ACK, b"a" * 1000)),
        (0.04, _tcp(S, C, 80, 40000, 5001, 1501, ACK)),                     # acknowledges half of it
        (0.50, _tcp(C, S, 40000, 80, 1001, 5001, PSH | ACK, b"a" * 1000)),  # retransmission
        (0.51, _tcp(S, C, 80, 40000, 5001, 2001, ACK)),  # the original (partly acked) answers: not ambiguous
        (0.60, _tcp(C, S, 40000, 80, 2001, 5001, FIN | ACK)),                # active close
        (0.61, _tcp(S, C, 80, 40000, 5001, 2002, FIN | ACK)),                # passive close
        (0.62, _tcp(C, S, 40000, 80, 2002, 5002, ACK)),
        # SYNs with options but without an MSS or SACK permitted
        (1.00, _tcp(C, S, 40001, 22, 7000, 0, SYN, opts=b"\x03\x03\x07")),
        (1.01, _tcp(C, S, 40002, 22, 8000, 0, SYN, opts=SACK_PERM)),
        # TTL notes
        (2.00, _udp(C, "255.255.255.255", 9999, 9999, b"hello", ttl=1)),
        (2.01, _udp(C, "224.0.0.251", 5353, 5353, dns_query(0, "printer.local"), ttl=1)),
        (2.02, _udp(C, "239.1.2.3", 9999, 9999, b"hello", ttl=1)),
        # ICMP: an error type and a deprecated one
        (3.00, _icmp(S, C, 5, 1, socket.inet_aton("10.1.0.3") + _udp(C, S, 1234, 53, b"x")[14:42])),
        (3.01, _icmp(S, C, 4, 0, b"\0" * 4 + _udp(C, S, 1234, 53, b"x")[14:42])),
        # DNS: a query and a response, each sent twice
        (4.00, _udp(C, S, 5555, 53, dns_query(0x1234, "example.com"))),
        (4.80, _udp(C, S, 5555, 53, dns_query(0x1234, "example.com"))),
        (5.00, _udp(S, C, 53, 5555, dns_response(0x1234, "example.com", 1, ["93.184.216.34"]))),
        (5.10, _udp(S, C, 53, 5555, dns_response(0x1234, "example.com", 1, ["93.184.216.34"]))),
        # DHCP Discover whose "seconds elapsed" was written little-endian (43)
        (6.00, _udp("0.0.0.0", "255.255.255.255", 68, 67,
                    struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, 0x85B86675, 0x2B00, 0, b"\0" * 4,
                                b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\x02\0\0\0\0\x01" + b"\0" * 10, b"", b"")
                    + b"\x63\x82\x53\x63\x35\x01\x01\xff")),
        # The server sends more than the MSS it announced; the client resends a segment
        # and the ACK can't say which copy arrived (Karn's ambiguity).
        (7.00, _tcp(C, S, 40003, 80, 100, 0, SYN, opts=_mss(1460) + SACK_PERM)),
        (7.01, _tcp(S, C, 80, 40003, 900, 101, SYN | ACK, opts=_mss(600) + SACK_PERM)),
        (7.02, _tcp(C, S, 40003, 80, 101, 901, ACK)),
        (7.03, _tcp(C, S, 40003, 80, 101, 901, PSH | ACK, b"c" * 500)),
        (7.04, _tcp(S, C, 80, 40003, 901, 101, PSH | ACK, b"d" * 700)),
        (7.50, _tcp(C, S, 40003, 80, 101, 901, PSH | ACK, b"c" * 500)),
        (7.51, _tcp(S, C, 80, 40003, 1601, 601, ACK)),
    ]
    write_pcap(path, f)


# Wireshark's expert tap (tshark -2 -z expert) on expert_capture()
EXPECTED_EXPERT = {
    ("Chat", "Sequence", "TCP", "Connection establish request (SYN): server port 80"): 2,
    ("Chat", "Sequence", "TCP", "Connection establish request (SYN): server port 22"): 2,
    ("Chat", "Sequence", "TCP", "Connection establish acknowledge (SYN+ACK): server port 80"): 2,
    ("Chat", "Sequence", "TCP", "Connection finish (FIN)"): 2,
    ("Note", "Sequence", "TCP", "This frame initiates the connection closing"): 1,
    ("Note", "Sequence", "TCP", "This frame undergoes the connection closing"): 1,
    ("Note", "Sequence", "TCP", "This frame is a (suspected) retransmission"): 2,
    ("Note", "Sequence", "TCP", "Partial Acknowledgement of a segment"): 1,
    ("Note", "Sequence", "TCP", "Ambiguous ACK following Karn's definition"): 1,
    ("Note", "Protocol", "TCP", "This packet's length exceeds MSS (common with TSO or incomplete conversations)"): 1,
    ("Note", "Protocol", "TCP", "The SYN packet does not contain a MSS option"): 2,
    ("Note", "Protocol", "TCP", "The SYN packet does not contain a SACK PERM option"): 1,
    ("Note", "Sequence", "IPv4", '"Time To Live" only 1'): 1,
    ("Note", "Sequence", "IPv4",
     '"Time To Live" != 255 for a packet sent to the Local Network Control Block (see RFC 3171)'): 1,
    ("Note", "Response", "ICMP", "Type indicates an error"): 1,
    ("Note", "Deprecated", "ICMP", "Type is deprecated"): 1,
    ("Warning", "Protocol", "DNS", "DNS query retransmission. Original request in frame 18"): 1,
    ("Warning", "Protocol", "DNS", "DNS response retransmission. Original response in frame 20"): 1,
    ("Note", "Protocol", "DHCP/BOOTP", "Seconds elapsed appears to be encoded as little-endian"): 1,
    ("Warning", "Protocol", "mDNS", "DNS response missing"): 1,
}


@pytest.fixture(scope="module")
def expert_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("expert") / "expert.pcap"
    expert_capture(path)
    return str(path)


def stats_of(engine, *args):
    return next(r for r in run_engine(engine, "--stats", *args) if r["type"] == "stats")


def frames(engine, path, flt):
    out = run_engine(engine, "--packets", "-r", path, "-Y", flt, "--limit", "100000")
    return [r["n"] for r in out if r["type"] == "packet"]


# --------------------------------------------------------------------- tests

def test_expert_information_matches_wireshark(engine, expert_pcap):
    got = {(e["severity"], e["group"], e["protocol"], e["summary"]): e["count"]
           for e in stats_of(engine, "-r", expert_pcap)["expert"]}
    assert got == EXPECTED_EXPERT


def test_expert_fields_filter_like_wireshark(engine, expert_pcap):
    assert frames(engine, expert_pcap, "tcp.analysis.partial_ack") == [5]
    assert frames(engine, expert_pcap, "tcp.analysis.ambiguous_ack") == [29]
    assert frames(engine, expert_pcap, "tcp.analysis.acks_frame == 26") == [29]
    assert frames(engine, expert_pcap, "tcp.analysis.acks_frame == 4") == [5, 7]  # the oldest copy is reported
    assert frames(engine, expert_pcap, "tcp.connection.fin_active") == [8]
    assert frames(engine, expert_pcap, "tcp.connection.fin_passive") == [9]
    assert frames(engine, expert_pcap, "ip.ttl.too_small") == [13]
    assert frames(engine, expert_pcap, "ip.ttl.lncb") == [14]
    assert frames(engine, expert_pcap, "dns.retransmit_request") == [19]
    assert frames(engine, expert_pcap, "dns.response_in == 20") == [18]
    assert frames(engine, expert_pcap, "dns.response_to == 18") == [20]
    assert frames(engine, expert_pcap, "dns.time > 0.9 && dns.time < 1.1") == [20]
    assert frames(engine, expert_pcap, "dhcp.secs == 43 && dhcp.secs_le") == [22]
    # Any expert item, chats included, makes a frame match _ws.expert.
    assert 1 in frames(engine, expert_pcap, "_ws.expert") and 3 not in frames(engine, expert_pcap, "_ws.expert")


def test_display_filters_on_demo_capture(engine, data_dir):
    demo = os.path.join(data_dir, "mixed_demo.pcap")
    counts = {flt: len(frames(engine, demo, flt)) for flt in (
        "tls.handshake.legacy_version", "tcp.connection.fin_active", "tcp.analysis.ambiguous_ack")}
    # tshark -2 on the same capture
    assert counts == {"tls.handshake.legacy_version": 2678, "tcp.connection.fin_active": 1359,
                      "tcp.analysis.ambiguous_ack": 37}


def test_check_filter_reports_wireshark_errors(engine):
    out = run_engine(engine, "--check-filter", "ip.sr == 1", "--check-filter", "tcp.port in {80, 443}",
                     "--check-filter", "ip.addr ==")
    assert [r["ok"] for r in out] == [False, True, False]
    assert out[0]["error"] == '"ip.sr" is not a valid protocol or protocol field.'


def test_statistics_and_network_map(engine, data_dir):
    s = stats_of(engine, "-r", os.path.join(data_dir, "edge_cases.pcap"))
    props = s["properties"]
    assert props["frames"] == props["frames_total"] > 0
    top = next(p for p in s["protocols"] if p["path"] == "frame")
    assert top["frames"] == props["frames"] and top["bytes"] == props["bytes"]
    # Every packet an endpoint sends is received by the other side of the conversation.
    for table in ("eth", "ipv4", "tcp", "udp"):  # rows: address, name, tx frames, tx bytes, rx frames, rx bytes
        rows = s["endpoints"][table]["rows"]
        assert rows and sum(r[2] for r in rows) == sum(r[4] for r in rows)
        assert sum(r[3] for r in rows) == sum(r[5] for r in rows)
    assert sum(b["count"] for b in s["lengths"]) == props["frames"]
    assert sum(sum(b[:1]) for b in s["io"]["bins"]) == props["frames"]
    m = netmap.build(s)
    ids = {n["id"] for n in m["nodes"]}
    assert m["nodes"] and all(n["kind"] and n["role"] and n["reasons"] for n in m["nodes"])
    assert all(e["a"] in ids and e["b"] in ids for e in m["edges"])


def test_network_map_keeps_a_routers_mac_off_the_hosts_it_forwards_for():
    # Captured on a router: packets it forwards carry its MAC and other hosts' addresses.
    host = {"tx_bytes": 100, "rx_bytes": 100, "tcp_uses": {"443": 3}}
    stats = {
        "hosts": [{**host, "addr": "192.168.2.50", "macs": ["00:0c:29:00:00:01", "00:1b:54:00:00:02"]},
                  {**host, "addr": "192.168.2.254", "macs": ["00:1b:54:00:00:02"], "tcp_uses": {}},
                  {**host, "addr": "93.184.216.34", "macs": ["00:1b:54:00:00:02"], "tcp_uses": {},
                   "tcp_serves": {"443": 3}}],
        "macs": [{"mac": "00:0c:29:00:00:01", "vendor": "VMware", "src_ip_count": 1, "src_ips": ["192.168.2.50"],
                  "arp_ips": ["192.168.2.50"]},
                 {"mac": "00:1b:54:00:00:02", "vendor": "Cisco", "src_ip_count": 3,
                  "src_ips": ["192.168.2.50", "192.168.2.254", "93.184.216.34"], "arp_ips": ["192.168.2.254"]}],
    }
    nodes = {n["addr"]: n for n in netmap.build(stats)["nodes"]}
    assert nodes["192.168.2.50"]["macs"] == ["00:0c:29:00:00:01"] and nodes["192.168.2.50"]["vendor"] == "VMware"
    assert nodes["192.168.2.254"]["role"] == "Router / gateway" and nodes["192.168.2.254"]["vendor"] == "Cisco"
    assert nodes["93.184.216.34"]["macs"] == [] and nodes["93.184.216.34"]["vendor"] is None
    assert nodes["93.184.216.34"]["role"] == "Web server"


def test_follow_tcp_stream_returns_payload_in_order(engine, data_dir):
    out = run_engine(engine, "--follow", "tcp,0", "-r", os.path.join(data_dir, "edge_cases.pcap"))[-1]
    assert out["found"] and out["chunks"][0]["dir"] == 0
    text = b"".join(bytes.fromhex(c["hex"]) for c in out["chunks"])
    assert text.startswith(b"GET /vlan HTTP/1.1") and b"HTTP/1.1 204" in text
    assert out["a_bytes"] + out["b_bytes"] == len(text)


# ------------------------------------------------------------------- the API

async def _client(tmp_path):
    dash = Dashboard(Analyzer(), ENGINE, TOKEN, allowed_hosts_for("127.0.0.1", []), set(), prefs_dir=str(tmp_path))
    queue = asyncio.Queue()
    dash.attach_sessions(queue)
    tasks = [asyncio.create_task(dash.consume(queue)), asyncio.create_task(dash.flusher())]
    client = TestClient(TestServer(dash.app(), host="127.0.0.1"))
    await client.start_server()
    return dash, client, tasks


async def _close(dash, client, tasks):
    await dash.sessions.stop()
    for t in tasks:
        t.cancel()
    await client.close()


def test_color_rules_api_validates_and_saves_privately(engine, tmp_path):
    async def go():
        dash, c, tasks = await _client(tmp_path)
        try:
            r = await c.get("/api/color-rules", headers=AUTH)
            data = await r.json()
            assert r.status == 200 and data["rules"] == data["defaults"] and data["rules"][0]["name"] == "Bad TCP"
            rule = {"name": "Web", "filter": "tcp.port == 80", "bg": "#FFEEDD", "fg": "#000000", "enabled": True}
            bad_color = await c.put("/api/color-rules", headers=JSON, json={"rules": [{**rule, "bg": "red"}]})
            assert bad_color.status == 400
            bad_filter = await c.put("/api/color-rules", headers=JSON, json={"rules": [{**rule, "filter": "tcp.port =="}]})
            assert bad_filter.status == 400 and "rule 1 (Web)" in (await bad_filter.json())["error"]
            assert (await c.put("/api/color-rules", json={"rules": [rule]})).status == 401
            ok = await c.put("/api/color-rules", headers=JSON, json={"rules": [rule]})
            assert ok.status == 200 and (await ok.json())["rules"][0]["bg"] == "#ffeedd"
            saved = tmp_path / "colorfilters.json"
            assert json.loads(saved.read_text())[0]["name"] == "Web"
            if os.name != "nt":
                assert stat.S_IMODE(saved.stat().st_mode) == 0o600
            assert (await (await c.get("/api/color-rules", headers=AUTH)).json())["rules"][0]["name"] == "Web"
        finally:
            await _close(dash, c, tasks)
    asyncio.run(go())


def test_analysis_api_on_a_capture(engine, data_dir, tmp_path):
    async def go():
        dash, c, tasks = await _client(tmp_path)
        try:
            assert (await c.get("/api/stats", headers=AUTH)).status == 409  # nothing open yet
            path = os.path.join(data_dir, "edge_cases.pcap")
            r = await c.post("/api/session", headers=JSON, json={"mode": "file", "path": path, "speed": 0})
            assert r.status == 200
            for _ in range(100):
                if (await c.get("/api/packets?limit=1", headers=AUTH)).status == 200:
                    break
                await asyncio.sleep(0.1)

            checks = await (await c.get("/api/filters/check?f=tcp&f=ip.sr", headers=AUTH)).json()
            assert checks[0]["ok"] and not checks[1]["ok"]
            fields = await (await c.get("/api/filters/fields", headers=AUTH)).json()
            assert {"tcp.analysis.acks_frame", "dns.time", "ip.ttl.too_small"} <= {f["name"] for f in fields}

            page = await (await c.get("/api/packets?dfilter=http&colorize=1&tmpcolor=tcp.stream+eq+0",
                                      headers=AUTH)).json()
            assert page["packets"] and all(p["proto"] == "HTTP" or "HTTP" in p["info"] for p in page["packets"])
            first = page["packets"][0]
            assert first["color"] == 0  # the temporary conversation rule comes first
            bad = await c.get("/api/packets?dfilter=ip.addr+%3D%3D", headers=AUTH)
            assert bad.status == 400

            r = await c.get("/api/stats?series=dns&interval=0.5", headers=AUTH)
            body = await r.json()
            assert r.status == 200 and body["stats"]["io"]["interval"] == 0.5 and body["map"]["nodes"]
            assert (await c.get("/api/stats?dfilter=ip.sr", headers=AUTH)).status == 400
            assert (await c.get("/api/stats?interval=abc", headers=AUTH)).status == 400

            follow = await (await c.get("/api/follow?proto=tcp&stream=0", headers=AUTH)).json()
            assert follow["found"] and follow["chunks"]
            assert (await c.get("/api/follow?proto=sctp&stream=0", headers=AUTH)).status == 400

            detail = await (await c.get("/api/packets/5", headers=AUTH)).json()
            assert ["frame.number", "5"] in detail["fields"]
        finally:
            await _close(dash, c, tasks)
    asyncio.run(go())


def _rule_case(cport, steps):
    """A connection with MSS/SACK options, then the given (time, frame) steps."""
    C, S = "10.1.0.1", "10.1.0.2"
    return [(0.00, tcp(C, S, cport, 80, 1000, 0, SYN, opts=mss_option(1460) + SACK_PERM)),
            (0.01, tcp(S, C, 80, cport, 5000, 1001, SYN | ACK, opts=mss_option(1460) + SACK_PERM)),
            (0.02, tcp(C, S, cport, 80, 1001, 5001, ACK))] + steps


def test_tcp_ack_analysis_follows_wireshark_on_real_world_patterns(engine, tmp_path):
    # Patterns from a real capture, checked against tshark -2: a retransmission that
    # spans two segments doesn't make their ACKs ambiguous; one inside a segment does;
    # a retransmitted FIN still "initiates" the close; a SACK block below the ACK is a D-SACK.
    C, S = "10.1.0.1", "10.1.0.2"

    def data(cp, seq, n, t):
        return (t, tcp(C, S, cp, 80, seq, 5001, PSH | ACK, b"x" * n))

    def ack(cp, a, t, sack=None):
        opts = b""
        if sack:
            opts = b"\x01\x01" + bytes([5, 2 + 8 * len(sack)]) + b"".join(struct.pack("!II", l, r) for l, r in sack)
        return (t, tcp(S, C, 80, cp, 5001, a, ACK, opts=opts))

    cases = {
        "coalesced": _rule_case(1, [data(1, 1001, 100, .1), data(1, 1101, 100, .11), data(1, 1001, 200, .5),
                                    ack(1, 1101, .6), ack(1, 1201, .7)]),
        "contained": _rule_case(2, [data(2, 1001, 1000, .1), data(2, 1501, 200, .5), ack(2, 2001, .6)]),
        "fin": _rule_case(3, [data(3, 1001, 10, .1), ack(3, 1011, .11),
                              (.2, tcp(C, S, 3, 80, 1011, 5001, FIN | ACK)), (.6, tcp(C, S, 3, 80, 1011, 5001, FIN | ACK)),
                              (.7, tcp(S, C, 80, 3, 5001, 1012, FIN | ACK))]),
        "dsack": _rule_case(4, [data(4, 1001, 100, .1), data(4, 1101, 100, .11), ack(4, 1201, .2),
                                data(4, 1001, 100, .5), ack(4, 1201, .6, sack=[(1001, 1101)])]),
    }
    got = {}
    for name, f in cases.items():
        path = tmp_path / f"{name}.pcap"
        write_pcap(path, f)
        got[name] = {flt: frames(engine, str(path), flt) for flt in (
            "tcp.analysis.ambiguous_ack", "tcp.analysis.acks_frame == 4", "tcp.analysis.acks_frame == 5",
            "tcp.connection.fin_active", "tcp.connection.fin_passive", "tcp.options.sack.dsack",
            "tcp.analysis.duplicate_ack_num == 1")}
    assert got["coalesced"]["tcp.analysis.ambiguous_ack"] == []
    assert got["coalesced"]["tcp.analysis.acks_frame == 4"] == [7] and got["coalesced"]["tcp.analysis.acks_frame == 5"] == [8]
    assert got["contained"]["tcp.analysis.ambiguous_ack"] == [6] and got["contained"]["tcp.analysis.acks_frame == 4"] == [6]
    assert got["fin"]["tcp.connection.fin_active"] == [6, 7] and got["fin"]["tcp.connection.fin_passive"] == [8]
    assert got["fin"]["tcp.analysis.ambiguous_ack"] == [8]
    assert got["dsack"]["tcp.options.sack.dsack"] == [8] and got["dsack"]["tcp.analysis.duplicate_ack_num == 1"] == [8]
