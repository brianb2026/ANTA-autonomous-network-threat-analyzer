"""Explain: connections and packets in plain words. Each failure in the
troubleshooting lab (anta.tools.samples.troubleshooting_lab) must be diagnosed as
what it is, from the decoded packets, with the frames it rests on. The packet-list
text and stream numbers are what Wireshark 4.6 shows for the same packets."""
import asyncio

import pytest

from anta import diagnose
from anta.tools import samples
from conftest import run_engine
from test_server import AUTH, make_client

C = samples.TROUBLE_CLIENT


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    path = tmp_path_factory.mktemp("trouble") / "trouble.pcap"
    samples.write_pcap(path, samples.troubleshooting_lab())
    return str(path)


def explained(engine, path, flt="frame"):
    records = run_engine(engine, "--packets", "-r", path, "-Y", flt, "--limit", "4000", "--fields", diagnose.FIELDS)
    return diagnose.explain(records)


def by_server(result):
    return {c["server"]: c for c in result["conversations"]}


# ---------------------------------------------------------------- the engine

def test_fields_come_with_every_occurrence_and_presence_items(engine, lab):
    rows = {r["n"]: r for r in run_engine(engine, "--packets", "-r", lab, "--fields", "ip.src,tcp.analysis.*,icmp.code,tcp.srcport")
            if r["type"] == "packet"}
    icmp = rows[7]["f"]  # the firewall's ICMP error: its own source, then the quoted packet's
    assert icmp["ip.src"] == ["10.20.0.1", C] and icmp["icmp.code"] == ["13"] and icmp["tcp.srcport"] == ["50003"]
    assert rows[62]["f"]["tcp.analysis.zero_window"] == [""]  # presence-only, as in the packet detail
    assert rows[62]["x"] == ["[TCP ZeroWindow]"]


def test_icmp_errors_carry_the_quoted_ports_and_stream(engine, lab, tmp_path):
    # Wireshark: a filter on the connection's ports also finds the ICMP error about it.
    flt = f"ip.addr == {C} && ip.addr == 198.51.100.20 && tcp.port == 50003 && tcp.port == 8443"
    assert [r["n"] for r in run_engine(engine, "--packets", "-r", lab, "-Y", flt) if r["type"] == "packet"] == [6, 7]
    # A quoted UDP packet takes its flow's udp.stream, and one never seen opens a new stream.
    frames = [(0.0, samples.udp(C, "10.30.0.1", 40000, 53, b"x" * 12))]
    q = samples.udp(C, "10.30.0.12", 40001, 161, b"y" * 20)
    ghost = samples.udp(C, "10.30.0.99", 40002, 9999, b"z" * 8)
    frames += [(1.0, q), (1.1, samples.icmp("10.30.0.12", C, 3, 3, samples._quoted(q))),
               (2.0, samples.icmp("10.30.0.99", C, 3, 3, samples._quoted(ghost))),
               (3.0, samples.udp(C, "10.30.0.7", 40003, 123, b"w" * 48))]
    path = tmp_path / "icmp.pcap"
    samples.write_pcap(path, frames)
    streams = [r["f"]["udp.stream"][0] for r in run_engine(engine, "--packets", "-r", str(path), "--fields", "udp.stream")
               if r["type"] == "packet"]
    assert streams == ["0", "1", "1", "2", "3"]  # what Wireshark 4.6 numbers them


def test_the_lab_reads_like_wireshark(engine, lab):
    rows = [(r["proto"], r["info"]) for r in run_engine(engine, "--packets", "-r", lab, "--limit", "1000") if r["type"] == "packet"]
    for row in [("TCP", "3389 → 50001 [RST, ACK] Seq=1 Ack=1 Win=65535 Len=0"),
                ("TCP", "[TCP Retransmission] 50002 → 22 [SYN] Seq=0 Win=65535 Len=0 MSS=1460"),
                ("ICMP", "Destination unreachable (Communication administratively filtered)"),
                ("ICMP", "Destination unreachable (Port unreachable)"),
                ("TLSv1.2", "Alert (Level: Fatal, Description: Handshake Failure)"),
                ("TLSv1.2", "Alert (Level: Fatal, Description: Unknown CA)"),
                ("TCP", "[TCP ZeroWindow] 50009 → 7070 [ACK] Seq=1 Ack=1401 Win=0 Len=0"),
                ("TCP", "[TCP Keep-Alive] [TCP Window Full] 7070 → 50009 [ACK] Seq=1400 Ack=1 Win=65535 Len=1"),
                ("TCP", "[TCP Window Update] 50009 → 7070 [ACK] Seq=1 Ack=1401 Win=65535 Len=0"),
                ("DNS", "Standard query response 0x2001 No such name A printer-old.corp.example"),
                ("KRB5", "KRB Error: KRB5KDC_ERR_PREAUTH_FAILED"),
                ("FTP", "Response: 530 Login incorrect.")]:
        assert row in rows


# ---------------------------------------------------------------- diagnoses

EXPECTED = {
    "10.20.0.10:3389": ("failed", "Refused", ["reset", "frame 2"]),
    "10.20.0.11:22": ("failed", "No answer", ["3 times", "no SYN-ACK"]),
    "198.51.100.20:8443": ("failed", "Blocked by a firewall", ["10.20.0.1", "administratively prohibited", "frame 7"]),
    "10.20.0.12:161": ("failed", "Port closed", ["port unreachable", "nothing is listening"]),
    "203.0.113.30:443": ("failed", "TLS handshake refused by the server", ["handshake_failure", "legacy.example.net"]),
    "10.20.0.13:443": ("failed", "Server rejected by the client", ["unknown_ca", "frame 27"]),
    "10.20.0.14:80": ("problem", "Server errors", ["HTTP 404", "HTTP 503"]),
    "10.20.0.15:8080": ("failed", "Reset by the server", ["frame 57", "middle of a transfer"]),
    "10.20.0.16:7070": ("problem", "Receiver stopped reading", ["zero window", "frame 62", C]),
    "10.20.0.17:5001": ("problem", "Packet loss", ["2 segments", "frame 75"]),
    "10.20.0.53:53": ("problem", "Name does not exist", ["NXDOMAIN", "printer-old.corp.example"]),
    "10.20.0.54:53": ("failed", "DNS server didn't answer", ["3 times", "updates.example.com"]),
    "10.20.0.88:88": ("problem", "Logon failed", ["KDC_ERR_PREAUTH_FAILED", "password was wrong"]),
    "10.20.0.21:21": ("problem", "Login failed", ["FTP 530"]),
    "10.20.0.80:80": ("ok", "Completed normally", ["orderly"]),
}


def test_every_failure_is_diagnosed_as_what_it_is(engine, lab):
    result = explained(engine, lab)
    convs = {c["server"]: c for c in result["conversations"] if not (c["server"] == "10.20.0.53:53" and "SERVFAIL" in c["summary"])}
    for server, (status, title, words) in EXPECTED.items():
        c = convs[server]
        assert (c["status"], c["title"]) == (status, title), (server, c["title"], c["summary"])
        for w in words:
            assert w in c["summary"], (server, w, c["summary"])
    servfail = next(c for c in result["conversations"] if "SERVFAIL" in c["summary"])
    assert servfail["title"] == "DNS server failure"
    # Every failed or troubled one says why and what to check.
    for c in result["conversations"]:
        if c["status"] in ("failed",) and c["proto"] == "TCP":
            assert c["causes"] and c["checks"], c["title"]


def test_the_timeline_cites_frames_in_plain_words(engine, lab):
    zw = by_server(explained(engine, lab))["10.20.0.16:7070"]
    lines = {e["n"]: e["text"] for e in zw["timeline"]}
    assert "open a connection (SYN)" in lines[58] and "accepts" in lines[59] and "connection is open" in lines[60]
    assert "buffer is full" in lines[62] and "room again" in lines[65]
    assert any("zero window" in x.lower() or "not reading" in x for x in zw["causes"] + [zw["summary"]])


def test_one_stream_with_its_icmp_error(engine, lab):
    # Explaining a stream also takes in the ICMP error about it (it has no tcp.stream).
    tcp = run_engine(engine, "--packets", "-r", lab, "-Y", "tcp.stream eq 2", "--fields", diagnose.FIELDS)
    icmp = run_engine(engine, "--packets", "-r", lab, "-Y",
                      f"icmp && ip.addr == {C} && ip.addr == 198.51.100.20 && tcp.port == 50003 && tcp.port == 8443",
                      "--fields", diagnose.FIELDS)
    result = diagnose.explain(sorted([r for r in tcp + icmp if r["type"] == "packet"], key=lambda r: r["n"]))
    [c] = result["conversations"]
    assert c["title"] == "Blocked by a firewall" and c["filter"] == "tcp.stream eq 2"


def test_hand_built_tcp_is_called_out(engine, tmp_path):
    path = tmp_path / "lab.pcap"
    samples.write_pcap(path, samples.router_lab())
    c = by_server(explained(engine, str(path), "tcp.flags == 0"))[f"{samples.FALSE_ADDR}:14159"]
    assert c["status"] == "suspicious" and c["title"] == "Hand-built TCP packets"


# ---------------------------------------------------------------- one packet

def detail(engine, path, n):
    return run_engine(engine, "--packet-detail", str(n), "-r", path)[0]


def test_single_packets_in_plain_words(engine, lab):
    lines = lambda n: {x["title"]: x for x in diagnose.explain_frame(detail(engine, lab, n))}  # noqa: E731
    assert "Reset (RST)" in lines(2)
    assert "Retransmission" in lines(4) and lines(4)["Retransmission"]["level"] == "warn"
    assert "Destination unreachable: communication administratively prohibited" in lines(7)
    assert "TLS alert: handshake_failure" in lines(15) and lines(15)["TLS alert: handshake_failure"]["level"] == "bad"
    assert "Zero window" in lines(62)
    assert "DNS NXDOMAIN" in lines(79)
    assert "Kerberos KDC_ERR_PREAUTH_FAILED" in lines(86)
    assert "FTP 530" in lines(98)
    assert diagnose.stream_of(detail(engine, lab, 62)) == ("tcp", 7)


def test_payloads_are_recognised():
    d = diagnose.describe_payload
    assert "TLS handshake" in d(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc")["what"]
    assert "HTTP request" in d(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n")["what"]
    assert "Windows program" in d(b"MZ\x90\x00" + bytes(200))["what"]
    shell = d(b"whoami\nipconfig /all\nnet user\n")
    assert "remote shell" in shell["what"] and shell["kind"] == "text"
    assert "Base64" in d(b"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA==")["what"]
    import random
    noise = d(random.Random(1).randbytes(4096))
    assert noise["entropy"] > 7.5 and "custom encrypted channel" in noise["what"]
    assert "structured binary" in d(bytes(500) + b"\x01\x02")["what"]
    beacon = diagnose.payload_summary({"a": "1.1.1.1:1", "b": "2.2.2.2:2", "chunks": [
        {"dir": 0, "hex": random.Random(i).randbytes(64).hex()} for i in range(5)]})
    assert "exactly 64 bytes" in beacon[0]["what"]


# ---------------------------------------------------------------- the endpoints

def test_explain_through_the_server(engine, lab):
    async def go():
        dash, c = await make_client()
        dash.packets.reset(lab)
        try:
            r = await (await c.get("/api/explain?stream=tcp:2", headers=AUTH)).json()
            [conv] = r["conversations"]
            assert conv["title"] == "Blocked by a firewall"
            r = await (await c.get("/api/explain?stream=tcp:3", headers=AUTH)).json()
            conv = r["conversations"][0]
            assert conv["title"] == "TLS handshake refused by the server"
            assert any("TLS handshake" in p["what"] for p in conv["payload"])  # the Client Hello, described
            r = await c.get("/api/explain?dfilter=" + "udp.port == 53", headers=AUTH)
            assert (await r.json())["total"] == 3
            assert (await c.get("/api/explain?stream=tcp:999", headers=AUTH)).status == 404
            assert (await c.get("/api/explain?stream=sctp:1", headers=AUTH)).status == 400
            assert (await c.get("/api/explain", headers=AUTH)).status == 400
            assert (await c.get("/api/explain?dfilter=tcp.port%20==", headers=AUTH)).status == 400
            d = await (await c.get("/api/packets/62", headers=AUTH)).json()
            assert d["stream_ref"] == ["tcp", 7] and any(x["title"] == "Zero window" for x in d["explain"])
        finally:
            await c.close()
    asyncio.run(go())


def test_the_vocabulary_covers_the_codes_analysts_meet_most():
    for code in (40, 42, 45, 46, 48, 70, 112):
        assert code in diagnose.TLS_ALERTS
    for code in (6, 18, 23, 24, 25, 37):
        assert code in diagnose.KERBEROS_ERRORS
    for code in (1, 3, 9, 10, 13):
        assert code in diagnose.ICMP_UNREACHABLE
    assert {"STATUS_LOGON_FAILURE", "STATUS_ACCESS_DENIED", "STATUS_BAD_NETWORK_NAME"} <= set(diagnose.SMB_STATUS)


def test_odd_ntp_and_dns_read_like_wireshark(engine, tmp_path):
    c, s = "10.30.0.5", "10.30.0.7"
    frames = [
        (0.0, samples.udp(c, s, 40010, 123, bytes([0x17, 0x00, 0x03, 0x2a]) + bytes(4))),         # ntpdc monlist
        (0.1, samples.udp(s, c, 123, 40010, bytes([0x97, 0x00, 0x03, 0x2a]) + bytes(76))),
        (0.2, samples.udp(c, s, 40011, 123, bytes([0x16, 0x02, 0, 1]) + bytes(8))),              # mode 6 control
        (0.3, samples.udp(c, s, 40012, 123, bytes([0x03]) + bytes(47))),                         # version 0
        (0.4, samples.udp(c, s, 40013, 53, b"x" * 12)),                                         # junk on port 53
    ]
    path = tmp_path / "odd.pcap"
    samples.write_pcap(path, frames)
    rows = [(r["proto"], r["info"]) for r in run_engine(engine, "--packets", "-r", str(path)) if r["type"] == "packet"]
    assert rows == [("NTP", "NTP Version 2, private, Request, MON_GETLIST_1"),
                    ("NTP", "NTP Version 2, private, Response, MON_GETLIST_1"),
                    ("NTP", "NTP Version 2, control"),
                    ("NTP", "reserved, client"),
                    ("DNS", "Unknown operation (15) 0x7878[Malformed Packet]")]
    stats = next(r for r in run_engine(engine, "--stats", "-r", str(path)) if r["type"] == "stats")
    assert [(e["severity"], e["protocol"], e["summary"]) for e in stats["expert"]] == \
        [("Error", "DNS", "Malformed Packet (Exception occurred)")]
