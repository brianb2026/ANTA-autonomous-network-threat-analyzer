"""The certificate of quiet: each device's traffic to the internet accounted for, the room it had
to hide data in headers and timing (an upper limit), and the stretches when it sent nothing."""
import asyncio

from anta import quiet
from anta.tools import samples
from conftest import run_engine
from test_server import AUTH, make_client


def S(src, dst, start, end, c2s_pk=4, c2s_pay=1000, s2c_pk=4, s2c_pay=500, proto="tcp", **kw):
    return {"proto": proto, "src_ip": src, "dst_ip": dst, "src_port": 50000, "dst_port": 443, "start": start, "end": end,
            "c2s": {"packets": c2s_pk, "bytes": 0, "payload_bytes": c2s_pay},
            "s2c": {"packets": s2c_pk, "bytes": 0, "payload_bytes": s2c_pay}, **kw}


def test_room_and_open_data():
    ss = [S("10.0.0.5", "203.0.113.9", 0, 10, tls={"sni": "x"}),                      # out, encrypted
          S("10.0.0.6", "10.0.0.7", 0, 10),                                           # inside only
          S("203.0.113.20", "10.0.0.7", 20, 30, c2s_pk=2, c2s_pay=50, s2c_pk=3, s2c_pay=900),  # a server here, answering out
          S("10.0.0.8", "10.0.0.1", 40, 41, proto="udp", dns=[{"qname": "abc.def.example.com"}, {"qname": "printer.local"}])]
    c = quiet.certify(ss, [(50.0, "10.0.0.5", "198.51.100.1", 98)], [], {"urgent": 0, "reserved": 0}, (0.0, 100.0))
    by = {r["ip"]: r for r in c["devices"]}
    a = by["10.0.0.5"]
    assert a["open"] == 1000 + 56 and a["encrypted"] == 1000 and a["icmp"] == 56 and a["connections"] == 1
    # 4 TCP packets + 1 ICMP: IPv4 IDs 5×16, timestamps 4×8, its sequence start 32, its port 16, timing 5×1.
    assert a["room"] == -(-(5 * 16 + 4 * 8 + 32 + 16 + 5) // 8) and "tcp_urgent" not in a["room_parts"]
    assert by["10.0.0.6"]["silent"] and by["10.0.0.6"]["room"] == 0
    s7 = by["10.0.0.7"]  # (it answered: its 3 packets out, no port of its own choosing)
    assert s7["open"] == 900 and s7["room"] == -(-(3 * 16 + 3 * 8 + 32 + 3) // 8)
    dns = by["10.0.0.8"]  # (names leave through the resolver, so it isn't silent)
    assert not dns["silent"] and dns["dns_names"] == 1 and dns["dns_bytes"] == len("abc.def")
    assert c["totals"]["most_room"] == a["room"] and c["fields"][2]["removed"]  # (urgent pointer never used)


def test_a_used_urgent_pointer_counts():
    ss = [S("10.0.0.5", "203.0.113.9", 0, 10)]
    free = quiet.certify(ss, [], [], {"urgent": 0}, None)["devices"][0]["room"]
    used = quiet.certify(ss, [], [], {"urgent": 3}, None)["devices"][0]
    assert used["room"] == free + 4 * 16 // 8 and used["room_parts"]["tcp_urgent"] == 8


def test_stretches_of_quiet():
    ss = [S("10.0.0.5", "203.0.113.9", 0, 10), S("10.0.0.5", "203.0.113.9", 5000, 5010)]
    r = quiet.certify(ss, [], [], {}, (0.0, 6000.0))["devices"][0]
    assert r["quiet"][0]["from"] == 10 and r["quiet"][0]["to"] == 5000 and r["quiet"][0]["seconds"] == 4990
    assert all(q["seconds"] >= 600 for q in r["quiet"])  # (short pauses aren't listed)


def test_ipv6_and_filters():
    ss = [S("fd00::5", "2001:db8::9", 0, 1, c2s_pk=2)]
    r = quiet.certify(ss, [], [], {}, None)["devices"][0]
    assert r["room_parts"]["ip6_flow"] == 5 and r["filter"].startswith("ipv6.src == fd00::5")


def test_the_endpoint(engine, tmp_path):
    path = tmp_path / "office.pcap"
    samples.write_pcap(str(path), samples.software_lab())

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(str(path))
            d = await (await c.get("/api/quiet", headers=AUTH)).json()
            by = {r["ip"]: r for r in d["devices"]}
            assert d["names"] == ["office.pcap"] and d["totals"]["talkers"] >= 3
            assert by["192.168.50.20"]["silent"] and not by["192.168.50.10"]["silent"]  # (the intranet server stays inside)
            out = run_engine(engine, "--packets", "-r", str(path), "-Y", by["192.168.50.10"]["filter"])
            assert any(r.get("type") == "packet" and r["dst"] == "93.184.216.34" for r in out)
            assert not any(r.get("type") == "packet" and r["dst"].startswith("192.168.") for r in out)
        finally:
            await c.close()
    asyncio.run(go())
