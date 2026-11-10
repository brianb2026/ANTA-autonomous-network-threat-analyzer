"""Before the capture: what the recorded traffic shows happened before recording began, from
leftovers only (connections already open, addresses already known, a resolver's cache counting
down, a DHCP lease partway through, a TLS session resumed)."""
import asyncio

from anta import before
from anta.tools import samples
from test_server import AUTH, make_client

BASE = 1_700_000_000


def test_the_lab_through_the_endpoint(engine, tmp_path):
    path = tmp_path / "before.pcap"
    samples.write_pcap(str(path), samples.before_lab())

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(str(path))
            d = await (await c.get("/api/before", headers=AUTH)).json()
        finally:
            await c.close()
        return d
    d = asyncio.run(go())
    start = d["start"]
    assert abs(start - (BASE + 0.1)) < 0.01
    by = {}
    for e in d["events"]:
        by.setdefault(e["kind"], []).append(e)
    assert set(by) == {"open", "known", "cache", "lease", "resumed"}
    assert by["open"][0]["who"] == "192.168.60.10" and "203.0.113.5" in by["open"][0]["what"]
    known = {e["peer"] for e in by["known"]}
    assert known == {"files.example.net", "mail.example.com"}  # (seen.example.org was looked up in the capture)
    cache = by["cache"]
    assert [e["peer"] for e in cache] == ["news.example.org"] and not cache[0]["sure"]  # (the usual 3,600 s assumed)
    assert abs(cache[0]["when"] - (BASE + 6.01 - (1800 - 1234))) < 1
    lease = by["lease"][0]
    assert lease["who"] == "192.168.60.20" and abs(lease["when"] - (BASE + 8.0 - 43200)) < 1 and lease["sure"]
    res = by["resumed"][0]
    assert res["who"] == "192.168.60.13" and res["peer"] == "mail.example.com" and abs(res["earliest"] - (BASE + 10 - 7 * 86400)) < 5
    assert d["earliest"] == lease["when"]  # (the oldest dated finding: the lease, 12 hours back)


def row(n, ts, src, dst, name, ttl):
    return {"type": "packet", "n": n, "ts": ts, "src": src, "dst": dst,
            "f": {"dns.qry.name": [name], "dns.resp.type": ["1"], "dns.resp.ttl": [str(ttl)], "dns.a": ["203.0.113.9"]}}


def test_a_resolvers_cache():
    rows = [row(1, 100.0, "10.0.0.1", "10.0.0.5", "a.example", 3600),   # (fresh: the full value, seen)
            row(2, 105.0, "10.0.0.1", "10.0.0.6", "b.example", 50),
            row(3, 300.0, "10.0.0.1", "10.0.0.7", "a.example", 3400),   # (cached at 100 s: in the capture, not before)
            row(4, 150.0, "8.8.8.8", "10.0.0.5", "c.example", 10),      # (a public resolver: everyone's cache)
            row(5, 120.0, "10.0.0.1", "10.0.0.5", "d.example", 7000),
            row(6, 130.0, "10.0.0.1", "10.0.0.5", "d.example", 86400)]
    d = before.reconstruct([], rows, [], [], 100.0)
    cache = {e["peer"]: e for e in d["events"] if e["kind"] == "cache"}
    assert set(cache) == {"b.example", "d.example"}
    assert cache["b.example"]["when"] == 105.0 - 10 and not cache["b.example"]["sure"]   # (usual 60 s assumed)
    assert cache["d.example"]["when"] == 120.0 - (86400 - 7000) and cache["d.example"]["sure"]  # (the full 86,400 is in it)


def test_a_device_rejoining_and_one_that_is_new():
    def dh(n, ts, mtype, mac, ciaddr="0.0.0.0", wanted=""):  # noqa: S104
        f = {"dhcp.option.dhcp": [str(mtype)], "dhcp.hw.mac_addr": [mac], "dhcp.ip.client": [ciaddr]}
        if wanted:
            f["dhcp.option.requested_ip_address"] = [wanted]
        return {"type": "packet", "n": n, "ts": ts, "src": "0.0.0.0", "dst": "255.255.255.255", "f": f}  # noqa: S104
    rows = [dh(1, 10.0, 3, "02:00:00:00:00:01", wanted="10.0.0.40"),   # (asks to keep its address: it had it)
            dh(2, 11.0, 1, "02:00:00:00:00:02"),                       # (a new device: discover first)
            dh(3, 12.0, 3, "02:00:00:00:00:02", wanted="10.0.0.41")]
    d = before.reconstruct([], [], rows, [], 5.0)
    leases = [e for e in d["events"] if e["kind"] == "lease"]
    assert [e["who"] for e in leases] == ["10.0.0.40"] and leases[0]["when"] is None


def test_a_connection_that_started_here_is_not_before():
    s = {"proto": "tcp", "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "src_port": 5000, "dst_port": 443, "start": 10, "end": 20,
         "tcp": {"handshake": True}, "c2s": {"packets": 5, "payload_bytes": 100}, "s2c": {"packets": 5, "payload_bytes": 100},
         "tls": {"sni": "x.example"}, "dns": []}
    lookup = {"proto": "udp", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "start": 9, "end": 9,
              "dns": [{"qname": "x.example", "answers": ["203.0.113.9"]}]}
    d = before.reconstruct([s, lookup], [], [], [], 9.0)
    assert d["events"] == []
    s2 = dict(s, tcp={"handshake": False}, stream_head={"c2s_from_start": False, "s2c_from_start": False})
    d = before.reconstruct([s2, lookup], [], [], [], 9.0)
    assert [e["kind"] for e in d["events"]] == ["open"]
