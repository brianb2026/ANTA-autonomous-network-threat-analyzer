"""Wireshark's everyday packet-list tools: Find Packet (Ctrl+F: text in the list or the
detail tree, a display filter, hex bytes, a regular expression; next, previous, wrapping
around, within the list's filter), custom columns ("Apply as column") and host names."""
import asyncio
import os

import pytest

from anta.packets import PacketError, PacketService
from conftest import ENGINE, run_engine


@pytest.fixture(scope="module")
def demo(engine, data_dir):
    ps = PacketService(engine)
    ps.reset(os.path.join(data_dir, "mixed_demo.pcap"))
    return ps


def find(ps, *args, **kw):
    return asyncio.run(ps.find(*args, **kw))


def test_find_text_in_the_list_and_the_details(demo):
    assert find(demo, "text", "JSDELIVR", "list", 0) == {"frame": 12, "wrapped": False}  # (any case)
    assert find(demo, "text", "jsdelivr", "list", 12)["frame"] == 20
    # A field name is only in the detail tree.
    assert find(demo, "text", "Transaction ID", "list", 0)["frame"] is None
    assert find(demo, "text", "Transaction ID", "details", 0)["frame"] == 1


def test_find_bytes_hex_regex_and_filters(demo):
    hits = {find(demo, "text", "GOOGLE", "bytes", 0)["frame"], find(demo, "hex", "67 6F 6F 67 6C 65", "bytes", 0)["frame"],
            find(demo, "hex", "0x676f6f676c65", "bytes", 0)["frame"], find(demo, "regex", r"goo\w+le", "bytes", 0)["frame"]}
    assert len(hits) == 1 and None not in hits
    assert find(demo, "filter", 'dns.qry.name contains "reddit"', "list", 0)["frame"] == 5
    with pytest.raises(PacketError):
        find(demo, "hex", "zz", "bytes", 0)
    with pytest.raises(PacketError):
        find(demo, "text", "", "list", 0)


def test_previous_and_wrapping_around(demo):
    last = find(demo, "text", "jsdelivr", "list", 0, backwards=True)
    assert last["wrapped"] and last["frame"] > 150_000                 # from nothing selected: the last match
    assert find(demo, "text", "jsdelivr", "list", 20, backwards=True) == {"frame": 12, "wrapped": False}
    assert find(demo, "text", "jsdelivr", "list", 12, backwards=True)["frame"] == last["frame"]  # wraps to the end
    assert find(demo, "text", "jsdelivr", "list", last["frame"]) == {"frame": 12, "wrapped": True}


def test_find_within_the_lists_filter(demo):
    # Only DNS shows: the TLS hello that names the server is skipped.
    first_any = find(demo, "text", "reddit", "list", 0)["frame"]
    first_tls = find(demo, "text", "reddit", "list", 0, dfilter="tls")["frame"]
    assert first_any < first_tls
    rows = [r for r in run_engine(ENGINE, "--packets", "-r", demo.files.path, "--from", str(first_tls), "--limit", "1")
            if r.get("type") == "packet"]
    assert rows[0]["proto"].startswith("TLS")


def test_custom_columns(demo):
    page = asyncio.run(demo.page(1, 30, columns=["dns.qry.name", "tcp.dstport", "not a field!"]))
    rows = page["packets"]
    assert rows[0]["f"]["dns.qry.name"] == ["zoom.us"]
    assert any("tcp.dstport" in r["f"] for r in rows) and all("not a field!" not in r["f"] for r in rows)


def test_host_names():
    from test_server import AUTH, make_client, run

    async def go():
        dash, c = await make_client()
        try:
            dash.analyzer.resolved["203.0.113.50"] = {"domain": "backup-sync.io.", "ts": 0}
            r = await (await c.get("/api/names", headers=AUTH)).json()
            assert r["names"]["203.0.113.50"] == "backup-sync.io"
        finally:
            await c.close()
    run(go())


def test_tcp_stream_graph_data(demo):
    g = asyncio.run(demo.tcp_graph(3))
    assert g["a"] == "10.0.0.12:51017" and g["b"] == "170.114.52.2:443" and not g["truncated"]
    n, t, direction, seq, length, ack, win, rtt, flags = g["points"][0]
    assert flags & 1 and direction == 0 and seq == 0                      # the opening SYN
    assert any(p[8] & 8 for p in g["points"])                             # retransmissions are flagged
    assert sum(1 for p in g["points"] if p[7] is not None) > 50           # ACKs carry their round trip
    assert all(p[1] >= g["points"][0][1] for p in g["points"])
    with pytest.raises(PacketError):
        asyncio.run(demo.tcp_graph(10**9))
