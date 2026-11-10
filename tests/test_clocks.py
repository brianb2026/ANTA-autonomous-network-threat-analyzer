"""Machines behind addresses, from the clocks their TCP timestamps read: several machines behind
one address, one machine behind several, clocks hidden per partner or per connection, and clocks
that don't keep steady time against the capture."""
import asyncio

from anta import clocks
from anta.tools import samples
from conftest import run_engine, sessions
from test_server import AUTH, make_client


def lab(engine, tmp_path):
    path = tmp_path / "clocks.pcap"
    samples.write_pcap(str(path), samples.clock_lab())
    return path, sessions(run_engine(engine, "-r", str(path)))


def test_the_engine_reads_each_sides_clock(engine, tmp_path):
    _, ss = lab(engine, tmp_path)
    s = next(x for x in ss if x["src_ip"] == "192.168.70.1")
    t0, v0, t1, v1, n = s["tcp"]["clock"]["c2s"]
    assert n >= 8 and t1 - t0 > 3 and abs((v1 - v0) / (t1 - t0) - 1000) < 5


def test_the_lab(engine, tmp_path):
    _, ss = lab(engine, tmp_path)
    r = clocks.analyse(ss)
    by = {a["ip"]: a for a in r["addresses"]}
    nat = by["192.168.70.1"]
    assert nat["machines"] == 3 and nat["rates"] == [100, 1000] and "different rates" in nat["why"]
    assert [a["ip"] for a in r["behind"]] == ["192.168.70.1"]
    assert r["shared"][0]["addresses"] == ["192.168.70.20", "192.168.70.21", "192.168.70.22"]
    assert by["192.168.70.30"]["machines"] == 1 and by["192.168.70.30"]["mode"] == "per-peer"
    assert by["192.168.70.40"]["machines"] is None and by["192.168.70.40"]["mode"] == "per-connection"
    assert by["192.168.70.50"]["verdict"] == "One machine" and not r["capture_off"]
    out = run_engine(engine, "--packets", "-r", str(tmp_path / "clocks.pcap"), "-Y", nat["filter"])
    assert any(x.get("type") == "packet" and x["src"] == "192.168.70.1" for x in out)


def reading(src, dst, t0, v0, t1, v1, n=10, sport=40000):
    return {"proto": "tcp", "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": 443,
            "tcp": {"clock": {"c2s": [t0, v0, t1, v1, n]}}}


def test_short_connections_timed_across_each_other():
    # Each connection is too short to time, but together they fall on one 1000/s clock.
    ss = [reading("10.0.0.5", "203.0.113.1", 100.0 + i * 10, 5_000_000 + i * 10_000, 100.2 + i * 10, 5_000_200 + i * 10_000,
                  n=3, sport=40000 + i) for i in range(3)]
    a = clocks.analyse(ss)["addresses"][0]
    assert a["verdict"] == "One machine" and a["rates"] == [1000] and "across" in a["why"]


def test_unsteady_clocks_and_a_capture_whose_timing_is_off():
    ss = [reading(f"10.0.0.{i}", "203.0.113.1", 100.0, 1_000_000, 110.0, 1_000_000 + 27_000 + i * 3000, sport=40000 + i)
          for i in range(1, 5)]
    r = clocks.analyse(ss)
    assert all(a["mode"] == "unsteady" and a["machines"] is None for a in r["addresses"])
    assert r["capture_off"] and "capture's own timing" in r["capture_note"]


def test_a_clock_that_wraps():
    # A 1000/s clock passing 2^32 during the connection still times right.
    ss = [reading("10.0.0.9", "203.0.113.1", 100.0, 2**32 - 2000, 110.0, 8000, sport=40000 + i) for i in range(2)]
    assert clocks.readings(ss)["10.0.0.9"][0]["rate"] == 1000.0


def test_the_endpoint(engine, tmp_path):
    path, _ = lab(engine, tmp_path)

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(str(path))
            return await (await c.get("/api/clocks", headers=AUTH)).json()
        finally:
            await c.close()
    d = asyncio.run(go())
    assert d["behind"][0]["ip"] == "192.168.70.1" and len(d["shared"]) == 1 and d["notes"]
