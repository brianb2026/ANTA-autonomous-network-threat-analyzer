"""The speed-of-light check: a server that answered its TCP handshake in t ms is at most
c x t / 2 from the capture point, so a registered country entirely farther away is impossible."""
import asyncio
import os

import pytest

from anta import physics
from conftest import run_engine
from test_server import AUTH, make_client

NEW_YORK = {"lat": 40.714, "lon": -74.006, "label": "New York", "how": "set"}


class FakeGeo:
    def __init__(self, table):
        self.table = table

    def lookup(self, ip):
        cc = self.table.get(ip)
        return {"country": cc, "country_name": {"JP": "Japan", "US": "United States", "DE": "Germany"}.get(cc, cc),
                "asn": 64500, "as_name": "EXAMPLE-NET"} if cc else None


def S(src, dst, syn=None, ack=None, sni=None):
    tcp = {}
    if syn is not None:
        tcp["syn_rtt_ms"] = syn
    if ack is not None:
        tcp["ack_rtt_ms"] = ack
    return {"proto": "tcp", "src_ip": src, "dst_ip": dst, "dst_port": 443, "tcp": tcp, "tls": {"sni": sni} if sni else {}}


def test_distances_and_the_limit_light_sets():
    assert 5550 < physics.distance_km(40.714, -74.006, 51.507, -0.128) < 5600   # New York to London
    assert physics.limit_km(10) == pytest.approx(1498.96, abs=0.01)              # 10 ms there and back
    assert physics.limit_km(10_000) == pytest.approx(physics.HALF_EARTH_KM)       # never past the far side of the Earth
    assert physics.country_km("US", 40.714, -74.006) == 0                         # inside
    assert physics.country_km("JP", 40.714, -74.006) > 9000
    assert 0 <= physics.country_km("FR", 51.507, -0.128) < 150                    # London: France is about 140 km off
    assert physics.country_km("ZZ", 0, 0) is None


def test_what_light_allows():
    geo = FakeGeo({"8.8.4.4": "JP", "9.9.9.9": "US", "1.0.0.1": "DE", "1.1.1.1": "JP"})
    sessions = [S("10.0.0.5", "8.8.4.4", syn=6.0, sni="cdn.example"), S("10.0.0.5", "8.8.4.4", syn=9.0),
                S("10.0.0.5", "9.9.9.9", syn=20.0), S("10.0.0.5", "1.0.0.1", syn=90.0), S("10.0.0.5", "1.1.1.1", syn=0.4),
                S("10.0.0.5", "10.0.0.9", syn=0.2),                       # (a local server: not judged)
                S("203.0.113.7", "10.0.0.5"), S("8.8.8.8", "10.0.0.5", ack=2.0)]  # (a client from the internet)
    r = physics.check(sessions, geo, NEW_YORK)
    by = {x["addr"]: x for x in r["rows"]}
    jp = by["8.8.4.4"]
    assert jp["verdict"] == "impossible" and jp["fastest_ms"] == 6.0 and jp["handshakes"] == 2 and jp["name"] == "cdn.example"
    assert jp["limit_km"] == 899 and jp["min_km"] > 9000 and "Can't be in Japan" in jp["why"]
    assert by["9.9.9.9"]["verdict"] == "possible" and by["1.0.0.1"]["verdict"] == "possible"   # Germany in reach in 90 ms
    assert by["1.1.1.1"]["verdict"] == "impossible"                                            # under 1 ms yet "Japan"
    assert by["8.8.8.8"]["role"] == "client" and by["8.8.8.8"]["fastest_ms"] == 2.0 and by["8.8.8.8"]["verdict"] == "unknown"
    assert "10.0.0.9" not in by and "203.0.113.7" not in by
    assert [x["verdict"] for x in r["rows"]][:2] == ["impossible", "impossible"]
    assert physics.check(sessions, geo, None)["counts"]["unknown"] == len(by)                  # no capture point: no verdicts


def test_many_near_servers_far_away_suggest_something_answers_for_them():
    geo = FakeGeo({f"8.8.{i}.1": "JP" for i in range(6)})
    r = physics.check([S("10.0.0.5", f"8.8.{i}.1", syn=1.5) for i in range(6)], geo, NEW_YORK)
    assert r["counts"]["impossible"] == 6 and "answering for them" in r["note"]


def test_where_the_capture_was_made(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTA_DATA_DIR", str(tmp_path))
    assert physics.load_point() == {"mode": "auto"}
    auto = physics.resolve_point({"mode": "auto"}, "Asia/Tokyo")
    assert auto["label"] == "Tokyo" and auto["how"] == "time zone" and abs(auto["lat"] - 35.65) < 0.1
    assert physics.resolve_point({"mode": "auto"}, "Nowhere/Else") is None
    assert physics.resolve_point({"mode": "off"}, "Asia/Tokyo") is None
    saved = physics.save_point({"mode": "coords", "lat": "48.8566", "lon": 2.3522, "label": "Paris\x00 office"})
    assert saved == {"mode": "coords", "lat": 48.8566, "lon": 2.3522, "label": "Paris office"} and physics.load_point() == saved
    if os.name != "nt":
        assert os.stat(physics.point_path()).st_mode & 0o777 == 0o600
    assert physics.save_point({"mode": "zone", "zone": "Europe/Berlin"})["zone"] == "Europe/Berlin"
    for bad in ({"mode": "zone", "zone": "Mars/Base"}, {"mode": "coords", "lat": 91, "lon": 0},
                {"mode": "coords", "lat": "x", "lon": 0}, {"mode": "teleport"}, "Paris"):
        with pytest.raises(physics.PhysicsError):
            physics.save_point(bad)
    assert any(p["zone"] == "America/New_York" for p in physics.places())


def test_the_engine_times_the_handshake(engine, data_dir):
    recs = [r for r in run_engine(engine, "-r", os.path.join(data_dir, "http_download.pcap"))
            if r.get("type") == "session" and r.get("final") and r.get("proto") == "tcp"]
    assert recs
    assert all(r["tcp"]["syn_rtt_ms"] == pytest.approx(5.0) and r["tcp"]["ack_rtt_ms"] == pytest.approx(5.0) for r in recs)


def test_the_physics_endpoints(engine, data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTA_DATA_DIR", str(tmp_path))

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(os.path.join(data_dir, "mixed_demo.pcap"))
            d = await (await c.get("/api/physics?tz=America/New_York&places=1", headers=AUTH)).json()
            assert d["point"]["label"] == "New York" and d["setting"] == {"mode": "auto"} and d["places"]
            assert d["rows"] and all(r["fastest_ms"] > 0 for r in d["rows"])
            r = await c.put("/api/physics/point", json={"point": {"mode": "zone", "zone": "Asia/Tokyo"}}, headers=AUTH)
            assert (await r.json())["setting"]["zone"] == "Asia/Tokyo"
            d = await (await c.get("/api/physics?tz=America/New_York", headers=AUTH)).json()
            assert d["point"]["label"] == "Tokyo" and "places" not in d
            bad = await c.put("/api/physics/point", json={"point": {"mode": "zone", "zone": "Mars/Base"}}, headers=AUTH)
            assert bad.status == 400
            world = await (await c.get("/api/physics/world", headers=AUTH)).json()
            assert len(world["countries"]) > 200 and world["countries"]["JP"]
            assert (await c.get("/api/physics")).status == 401
        finally:
            await c.close()
    asyncio.run(go())
