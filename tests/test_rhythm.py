"""Rhythm view: channels binned over the capture, the steadiest (timers) first, each with
its period, how steady it is, and the alert it raised."""
import random
from types import SimpleNamespace

from anta import rhythm


def channel(src, dst, port, times):
    flows = {i: SimpleNamespace(bursts=[(t, 100, 400)]) for i, t in enumerate(times)}
    return SimpleNamespace(src_ip=src, dst_ip=dst, dst_port=port, proto="tcp", flows=flows)


def test_a_timer_comes_first_and_reads_as_steady():
    rng = random.Random(7)
    timer = [1000 + 30 * i + rng.uniform(-0.3, 0.3) for i in range(40)]
    browsing = sorted(1000 + rng.uniform(0, 1200) for _ in range(40))
    chans = {1: channel("10.0.0.5", "203.0.113.9", 443, timer), 2: channel("10.0.0.6", "198.51.100.4", 443, browsing),
             3: channel("10.0.0.7", "198.51.100.5", 80, [1000, 1001])}  # (two check-ins: left out)
    alerts = [{"id": "A00001", "kind": "beacon", "severity": "critical", "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9",
               "dst_port": 443}]
    out = rhythm.build(rhythm.snapshot(chans), {"203.0.113.9": "c2.example"}, alerts)
    assert out["total"] == 2 and out["steady"] == 1
    first, second = out["rows"]
    assert (first["src"], first["rhythm"], first["alert"]["id"], first["dst_name"]) == ("10.0.0.5", "steady", "A00001", "c2.example")
    assert abs(first["period"] - 30) < 0.5 and first["jitter_pct"] < 5 and first["regularity"] > 0.9
    assert second["rhythm"] in ("irregular", "loose") and second["alert"] is None
    # Every check-in lands in a cell; the gaps are listed for the detail chart.
    assert sum(c[1] for c in first["cells"]) == 40 and len(first["intervals"]) == 39
    assert out["bins"] * out["bin_s"] >= out["end"] - out["start"] and out["bins"] <= 121


def test_too_few_check_ins_are_not_judged():
    out = rhythm.build(rhythm.snapshot({1: channel("10.0.0.5", "203.0.113.9", 443, [0, 10, 20, 30])}))
    [row] = out["rows"]
    assert row["regularity"] is None and row["rhythm"] == "too few" and row["period"] == 10
    assert rhythm.build([])["rows"] == []


def test_a_timer_many_devices_share_is_marked():
    chans = {i: channel(f"10.0.0.{i}", "52.40.17.9", 443, [100 + 45 * k for k in range(12)]) for i in range(1, 6)}
    alerts = [{"id": "A00008", "kind": "shared", "severity": "low", "dst_ip": "52.40.17.9", "dst_port": 443}]
    rows = rhythm.build(rhythm.snapshot(chans), alerts=alerts)["rows"]
    assert {r["shared_by"] for r in rows} == {5} and {r["alert"]["id"] for r in rows} == {"A00008"}
