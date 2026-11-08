"""The network time machine's data: traffic per slice, connections and alerts on one clock."""
import asyncio
import json
import os
import shutil
import subprocess

import pytest

from anta import timeline
from test_server import AUTH, make_client


def test_slices_and_the_timeline():
    assert timeline.interval_for(774) == 5.0 and timeline.interval_for(0) == 1.0 and timeline.interval_for(1) == 0.005
    stats = {"io": {"start": 100.0, "interval": 5.0, "bins": [[3, 300, 0], [5, 900, 0]]}, "properties": {"first": 100.0, "last": 110.0}}
    sessions = [{"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "start": 104.0, "end": 106.0, "c2s": {"payload_bytes": 50},
                 "s2c": {"payload_bytes": 70}},
                {"src_ip": "10.0.0.6", "dst_ip": "10.0.0.5", "start": 101.0, "end": 101.5, "c2s": {"payload_bytes": 1},
                 "s2c": {"payload_bytes": 0}}]
    alerts = [{"id": "A1", "first_seen": 105.0, "last_seen": 109.0, "severity": "high", "title": "T", "src_ip": "10.0.0.5",
               "dst_ip": "8.8.8.8"}]
    d = timeline.build(stats, sessions, alerts)
    assert d["start"] == 100.0 and d["duration"] == 10.0 and d["bins"] == [[3, 300], [5, 900]]
    assert d["sessions"][0][:2] == [1.0, 1.5] and d["sessions"][1] == [4.0, 6.0, d["hosts"].index("10.0.0.5"),
                                                                         d["hosts"].index("8.8.8.8"), 120]
    assert d["alerts"] == [{"id": "A1", "t": 5.0, "last": 9.0, "severity": "high", "title": "T", "src": "10.0.0.5",
                            "dst": "8.8.8.8", "offender": ""}]


def test_the_timeline_endpoint(engine, data_dir):
    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(os.path.join(data_dir, "mixed_demo.pcap"))
            d = await (await c.get("/api/timeline", headers=AUTH)).json()
            assert d["interval"] == 5.0 and len(d["bins"]) >= 150 and d["kept"] == d["total_sessions"] == 2242
            assert sum(b[0] for b in d["bins"]) == 157181  # (every packet in some slice)
            assert all(d["sessions"][i][0] <= d["sessions"][i + 1][0] for i in range(len(d["sessions"]) - 1))
            assert (await c.get("/api/timeline")).status == 401
        finally:
            await c.close()
    asyncio.run(go())


def test_the_packets_of_a_stretch_for_the_arrows(engine, data_dir):
    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(os.path.join(data_dir, "mixed_demo.pcap"))
            d = await (await c.get("/api/timeline/packets?from=220&to=221&max=50000", headers=AUTH)).json()
            assert d["complete"] and d["packets"] and all(220 <= p[0] < 221 for p in d["packets"])
            assert all(d["packets"][i][0] <= d["packets"][i + 1][0] for i in range(len(d["packets"]) - 1))
            hosts = d["hosts"]
            assert any(hosts[p[1]] == "10.0.0.44" and hosts[p[2]] == "203.0.113.50" for p in d["packets"])  # (the upload)
            few = await (await c.get("/api/timeline/packets?from=220&to=226&max=10", headers=AUTH)).json()
            assert len(few["packets"]) == 10 and not few["complete"]
            for bad in ("from=5&to=1", "from=x&to=2", "from=0&to=100000"):
                assert (await c.get(f"/api/timeline/packets?{bad}", headers=AUTH)).status == 400
        finally:
            await c.close()
    asyncio.run(go())


def _replay_functions(*names: str) -> str:
    """The source of some of the replay's functions (anta/web/timemachine.js), to run under Node."""
    src = open(os.path.join(os.path.dirname(timeline.__file__), "web", "timemachine.js"), encoding="utf-8").read()
    out = []
    for name in names:
        start = src.index(f"function {name}(")
        out.append(src[start:src.index("\n}\n", start) + 3])
    return "\n".join(out)


@pytest.mark.skipif(not shutil.which("node"), reason="needs Node.js")
def test_the_replay_plans_its_fetches_without_stalling(tmp_path):
    # Fractional slices (any capture under about a minute) once stalled the planning loop for good:
    # 43 × 0.05 / 0.05 floors to 42, so the stretch never grew and the page froze on Play.
    script = tmp_path / "plan.js"
    script.write_text("""
const TM_FETCH = 12000;
let range = [0, 0];
const tm = { data: null, pk: null, pkLoading: null };
const tmRange = () => range;
const withFocus = (u) => u;
let asked = [];
const api = (url) => { asked.push(new URLSearchParams(url.split("?")[1])); return { then: () => ({ catch: () => ({ finally: () => {} }) }) }; };
""" + _replay_functions("tmFetch") + """
const out = [];
for (const [interval, duration] of [[0.05, 9.07], [0.1, 30], [0.001, 0.3], [0.2, 60], [0.005, 1.4], [5, 774]]) {
  const n = Math.ceil(duration / interval);
  tm.data = { interval, bins: Array.from({ length: n }, () => [3, 300]) };
  range = [0, duration];
  for (const from of [0, interval * 29, interval * 43, interval * 2001, duration / 2]) {
    if (from >= duration) continue;
    asked = [];
    tmFetch(from, false);
    const q = asked[0];
    out.push([interval, from, Number(q.get("from")), Number(q.get("to"))]);
  }
}
console.log(JSON.stringify(out));
""")
    r = subprocess.run(["node", str(script)], capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr
    plans = json.loads(r.stdout)
    assert len(plans) >= 20
    for _interval, start, asked_from, asked_to in plans:
        assert abs(asked_from - start) < 1e-6 and asked_to > asked_from


@pytest.mark.skipif(not shutil.which("node"), reason="needs Node.js")
def test_replay_speeds_typed_in(tmp_path):
    script = tmp_path / "speed.js"
    script.write_text("const TM_MAX_SPEED = 10000;\n" + _replay_functions("tmParseSpeed") + """
console.log(JSON.stringify(["1", "0.5", "0.01", "2x", "×3", "x0.25", "0.3 x", "1/20", ".5", "1e-3", "0", "-2", "abc", "20000", "", "1/0"]
  .map(tmParseSpeed)));
""")
    r = subprocess.run(["node", str(script)], capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == [1, 0.5, 0.01, 2, 3, 0.25, 0.3, 0.05, 0.5, 0.001, None, None, None, None, None, None]
