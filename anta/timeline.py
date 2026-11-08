"""The network time machine's data: the capture as a timeline the map can replay. Traffic per
time slice (exact, from the engine's I/O counts), every connection's start, end, ends and
size, and when each alert was first raised, all in seconds from the capture's start.
"""
from __future__ import annotations

MAX_SESSIONS = 20_000
BINS = 300


def interval_for(duration: float, bins: int = BINS) -> float:
    """A slice length that cuts the capture into about `bins` slices (a round-ish number)."""
    if duration <= 0:
        return 1.0
    raw = duration / bins
    for step in (0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600):
        if step >= raw:
            return float(step)
    return float(int(raw / 3600 + 1) * 3600)


def build(stats: dict, sessions: list[dict], alerts: list[dict]) -> dict:
    io = stats.get("io") or {}
    props = stats.get("properties") or {}
    start = float(io.get("start") or props.get("first") or 0)
    interval = float(io.get("interval") or 1)
    bins = [[int(b[0]), int(b[1])] for b in io.get("bins") or []]
    end = float(props.get("last") or start)

    hosts: dict[str, int] = {}

    def idx(ip: str) -> int:
        if ip not in hosts:
            hosts[ip] = len(hosts)
        return hosts[ip]

    alerted = {frozenset((a.get("src_ip"), a.get("dst_ip"))) for a in alerts}
    ranked = sorted(sessions, key=lambda s: (frozenset((s["src_ip"], s["dst_ip"])) not in alerted,
                                             -((s.get("c2s") or {}).get("payload_bytes", 0) + (s.get("s2c") or {}).get("payload_bytes", 0))))
    kept = ranked[:MAX_SESSIONS]
    rows = []
    for s in sorted(kept, key=lambda s: s.get("start") or 0):
        size = int((s.get("c2s") or {}).get("payload_bytes", 0)) + int((s.get("s2c") or {}).get("payload_bytes", 0))
        rows.append([round(float(s.get("start") or start) - start, 3), round(float(s.get("end") or s.get("start") or start) - start, 3),
                     idx(s["src_ip"]), idx(s["dst_ip"]), size])
    marks = []
    for a in sorted(alerts, key=lambda a: a.get("first_seen") or 0):
        if not a.get("first_seen"):
            continue
        marks.append({"id": a["id"], "t": round(float(a["first_seen"]) - start, 3),
                      "last": round(float(a.get("last_seen") or a["first_seen"]) - start, 3), "severity": a.get("severity"),
                      "title": a.get("title"), "src": a.get("src_ip") or "", "dst": a.get("dst_ip") or a.get("target") or "",
                      "offender": a.get("offender") or ""})
    return {"start": start, "duration": max(0.0, end - start), "interval": interval, "bins": bins,
            "hosts": list(hosts), "sessions": rows, "kept": len(rows), "total_sessions": len(sessions), "alerts": marks}
