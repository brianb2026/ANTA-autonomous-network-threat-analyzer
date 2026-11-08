"""Rhythm view: when each channel (a client to one server and port) was active, binned
over the capture, with how steady its rhythm is. People browse in bursts; malware that
calls home does it on a timer, and on a time grid a timer shows as evenly spaced stripes.
The check-ins are the bursts the beacon detector reads (one per new connection, or one per
message on a kept-open one), so what the view shows is what the detector judged.
"""
from __future__ import annotations

import numpy as np

from .analyzer import Analyzer

MIN_EVENTS = 6  # check-ins needed before a rhythm is judged
NICE_BINS = (0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 43200, 86400)


def snapshot(channels: dict, max_channels: int = 20_000) -> list[tuple]:
    """(src, dst, port, proto, bursts) of the channels with a few check-ins, the busiest
    first: a copy taken where the analyzer runs, to be built elsewhere."""
    rows = []
    for ch in list(channels.values()):
        bursts = [b for f in list(ch.flows.values()) for b in f.bursts]
        if len(bursts) >= 3:
            rows.append((ch.src_ip, ch.dst_ip, ch.dst_port, ch.proto, sorted(bursts)))
    rows.sort(key=lambda r: -len(r[4]))
    return rows[:max_channels]


def judge(times: np.ndarray) -> dict:
    """The rhythm of check-in times: its period, how steady it is (0-1, as the beacon
    detector scores timing: RITA's regularity of the intervals near the period, and how
    many intervals are near it) and how much the intervals wander."""
    intervals = np.diff(times)
    if len(intervals) == 0:
        return {"period": None, "regularity": None, "jitter_pct": None}
    median = float(np.median(intervals))
    if len(times) < MIN_EVENTS or median <= 0:
        return {"period": median or None, "regularity": None, "jitter_pct": None}
    near = (intervals > 0.5 * median) & (intervals < 1.5 * median)
    presence = float(near.mean())
    kept = intervals[near]
    if len(kept) < 3:
        return {"period": median, "regularity": round(presence / 3, 3), "jitter_pct": None}
    score = Analyzer._regularity(kept, mad_scale=0.25)[0]
    p5, p95 = np.percentile(kept, [5, 95])
    return {"period": median, "regularity": round((2 * score + presence) / 3, 3),
            "jitter_pct": round(float((p95 - p5) / (2 * median) * 100), 1)}


def describe(regularity: float | None) -> str:
    if regularity is None:
        return "too few"
    return "steady" if regularity >= 0.75 else "loose" if regularity >= 0.5 else "irregular"


def build(snap: list[tuple], names: dict | None = None, alerts: list[dict] | None = None, bins: int = 120,
          limit: int = 400) -> dict:
    names = names or {}
    if not snap:
        return {"rows": [], "start": None, "end": None, "bin_s": None, "bins": 0, "total": 0}
    start = min(r[4][0][0] for r in snap)
    end = max(r[4][-1][0] for r in snap)
    span = max(end - start, 1e-3)
    bin_s = next((b for b in NICE_BINS if span / b <= bins), NICE_BINS[-1])
    nbins = int(span // bin_s) + 1
    flagged, shared = {}, {}  # the alert about a channel's rhythm; about a destination many devices keep time with
    for a in alerts or []:
        if a.get("kind") == "beacon" and a.get("src_ip") and a.get("dst_ip"):
            flagged[(a["src_ip"], a["dst_ip"], a.get("dst_port"))] = {"id": a["id"], "severity": a["severity"]}
        elif a.get("kind") == "shared" and a.get("dst_ip"):
            shared[(a["dst_ip"], a.get("dst_port"))] = {"id": a["id"], "severity": a["severity"]}
    clients: dict[tuple, set] = {}  # (dst, port) -> the devices that use it
    for src, dst, port, _, _ in snap:
        clients.setdefault((dst, port), set()).add(src)
    rows = []
    for src, dst, port, proto, bursts in snap:
        times = np.array([b[0] for b in bursts], dtype=float)
        verdict = judge(times)
        cells: dict[int, list] = {}
        for t, out_b, in_b in bursts:
            c = cells.setdefault(int((t - start) // bin_s), [0, 0, 0])
            c[0] += 1
            c[1] += int(out_b)
            c[2] += int(in_b)
        gaps = np.diff(times)
        rows.append({
            "src": src, "dst": dst, "port": port, "proto": proto,
            "src_name": names.get(src, ""), "dst_name": names.get(dst, ""),
            "events": len(bursts), "first": float(times[0]), "last": float(times[-1]),
            "bytes_out": int(sum(b[1] for b in bursts)), "bytes_in": int(sum(b[2] for b in bursts)),
            **verdict, "rhythm": describe(verdict["regularity"]),
            "alert": flagged.get((src, dst, port)) or shared.get((dst, port)),
            "shared_by": len(clients[(dst, port)]),
            "cells": [[i, *v] for i, v in sorted(cells.items())],
            # Each check-in's gap since the one before: a flat line is a timer.
            "intervals": [[round(float(t - start), 3), round(float(g), 3)]
                          for t, g in zip(times[1:][-600:], gaps[-600:], strict=True)],
        })
    # The steadiest rhythms first (what a timer looks like), then the busiest of the rest.
    rows.sort(key=lambda r: (r["regularity"] is None, -(r["regularity"] or 0), -r["events"]))
    return {"rows": rows[:limit], "total": len(rows), "start": start, "end": end, "bin_s": bin_s, "bins": nbins,
            "steady": sum(1 for r in rows if r["rhythm"] == "steady")}
