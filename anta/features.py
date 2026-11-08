"""Statistical feature extraction from engine session records."""
from __future__ import annotations

import math
from collections import Counter

import numpy as np

# Order matters: this is the ONNX model's input layout.
FEATURE_NAMES = [
    "log_duration",        # seconds, log1p
    "log_bytes_out",       # client->server payload bytes, log1p
    "log_bytes_in",        # server->client payload bytes, log1p
    "byte_asymmetry",      # (out - in) / (out + in), in [-1, 1]
    "size_entropy",        # Shannon entropy (bits) of the payload-size distribution
    "iat_cv",              # jitter: stdev / mean of inter-arrival times
    "log_iat_mean",        # mean inter-arrival time in ms, log1p
    "log_mean_payload",    # mean payload size, log1p
    "log_packets",         # total packets, log1p
    "out_pkt_ratio",       # share of payload packets sent by the client
]


def shannon_entropy(values) -> float:
    """Shannon entropy in bits of a sequence of hashable symbols."""
    counts = Counter(values)
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def string_entropy(s: str) -> float:
    return shannon_entropy(s) if s else 0.0


def jitter(intervals) -> tuple[float, float, float]:
    """Return (mean, stdev, coefficient of variation) of a list of intervals."""
    if len(intervals) == 0:
        return 0.0, 0.0, 0.0
    arr = np.asarray(intervals, dtype=float)
    mean = float(arr.mean())
    std = float(arr.std())
    return mean, std, (std / mean if mean > 0 else 0.0)


def session_bytes(rec: dict) -> tuple[int, int]:
    return rec["c2s"]["payload_bytes"], rec["s2c"]["payload_bytes"]


def session_features(rec: dict) -> dict:
    out_b, in_b = session_bytes(rec)
    duration = max(rec["end"] - rec["start"], 0.0)
    events = rec.get("events", [])
    sizes = [abs(e[1]) for e in events]
    times = [e[0] for e in events]
    iats = np.diff(times) if len(times) > 1 else np.array([])
    iat_mean, _, iat_cv = jitter(iats)
    # Bucket sizes into 32-byte bins so near-identical sizes count as the same symbol.
    size_entropy = shannon_entropy(s // 32 for s in sizes)
    total = out_b + in_b
    packets = rec["c2s"]["packets"] + rec["s2c"]["packets"]
    out_pkts = sum(1 for e in events if e[1] > 0)
    return {
        "log_duration": math.log1p(duration),
        "log_bytes_out": math.log1p(out_b),
        "log_bytes_in": math.log1p(in_b),
        "byte_asymmetry": (out_b - in_b) / total if total else 0.0,
        "size_entropy": size_entropy,
        "iat_cv": min(iat_cv, 10.0),
        "log_iat_mean": math.log1p(iat_mean),
        "log_mean_payload": math.log1p(float(np.mean(sizes)) if sizes else 0.0),
        "log_packets": math.log1p(packets),
        "out_pkt_ratio": out_pkts / len(events) if events else 0.0,
    }


def feature_vector(feats: dict) -> np.ndarray:
    return np.array([feats[n] for n in FEATURE_NAMES], dtype=np.float32)


def bursts(rec: dict, gap_s: float = 1.0) -> list[tuple[float, int, int]]:
    """Activity bursts within a session as (absolute start, bytes out, bytes in).

    A short-lived connection is one burst; a long-lived keep-alive channel that
    checks in periodically yields one burst per check-in. Treating both the same
    way lets one beacon detector cover "new connection every N seconds" and
    "same connection, message every N seconds".
    """
    events = rec.get("events", [])
    if not events:
        return [(rec["start"], 0, 0)]
    out = []
    cur_start, cur_out, cur_in = events[0][0], 0, 0
    prev = events[0][0]
    for t_ms, size in events:
        if (t_ms - prev) / 1000.0 > gap_s:
            out.append((rec["start"] + cur_start / 1000.0, cur_out, cur_in))
            cur_start, cur_out, cur_in = t_ms, 0, 0
        if size > 0:
            cur_out += size
        else:
            cur_in -= size
        prev = t_ms
    out.append((rec["start"] + cur_start / 1000.0, cur_out, cur_in))
    return out


def registered_domain(qname: str) -> str:
    """Naive eTLD+1 (handles common two-level public suffixes)."""
    parts = qname.rstrip(".").lower().split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    two_level = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "org.uk", "ac.uk"}
    if ".".join(parts[-2:]) in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
