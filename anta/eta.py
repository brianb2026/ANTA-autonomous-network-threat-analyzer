"""Encrypted traffic analytics: what an encrypted session is doing, from its shape
alone (how much each side sent, in what sizes, at what rhythm), without decrypting
anything. Rule-based, with the evidence spelled out, so an analyst can check it:
a remote shell is many small packets both ways at human pace; streaming is a long,
steady downstream in bursts; an upload of gigabytes to a rare destination is what
exfiltration looks like whether or not it is encrypted.
"""
from __future__ import annotations

import statistics

ENCRYPTED_APPS = {"tls", "quic", "ssh", "openvpn", "wireguard", "dtls", "rdp"}

CLASSES = {
    "handshake": "Handshake only",
    "interactive": "Interactive session (remote shell or desktop)",
    "call": "Voice or video call",
    "streaming": "Media streaming",
    "download": "Bulk download",
    "upload": "Bulk upload",
    "heartbeat": "Periodic heartbeat",
    "web": "Web browsing / API calls",
    "idle": "Mostly idle connection",
    "mixed": "Mixed traffic",
}


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.0f} B"


def is_encrypted(rec: dict) -> bool:
    if rec.get("app") in ENCRYPTED_APPS or rec.get("tls"):
        return True
    pe = rec.get("payload_entropy") or {}
    vals = [v for v in (pe.get("c2s"), pe.get("s2c")) if v is not None]
    return bool(vals) and min(vals) >= 7.2 and rec.get("app_source") != "payload"


def classify(rec: dict) -> dict:
    """{class, label, confidence, why} for one (encrypted) session record."""
    up = rec["c2s"]["payload_bytes"]
    down = rec["s2c"]["payload_bytes"]
    total = up + down
    dur = max(0.0, rec["end"] - rec["start"])
    events = rec.get("events") or []          # [ms, +out/-in bytes], capped
    sizes = [abs(e[1]) for e in events]
    times = [e[0] / 1000.0 for e in events]
    gaps = [b - a for a, b in zip(times, times[1:], strict=False) if b > a]
    n_out = sum(1 for e in events if e[1] > 0)
    n_in = sum(1 for e in events if e[1] < 0)
    med_size = statistics.median(sizes) if sizes else 0
    med_gap = statistics.median(gaps) if gaps else 0
    cv_gap = (statistics.pstdev(gaps) / statistics.mean(gaps)) if len(gaps) > 2 and statistics.mean(gaps) > 0 else 0
    pps = len(events) / dur if dur > 0 else 0
    down_share = down / total if total else 0
    udp = rec.get("proto") == "udp"

    def out(cls, conf, why):
        return {"class": cls, "label": CLASSES[cls], "confidence": round(conf, 2), "why": why}

    if total < 2048 and len(events) <= 6:
        return out("handshake", 0.9, f"only {_fmt_bytes(total)} of payload: the session set up its encryption and "
                                     "carried next to nothing")
    if udp and dur >= 20 and 0.25 <= down_share <= 0.75 and pps >= 20 and 60 <= med_size <= 1300:
        return out("call", 0.75, f"{dur:.0f} s of steady traffic both ways ({pps:.0f} packets/s, typical size "
                                 f"{med_size:.0f} B): audio/video frames at a fixed rate")
    if up >= 1_000_000 and up >= 4 * down:
        return out("upload", 0.85, f"{_fmt_bytes(up)} sent and only {_fmt_bytes(down)} received "
                                   f"({1 - down_share:.0%} upstream): a file or backup upload, or data exfiltration")
    if dur >= 60 and down >= 5_000_000 and down_share >= 0.85 and _bursty(rec):
        return out("streaming", 0.7, f"{_fmt_bytes(down)} downstream over {dur:.0f} s in regular bursts: a player "
                                     "fetching media segments")
    if down >= 1_000_000 and down_share >= 0.85:
        return out("download", 0.8, f"{_fmt_bytes(down)} received against {_fmt_bytes(up)} sent "
                                    f"({down_share:.0%} downstream): a file, update or software download")
    if (dur >= 20 and n_out >= 10 and n_in >= 10 and med_size <= 200 and 0.03 <= med_gap <= 3 and cv_gap >= 1.0
            and total <= 2_000_000):
        return out("interactive", 0.7, f"{n_out + n_in} small packets (typical {med_size:.0f} B) both ways over "
                                       f"{dur:.0f} s with irregular, human-paced gaps (median {med_gap * 1000:.0f} ms): "
                                       "keystrokes and screen updates")
    if dur >= 60 and len(gaps) >= 6 and cv_gap < 0.25 and med_size <= 600:
        return out("heartbeat", 0.7, f"small exchanges every {med_gap:.1f} s (timing varies only {cv_gap:.0%}) over "
                                     f"{dur:.0f} s: a keep-alive, telemetry, or a beacon")
    if dur >= 60 and total <= 20_000:
        return out("idle", 0.6, f"open for {dur:.0f} s but only {_fmt_bytes(total)} moved: a connection kept open "
                                "for notifications or reuse")
    if dur <= 120 and down >= up:
        return out("web", 0.55, f"short exchange, {_fmt_bytes(up)} up and {_fmt_bytes(down)} down in "
                                "request/response bursts")
    return out("mixed", 0.4, f"{_fmt_bytes(up)} up, {_fmt_bytes(down)} down over {dur:.0f} s with no dominant pattern")


def _bursty(rec: dict) -> bool:
    """Downstream arriving in on/off bursts (rate buckets alternating busy and quiet)."""
    rate = (rec.get("rate") or {}).get("in") or []
    if len(rate) < 8:
        return False
    peak = max(rate) or 1
    busy = sum(1 for v in rate if v >= 0.3 * peak)
    quiet = sum(1 for v in rate if v <= 0.05 * peak)
    return busy >= 3 and quiet >= 3


def row(rec: dict, verdict: dict) -> dict:
    """A compact table row for the Encrypted traffic view."""
    tls = rec.get("tls") or {}
    return {"ts": rec["start"], "duration": round(rec["end"] - rec["start"], 3), "proto": rec["proto"],
            "src": rec["src_ip"], "sport": rec["src_port"], "dst": rec["dst_ip"], "dport": rec["dst_port"],
            "app": rec.get("app") or "", "sni": tls.get("sni") or "", "ja4": tls.get("ja4") or "",
            "up": rec["c2s"]["payload_bytes"], "down": rec["s2c"]["payload_bytes"],
            "packets": rec["c2s"]["packets"] + rec["s2c"]["packets"], **verdict}
