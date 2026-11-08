"""Scopes: the packets an analysis is limited to. A scope is built from what the user
selected in the packet list, as parts that are unioned: each part is the list's view (a
display filter, an alert's connections, or everything), narrowed to frame-number ranges.
It becomes one display filter, so every tool that takes a filter (the packet list,
statistics, the network map, flow and TCP graphs, Explain, saving) can be limited to it;
tools that work on sessions (rhythm, logins, files, alerts) use the connections and
addresses in it.

Scopes live on the server, under short ids: a selection can be thousands of ranges, too
long for a URL (or, on Windows, a command line; see packets.py).
"""
from __future__ import annotations

import ipaddress
import re
import secrets
import time
from collections import OrderedDict

MAX_PARTS = 64
MAX_RANGES = 200_000
MAX_SCOPES = 64
FRAMES = re.compile(r"\d{1,12}(?:-\d{0,12})?(?:,\d{1,12}(?:-\d{0,12})?)*")


class ScopeError(ValueError):
    pass


def parse_frames(text: str) -> list[tuple[int, int | None]]:
    """"1-20,35,40-" -> [(1, 20), (35, 35), (40, None)]: sorted and merged (None: to the end)."""
    text = (text or "").replace(" ", "")
    if not FRAMES.fullmatch(text):
        raise ScopeError("frames must look like 1-20,35,40-")
    out: list[tuple[int, int | None]] = []
    for item in text.split(","):
        a, _, b = item.partition("-")
        lo = int(a)
        hi = None if (_ and not b) else int(b) if b else lo
        if lo < 1 or (hi is not None and hi < lo):
            raise ScopeError(f"bad frame range {item}")
        out.append((lo, hi))
    if len(out) > MAX_RANGES:
        raise ScopeError("too many separate packets selected; select a range or use a filter")
    out.sort(key=lambda r: r[0])
    merged: list[tuple[int, int | None]] = []
    for lo, hi in out:
        if merged:
            plo, phi = merged[-1]
            if phi is None or lo <= phi + 1:
                merged[-1] = (plo, None if (phi is None or hi is None) else max(phi, hi))
                continue
        merged.append((lo, hi))
    return merged


def frames_clause(ranges: list[tuple[int, int | None]]) -> str:
    if not ranges:
        return ""
    closed = [f"{lo}" if lo == hi else f"{lo}..{hi}" for lo, hi in ranges if hi is not None]
    open_from = [lo for lo, hi in ranges if hi is None]
    terms = []
    if closed:
        terms.append(f"frame.number in {{{', '.join(closed)}}}")
    if open_from:
        terms.append(f"frame.number >= {min(open_from)}")
    return terms[0] if len(terms) == 1 else f"({' || '.join(terms)})"


def frames_count(ranges: list[tuple[int, int | None]]) -> int | None:
    """How many frames the ranges name (None when one runs to the end)."""
    if any(hi is None for _, hi in ranges):
        return None
    return sum(hi - lo + 1 for lo, hi in ranges)


def build_filter(parts: list[dict], flow_filter_of) -> str:
    """The display filter for a union of parts. `flow_filter_of(alert_id)` gives an alert's
    connections as a filter (or raises ScopeError)."""
    if not isinstance(parts, list) or not 1 <= len(parts) <= MAX_PARTS:
        raise ScopeError(f"a selection has 1 to {MAX_PARTS} parts")
    out = []
    for part in parts:
        if not isinstance(part, dict):
            raise ScopeError("each part must be an object")
        clauses = []
        flt = part.get("filter") or ""
        if not isinstance(flt, str) or len(flt) > 8192 or any(c in flt for c in "\x00\r\n"):
            raise ScopeError("bad filter in the selection")
        if flt.strip():
            clauses.append(f"({flt.strip()})")
        if part.get("alert"):
            clauses.append(f"({flow_filter_of(str(part['alert']))})")
        frames = part.get("frames") or ""
        if not isinstance(frames, str):
            raise ScopeError("frames must be a string")
        if frames:
            clauses.append(frames_clause(parse_frames(frames)))
        out.append(" && ".join(clauses) if clauses else "frame")
    if len(out) == 1:
        return out[0]
    return " || ".join(f"({p})" for p in out)


def label_for(parts: list[dict]) -> str:
    """What a selection is, without its count (the page puts the count in front)."""
    if len(parts) == 1 and not parts[0].get("frames") and parts[0].get("filter"):
        return f"packets matching {parts[0]['filter']}"
    return "selected packets"


class ScopeStore:
    """The scopes made in this session, newest last (the oldest are forgotten)."""

    def __init__(self, limit: int = MAX_SCOPES):
        self.limit = limit
        self.items: OrderedDict[str, dict] = OrderedDict()

    def add(self, filter_text: str, parts: list[dict], label: str, count: int | None, capture: str) -> dict:
        sid = secrets.token_urlsafe(9)
        scope = {"id": sid, "filter": filter_text, "parts": parts, "label": label[:200], "count": count,
                 "capture": capture, "created": time.time(), "sessions": None}
        self.items[sid] = scope
        while len(self.items) > self.limit:
            self.items.popitem(last=False)
        return scope

    def get(self, sid: str | None, capture: str) -> dict | None:
        scope = self.items.get(sid or "")
        if scope is None or scope["capture"] != capture:
            return None
        self.items.move_to_end(scope["id"])
        return scope


# ---------------------------------------------------------------- session-level tools

def _key(proto: str, a: str, pa, b: str, pb) -> tuple:
    ends = sorted([(str(a), int(pa or 0)), (str(b), int(pb or 0))])
    return (proto, *ends[0], *ends[1])


def connections(stats: dict) -> dict:
    """The connections and addresses in a scope's statistics: {flows: set of (proto, a, pa,
    b, pb) with the ends sorted, addresses: set, complete: whether no table was capped}."""
    conv = (stats or {}).get("conversations") or {}
    flows, channels, complete = set(), set(), True
    for proto in ("tcp", "udp"):
        t = conv.get(proto) or {}
        rows = t.get("rows") or []
        complete &= len(rows) >= int(t.get("total") or 0)
        for r in rows:
            flows.add(_key(proto, r[0], r[1], r[2], r[3]))
            channels.add((proto, str(r[0]), str(r[2]), int(r[3] or 0)))  # (a client to a server port, either way)
            channels.add((proto, str(r[2]), str(r[0]), int(r[1] or 0)))
    addresses = set()
    for kind in ("ipv4", "ipv6"):
        t = ((stats or {}).get("endpoints") or {}).get(kind) or {}
        complete &= len(t.get("rows") or []) >= int(t.get("total") or 0)
        addresses.update(str(r[0]) for r in t.get("rows") or [])
    props = (stats or {}).get("properties") or {}
    return {"flows": flows, "channels": channels, "addresses": addresses, "complete": complete,
            "first": props.get("first"), "last": props.get("last"), "frames": props.get("frames")}


def session_in(rec: dict, conn: dict) -> bool:
    return _key(rec.get("proto", ""), rec.get("src_ip"), rec.get("src_port"), rec.get("dst_ip"),
                rec.get("dst_port")) in conn["flows"]


def flow_spec_in(spec: str, conn: dict) -> bool:
    """An alert's flow spec ("6,a,pa,b,pb") in the scope."""
    try:
        proto, a, pa, b, pb = spec.split(",")
    except ValueError:
        return False
    return _key({"6": "tcp", "17": "udp"}.get(proto, proto), a, pa, b, pb) in conn["flows"]


def address_in(addr, conn: dict) -> bool:
    try:
        return str(ipaddress.ip_address(str(addr))) in conn["addresses"]
    except ValueError:
        return False


def channel_in(src: str, dst: str, port: int, proto: str, conn: dict) -> bool:
    return (proto, str(src), str(dst), int(port or 0)) in conn["channels"]


def rhythm_snapshot(snap: list[tuple], conn: dict) -> list[tuple]:
    """The rhythm view's channels within a scope: those it holds, with their check-ins in
    its time window."""
    lo, hi = conn.get("first"), conn.get("last")
    out = []
    for src, dst, port, proto, bursts in snap:
        if not channel_in(src, dst, port, proto, conn):
            continue
        kept = [b for b in bursts if lo is None or hi is None or lo - 1e-6 <= b[0] <= hi + 1e-6]
        if len(kept) >= 3:
            out.append((src, dst, port, proto, kept))
    return out


def alert_in(alert: dict, flows: list[str], conn: dict) -> bool:
    """An alert is in a scope when one of its connections is; one with no connections (ARP
    spoofing, say) when one of its addresses is."""
    if flows:
        return any(flow_spec_in(f, conn) for f in flows)
    return any(address_in(alert.get(k), conn) for k in ("offender", "src_ip", "dst_ip") if alert.get(k))
