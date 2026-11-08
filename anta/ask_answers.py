"""Answers to questions about the capture, from what ANTA already read (its statistics, the
asset inventory, the alerts): who an address talked to, the busiest hosts and conversations,
ports, protocols, names, how much and when. Each answer is a line or two and, where a list
answers better, a small table whose rows open their packets.

Everything here is computed on this computer from the capture; nothing is sent anywhere.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import re
from collections import defaultdict

from . import netmap
from .explain import fmt_bytes

BASE_PROTOCOLS = {"frame", "eth", "ip", "ipv6", "tcp", "udp", "sll", "vlan", "data", "ethertype", "llc", "wlan", "radiotap",
                  "null", "loop", "ppp", "pppoe", "gre", "vxlan", "mpls", "ipx"}
MAX_ROWS = 25
DEFAULT_ROWS = 10


# ---------------------------------------------------------------- words and numbers

def num(n) -> str:
    return f"{int(n):,}"


def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{num(n)} {word if n == 1 else many or word + 's'}"


def span(seconds: float) -> str:
    s = max(0.0, float(seconds))
    if s < 1:
        return f"{s * 1000:.0f} ms"
    if s < 60:
        return f"{s:.1f} s"
    if s < 3600:
        return f"{int(s // 60)} min {int(s % 60)} s"
    if s < 86400:
        return f"{int(s // 3600)} h {int(s % 3600 // 60)} min"
    return f"{s / 86400:.1f} days"


def clock(epoch: float, tz_min: int, with_day: bool = False) -> str:
    """A time as the packet list shows it, in the viewer's time zone."""
    t = dt.datetime.fromtimestamp(float(epoch), dt.timezone(dt.timedelta(minutes=-tz_min)))
    return t.strftime("%b %d %H:%M:%S" if with_day else "%H:%M:%S")


def addr_filter(addr: str) -> str:
    if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", addr.lower()):
        return f"eth.addr == {addr.lower()}"
    return f"{'ipv6' if ':' in addr else 'ip'}.addr == {addr}"


def both(*flts: str) -> str:
    """Filters AND'ed, each grouped."""
    out = [f for f in flts if f]
    return " && ".join(f"({f})" if ("||" in f or "&&" in f) and len(out) > 1 else f for f in out)


class Ctx:
    """What an answer may read: names for addresses, the viewer's time zone, the start of the
    capture, the location database, the inventory and the alerts."""

    def __init__(self, names: dict | None = None, tz_min: int = 0, start: float | None = None, geo=None,
                 assets: list | None = None, alerts: list | None = None, resolved: dict | None = None,
                 scoped: bool = False):
        self.names = names or {}
        self.tz_min = tz_min
        self.start = start
        self.geo = geo
        self.assets = assets or []
        self.alerts = alerts or []
        self.resolved = resolved or {}
        self.scoped = scoped  # (within the packets the user focused on)

    def where(self, flt: str) -> str:
        return "these packets" if flt or self.scoped else "the capture"

    def host(self, addr: str) -> str:
        name = self.names.get(addr)
        return f"{addr} ({name})" if name and name != addr else addr

    def when(self, epoch: float) -> str:
        rel = f" (+{span(epoch - self.start)})" if self.start is not None and epoch >= self.start else ""
        return clock(epoch, self.tz_min) + rel


def member(subject: str):
    """A test for addresses the subject covers (an address, a network or a MAC)."""
    s = subject.lower()
    if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", s):
        return lambda x: str(x).lower() == s
    try:
        net = ipaddress.ip_network(subject, strict=False)
    except ValueError:
        return lambda x: x == subject

    def test(x) -> bool:
        try:
            return ipaddress.ip_address(x) in net
        except ValueError:
            return False
    return test


def family(subject: str) -> str:
    if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", subject.lower()):
        return "eth"
    return "ipv6" if ":" in subject else "ipv4"


def _in_scope(addr: str, scope: str | None) -> bool:
    if not scope:
        return True
    kind = netmap.scope_of(addr)
    return kind == "public" if scope == "public" else kind in ("private", "link-local", "cgnat", "loopback")


def _not_a_host(addr: str) -> bool:
    return netmap.scope_of(addr) in ("broadcast", "multicast", "unspecified")


def _rows(stats: dict, kind: str, fam: str) -> list:
    return ((stats.get(kind) or {}).get(fam) or {}).get("rows") or []


def _total(stats: dict, kind: str, fam: str) -> int:
    return int(((stats.get(kind) or {}).get(fam) or {}).get("total") or 0)


def _ip_rows(stats: dict, kind: str) -> list:
    return _rows(stats, kind, "ipv4") + _rows(stats, kind, "ipv6")


def _serves(stats: dict) -> dict:
    """(proto, address) -> the ports the host accepted connections on (from the SYNs)."""
    out = {}
    for h in stats.get("hosts") or []:
        out[("tcp", h["addr"])] = {int(p) for p in (h.get("tcp_serves") or {})}
        out[("udp", h["addr"])] = {int(p) for p in (h.get("udp_serves") or {})}
    return out


def _service(proto: str, port: int) -> str:
    name = (netmap.TCP_SERVICES if proto == "tcp" else netmap.UDP_SERVICES).get(port)
    return f"{proto.upper()} {port}" + (f" ({name})" if name else "")


def _server_side(proto: str, a: str, pa, b: str, pb, serves: dict) -> int:
    """Which side of a TCP/UDP conversation is the server: 0 (a), 1 (b) or -1 (can't tell)."""
    if pa is None or pb is None:
        return -1
    if pb in serves.get((proto, b), ()) and pa not in serves.get((proto, a), ()):
        return 1
    if pa in serves.get((proto, a), ()) and pb not in serves.get((proto, b), ()):
        return 0
    if pa == pb:
        return -1
    return 1 if pb < pa else 0


def _apps(d: dict, n: int = 3) -> str:
    names = [k for k, _ in sorted((d or {}).items(), key=lambda kv: -kv[1]) if k not in BASE_PROTOCOLS][:n]
    return ", ".join(x.upper() if len(x) <= 5 else x for x in names)


def _limit(about: dict) -> int:
    return min(MAX_ROWS, int(about.get("n") or DEFAULT_ROWS))


def _table(columns: list[str], rows: list[dict], note: str = "") -> dict:
    return {"columns": columns, "rows": rows, "note": note}


# ---------------------------------------------------------------- who talked to whom

def peers(about: dict, stats: dict, ctx: Ctx) -> dict:
    subject = about["subject"]
    inside = member(subject)
    flt = about.get("filter") or ""
    fam = family(subject)
    agg: dict[str, dict] = {}
    for r in _rows(stats, "conversations", fam):
        a, b = r[0], r[2]
        ia, ib = inside(a), inside(b)
        if ia == ib:
            continue
        peer = b if ia else a
        out_p, out_b, in_p, in_b = (r[4], r[5], r[6], r[7]) if ia else (r[6], r[7], r[4], r[5])
        p = agg.setdefault(peer, {"out_p": 0, "out_b": 0, "in_p": 0, "in_b": 0, "first": None, "last": 0.0,
                                  "apps": defaultdict(int), "conns": 0, "to_it": 0, "from_it": 0, "services": defaultdict(int)})
        p["out_p"] += out_p
        p["out_b"] += out_b
        p["in_p"] += in_p
        p["in_b"] += in_b
        start, dur = float(r[8] or 0), float(r[9] or 0)
        p["first"] = start if p["first"] is None else min(p["first"], start)
        p["last"] = max(p["last"], start + dur)
        for k, v in (r[11] if len(r) > 11 and isinstance(r[11], dict) else {}).items():
            p["apps"][k] += v
    if fam != "eth":
        serves = _serves(stats)
        for proto in ("tcp", "udp"):
            for r in _rows(stats, "conversations", proto):
                a, pa, b, pb = r[0], r[1], r[2], r[3]
                ia, ib = inside(a), inside(b)
                if ia == ib:
                    continue
                peer = b if ia else a
                if peer not in agg:
                    continue
                p = agg[peer]
                p["conns"] += 1
                side = _server_side(proto, a, pa, b, pb, serves)
                if side == -1:
                    continue
                server_is_peer = (side == 1) == ia
                port = pb if side == 1 else pa
                if server_is_peer:
                    p["to_it"] += 1  # the subject connected to the peer
                else:
                    p["from_it"] += 1  # the peer connected to the subject
                p["services"][(proto, port, server_is_peer)] += 1
    direction = about.get("dir") or "any"
    rank, least = about.get("rank") or "bytes", about.get("order") == "least"
    pick = {"servers": lambda p: p["to_it"] > 0, "clients": lambda p: p["from_it"] > 0,
            "out": lambda p: p["out_b"] > 0, "in": lambda p: p["in_b"] > 0}.get(direction, lambda p: True)
    note = ""
    chosen = {k: v for k, v in agg.items() if pick(v) and _in_scope(k, about.get("scope"))}
    if not chosen and agg and direction in ("servers", "clients"):
        chosen = {k: v for k, v in agg.items() if _in_scope(k, about.get("scope"))}
        note = ("Which side opened each connection can't be told from these packets, so this lists every peer."
                if fam != "eth" else "")
        direction = "any"

    def key(item):
        k, p = item
        if rank == "packets":
            v = p["out_p"] if direction == "out" else p["in_p"] if direction == "in" else p["out_p"] + p["in_p"]
        elif rank == "connections":
            v = p["to_it"] if direction == "servers" else p["from_it"] if direction == "clients" else p["conns"]
        elif rank == "duration":
            v = p["last"] - (p["first"] or 0)
        else:
            v = p["out_b"] if direction == "out" else p["in_b"] if direction == "in" else p["out_b"] + p["in_b"]
        return (v, p["out_b"] + p["in_b"])
    ordered = sorted(chosen.items(), key=key, reverse=not least)
    who = ctx.host(subject)
    if not ordered:
        extra = " of that kind" if agg else ""
        return {"lines": [f"{who} has no conversations{extra} in these packets." if not about.get("scope") else
                          f"{who} talked to no {'public' if about['scope'] == 'public' else 'internal'} hosts in these packets."]}
    total_conns = sum(p["conns"] for _, p in ordered)
    noun = {"servers": "servers", "clients": "clients"}.get(direction, "hosts")
    count = {"servers": f"{who} connected to {plural(len(ordered), 'server')}",
             "clients": f"{plural(len(ordered), 'host')} connected to {who}",
             "out": f"{who} sent data to {plural(len(ordered), 'host')}",
             "in": f"{plural(len(ordered), 'host')} sent data to {who}"}.get(direction, f"{who} talked to {plural(len(ordered), 'host')}")
    scope_word = {"public": " on the internet", "private": " on your network"}.get(about.get("scope") or "", "")
    lines = [f"{count}{scope_word}" + (f" in {plural(total_conns, 'connection')}." if total_conns else ".")]
    top_k, top = ordered[0]
    by = {"bytes": "data", "packets": "packets", "connections": "connections", "duration": "time"}[rank]
    services = ", ".join(_service(pr, po) for (pr, po, _), _ in sorted(top["services"].items(), key=lambda kv: -kv[1])[:3])
    lines.append(f"{'Least' if least else 'Most'} {by}: {ctx.host(top_k)}: {fmt_bytes(top['out_b'] + top['in_b'])} "
                 f"({fmt_bytes(top['out_b'])} sent, {fmt_bytes(top['in_b'])} received) in {plural(top['out_p'] + top['in_p'], 'packet')}"
                 + (f", {plural(top['conns'], 'connection')}" if top["conns"] else "")
                 + (f" over {services}" if services else f" ({_apps(top['apps'])})" if _apps(top["apps"]) else "") + ".")
    rows = []
    for k, p in ordered[:_limit(about)]:
        svc = sorted(p["services"].items(), key=lambda kv: -kv[1])
        rows.append({"cells": [ctx.host(k), fmt_bytes(p["out_b"]), fmt_bytes(p["in_b"]), num(p["out_p"] + p["in_p"]),
                               num(p["conns"]) if fam != "eth" else "",
                               ", ".join(_service(pr, po) + ("" if to else " (it served)") for (pr, po, to), _ in svc[:2])
                               or _apps(p["apps"])],
                     "filter": both(flt or addr_filter(subject), addr_filter(k)), "host": k})
    if len(ordered) > len(rows):
        note = (note + " " if note else "") + f"The first {len(rows)} of {num(len(ordered))} {noun}."
    return {"lines": lines, "table": _table(["Host", "Sent", "Received", "Packets", "Connections", "Services"], rows, note),
            "count": len(ordered)}


def talkers(about: dict, stats: dict, ctx: Ctx, conns: dict | None = None) -> dict:
    """The busiest hosts (or, with a filter, the hosts in that traffic)."""
    flt = about.get("filter") or ""
    direction, rank, least = about.get("dir") or "any", about.get("rank") or "bytes", about.get("order") == "least"
    if conns is None:
        conns = defaultdict(int)
        for proto in ("tcp", "udp"):
            for r in _rows(stats, "conversations", proto):
                conns[r[0]] += 1
                conns[r[2]] += 1
    hosts = [r for r in _ip_rows(stats, "endpoints") if not _not_a_host(r[0]) and _in_scope(r[0], about.get("scope"))]
    if direction == "out":
        hosts = [r for r in hosts if r[3]]
    elif direction == "in":
        hosts = [r for r in hosts if r[5]]

    def key(r):
        if rank == "packets":
            v = r[2] if direction == "out" else r[4] if direction == "in" else r[2] + r[4]
        elif rank == "connections":
            v = conns.get(r[0], 0)
        else:
            v = r[3] if direction == "out" else r[5] if direction == "in" else r[3] + r[5]
        return (v, r[3] + r[5])
    hosts.sort(key=key, reverse=not least)
    if not hosts:
        return {"lines": ["No hosts in these packets." if flt else "No hosts in this capture."]}
    top = hosts[0]
    word = {"out": "sent", "in": "received"}.get(direction)
    head = ("Quietest" if least else "Busiest") if not word else ("Sent the least" if least else "Sent the most") \
        if word == "sent" else ("Received the least" if least else "Received the most")
    measure = {"packets": f"{plural(top[2] + top[4], 'packet')}", "connections": plural(conns.get(top[0], 0), "connection")}.get(
        rank, fmt_bytes(top[3] + top[5]))
    lines = [f"{head}: {ctx.host(top[0])}: {measure} ({fmt_bytes(top[3])} sent, {fmt_bytes(top[5])} received, "
             f"{plural(top[2] + top[4], 'packet')})."]
    lines.append(f"{plural(len(hosts), 'host')} in {ctx.where(flt)}"
                 + {"public": " on the internet", "private": " on your network"}.get(about.get("scope") or "", "") + ".")
    rows = [{"cells": [ctx.host(r[0]), fmt_bytes(r[3]), fmt_bytes(r[5]), num(r[2] + r[4]), num(conns.get(r[0], 0))],
             "filter": both(flt, addr_filter(r[0])), "host": r[0]} for r in hosts[:_limit(about)]]
    note = f"The first {len(rows)} of {num(len(hosts))} hosts." if len(hosts) > len(rows) else ""
    return {"lines": lines, "table": _table(["Host", "Sent", "Received", "Packets", "Connections"], rows, note)}


def conversations(about: dict, stats: dict, ctx: Ctx) -> dict:
    flt = about.get("filter") or ""
    rank, least = about.get("rank") or "bytes", about.get("order") == "least"
    rows = [r for r in _ip_rows(stats, "conversations")
            if not about.get("scope") or _in_scope(r[0], about["scope"]) or _in_scope(r[2], about["scope"])]
    key = {"packets": lambda r: r[4] + r[6], "duration": lambda r: float(r[9] or 0),
           "connections": lambda r: r[4] + r[6]}.get(rank, lambda r: r[5] + r[7])
    rows.sort(key=key, reverse=not least)
    if not rows:
        return {"lines": ["No conversations in these packets."]}
    top = rows[0]
    lines = [f"{'Smallest' if least and rank != 'duration' else 'Shortest' if least else 'Longest' if rank == 'duration' else 'Biggest'}: "
             f"{ctx.host(top[0])} ↔ {ctx.host(top[2])}: {fmt_bytes(top[5] + top[7])} in {plural(top[4] + top[6], 'packet')} "
             f"over {span(top[9] or 0)}" + (f" ({_apps(top[11])})" if len(top) > 11 and _apps(top[11]) else "") + ".",
             f"{plural(len(rows), 'conversation')} between addresses in {ctx.where(flt)}."]
    out = [{"cells": [f"{ctx.host(r[0])} ↔ {ctx.host(r[2])}", fmt_bytes(r[5] + r[7]), num(r[4] + r[6]), span(r[9] or 0),
                      _apps(r[11]) if len(r) > 11 else ""],
            "filter": both(flt, addr_filter(r[0]), addr_filter(r[2]))} for r in rows[:_limit(about)]]
    note = f"The first {len(out)} of {num(len(rows))}." if len(rows) > len(out) else ""
    return {"lines": lines, "table": _table(["Conversation", "Data", "Packets", "Duration", "Protocols"], out, note)}


def pair(about: dict, stats: dict, ctx: Ctx, subject_stats: dict | None = None) -> dict:
    a, b = about["subject"], about.get("other")
    flt = about.get("filter") or ""
    props = stats.get("properties") or {}
    frames, size = int(props.get("frames") or 0), int(props.get("bytes") or 0)
    if not b:  # an address and a name
        name = about.get("name") or ""
        lines = [f"Yes: {ctx.host(a)} named {name} in {plural(frames, 'packet')} (DNS lookups, TLS server names or HTTP hosts)."
                 if frames else f"No: {ctx.host(a)} never named {name} in a DNS lookup, TLS server name or HTTP host here."]
        named = [addr for addr, n in ctx.names.items() if n == name or n.endswith("." + name)]
        rows = []
        if subject_stats is not None and named:
            inside = member(a)
            for r in _rows(subject_stats, "conversations", family(a)):
                peer = r[2] if inside(r[0]) else r[0] if inside(r[2]) else None
                if peer in named:
                    rows.append({"cells": [ctx.host(peer), fmt_bytes(r[5] + r[7]), num(r[4] + r[6]), span(r[9] or 0)],
                                 "filter": both(addr_filter(a), addr_filter(peer))})
            if rows:
                lines.append(f"It exchanged data with {plural(len(rows), 'address', 'addresses')} named {name}.")
        return {"lines": lines, "table": _table(["Address", "Data", "Packets", "Duration"], rows[:MAX_ROWS]) if rows else None}
    if not frames:
        rest = " matching the rest of the question" if flt and flt != both(addr_filter(a), addr_filter(b)) else ""
        return {"lines": [f"No: {ctx.host(a)} and {ctx.host(b)} exchanged no packets{rest} in this capture."]}
    ia = member(a)
    ab = [0, 0, 0, 0]
    for r in _rows(stats, "conversations", family(a)):
        if ia(r[0]) or ia(r[2]):
            fwd = ia(r[0])
            ab[0] += r[4] if fwd else r[6]
            ab[1] += r[5] if fwd else r[7]
            ab[2] += r[6] if fwd else r[4]
            ab[3] += r[7] if fwd else r[5]
    lines = [f"Yes: {ctx.host(a)} and {ctx.host(b)} exchanged {plural(frames, 'packet')} ({fmt_bytes(size)})"
             + (f": {a} sent {fmt_bytes(ab[1])} in {plural(ab[0], 'packet')}, {b} sent {fmt_bytes(ab[3])} in "
                f"{plural(ab[2], 'packet')}." if ab[0] + ab[2] else ".")]
    first, last = props.get("first"), props.get("last")
    serves = _serves(stats)
    conns = []
    for proto in ("tcp", "udp"):
        for r in _rows(stats, "conversations", proto):
            side = _server_side(proto, r[0], r[1], r[2], r[3], serves)
            client, cport, server, sport = (r[0], r[1], r[2], r[3]) if side != 0 else (r[2], r[3], r[0], r[1])
            conns.append((proto, client, cport, server, sport, r))
    if first is not None and last is not None:
        lines.append(f"From {ctx.when(float(first))} to {clock(float(last), ctx.tz_min)} ({span(float(last) - float(first))})"
                     + (f"; {plural(len(conns), 'connection')}" if conns else "")
                     + (": " + ", ".join(f"{_service(p, s)} ×{c}" for (p, s), c in sorted(
                         _count((p, s) for p, _, _, _, s, _ in conns).items(), key=lambda kv: -kv[1])[:4]) if conns else "") + ".")
    rows = []
    for proto, client, cport, server, sport, r in sorted(conns, key=lambda c: -(c[5][5] + c[5][7]))[:MAX_ROWS]:
        stream = r[10] if len(r) > 10 else None
        rows.append({"cells": [f"{client}:{cport} → {server}:{sport}", proto.upper(), fmt_bytes(r[5] + r[7]), num(r[4] + r[6]),
                               span(r[9] or 0)],
                     "filter": f"{proto}.stream == {stream}" if isinstance(stream, int) and proto == "tcp" else
                     both(flt, f"{proto}.port == {cport}", f"{proto}.port == {sport}")})
    return {"lines": lines, "table": _table(["Connection", "Protocol", "Data", "Packets", "Duration"], rows) if rows else None}


def _count(items) -> dict:
    out: dict = defaultdict(int)
    for x in items:
        out[x] += 1
    return out


# ---------------------------------------------------------------- what a host is and does

def ports(about: dict, stats: dict, ctx: Ctx) -> dict:
    subject = about.get("subject")
    flt = about.get("filter") or ""
    inside = member(subject) if subject else None
    serves = _serves(stats)
    agg: dict[tuple, dict] = {}
    for proto in ("tcp", "udp"):
        for r in _rows(stats, "conversations", proto):
            side = _server_side(proto, r[0], r[1], r[2], r[3], serves)
            if side == -1:
                continue
            server, port, client = (r[2], r[3], r[0]) if side == 1 else (r[0], r[1], r[2])
            if inside:
                if inside(server) and not inside(client):
                    role = "serves"
                elif inside(client) and not inside(server):
                    role = "uses"
                else:
                    continue
            else:
                role = "serves"
            k = (proto, port, role)
            p = agg.setdefault(k, {"conns": 0, "bytes": 0, "servers": set(), "clients": set()})
            p["conns"] += 1
            p["bytes"] += r[5] + r[7]
            p["servers"].add(server)
            p["clients"].add(client)
    want = about.get("dir") or "both"
    items = [(k, v) for k, v in agg.items() if want == "both" or k[2] == want]
    rank = about.get("rank") or "bytes"
    items.sort(key=lambda kv: (kv[1]["conns"] if rank in ("connections", "packets") else kv[1]["bytes"], kv[1]["conns"]),
               reverse=about.get("order") != "least")
    if subject:
        who = ctx.host(subject)
        served = [k for k, _ in items if k[2] == "serves"]
        used = [k for k, _ in items if k[2] == "uses"]
        lines = []
        if want in ("serves", "both"):
            lines.append(f"{who} accepted connections on {', '.join(_service(p, po) for p, po, _ in served[:6])}"
                         + (f" and {len(served) - 6} more" if len(served) > 6 else "") + "." if served else
                         f"{who} accepted no connections in these packets (ANTA only listens: a port nobody used doesn't show).")
        if want in ("uses", "both"):
            lines.append(f"It connected to {', '.join(_service(p, po) for p, po, _ in used[:6])}"
                         + (f" and {len(used) - 6} more" if len(used) > 6 else "") + " on other hosts." if used else
                         f"{who} opened no connections to other hosts in these packets.")
    else:
        lines = [f"Busiest: {_service(items[0][0][0], items[0][0][1])}: {plural(items[0][1]['conns'], 'connection')} to "
                 f"{plural(len(items[0][1]['servers']), 'server')}, {fmt_bytes(items[0][1]['bytes'])}." if items else
                 "No TCP or UDP services in these packets.",
                 f"{plural(len(items), 'service port')} in use." if items else ""]
    rows = []
    for (proto, port, role), v in items[:_limit(about)]:
        servers = sorted(v["servers"], key=str)
        rows.append({"cells": [_service(proto, port), "it serves" if subject and role == "serves" else "on other hosts" if subject else
                               ", ".join(ctx.host(s) for s in servers[:2]) + (f" +{len(servers) - 2}" if len(servers) > 2 else ""),
                               num(v["conns"]), fmt_bytes(v["bytes"]), num(len(v["clients"] if role == "serves" else v["servers"]))],
                     "filter": both(flt, f"{proto}.port == {port}")})
    cols = ["Port", "Role" if subject else "Servers", "Connections", "Data", "Clients" if not subject else "Peers"]
    return {"lines": [x for x in lines if x], "table": _table(cols, rows) if rows else None}


def protocols(about: dict, stats: dict, ctx: Ctx) -> dict:
    flt = about.get("filter") or ""
    agg: dict[str, list] = {}
    transport = defaultdict(int)
    total = int((stats.get("properties") or {}).get("frames") or 0)
    for r in stats.get("protocols") or []:
        parts = r["path"].split("/")
        abbr = r["abbr"]
        if abbr in ("tcp", "udp") and parts.count(abbr) == 1:
            transport[abbr] += r["frames"]
        if abbr in BASE_PROTOCOLS or abbr in parts[:-1]:
            continue
        a = agg.setdefault(abbr, [r.get("name") or abbr, 0, 0])
        a[1] += r["frames"]
        a[2] += r["bytes"]
    by_bytes = (about.get("rank") or "bytes") == "bytes"
    items = sorted(agg.items(), key=lambda kv: kv[1][2] if by_bytes else kv[1][1], reverse=about.get("order") != "least")
    who = ctx.host(about["subject"]) if about.get("subject") else "The capture"
    if not items:
        return {"lines": [f"{who}: no application protocols in these packets."]}
    lines = [f"{who}: " + ", ".join(f"{_short(k, v[0])} ({plural(v[1], 'packet')})" for k, v in items[:4]) + "."]
    if total and transport:
        lines.append("Transport: " + ", ".join(f"{k.upper()} {_pct(v, total)}" for k, v in
                                               sorted(transport.items(), key=lambda kv: -kv[1])) + " of packets.")
    rows = [{"cells": [f"{_short(k, v[0])}" + (f" ({v[0]})" if _short(k, v[0]) != v[0] else ""), num(v[1]), fmt_bytes(v[2]),
                       _pct(v[1], total) if total else ""],
             "filter": both(flt, k)} for k, v in items[:_limit(about)]]
    return {"lines": lines, "table": _table(["Protocol", "Packets", "Data", "Share"], rows)}


def _short(abbr: str, name: str) -> str:
    """A protocol as people say it: TLS, DNS, HTTP (the full name when there's no short one)."""
    return abbr.upper() if len(abbr) <= 6 and abbr.isalnum() else name


def _pct(part: float, whole: float) -> str:
    p = part * 100 / whole if whole else 0
    return f"{p:.0f}%" if p >= 10 or p == 0 else f"{p:.1f}%" if p >= 0.1 else "<0.1%"


SAFE_NAME = re.compile(r"[A-Za-z0-9._*:-]{1,253}")


def names(about: dict, stats: dict, ctx: Ctx) -> dict:
    flt = about.get("filter") or ""
    agg: dict[str, list] = defaultdict(lambda: [0, 0, 0])
    for i, (section, key) in enumerate((("dns", "names"), ("tls", "server_names"), ("http", "hosts"))):
        for name, n in (stats.get(section) or {}).get(key) or []:
            agg[str(name).rstrip(".").lower()][i] += int(n)
    items = sorted(agg.items(), key=lambda kv: sum(kv[1]), reverse=about.get("order") != "least")
    who = ctx.host(about["subject"]) if about.get("subject") else "The capture"
    if not items:
        return {"lines": [f"{who}: no DNS lookups, TLS server names or HTTP hosts in these packets."]}
    looked = sum(1 for _, v in items if v[0])
    visited = sum(1 for _, v in items if v[1] or v[2])
    lines = [f"{who}: {plural(looked, 'name')} looked up, {plural(visited, 'site')} visited (TLS or HTTP).",
             "Most: " + ", ".join(f"{k} ({', '.join(x for x in (plural(v[0], 'lookup') if v[0] else '', plural(v[1], 'TLS connection') if v[1] else '', plural(v[2], 'HTTP request') if v[2] else '') if x)})"
                                  for k, v in items[:3]) + "."]
    rows = []
    for k, v in items[:_limit(about)]:
        f = (f'dns.qry.name == "{k}" || tls.handshake.extensions_server_name == "{k}" || http.host == "{k}"'
             if SAFE_NAME.fullmatch(k) else "")
        rows.append({"cells": [k, num(v[0]), num(v[1]), num(v[2])], "filter": both(flt, f) if f else ""})
    note = f"The first {len(rows)} of {num(len(items))} names." if len(items) > len(rows) else ""
    return {"lines": lines, "table": _table(["Name", "DNS lookups", "TLS connections", "HTTP requests"], rows, note)}


def volume(about: dict, stats: dict, ctx: Ctx, whole: dict | None = None) -> dict:
    props = stats.get("properties") or {}
    frames, size = int(props.get("frames") or 0), int(props.get("bytes") or 0)
    share = ""
    whole_bytes = int(((whole or {}).get("properties") or {}).get("bytes") or 0)
    subject = about.get("subject")
    if not subject:
        if whole_bytes and size:
            share = f", {size * 100 / whole_bytes:.1f}% of the capture's bytes"
        hosts = sum(1 for r in _ip_rows(stats, "endpoints") if not _not_a_host(r[0]))
        return {"lines": [f"{plural(frames, 'packet')} ({fmt_bytes(size)}{share}) between {plural(hosts, 'host')}."
                          if frames else "No packets match."]}
    inside = member(subject)
    tx_p = tx_b = rx_p = rx_b = 0
    for r in _rows(stats, "endpoints", family(subject)):
        if inside(r[0]):
            tx_p += r[2]
            tx_b += r[3]
            rx_p += r[4]
            rx_b += r[5]
    who = ctx.host(subject)
    if not (tx_p or rx_p):
        return {"lines": [f"{who} sent and received nothing in these packets."]}
    if whole_bytes:
        share = f" That's {(tx_b + rx_b) * 100 / whole_bytes:.1f}% of the capture's traffic."
    sent = f"sent {fmt_bytes(tx_b)} in {plural(tx_p, 'packet')}"
    got = f"received {fmt_bytes(rx_b)} in {plural(rx_p, 'packet')}"
    first, last = props.get("first"), props.get("last")
    rate = ""
    if first is not None and last is not None and float(last) > float(first):
        rate = f" Over {span(float(last) - float(first))}, about {fmt_bytes((tx_b + rx_b) / (float(last) - float(first)))}/s."
    lead = f"{who} {got} and {sent}." if about.get("dir") == "in" else f"{who} {sent} and {got}."
    return {"lines": [lead + share, rate.strip()] if rate else [lead + share]}


def when(about: dict, stats: dict, ctx: Ctx) -> dict:
    props = stats.get("properties") or {}
    frames = int(props.get("frames") or 0)
    who = ctx.host(about["subject"]) if about.get("subject") else "These packets"
    if not frames:
        return {"lines": [f"{who}: nothing in these packets." if about.get("subject") else "No packets match."]}
    first, last = float(props["first"]), float(props["last"])
    multi = clock(first, ctx.tz_min, True)[:6] != clock(last, ctx.tz_min, True)[:6]
    lines = [f"{who}: first seen {clock(first, ctx.tz_min, multi)}"
             + (f" (+{span(first - ctx.start)} into the capture)" if ctx.start is not None and first >= ctx.start else "")
             + f", last seen {clock(last, ctx.tz_min, multi)}; active over {span(last - first)}, {plural(frames, 'packet')}."]
    bins = ((stats.get("io") or {}).get("bins") or [])
    interval = float((stats.get("io") or {}).get("interval") or 0)
    start = float((stats.get("io") or {}).get("start") or first)
    if bins and interval:
        i = max(range(len(bins)), key=lambda j: bins[j][1])
        if bins[i][1]:
            lines.append(f"Busiest {span(interval)}: from {clock(start + i * interval, ctx.tz_min)} "
                         f"({plural(bins[i][0], 'packet')}, {fmt_bytes(bins[i][1])}).")
    return {"lines": lines}


def identity(about: dict, stats: dict, ctx: Ctx) -> dict:
    subject = about["subject"]
    if family(subject) == "eth":
        mac = subject.lower()
        rows = [r for r in ctx.assets if mac in [m.lower() for m in r.get("macs") or []]]
        if not rows:
            return {"lines": [f"No address in this capture used {mac}."]}
        lines = [f"{mac} is used by " + ", ".join(ctx.host(r["ip"]) for r in rows[:5]) + "."]
        subject = rows[0]["ip"]
    else:
        lines = []
    inside = member(subject)
    row = next((r for r in ctx.assets if r["ip"] == subject), None) or \
        next((r for r in ctx.assets if inside(r["ip"])), None)
    if not row:
        return {"lines": lines + [f"{subject} isn't in these packets."]}
    name = row.get("name") or ""
    kind = row.get("device") or "Device"
    lines.append(f"{row['ip']}{f' ({name})' if name and name != row['ip'] else ''}: {kind}"
                 + (f", {row['os']}" if row.get("os") else "") + ".")
    facts = [("Address", f"{row['ip']} ({netmap.SCOPE_TEXT.get(row.get('scope') or '', 'Address').lower()})")]
    if name:
        facts.append(("Name", ", ".join(dict.fromkeys([name] + (row.get("names") or [])))))
    facts.append(("Device", kind + (f" ({row['role']})" if row.get("role") and row["role"] != kind else "")))
    if row.get("os"):
        facts.append(("Operating system", row["os"] + (f" — {', '.join(row['os_evidence'][:2])}" if row.get("os_evidence") else "")))
    if row.get("macs"):
        facts.append(("MAC", ", ".join(row["macs"][:3]) + (f" ({row['vendor']})" if row.get("vendor") else "")))
    if row.get("first") is not None and row.get("last") is not None:
        facts.append(("Seen", f"{ctx.when(float(row['first']))} to {clock(float(row['last']), ctx.tz_min)}"))
    facts.append(("Traffic", f"{fmt_bytes(row.get('tx_bytes') or 0)} sent, {fmt_bytes(row.get('rx_bytes') or 0)} received, "
                             f"{plural(int(row.get('peers') or 0), 'peer')}"))
    if row.get("services"):
        facts.append(("Serves", ", ".join(row["services"][:6])))
    if row.get("apps_used"):
        facts.append(("Uses", ", ".join(a.upper() if len(a) <= 5 else a for a in row["apps_used"][:6])))
    if row.get("users"):
        facts.append(("Accounts seen", ", ".join(str(u) for u in row["users"][:4])))
    if row.get("country") or row.get("as_name"):
        facts.append(("Location", ", ".join(x for x in (row.get("country_name") or row.get("country"),
                                                        row.get("as_name") and f"{row['as_name']} (AS{row.get('asn')})") if x)))
    facts.append(("Alerts", plural(int(row.get("alerts") or 0), "alert") if row.get("alerts") else "none"))
    alerts = int(row.get("alerts") or 0)
    lines.append(f"Sent {fmt_bytes(row.get('tx_bytes') or 0)}, received {fmt_bytes(row.get('rx_bytes') or 0)}, talked to "
                 f"{plural(int(row.get('peers') or 0), 'host')}; " + (f"{plural(alerts, 'alert')} involve it." if alerts
                                                                      else "no alerts involve it."))
    table = _table(["", ""], [{"cells": [k, v], "filter": ""} for k, v in facts])
    table["facts"] = True
    return {"lines": lines, "table": table}


def geo(about: dict, stats: dict, ctx: Ctx) -> dict:
    subject = about["subject"]
    if about.get("peers"):
        inside = member(subject)
        by: dict[str, list] = {}
        waiting = False
        for r in _rows(stats, "conversations", family(subject)):
            peer = r[2] if inside(r[0]) else r[0] if inside(r[2]) else None
            if not peer or netmap.scope_of(peer) != "public":
                continue
            g = ctx.geo.lookup(peer) if ctx.geo is not None else None
            if g is None:
                waiting = waiting or ctx.geo is not None
                continue
            c = by.setdefault(g.get("country_name") or g.get("country") or "unknown", [set(), 0, set()])
            c[0].add(peer)
            c[1] += r[5] + r[7]
            if g.get("as_name"):
                c[2].add(g["as_name"])
        if not by:
            return {"lines": ["The location database is still loading; ask again in a moment." if waiting else
                              f"{ctx.host(subject)} talked to no public addresses in these packets."]}
        items = sorted(by.items(), key=lambda kv: -kv[1][1])
        lines = [f"{ctx.host(subject)} talked to hosts in {plural(len(items), 'country', 'countries')}; most data: "
                 f"{items[0][0]} ({fmt_bytes(items[0][1][1])} with {plural(len(items[0][1][0]), 'host')})."]
        rows = [{"cells": [k, num(len(v[0])), fmt_bytes(v[1]), ", ".join(sorted(v[2])[:2])],
                 "filter": both(addr_filter(subject), " || ".join(addr_filter(x) for x in sorted(v[0])[:40]))}
                for k, v in items[:_limit(about)]]
        return {"lines": lines, "table": _table(["Country", "Hosts", "Data", "Networks"], rows)}
    kind = netmap.scope_of(subject) if family(subject) != "eth" else "unknown"
    if kind != "public":
        return {"lines": [f"{ctx.host(subject)} is a {netmap.SCOPE_TEXT.get(kind, 'local address').lower()}: it isn't on the "
                          "internet, so it has no location (it's on your network)."]}
    g = ctx.geo.lookup(subject) if ctx.geo is not None else None
    if not g:
        return {"lines": ["The location database is still loading; ask again in a moment." if ctx.geo is not None
                          else "No location database is available."]}
    return {"lines": [f"{ctx.host(subject)}: {g.get('country_name') or g.get('country') or 'unknown country'}"
                      + (f", network {g['as_name']} (AS{g.get('asn')})" if g.get("as_name") else "") + "."]}


def resolve(about: dict, whole: dict, ctx: Ctx) -> dict:
    name = (about.get("name") or "").lower()
    addrs = sorted({ip for ip, n in ctx.names.items() if n.lower() == name or n.lower().endswith("." + name)} |
                   {ip for ip, r in ctx.resolved.items() if isinstance(r, dict) and str(r.get("domain") or "").rstrip(".").lower()
                    in (name,)})
    lookups = sum(int(n) for q, n in (whole.get("dns") or {}).get("names") or [] if str(q).rstrip(".").lower() == name)
    if not addrs:
        return {"lines": [f"No DNS answer in this capture gives {name} an address."
                          + (f" It was looked up {plural(lookups, 'time')}." if lookups else "")]}
    traffic = {r[0]: r for r in _ip_rows(whole, "endpoints")}
    lines = [f"{name} → {', '.join(addrs[:6])}" + (f" and {len(addrs) - 6} more" if len(addrs) > 6 else "")
             + " (from DNS answers in this capture)" + (f"; looked up {plural(lookups, 'time')}." if lookups else ".")]
    rows = [{"cells": [a, ctx.names.get(a, ""), fmt_bytes((traffic[a][3] + traffic[a][5]) if a in traffic else 0),
                       num((traffic[a][2] + traffic[a][4]) if a in traffic else 0)],
             "filter": addr_filter(a), "host": a} for a in addrs[:MAX_ROWS]]
    return {"lines": lines, "table": _table(["Address", "Name", "Data", "Packets"], rows)}


def capture(stats: dict, ctx: Ctx) -> dict:
    props = stats.get("properties") or {}
    frames = int(props.get("frames") or 0)
    if not frames:
        return {"lines": ["The capture has no packets yet."]}
    first, last = float(props["first"]), float(props["last"])
    multi = clock(first, ctx.tz_min, True)[:6] != clock(last, ctx.tz_min, True)[:6]
    hosts = [r[0] for r in _ip_rows(stats, "endpoints") if not _not_a_host(r[0])]
    local = sum(1 for h in hosts if _in_scope(h, "private"))
    lines = [f"{plural(frames, 'packet')} ({fmt_bytes(int(props.get('bytes') or 0))}) over {span(last - first)}, "
             f"from {clock(first, ctx.tz_min, True)} to {clock(last, ctx.tz_min, multi)}.",
             f"{plural(len(hosts), 'host')} ({num(local)} on your network, {num(len(hosts) - local)} elsewhere); "
             f"{plural(_total(stats, 'conversations', 'ipv4') + _total(stats, 'conversations', 'ipv6'), 'conversation')}, "
             f"{plural(_total(stats, 'conversations', 'tcp'), 'TCP connection')}."]
    prot = protocols({"rank": "packets"}, stats, ctx)
    if prot.get("table"):
        lines.append("Most packets: " + ", ".join(f"{r['cells'][0].split(' (')[0]} ({r['cells'][3]})"
                                                  for r in prot["table"]["rows"][:4]) + ".")
    sev = defaultdict(int)
    for a in ctx.alerts:
        sev[a.get("severity")] += 1
    lines.append((f"{plural(len(ctx.alerts), 'alert')}: " + ", ".join(f"{sev[k]} {k}" for k in ("critical", "high", "medium", "low")
                                                                      if sev.get(k)) + ".") if ctx.alerts else "No alerts.")
    return {"lines": lines}


def count(about: dict, stats: dict, ctx: Ctx) -> dict:
    what = about.get("what") or "packets"
    props = stats.get("properties") or {}
    if what == "hosts":
        hosts = [r[0] for r in _ip_rows(stats, "endpoints") if not _not_a_host(r[0])]
        local = sum(1 for h in hosts if _in_scope(h, "private"))
        v4 = sum(1 for h in hosts if ":" not in h)
        return {"lines": [f"{plural(len(hosts), 'host')}: {num(v4)} IPv4 and {num(len(hosts) - v4)} IPv6 addresses "
                          f"({num(local)} on your network)."]}
    if what == "conversations":
        return {"lines": [f"{plural(_total(stats, 'conversations', 'ipv4') + _total(stats, 'conversations', 'ipv6'), 'conversation')} "
                          f"between addresses: {plural(_total(stats, 'conversations', 'tcp'), 'TCP connection')} and "
                          f"{plural(_total(stats, 'conversations', 'udp'), 'UDP flow')}."]}
    if what == "names":
        out = names({"order": "most", "n": 3}, stats, ctx)
        return {"lines": out["lines"][:1]}
    frames = int(props.get("frames") or 0)
    return {"lines": [f"{plural(frames, 'packet')} ({fmt_bytes(int(props.get('bytes') or 0))})." if frames else "No packets match."]}


def apps(about: dict, usage: dict, ctx: Ctx) -> dict:
    """Which applications moved the data (anta/apps.py), for the network or one device."""
    subject = about.get("subject")
    if subject:
        rows = usage["devices"].get(subject, [])
        who = ctx.host(subject)
        if not rows:
            return {"lines": [f"{who} used no named application in this capture."]}
        total = sum(r["up"] + r["down"] for r in rows)
        top = rows[0]
        lines = [f"{who} used {plural(len(rows), 'application')}; most data: {top['app']} "
                 f"({fmt_bytes(top['up'] + top['down'])}, {round((top['up'] + top['down']) * 100 / max(1, total))}% of its traffic)."]
        table = [{"cells": [r["app"], r["category"], fmt_bytes(r["up"]), fmt_bytes(r["down"]), num(r["sessions"])],
                  "filter": ""} for r in rows[:_limit(about)]]
        app_filter = {a["app"]: a["filter"] for a in usage["apps"]}
        for row, r in zip(table, rows, strict=False):
            if app_filter.get(r["app"]):
                row["filter"] = both(addr_filter(subject), app_filter[r["app"]])
        return {"lines": lines, "table": _table(["Application", "Category", "Sent", "Received", "Connections"], table)}
    items = usage["apps"]
    if not items:
        return {"lines": ["No applications in these packets."]}
    named = (about.get("named") or "").lower()
    if named:  # ("who uses Zoom?": that application's devices)
        app = next((r for r in items if named in r["app"].lower()), None)
        if not app:
            return {"lines": [f"No one used {named.title()} in this capture."]}
        users = sorted(((ip, next(x for x in rows if x["app"] == app["app"])) for ip, rows in usage["devices"].items()
                        if any(x["app"] == app["app"] for x in rows)), key=lambda kv: -(kv[1]["up"] + kv[1]["down"]))
        lines = [f"{app['app']}: {plural(app['devices'], 'device')}, {fmt_bytes(app['bytes'])} in "
                 f"{plural(app['sessions'], 'connection')} (seen as {', '.join(app['names'][:3]) or 'its addresses'})."]
        rows = [{"cells": [ctx.host(ip), fmt_bytes(x["up"]), fmt_bytes(x["down"]), num(x["sessions"])],
                 "filter": both(addr_filter(ip), app["filter"]) if app["filter"] else addr_filter(ip), "host": ip}
                for ip, x in users[:_limit(about)]]
        return {"lines": lines, "table": _table(["Device", "Sent", "Received", "Connections"], rows)}
    top = items[0]
    lines = [f"{plural(len(items), 'application')} on the network; most data: {top['app']} ({fmt_bytes(top['bytes'])}, "
             f"{plural(top['devices'], 'device')})."]
    cats = usage.get("categories") or []
    if cats:
        lines.append("By kind: " + ", ".join(f"{c['category']} {fmt_bytes(c['bytes'])}" for c in cats[:4]) + ".")
    rows = [{"cells": [r["app"], r["category"], fmt_bytes(r["bytes"]), num(r["devices"]), ", ".join(r["names"][:2])],
             "filter": r["filter"]} for r in items[:_limit(about)]]
    return {"lines": lines, "table": _table(["Application", "Category", "Data", "Devices", "Seen as"], rows)}


def answer(about: dict, stats: dict, ctx: Ctx, whole: dict | None = None, subject_stats: dict | None = None) -> dict:
    """The answer to a question `about` (from ask.parse): {"lines", "table"}. `stats` are the
    statistics of the question's packets, `whole` the capture's."""
    k = about["kind"]
    if k == "peers":
        return peers(about, stats, ctx)
    if k in ("talkers", "hosts"):
        return talkers(about, stats, ctx)
    if k == "conversations":
        return conversations(about, stats, ctx)
    if k == "pair":
        return pair(about, stats, ctx, subject_stats)
    if k == "ports":
        return ports(about, stats, ctx)
    if k == "protocols":
        return protocols(about, stats, ctx)
    if k == "names":
        return names(about, stats, ctx)
    if k == "volume":
        return volume(about, stats, ctx, whole)
    if k == "when":
        return when(about, stats, ctx)
    if k == "identity":
        return identity(about, stats, ctx)
    if k == "geo":
        return geo(about, stats, ctx)
    if k == "resolve":
        return resolve(about, whole or stats, ctx)
    if k == "capture":
        return capture(whole or stats, ctx)
    if k == "count":
        return count(about, stats, ctx)
    return {"lines": []}
