"""Before the capture: what happened before recording began, read from leftovers in the traffic
that was recorded. Nothing here is guessed from patterns; each finding is something the capture
can only show if an earlier event happened.

  Connections already open: TCP connections whose handshake isn't in the capture but which carry
  data in both directions. They began before recording.
  Addresses already known: a device reaching a server by name (TLS server name, HTTP Host) whose
  address no DNS answer in the capture gave. It looked the name up before (or uses encrypted DNS,
  or has the address written in).
  The resolver's memory: a DNS answer from a resolver on this network counts its time to live
  down while the answer sits in its cache. One answered with 1,200 of 3,600 seconds left was
  fetched 40 minutes earlier, by someone. The full time to live is the largest one seen for the
  name, or else the usual round value above what's left (an estimate, and said so). A public
  resolver's cache is shared with the world, so only resolvers on this network count.
  Leases already held: a DHCP renewal comes partway through a lease (by default halfway), so a
  device renewing a 24-hour lease got it about 12 hours before. A device asking to keep an
  address it names (without asking for a new one first) held that address before.
  Sessions resumed: a TLS 1.3 Client Hello offering a pre-shared key resumes a session from
  earlier. Tickets last at most 7 days (RFC 8446), so the two talked within the week before.
"""
from __future__ import annotations

import ipaddress
import time
from collections import defaultdict

from . import netmap

DEVICE = {"private", "link-local", "cgnat"}
LOCAL = {"private", "link-local", "cgnat", "loopback", "multicast", "broadcast", "unspecified"}
COMMON_TTLS = (5, 10, 15, 20, 30, 60, 120, 180, 240, 300, 600, 900, 1200, 1800, 3600, 7200, 10800, 14400, 21600, 28800,
               43200, 86400, 172800, 604800)
TICKET_LIFETIME = 7 * 86400
NO_ADDRESS = "0.0.0.0"  # noqa: S104 - DHCP's "no address yet", not a listening socket
MAX_EVENTS = 400


def _f(row: dict, name: str) -> list[str]:
    return (row.get("f") or {}).get(name) or []


def _ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _v(ip: str) -> str:
    return "ipv6" if ":" in ip else "ip"


def _name(s: dict) -> str:
    sni = (s.get("tls") or {}).get("sni") or ""
    if sni and not _ip(sni):
        return str(sni).lower()
    for h in s.get("http") or []:
        host = str(h.get("host") or "").split(":")[0].lower()
        if host and not _ip(host):
            return host
    return ""


def reconstruct(sessions: list[dict], dns_rows: list[dict], dhcp_rows: list[dict], resumed_rows: list[dict],
                start: float | None, scope_of=None) -> dict:
    """What the capture shows happened before `start` (its first packet)."""
    scope_of = scope_of or netmap.scope_of
    if start is None:
        start = min((s.get("start") or 0 for s in sessions), default=0) or 0.0
    events: list[dict] = []

    def add(kind, who, what, why, when=None, earliest=None, sure=True, flt="", frames=None, peer=""):
        if len(events) < MAX_EVENTS * 4:
            events.append({"kind": kind, "who": who, "peer": peer, "what": what, "why": why, "when": when, "earliest": earliest,
                           "sure": sure, "filter": flt, "frames": [f for f in (frames or []) if isinstance(f, int)][:12]})

    # ---- connections already open
    for s in sessions:
        t = s.get("tcp") or {}
        if s.get("proto") != "tcp" or t.get("handshake"):
            continue
        head = s.get("stream_head") or {}
        if head.get("c2s_from_start") or head.get("s2c_from_start"):
            continue
        c2s, s2c = s.get("c2s") or {}, s.get("s2c") or {}
        if not (c2s.get("packets") and s2c.get("packets")) or not (c2s.get("payload_bytes") or s2c.get("payload_bytes")):
            continue
        src, dst = s.get("src_ip") or "", s.get("dst_ip") or ""
        local, peer = (src, dst) if scope_of(src) in DEVICE else (dst, src)
        name = _name(s)
        label = name or s.get("app_label") or s.get("app") or f"port {s.get('dst_port')}"
        add("open", local, f"was already connected to {peer}{f' ({label})' if label else ''}",
            "Its connection's opening handshake isn't in the capture, but data flows both ways: it began before recording.",
            None, None, True,
            f"{_v(src)}.addr == {src} && {_v(dst)}.addr == {dst} && tcp.port == {s.get('src_port')} && tcp.port == {s.get('dst_port')}",
            peer=peer)

    # ---- addresses already known
    answered: set[str] = set()
    asked: dict[str, set] = defaultdict(set)
    for s in sessions:
        for q in s.get("dns") or []:
            if q.get("qname"):
                asked[s.get("src_ip") or ""].add(str(q["qname"]).lower().rstrip("."))
            for a in q.get("answers") or []:
                if isinstance(a, str):
                    answered.add(a)
    for r in dns_rows:
        answered.update(_f(r, "dns.a") + _f(r, "dns.aaaa"))
    known: dict[tuple, dict] = {}
    for s in sessions:
        src, dst = s.get("src_ip") or "", s.get("dst_ip") or ""
        name = _name(s)
        if not name or scope_of(src) not in DEVICE or scope_of(dst) in LOCAL or dst in answered or name in asked.get(src, ()):
            continue
        k = (src, name)
        if k not in known:
            known[k] = {"src": src, "dst": dst, "name": name, "first": s.get("start") or 0, "count": 0}
        known[k]["count"] += 1
        known[k]["first"] = min(known[k]["first"], s.get("start") or known[k]["first"])
    for k in sorted(known, key=lambda k: known[k]["first"]):
        x = known[k]
        add("known", x["src"], f"already knew the address of {x['name']} ({x['dst']})",
            "It connected by that name, but no DNS answer in the capture gave the address: it looked it up before "
            "recording (or uses encrypted DNS, or has the address written in).", None, None, True,
            f"{_v(x['src'])}.addr == {x['src']} && {_v(x['dst'])}.addr == {x['dst']}", peer=x["name"])

    # ---- the resolver's memory
    by_name: dict[str, list] = defaultdict(list)
    max_ttl: dict[str, int] = defaultdict(int)
    for r in dns_rows:
        server = str(r.get("src") or "")
        names = _f(r, "dns.qry.name")
        if not names:
            continue
        name = names[0].lower().rstrip(".")
        ttls = [int(x) for x in _f(r, "dns.resp.ttl") if str(x).isdigit()]
        types = _f(r, "dns.resp.type")
        addr_ttls = [t for t, ty in zip(ttls, types, strict=False) if str(ty) in ("1", "28")] or ttls
        if not addr_ttls:
            continue
        ttl = min(addr_ttls)
        max_ttl[name] = max(max_ttl[name], max(addr_ttls))
        if scope_of(server) in DEVICE:  # (a public resolver's cache is everyone's)
            by_name[name].append((float(r.get("ts") or 0), ttl, server, str(r.get("dst") or ""), int(r.get("n") or 0)))
    cached: list[dict] = []
    for name, answers in by_name.items():
        best = None
        top = max_ttl[name]
        full = max(top, next((c for c in COMMON_TTLS if c >= top), top))  # (the largest seen, or the usual value above it)
        fresh = [ts for ts, ttl, *_ in answers if ttl >= full]  # (fetched just then: later answers come from it)
        for ts, ttl, server, asker, frame in answers:
            if ttl >= full or any(f <= ts for f in fresh):
                continue
            fetched = ts - (full - ttl)
            if fetched < start - 1 and (best is None or fetched < best["when"]):
                best = {"when": fetched, "ttl": ttl, "full": full, "seen": top == full and top > ttl,
                        "server": server, "asker": asker, "frame": frame, "ts": ts}
        if best:
            cached.append({"name": name, **best})
    for c in sorted(cached, key=lambda c: c["when"])[:MAX_EVENTS]:
        how = (f"the full time to live, {c['full']:,} s, is in the capture" if c["seen"]
               else f"assuming the usual {c['full']:,} s; the full value isn't in the capture")
        add("cache", c["server"], f"had {c['name']} in its cache already",
            f"It answered with {c['ttl']:,} s of its time to live left ({how}), so it fetched the name about "
            f"{_dur(c['full'] - c['ttl'])} before that answer, for some device on the network.",
            c["when"], None, c["seen"], f'dns.qry.name == "{c["name"]}" && dns.flags.response == 1', [c["frame"]],
            peer=c["name"])

    # ---- leases already held
    discovered: set[str] = set()
    acks: dict[str, list] = defaultdict(list)
    for r in dhcp_rows:
        mtype = (_f(r, "dhcp.option.dhcp") or ["0"])[0]
        mac = (_f(r, "dhcp.hw.mac_addr") or [""])[0].lower()
        if mtype == "1":
            discovered.add(mac)
        if mtype == "5":
            lease = (_f(r, "dhcp.option.dhcp_lease_time") or [""])[0]
            t1 = (_f(r, "dhcp.option.renewal_time_value") or [""])[0]
            acks[mac].append((float(r.get("ts") or 0), int(lease) if lease.isdigit() else 0, int(t1) if t1.isdigit() else 0))
    done: set[tuple] = set()
    for r in dhcp_rows:
        if (_f(r, "dhcp.option.dhcp") or ["0"])[0] != "3":
            continue
        ts = float(r.get("ts") or 0)
        mac = (_f(r, "dhcp.hw.mac_addr") or [""])[0].lower()
        ciaddr = (_f(r, "dhcp.ip.client") or [NO_ADDRESS])[0]
        wanted = (_f(r, "dhcp.option.requested_ip_address") or [""])[0]
        n = int(r.get("n") or 0)
        if ciaddr and ciaddr != NO_ADDRESS:  # renewing: it holds ciaddr
            if (mac, ciaddr) in done:
                continue
            done.add((mac, ciaddr))
            ack = next((a for a in acks.get(mac, []) if a[0] >= ts - 1), None)
            t1 = (ack[2] or ack[1] // 2) if ack and (ack[2] or ack[1]) else 0
            if t1:
                add("lease", ciaddr, f"held its address {ciaddr} already (renewed at {_clock(ts)})",
                    f"A DHCP renewal comes partway through the lease: with a lease of {_dur(ack[1] or t1 * 2)} it renews after "
                    f"{_dur(t1)}, so it got or last renewed this address about {_dur(t1)} before.",
                    ts - t1, None, bool(ack[2]), f"dhcp.hw.mac_addr == {mac}" if mac else f"dhcp.ip.client == {ciaddr}", [n],
                    peer=mac)
            else:
                add("lease", ciaddr, f"held its address {ciaddr} already (renewed at {_clock(ts)})",
                    "It renewed a lease it already had; the capture doesn't show how long the lease is.", None, None, True,
                    f"dhcp.hw.mac_addr == {mac}" if mac else f"dhcp.ip.client == {ciaddr}", [n], peer=mac)
        elif wanted and mac not in discovered and (mac, wanted) not in done:
            done.add((mac, wanted))
            add("lease", wanted, f"had the address {wanted} before (asked to keep it)",
                "It asked for this exact address without asking for a new one first: a device rejoining the network "
                "asks to keep the address it held before.", None, None, True, f"dhcp.hw.mac_addr == {mac}" if mac else "", [n],
                peer=mac)

    # ---- sessions resumed
    first_to: dict[tuple, float] = {}
    for s in sessions:
        sni = (s.get("tls") or {}).get("sni")
        if sni:
            k = (s.get("src_ip") or "", str(sni).lower())
            first_to[k] = min(first_to.get(k, s.get("start") or 0), s.get("start") or 0)
    said: set[tuple] = set()
    for r in resumed_rows:
        ts = float(r.get("ts") or 0)
        src = str(r.get("src") or "")
        sni = ((_f(r, "tls.handshake.extensions_server_name") or [""])[0]).lower()
        k = (src, sni or str(r.get("dst") or ""))
        if k in said or (sni and first_to.get((src, sni), ts) < ts - 1):  # (an earlier connection here could be the one)
            continue
        said.add(k)
        add("resumed", src, f"resumed an earlier encrypted session with {sni or r.get('dst')}",
            "Its TLS 1.3 Client Hello offers a pre-shared key from a session before this capture; tickets last at most 7 days, "
            "so the two talked within the week before.", None, ts - TICKET_LIFETIME, True,
            f"{_v(src)}.addr == {src} && tls.handshake.extension.type == 41", [int(r.get("n") or 0)], peer=sni)

    order = {"lease": 0, "cache": 1, "resumed": 2, "open": 3, "known": 4}
    events.sort(key=lambda e: (e["when"] if e["when"] is not None else (e["earliest"] or start), order[e["kind"]]))
    counts = defaultdict(int)
    for e in events:
        counts[e["kind"]] += 1
    dated = [e for e in events if e["when"] is not None]
    devices: dict[str, int] = defaultdict(int)
    for e in events:
        devices[e["who"]] += 1
    return {"start": start, "events": events[:MAX_EVENTS], "counts": dict(counts), "truncated": len(events) > MAX_EVENTS,
            "earliest": min((e["when"] for e in dated), default=None),
            "earliest_bound": min((e["earliest"] for e in events if e["earliest"]), default=None),
            "devices": sorted(({"ip": k, "events": v} for k, v in devices.items()), key=lambda d: -d["events"])[:200],
            "notes": ["Each finding is something the capture can only show if an earlier event happened.",
                      "Times from a DNS cache are estimates when the full time to live isn't in the capture (it says so).",
                      "Devices using encrypted DNS (DNS over HTTPS or TLS) look up names the capture can't see, so they can "
                      "appear to know addresses already."]}


def _dur(s: float) -> str:
    s = abs(s)
    if s < 120:
        return f"{s:.0f} seconds"
    if s < 7200:
        return f"{s / 60:.0f} minutes"
    if s < 172800:
        return f"{s / 3600:.1f} hours".replace(".0 hours", " hours")
    return f"{s / 86400:.1f} days".replace(".0 days", " days")


def _clock(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))
