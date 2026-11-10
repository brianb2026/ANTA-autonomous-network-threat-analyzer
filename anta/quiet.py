"""The certificate of quiet: for each device, everything it sent to the internet accounted for,
and an upper limit on what it could have sent that the capture doesn't show as data.

What a device sends openly is in the capture: the payload of its connections (readable, or
encrypted and only countable), the names it looked up in DNS (which leave through any
resolver), its ICMP and other packets. Anything else would have to ride inside traffic that
looks normal, in the room each packet leaves its sender: header values a sender may choose
freely, the first sequence number and source port of each connection, and the timing between
packets. That room is finite and countable, so the certificate can say "besides the 40 KB it
visibly sent, this device could not have slipped out more than 1.2 KB". Fields a check shows
were never used (the TCP urgent pointer outside urgent data, reserved bits) are taken out.

And where a device sent nothing to the internet at all, it says when: a stretch of quiet is a
plain fact, not an estimate.

The limits hold for what passed the capture point while it was recording. Timing is an estimate
(a pattern hidden in timing has to stay within normal jitter to pass unnoticed; one bit per
packet is allowed for it).
"""
from __future__ import annotations

import math
from collections import defaultdict

from . import netmap

LOCAL = {"private", "link-local", "cgnat", "loopback", "multicast", "broadcast", "unspecified"}
DEVICE = {"private", "link-local", "cgnat"}
ENCRYPTED_APPS = {"tls", "https", "quic", "ssh", "dtls", "ipsec", "wireguard", "openvpn", "rdp"}
# Bits a sender may choose freely, per packet and per connection.
ROOM = {
    "ip4_id": (16, "IPv4 identification", "per IPv4 packet"),
    "ip6_flow": (20, "IPv6 flow label", "per IPv6 packet"),
    "tcp_urgent": (16, "TCP urgent pointer (outside urgent data)", "per TCP packet"),
    "tcp_ts": (8, "low bits of TCP timestamps", "per TCP packet"),
    "tcp_isn": (32, "first sequence number", "per TCP connection, each side"),
    "port": (16, "source port", "per connection it opened"),
    "timing": (1, "timing between packets (estimate)", "per packet"),
}
MAX_DEVICES = 2000


def _merge(intervals: list[tuple[float, float]]) -> list[tuple[float, float]]:
    out: list[list[float]] = []
    for a, b in sorted(intervals):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]


def _dns_room(name: str) -> int:
    """Bytes of a looked-up name that a sender could choose: everything before its last two labels."""
    labels = name.rstrip(".").split(".")
    return max(0, len(".".join(labels[:-2]))) if len(labels) > 2 else 0


def _outside_filter(ip: str) -> str:
    if ":" in ip:
        return f"ipv6.src == {ip} && !(ipv6.dst == fe80::/10 || ipv6.dst == fc00::/7 || ipv6.dst == ff00::/8)"
    return (f"ip.src == {ip} && !(ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || "
            "ip.dst == 100.64.0.0/10 || ip.dst == 169.254.0.0/16 || ip.dst == 224.0.0.0/4 || ip.dst == 255.255.255.255)")


def certify(sessions: list[dict], icmp: list[tuple], other: list[tuple], used: dict, span: tuple[float, float] | None,
            scope_of=None) -> dict:
    """The certificate. `icmp`/`other`: (time, source, destination, length) of ICMP packets and of
    IP packets that are neither TCP, UDP nor ICMP; `used`: {"urgent": packets whose urgent pointer
    is set outside urgent data, "reserved": packets with reserved bits set} over the whole capture."""
    scope_of = scope_of or netmap.scope_of
    scopes: dict[str, str] = {}

    def scope(ip):
        s = scopes.get(ip)
        if s is None:
            s = scopes[ip] = scope_of(ip) if ip else "unspecified"
        return s

    dev: dict[str, dict] = {}
    names: dict[str, set] = defaultdict(set)
    lookups: dict[str, list] = defaultdict(list)   # when each device looked names up (they leave through the resolver)
    seen_local: set[str] = set()

    def d(ip):
        x = dev.get(ip)
        if x is None:
            if len(dev) >= MAX_DEVICES:
                return None
            x = dev[ip] = {"ip": ip, "connections": 0, "packets": 0, "open": 0, "encrypted": 0, "icmp": 0, "other": 0,
                           "bits": defaultdict(int), "spans": []}
        return x

    urgent_free = not used.get("urgent")
    first = last = None
    for s in sessions:
        src, dst = s.get("src_ip") or "", s.get("dst_ip") or ""
        start, end = s.get("start") or 0.0, s.get("end") or s.get("start") or 0.0
        if start:
            first = start if first is None else min(first, start)
            last = end if last is None else max(last, end)
        for ip in (src, dst):
            if scope(ip) in DEVICE:
                seen_local.add(ip)
        if scope(src) in DEVICE:
            for q in s.get("dns") or []:
                qn = str(q.get("qname") or "").lower()
                if qn and not qn.endswith((".local", ".local.")) and len(names[src]) < 20000:
                    names[src].add(qn)
            if s.get("dns") and len(lookups[src]) < 200000:
                lookups[src].append((start, end))
        tcp = s.get("proto") == "tcp"
        enc = bool(s.get("tls")) or str(s.get("app") or "").lower() in ENCRYPTED_APPS
        for me, peer, side, opener in ((src, dst, "c2s", True), (dst, src, "s2c", False)):
            if scope(me) not in DEVICE or scope(peer) in LOCAL:
                continue
            out = s.get(side) or {}
            pk = int(out.get("packets") or 0)
            if not pk:
                continue
            x = d(me)
            if x is None:
                continue
            payload = int(out.get("payload_bytes") or 0)
            x["connections"] += 1
            x["packets"] += pk
            x["open"] += payload
            if enc:
                x["encrypted"] += payload
            b = x["bits"]
            b["ip6_flow" if ":" in me else "ip4_id"] += pk * ROOM["ip6_flow" if ":" in me else "ip4_id"][0]
            if tcp:
                if not urgent_free:
                    b["tcp_urgent"] += pk * ROOM["tcp_urgent"][0]
                b["tcp_ts"] += pk * ROOM["tcp_ts"][0]
                b["tcp_isn"] += ROOM["tcp_isn"][0]
            if opener:
                b["port"] += ROOM["port"][0]
            b["timing"] += pk * ROOM["timing"][0]
            x["spans"].append((start, end))
    for rows, key in ((icmp, "icmp"), (other, "other")):
        for row in rows:
            ts, src, dst, length = row[0], row[1], row[2], row[3]
            if scope(src) not in DEVICE or scope(dst) in LOCAL:
                continue
            x = d(src)
            if x is None:
                continue
            x[key] += max(0, int(length) - (62 if ":" in src else 42))  # (the headers before the payload)
            x["open"] += max(0, int(length) - (62 if ":" in src else 42))
            x["packets"] += 1
            x["bits"]["ip6_flow" if ":" in src else "ip4_id"] += ROOM["ip6_flow" if ":" in src else "ip4_id"][0]
            x["bits"]["timing"] += 1
            x["spans"].append((ts, ts))
            first = ts if first is None else min(first, ts)
            last = ts if last is None else max(last, ts)
    if span and span[0] is not None:
        first, last = span
    first = first or 0.0
    last = last or first
    length = max(0.0, last - first)
    min_quiet = max(600.0, 0.05 * length)

    devices = []
    for ip in sorted(seen_local | set(dev)):
        x = dev.get(ip) or {"ip": ip, "connections": 0, "packets": 0, "open": 0, "encrypted": 0, "icmp": 0, "other": 0,
                            "bits": {}, "spans": []}
        dns_bytes = sum(_dns_room(n) for n in names.get(ip, ()))
        room_bits = sum(x["bits"].values())
        quiet = []
        prev = first
        for a, b in _merge(x["spans"] + lookups.get(ip, [])) + [(last, last)]:
            if a - prev >= min_quiet:
                quiet.append({"from": prev, "to": a, "seconds": a - prev})
            prev = max(prev, b)
        quiet.sort(key=lambda q: -q["seconds"])
        devices.append({
            "ip": ip, "connections": x["connections"], "packets": x["packets"], "open": x["open"], "encrypted": x["encrypted"],
            "icmp": x["icmp"], "other": x["other"], "dns_names": len(names.get(ip, ())), "dns_bytes": dns_bytes,
            "room": math.ceil(room_bits / 8),
            "room_parts": {k: math.ceil(v / 8) for k, v in sorted(x["bits"].items(), key=lambda kv: -kv[1]) if v},
            "silent": x["packets"] == 0 and not names.get(ip), "quiet": quiet[:3],
            "quiet_seconds": sum(q["seconds"] for q in quiet),
            "filter": _outside_filter(ip),
        })
    devices.sort(key=lambda r: (r["silent"], -r["room"], -r["open"], r["ip"]))
    talkers = [r for r in devices if not r["silent"]]
    total_room = sum(r["room"] for r in devices)
    fields = []
    for key, (bits, label, unit) in ROOM.items():
        removed = key == "tcp_urgent" and urgent_free
        fields.append({"key": key, "label": label, "bits": bits, "unit": unit, "removed": removed,
                       "why": "never set outside urgent data anywhere in this capture" if removed else ""})
    return {
        "first": first, "last": last, "seconds": length,
        "devices": devices,
        "totals": {"devices": len(devices), "talkers": len(talkers), "silent": len(devices) - len(talkers),
                   "open": sum(r["open"] for r in devices), "encrypted": sum(r["encrypted"] for r in devices),
                   "dns_bytes": sum(r["dns_bytes"] for r in devices), "room": total_room,
                   "most_room": max((r["room"] for r in devices), default=0),
                   "connections": sum(r["connections"] for r in devices)},
        "fields": fields,
        "used": {"urgent": int(used.get("urgent") or 0), "reserved": int(used.get("reserved") or 0)},
        "notes": [
            "The limits hold for what passed the capture point while it was recording; traffic that went another way "
            "(a phone's mobile data, another network) isn't in it.",
            "Encrypted data is counted, not read: its size is certain, its content isn't.",
            "Timing is an estimate: one bit per packet is allowed for a pattern hidden in the gaps between packets.",
            "A device that hands data to another device on the network to send counts under the one that sent it out.",
            "If the file was edited, so is this certificate: see Tamper seal.",
        ],
    }
