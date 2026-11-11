"""Recognising devices when their addresses change, on this network, from what each device says
about itself:

  Same network card (MAC), new IP address: DHCP gave it another one, or it was set by hand.
  New MAC, same host name: phones and laptops use a private (randomised) Wi-Fi address that
    changes; the name they give DHCP, mDNS or Windows naming usually stays.
  Common names ("iPhone") are shared by many devices: they link two MACs only when the DHCP
    request looks the same and one stops shortly before the other starts, with no other candidate.

It also says which addresses changed hands: one IP address used by two different devices, so
what happened on it before and after belongs to different machines.

Only MACs that are a device's own count: a MAC carrying internet addresses, or several local
addresses at once, is a router's. A device that changes its MAC and its name, or gives no name,
isn't followed, and isn't guessed at.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .netmap import scope_of as _scope_of

LOCAL = ("private", "link-local", "cgnat")
NAME_SOURCES = ("DHCP", "mDNS", "LLMNR", "NetBIOS", "Kerberos", "NTLM", "Browser", "CLDAP")
GENERIC = re.compile(
    r"^(?:i(?:phone|pad|mac|pod)(?:-\d+)?|android|localhost|unknown|none|galaxy[\w-]*|pixel[\w-]*|"
    r"macbook(?:-?(?:pro|air))?|(?:my-?)?(?:phone|laptop|pc|computer|tablet)|espressif|esp32|esp8266|"
    r"amazon[\w-]*|echo[\w-]*|chromecast|desktop|windows|linux|raspberrypi|ubuntu(?:-server)?|debian|kali|fedora|"
    r"openwrt|dd-?wrt|router|gateway|homeassistant|android-?\w{0,4})$", re.I)
HANDOVER = 1800.0  # seconds: a common name links two MACs only when one starts this soon after the other stopped
DHCP_TYPES = {1: "discover", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}


def randomised(mac: str) -> bool:
    """A locally administered MAC (the second-lowest bit of the first byte): private Wi-Fi
    addresses and virtual machines use these, not a maker's own."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except ValueError:
        return False


def name_key(name: str) -> str:
    """One device's names compared: the first label, lower case, NetBIOS-length."""
    return (name or "").strip().rstrip(".").split(".")[0].lower()[:15]


def _net(ip: str) -> str | None:
    """An IPv4 address's network, as /24 (self-assigned 169.254 addresses belong to none)."""
    return None if ip.startswith("169.254.") else ip.rsplit(".", 1)[0]


def _max_concurrent(spans) -> int:
    edges = sorted([(f, 1) for _, f, _ in spans] + [(last, -1) for _, _, last in spans], key=lambda e: (e[0], e[1]))
    best = now = 0
    for _, d in edges:
        now += d
        best = max(best, now)
    return best


def _overlap(a: dict, b: dict) -> bool:
    return a["first"] < b["last"] and b["first"] < a["last"]


def _first(f: dict, key: str):
    v = f.get(key)
    return v[0] if isinstance(v, list) and v else None


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


class _Union:
    def __init__(self):
        self.up: dict[str, str] = {}

    def find(self, x):
        self.up.setdefault(x, x)
        while self.up[x] != x:
            self.up[x] = self.up[self.up[x]]
            x = self.up[x]
        return x

    def join(self, a, b):
        self.up[self.find(a)] = self.find(b)


def link(stats: dict, dhcp_rows: list[dict], scope_of=_scope_of) -> dict:
    """Devices followed across their addresses, and addresses that changed hands."""
    hosts = {h["addr"]: h for h in stats.get("hosts") or []}
    ids: dict[str, dict] = {}
    routers = []
    claimed: dict[str, set] = defaultdict(set)  # address -> the MACs that announced it in ARP
    for m in stats.get("macs") or []:
        for ip in m.get("arp_ips") or []:
            claimed[ip].add(m.get("mac"))
    for m in stats.get("macs") or []:
        mac = m.get("mac") or ""
        if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac) or mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1:
            continue  # (not a MAC, or a group address: broadcast and multicast)
        if any(scope_of(ip) == "public" for ip in m.get("src_ips") or []):
            routers.append(mac)
            continue
        spans = [(ip, float(f), float(last)) for ip, f, last in m.get("ip_spans") or [] if scope_of(ip) in LOCAL]
        v4 = [s for s in spans if ":" not in s[0]]
        arp = set(m.get("arp_ips") or [])
        if arp:  # its own addresses: those it announced, and others on its network nobody else announced
            nets = {_net(ip) for ip in arp}
            own = [s for s in v4 if s[0] in arp or (_net(s[0]) in nets and not claimed.get(s[0]))]
        elif len({_net(s[0]) for s in v4} - {None}) > 1:
            routers.append(mac)  # (addresses from several networks, none announced: forwarding between them)
            continue
        else:
            own = v4
        forwards = len(own) < len(v4)
        if _max_concurrent(own) >= 3:
            routers.append(mac)  # (forwarding for several local addresses at once)
            continue
        spans = own + [s for s in spans if ":" in s[0] and (s[0].startswith("fe80:") or not forwards)]
        if not spans:
            continue
        ids[mac] = {"mac": mac, "vendor": m.get("vendor") or "", "randomised": randomised(mac), "spans": sorted(spans, key=lambda s: s[1]),
                    "first": min(s[1] for s in spans), "last": max(s[2] for s in spans), "names": {}, "fp": None, "events": []}

    # What DHCP says, per client MAC (the client's own, even through a relay).
    for r in dhcp_rows:
        f = r.get("f") or {}
        mac = _first(f, "dhcp.hw.mac_addr")
        if not mac or mac in routers:
            continue
        ts = float(r.get("ts") or 0)
        e = ids.get(mac)
        if e is None:  # (a device seen only asking for an address)
            e = ids[mac] = {"mac": mac, "vendor": "", "randomised": randomised(mac), "spans": [], "first": ts, "last": ts,
                            "names": {}, "fp": None, "events": []}
        e["first"], e["last"] = min(e["first"], ts), max(e["last"], ts)
        mtype = _int(_first(f, "dhcp.option.dhcp"))
        name = _first(f, "dhcp.option.hostname")
        if name and mtype not in (2, 5, 6):  # (the client's own name, not one a server suggests)
            e["names"].setdefault(name, set()).add("DHCP")
        prl = tuple(_int(x) for x in f.get("dhcp.option.request_list_item") or [])
        vendor = _first(f, "dhcp.option.vendor_class_id")
        if (prl or vendor) and mtype in (1, 3, 8):
            e["fp"] = (vendor or "", prl)
        if mtype == 5 and _first(f, "dhcp.ip.your") not in (None, "0.0.0.0"):  # noqa: S104
            e["events"].append((ts, "given", _first(f, "dhcp.ip.your")))
        elif mtype == 7 and _first(f, "dhcp.ip.client") not in (None, "0.0.0.0"):  # noqa: S104
            e["events"].append((ts, "released", _first(f, "dhcp.ip.client")))

    # Names announced from an address only one device MAC used.
    users: dict[str, list[str]] = defaultdict(list)
    for mac, e in ids.items():
        for ip in {s[0] for s in e["spans"]}:
            users[ip].append(mac)
    for ip, macs in users.items():
        if len(macs) != 1:
            continue
        for name, src in (hosts.get(ip) or {}).get("names") or []:
            if src in NAME_SOURCES and src != "DHCP":
                ids[macs[0]]["names"].setdefault(name, set()).add(src)

    # Link MACs: one specific name; or one common name, the same DHCP request, and a handover.
    u = _Union()
    clues: dict[str, list[dict]] = defaultdict(list)
    conflicts = []
    by_name: dict[str, list[str]] = defaultdict(list)
    for mac, e in ids.items():
        u.find(mac)
        for key in {name_key(n) for n in e["names"]}:
            if key:
                by_name[key].append(mac)
    for key, macs in by_name.items():
        if len(macs) < 2:
            continue
        macs.sort(key=lambda m: ids[m]["first"])
        shown = next(n for n in ids[macs[0]]["names"] if name_key(n) == key)
        if GENERIC.match(key):
            for i, a in enumerate(macs):
                ea = ids[a]
                after = [b for b in macs[i + 1:] if ids[b]["first"] >= ea["last"] and ids[b]["first"] - ea["last"] <= HANDOVER]
                same = [b for b in after if ea["fp"] and ids[b]["fp"] == ea["fp"]]
                if len(same) == 1 and len(after) == 1:
                    b = same[0]
                    u.join(a, b)
                    clues[a].append({"strength": "probably", "with": b,
                                     "text": f"both called “{shown}” (a name many devices use), with the same DHCP request, and "
                                             f"{b} began {_gap(ids[b]['first'] - ea['last'])} after {a} stopped"})
            continue
        base = ids[macs[0]]
        for b in macs[1:]:
            eb = ids[b]
            if base["fp"] and eb["fp"] and base["fp"][0] != eb["fp"][0]:
                conflicts.append({"name": shown, "macs": [macs[0], b],
                                  "why": f"both called “{shown}”, but their DHCP requests come from different systems "
                                         f"({base['fp'][0] or 'no vendor class'} and {eb['fp'][0] or 'no vendor class'})"})
                continue
            u.join(macs[0], b)
            srcs = sorted(set().union(*(v for n, v in base["names"].items() if name_key(n) == key),
                                      *(v for n, v in eb["names"].items() if name_key(n) == key)))
            together = _overlap(base, eb)
            clues[macs[0]].append({"strength": "probably" if together else "same", "with": b, "together": together,
                                   "text": f"both called “{shown}” ({', '.join(srcs)})"
                                           + (", at the same time: one machine on two connections (Wi-Fi and a cable), "
                                              "or two machines given one name" if together else "")})

    groups: dict[str, list[str]] = defaultdict(list)
    for mac in ids:
        groups[u.find(mac)].append(mac)

    devices = []
    owner: dict[str, str] = {}
    for members in groups.values():
        members.sort(key=lambda m: ids[m]["first"])
        es = [ids[m] for m in members]
        v4 = sorted([(ip, f, last, e["mac"]) for e in es for ip, f, last in e["spans"] if ":" not in ip], key=lambda s: s[1])
        v6 = sorted({ip for e in es for ip, _, _ in e["spans"] if ":" in ip})
        names = {}
        for e in es:
            for n, src in e["names"].items():
                names.setdefault(n, set()).update(src)
        label = _label(names, es[0])
        dev_id = members[0]
        for m in members:
            owner[m] = dev_id
        changes = []
        for (ip_a, _, last_a, mac_a), (ip_b, first_b, _, mac_b) in zip(v4, v4[1:], strict=False):
            if first_b < last_a:
                continue  # (both at once: a second address, not a change)
            if ip_a == ip_b and mac_a == mac_b:
                continue
            how = []
            if mac_a != mac_b:
                how.append("a new private Wi-Fi address (MAC)" if ids[mac_b]["randomised"] else "a different network card (MAC)")
            if ip_a != ip_b:
                given = [t for t, kind, ip in ids[mac_b]["events"] if kind == "given" and ip == ip_b and last_a - 5 <= t <= first_b + 5]
                how.append(f"DHCP gave it {ip_b}" if given else f"a new address, {ip_b}")
            released = any(kind == "released" and ip == ip_a for _, kind, ip in ids[mac_a]["events"])
            changes.append({"at": first_b, "after": last_a, "from_ip": ip_a, "to_ip": ip_b, "from_mac": mac_a, "to_mac": mac_b,
                            "how": " and ".join(how) + ("; it gave the old address back first" if released else "")})
        together_v4 = _max_concurrent([(ip, f, last) for ip, f, last, _ in v4]) >= 2 and len({s[0] for s in v4}) >= 2
        two_links = [c for m in members for c in clues[m] if c.get("together")]
        if len(members) < 2 and not changes and not (together_v4 or (v4 and v6)):
            continue
        kind = "moved" if changes else "two-connections" if two_links else "several"
        cl = [c for m in members for c in clues[m]]
        if len(members) == 1 or (any(c["strength"] == "same" for c in cl) and not any(c["strength"] == "probably" for c in cl)):
            verdict = "Same device"
        else:
            verdict = "Probably the same device"
        why = []
        if len(members) == 1:
            why.append(f"one network card ({members[0]}) used every address")
        why += [c["text"] for c in cl]
        devices.append({
            "id": dev_id, "label": label, "verdict": verdict, "kind": kind, "names": sorted(names)[:8],
            "macs": [{"mac": e["mac"], "vendor": e["vendor"], "randomised": e["randomised"], "first": e["first"], "last": e["last"],
                      "addresses": sorted({s[0] for s in e["spans"]})[:12]} for e in es],
            "addresses": [{"ip": ip, "first": f, "last": last, "mac": mac} for ip, f, last, mac in v4][:24], "v6": v6[:12],
            "changes": changes[:24], "why": why, "first": min(e["first"] for e in es), "last": max(e["last"] for e in es),
            "filter": " || ".join(f"eth.addr == {m}" for m in members[:12]),
        })
    devices.sort(key=lambda d: ({"moved": 0, "two-connections": 1, "several": 2}[d["kind"]], d["first"]))

    # Addresses that changed hands: one local IPv4 address, different devices, one after another.
    handovers = []
    for ip, macs in users.items():
        if ":" in ip:
            continue
        holders = {}
        for mac in macs:
            span = next(s for s in ids[mac]["spans"] if s[0] == ip)
            h = holders.setdefault(owner.get(mac, mac), {"device": owner.get(mac, mac), "macs": [], "first": span[1], "last": span[2]})
            h["macs"].append(mac)
            h["first"], h["last"] = min(h["first"], span[1]), max(h["last"], span[2])
        if len(holders) < 2:
            continue
        hs = sorted(holders.values(), key=lambda h: h["first"])
        for h in hs:
            e = ids[h["macs"][0]]
            h["label"] = _label(e["names"], e)
        at_once = any(b["first"] < a["last"] for a, b in zip(hs, hs[1:], strict=False))
        handovers.append({"ip": ip, "holders": hs, "at_once": at_once, "filter": f"ip.addr == {ip}",
                          "why": ("two devices used it at the same time: an address conflict, or one answering for the other "
                                  "(see ARP spoofing)" if at_once else
                                  f"{len(hs)} different devices used it one after another, so what happened on it belongs to "
                                  "different machines depending on when"), "changed_at": hs[1]["first"]})
    handovers.sort(key=lambda h: h["holders"][0]["first"])

    moved = [d for d in devices if d["kind"] == "moved"]
    return {
        "devices": devices, "handovers": handovers, "conflicts": conflicts[:20], "routers": routers[:20],
        "totals": {"devices": len(groups), "moved": len(moved), "new_mac": sum(1 for d in moved if len(d["macs"]) > 1),
                   "new_ip": sum(1 for d in moved if any(c["from_ip"] != c["to_ip"] for c in d["changes"])),
                   "two_connections": sum(1 for d in devices if d["kind"] == "two-connections"),
                   "handovers": len(handovers), "randomised": sum(1 for e in ids.values() if e["randomised"])},
        "notes": [
            "Only what devices say about themselves on this network is used: their network card's address (MAC), the host "
            "name they give DHCP, mDNS or Windows naming, and the shape of their DHCP request. Nothing is sent to them.",
            "Phones and laptops use a private (randomised) Wi-Fi address that can change. When they keep their host name, "
            "they're recognised; a device that changes its name too, or gives none, isn't followed or guessed at.",
            "Names many devices use, like “iPhone”, link two MACs only when the DHCP requests match and one began within "
            f"{int(HANDOVER // 60)} minutes of the other stopping, with no other candidate.",
            "MACs are only seen on the device's own network segment; behind a router every device shows the router's MAC, "
            "so a capture from the internet side can't follow devices this way.",
            "Two names that are the same but come with DHCP requests from different systems are kept apart and listed.",
        ],
    }


def _label(names: dict, e: dict) -> str:
    specific = [n for n in names if not GENERIC.match(name_key(n))]
    pick = sorted(specific or names, key=lambda n: (0 if "DHCP" in names[n] else 1, -len(n)))
    if pick:
        return pick[0]
    return f"{e['vendor'] or ('private address' if e['randomised'] else 'device')} {e['mac']}"


def _gap(s: float) -> str:
    s = max(0.0, s)
    if s < 90:
        return f"{round(s)} s"
    if s < 5400:
        return f"{round(s / 60)} min"
    return f"{s / 3600:.1f} h"

