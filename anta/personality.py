"""Device personalities and drift: each device on the network summed up in one plain sentence
(what kind of device, what it mostly does, which way its data flows, whom it talks to, what it
offers), and, once you have told ANTA what is normal ("Remember these as normal"), what each
device does differently in a later capture: a kind of traffic it never had, a service it
started offering, local hosts it never talked to, much more data leaving.

Devices are recognised across captures by their MAC address when the capture shows one that
belongs to them alone, otherwise by their address. The remembered profiles are kept in the
data folder (owner-only JSON). Everything is read from the capture on this computer.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
from collections import defaultdict

from . import netmap, paths
from .explain import fmt_bytes

# What each kind of application says about a device, as a verb phrase.
DOES = {"Video calls": "joins video calls", "Messaging": "chats", "Video streaming": "streams video", "Music": "streams music",
        "Software updates": "downloads updates", "Developer tools": "uses developer sites", "Email and office": "uses email and office apps",
        "Cloud storage": "syncs files to the cloud", "File sharing": "shares files", "Remote access": "uses remote access",
        "Printing": "prints", "Databases": "talks to databases", "VPN": "uses a VPN", "IoT": "reports to an IoT service",
        "Games": "plays online games", "Social media": "uses social media", "Cloud hosting": "talks to cloud services",
        "Work apps": "uses work apps"}
WEB = {"Search", "News", "Reference", "Shopping", "Other web"}
QUIET = {"Network services", "Operating system", "Other"}
# Kinds of traffic whose first appearance on a device is worth a look.
NOTABLE_NEW = {"Remote access", "File sharing", "VPN", "Databases", "Cloud storage", "Games"}
MIN_UPLOAD_GROWTH = 5_000_000


def _key(ip: str, asset: dict | None) -> str:
    macs = (asset or {}).get("macs") or []
    return f"mac:{macs[0].lower()}" if len(macs) == 1 else f"ip:{ip}"


def profiles(sessions: list[dict], usage: dict, assets: list[dict]) -> dict[str, dict]:
    """Each local device's profile, keyed by its identity (MAC, else address)."""
    by_ip = {r["ip"]: r for r in assets}
    stat: dict[str, dict] = defaultdict(lambda: {"up": 0, "down": 0, "peers": set(), "internet": set(), "local": set(),
                                                 "served": defaultdict(int), "clients": set(), "first": None, "last": 0.0})
    for s in sessions:
        if s.get("proto") not in ("tcp", "udp"):
            continue
        src, dst = s["src_ip"], s["dst_ip"]
        up = int((s.get("c2s") or {}).get("payload_bytes") or 0)
        down = int((s.get("s2c") or {}).get("payload_bytes") or 0)
        if netmap.scope_of(src) in ("private", "link-local", "cgnat"):
            a = stat[src]
            a["up"] += up
            a["down"] += down
            kind = netmap.scope_of(dst)
            if kind not in ("broadcast", "multicast"):
                a["peers"].add(dst)
                (a["internet"] if kind == "public" else a["local"]).add(dst)
            a["first"] = s.get("start") if a["first"] is None else min(a["first"], s.get("start") or a["first"])
            a["last"] = max(a["last"], s.get("end") or 0)
        if netmap.scope_of(dst) in ("private", "link-local", "cgnat") and (s.get("tcp") or {}).get("handshake", s.get("proto") == "udp"):
            b = stat[dst]
            b["served"][f"{s['proto']}/{s['dst_port']}"] += 1
            b["clients"].add(src)
            b["up"] += down
            b["down"] += up
    out = {}
    for ip, a in stat.items():
        asset = by_ip.get(ip)
        if asset and asset.get("device") in ("Router / gateway",) and not a["peers"]:
            continue
        apps = {x["app"]: x["up"] + x["down"] for x in usage.get("devices", {}).get(ip, [])}
        cats: dict[str, int] = defaultdict(int)
        for x in usage.get("devices", {}).get(ip, []):
            cats[x["category"]] += x["up"] + x["down"]
        served = {p: n for p, n in a["served"].items() if n >= 2 or p.startswith("tcp/")}
        out[_key(ip, asset)] = {
            "ip": ip, "name": (asset or {}).get("name") or "", "device": (asset or {}).get("device") or "Device",
            "os": (asset or {}).get("os") or "", "up": a["up"], "down": a["down"],
            "peers": len(a["peers"]), "internet": len(a["internet"]), "local_peers": sorted(a["local"])[:200],
            "served": sorted(served, key=lambda p: -served[p])[:20], "clients": len(a["clients"]),
            "apps": dict(sorted(apps.items(), key=lambda kv: -kv[1])[:20]),
            "app_kind": {x["app"]: x["category"] for x in usage.get("devices", {}).get(ip, [])[:20]},
            "categories": dict(sorted(cats.items(), key=lambda kv: -kv[1])),
            "first": a["first"], "last": a["last"],
        }
    return out


def sentence(p: dict) -> str:
    """The device in one sentence."""
    kind = p["device"] if p["device"] not in ("Device",) else "A device"
    if not kind.lower().startswith(("a ", "an ")):
        kind = f"{'An' if kind[0].lower() in 'aeiou' else 'A'} {kind[0].lower()}{kind[1:]}" if kind != "IoT / smart device" \
            else "A smart (IoT) device"
    if p["os"]:
        kind += f" ({p['os']})"
    doing = []
    for cat in p["categories"]:
        if cat in WEB:
            if "browses the web" not in doing:
                doing.append("browses the web")
        elif cat in DOES and DOES[cat] not in doing:
            doing.append(DOES[cat])
        if len(doing) == 3:
            break
    parts = [f"{kind} that {_join(doing)}" if doing else f"{kind} with little traffic of its own"]
    up, down = p["up"], p["down"]
    if up + down:
        if down > 4 * up:
            parts.append("it mostly downloads")
        elif up > 4 * down:
            parts.append("it mostly sends data out")
        else:
            parts.append("it sends and receives about equally")
    if p["peers"]:
        parts.append(f"it talks to {p['peers']} host{'s' if p['peers'] != 1 else ''}"
                     + (f", {p['internet']} on the internet" if p["internet"] else ", all on the local network"))
    if p["served"]:
        parts.append(f"it answers on {_join([_port(x) for x in p['served'][:3]])} for {p['clients']} client"
                     f"{'s' if p['clients'] != 1 else ''}")
    return "; ".join(parts) + "."


def _port(spec: str) -> str:
    proto, port = spec.split("/")
    name = (netmap.TCP_SERVICES if proto == "tcp" else netmap.UDP_SERVICES).get(int(port))
    return f"{name} ({proto.upper()} {port})" if name else f"{proto.upper()} {port}"


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1] if items else ""


def _addr(ip: str) -> str:
    return f"{'ipv6' if ':' in ip else 'ip'}.addr == {ip}"


def drift(old: dict | None, new: dict, app_filters: dict[str, str]) -> list[dict]:
    """What a device does differently from its remembered profile: [{what, notable, filter}]."""
    ip = new["ip"]
    if old is None:
        return [{"what": "A device that wasn't on the network when you last remembered it.", "notable": True, "filter": _addr(ip)}]
    out = []
    for cat in new["categories"]:
        if cat not in old.get("categories", {}) and cat not in QUIET:
            apps = [a for a in new["apps"] if (new.get("app_kind") or {}).get(a) == cat]
            flt = " || ".join(f"({app_filters[a]})" for a in apps[:3] if app_filters.get(a))
            out.append({"what": f"New kind of traffic: {cat.lower()}" + (f" ({', '.join(apps[:3])})" if apps else "") + ".",
                        "notable": cat in NOTABLE_NEW, "filter": f"{_addr(ip)} && ({flt})" if flt else _addr(ip)})
    for spec in new["served"]:
        if spec not in old.get("served", []):
            proto, port = spec.split("/")
            out.append({"what": f"Started answering on {_port(spec)}.", "notable": True,
                        "filter": f"{_addr(ip)} && {proto}.dstport == {port}"})
    fresh = [h for h in new["local_peers"] if h not in set(old.get("local_peers", []))]
    if len(fresh) >= 3:
        out.append({"what": f"Talks to {len(fresh)} local hosts it never talked to before ({', '.join(fresh[:3])}"
                            f"{'…' if len(fresh) > 3 else ''}).", "notable": len(fresh) >= 5,
                    "filter": f"{_addr(ip)} && ({' || '.join(_addr(h) for h in fresh[:20])})"})
    if new["up"] > max(5 * old.get("up", 0), MIN_UPLOAD_GROWTH):
        out.append({"what": f"Sends much more data: {fmt_bytes(new['up'])}, against {fmt_bytes(old.get('up', 0))} before.",
                    "notable": True, "filter": f"{'ipv6' if ':' in ip else 'ip'}.src == {ip}"})
    if old.get("internet") and new["internet"] > max(3 * old["internet"], old["internet"] + 20):
        out.append({"what": f"Reaches many more internet hosts: {new['internet']}, against {old['internet']} before.",
                    "notable": False, "filter": _addr(ip)})
    gone = [c for c in old.get("categories", {}) if c not in new["categories"] and c not in QUIET]
    if gone:
        out.append({"what": f"No longer seen: {', '.join(c.lower() for c in gone[:3])}.", "notable": False, "filter": ""})
    return out


def report(current: dict[str, dict], remembered: dict | None, app_filters: dict[str, str]) -> dict:
    devices = []
    known = (remembered or {}).get("devices") or {}
    for key, p in sorted(current.items(), key=lambda kv: -(kv[1]["up"] + kv[1]["down"])):
        changes = drift(known.get(key), p, app_filters) if remembered else []
        devices.append({"key": key, "ip": p["ip"], "name": p["name"], "device": p["device"], "os": p["os"],
                        "sentence": sentence(p), "up": p["up"], "down": p["down"], "peers": p["peers"],
                        "apps": list(p["apps"])[:6], "served": [_port(x) for x in p["served"][:5]],
                        "changes": changes, "notable": sum(1 for c in changes if c["notable"])})
    missing = [{"key": k, "ip": v.get("ip"), "name": v.get("name") or "", "device": v.get("device") or ""}
               for k, v in known.items() if k not in current] if remembered else []
    return {"devices": devices, "missing": missing[:200],
            "remembered": {"saved": remembered.get("saved"), "capture": remembered.get("capture"), "devices": len(known)}
            if remembered else None}


# ---------------------------------------------------------------- what is normal

def path() -> str:
    return os.path.join(paths.app_data_dir(), "devices-normal.json")


def load() -> dict | None:
    try:
        with open(path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) and isinstance(data.get("devices"), dict) else None
    except (OSError, ValueError):
        return None


def remember(current: dict[str, dict], capture: str, merge: bool = True) -> dict:
    """Keep these profiles as the normal to compare later captures with (added to what was
    remembered before, a device's newer profile replacing its older one)."""
    old = (load() or {}).get("devices", {}) if merge else {}
    data = {"saved": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "capture": capture[:255],
            "devices": {**old, **current}}
    directory = os.path.dirname(path())
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".devices-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return data


def forget() -> None:
    try:
        os.unlink(path())
    except FileNotFoundError:
        pass
