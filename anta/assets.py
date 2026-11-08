"""Passive asset inventory: every device the capture shows, what it probably is and
runs, built only from listening.

Each host's operating system is inferred from independent fingerprints, each with
its weight: Windows browser announcements, the DHCP client's vendor class and
parameter request list (option 55), the shape of its TCP SYN (initial TTL, window,
MSS, window scale and option order, as p0f reads them), HTTP User-Agents and,
weakest, the IP TTL alone. IoT devices are recognised by their maker (MAC vendor),
the services they announce over mDNS, their host names, an embedded DHCP client
and IoT protocols (MQTT, CoAP). The inventory says which evidence each label rests on.
"""
from __future__ import annotations

import re
from collections import defaultdict

from . import netmap

# (pattern in the vendor display name, device kind)
IOT_VENDORS = {"Espressif": "smart device (ESP32/ESP8266 module)", "Sonos": "Sonos speaker", "Ring": "Ring camera/doorbell",
               "Roku": "Roku streaming device", "Google Nest": "Google Nest device", "Hikvision": "Hikvision camera",
               "Belkin": "Belkin/Wemo device", "Silicon Labs": "IoT radio module", "Texas Instruments": "embedded device",
               "Raspberry Pi": "Raspberry Pi", "Amazon": "Amazon device (Echo, Fire TV, Kindle, Ring)"}
IOT_MDNS = {"_googlecast._tcp": "Chromecast / Google cast device", "_hue._tcp": "Philips Hue bridge",
            "_hap._tcp": "HomeKit accessory", "_hap._udp": "HomeKit accessory", "_matter._tcp": "Matter device",
            "_matterc._udp": "Matter device", "_sonos._tcp": "Sonos speaker", "_spotify-connect._tcp": "smart speaker",
            "_amzn-wplay._tcp": "Amazon Fire TV / Echo", "_esphomelib._tcp": "ESPHome device",
            "_arduino._tcp": "Arduino", "_shelly._tcp": "Shelly smart switch", "_miio._udp": "Xiaomi smart device",
            "_ewelink._tcp": "Sonoff/eWeLink device", "_airplay._tcp": "AirPlay receiver (Apple TV, speaker, TV)",
            "_raop._tcp": "AirPlay audio receiver", "_ipp._tcp": "printer", "_printer._tcp": "printer",
            "_pdl-datastream._tcp": "printer", "_ipps._tcp": "printer", "_scanner._tcp": "scanner",
            "_smb._tcp": "file sharing", "_rfb._tcp": "screen sharing (VNC)", "_ssh._tcp": "SSH server"}
IOT_HOSTNAMES = [(re.compile(p, re.I), what) for p, what in [
    (r"^esp[_-]?[0-9a-f]{4,}", "ESP8266/ESP32 module"), (r"chromecast", "Chromecast"), (r"google-?home", "Google Home"),
    (r"^(amazon|echo|fire-?tv)", "Amazon device"), (r"^ring-", "Ring camera/doorbell"), (r"^(hs1|kp1|ep10|kl1)\d", "TP-Link Kasa plug/bulb"),
    (r"wemo", "Wemo plug"), (r"^(philips-)?hue", "Philips Hue"), (r"sonos", "Sonos speaker"), (r"roku", "Roku"),
    (r"lgwebostv|webos", "LG smart TV"), (r"samsung.*tv|^\[tv\]", "Samsung smart TV"), (r"shelly", "Shelly switch"),
    (r"tasmota", "Tasmota smart plug"), (r"^(nest|thermostat)", "thermostat"), (r"^(ipcam|camera|cam-)", "IP camera"),
    (r"printer|^(hp|brw|epson|canon)[0-9a-f]{6,}", "printer"), (r"^wyze", "Wyze camera"), (r"^roomba|^irobot", "robot vacuum")]]
PRINTER_PORTS = {9100: "raw printing (JetDirect)", 631: "IPP printing", 515: "LPD printing"}
IOT_APPS = {"mqtt": "MQTT (IoT messaging)"}
IOT_UDP_PORTS = {5683: "CoAP (constrained IoT protocol)", 6666: "Tuya smart-home protocol", 6667: "Tuya smart-home protocol"}


def _initial_ttl(ttl: int) -> int:
    for start in (32, 64, 128, 255):
        if ttl <= start:
            return start
    return 255


def os_fingerprint(h: dict, trusted_mac: bool, local: bool = True) -> tuple[str | None, str | None, list[str]]:
    """(family, detail, evidence) from every fingerprint the host shows."""
    votes: dict[str, float] = defaultdict(float)
    detail: dict[str, str] = {}
    evidence: list[str] = []

    def vote(family, weight, why, specific=None):
        votes[family] += weight
        if specific and family not in detail:
            detail[family] = specific
        evidence.append(why)

    winver = h.get("windows_version")
    if winver:
        name = netmap.WINDOWS_VERSIONS.get(winver, f"Windows {winver}")
        vote("Windows", 0.9, f"Windows browser announcements say {name}", name)
    if trusted_mac:
        for v in h.get("dhcp_vendor") or []:
            low = v.lower()
            m = re.match(r"android-dhcp-(\d+)", low)
            if low.startswith("msft"):
                vote("Windows", 0.8, f"its DHCP client calls itself “{v}” (Windows)")
            elif m:
                vote("Android", 0.85, f"its DHCP client calls itself “{v}”", f"Android {m.group(1)}")
            elif low.startswith("udhcp"):
                vote("Linux", 0.6, f"its DHCP client is BusyBox udhcp (“{v}”): embedded Linux", "embedded Linux (BusyBox)")
            elif low.startswith("dhcpcd"):
                vote("Linux", 0.5, f"its DHCP client is dhcpcd (“{v}”)")
            elif "cisco" in low:
                vote("Cisco IOS", 0.7, f"DHCP vendor class “{v}”")
        prl = [int(x) for x in str(h.get("dhcp_prl") or "").split(",") if x.isdigit()]
        if prl:
            sp = set(prl)
            if {43, 249, 252}.issubset(sp) and 44 in sp:
                vote("Windows", 0.6, f"its DHCP parameter request list ({h['dhcp_prl']}) is Windows'")
            elif prl[:2] == [1, 121] and {108, 114}.issubset(sp):
                vote("Apple", 0.6, f"its DHCP parameter request list ({h['dhcp_prl']}) is an Apple device's",
                     "macOS / iOS")
            elif {26, 28, 51, 58, 59}.issubset(sp) and 43 not in sp:
                vote("Android", 0.4, f"its DHCP parameter request list ({h['dhcp_prl']}) looks like Android's")
    syn = h.get("syn")
    if syn:
        start = _initial_ttl(int(syn.get("ttl") or 0))
        opts = str(syn.get("opts") or "")
        shape = (f"TTL {syn.get('ttl')} (from {start}), window {syn.get('win')}, MSS {syn.get('mss', '-')}, "
                 f"options {opts or 'none'}")
        if start == 128 and opts.startswith("2,1,3,1,1,4"):
            vote("Windows", 0.6, f"its TCP SYN is Windows' ({shape})")
        elif start == 64 and opts.startswith("2,4,8,1,3"):
            vote("Linux", 0.5, f"its TCP SYN is Linux's or Android's ({shape})")
        elif start == 64 and opts.startswith("2,1,3,1,1,8,4"):
            vote("Apple", 0.55, f"its TCP SYN is macOS/iOS's ({shape})", "macOS / iOS")
        elif start == 255:
            vote("Network OS", 0.4, f"its TCP SYN starts at TTL 255 ({shape}): a router or switch")
        elif not opts and syn.get("win") in (1024, 2048, 3072, 4096):
            evidence.append(f"its TCP SYN has no options and a {syn.get('win')} window ({shape}): a port scanner")
    for ua in (h.get("user_agents") or [])[:4]:
        for needle, family, specific in (("Windows NT 10.0", "Windows", "Windows 10/11"), ("Windows NT", "Windows", None),
                                         ("iPhone", "Apple", "iOS"), ("iPad", "Apple", "iPadOS"),
                                         ("Mac OS X", "Apple", "macOS"), ("Android", "Android", None),
                                         ("CrOS", "ChromeOS", None), ("Linux", "Linux", None)):
            if needle in ua:
                vote(family, 0.5, f"its HTTP User-Agent says {specific or family}", specific)
                break
    ttl = int(h.get("ttl") or 0)
    if not votes and ttl and local:  # a far host's TTL has been counted down by every router on the way
        start = _initial_ttl(ttl)
        guess = {64: "Linux", 128: "Windows", 255: "Network OS"}.get(start)
        if guess:
            vote(guess, 0.2, f"its IP TTL {ttl} starts at {start}")
    if not votes:
        return None, None, evidence
    family = max(votes, key=votes.get)
    confidence = votes[family] / (sum(votes.values()) or 1)
    label = detail.get(family, family)
    if confidence < 0.6 and len(votes) > 1:
        label += " (conflicting evidence)"
    return family, label, evidence


def iot_evidence(h: dict, node: dict, apps: dict, trusted_mac: bool) -> list[str]:
    reasons = []
    vendor = node.get("vendor") or ""
    if trusted_mac and vendor in IOT_VENDORS:
        reasons.append(f"made by {vendor}: {IOT_VENDORS[vendor]}")
    for sv in h.get("mdns_services") or []:
        if sv in IOT_MDNS and IOT_MDNS[sv] not in ("file sharing", "screen sharing (VNC)", "SSH server"):
            reasons.append(f"announces {sv} over mDNS: {IOT_MDNS[sv]}")
    for name, _src in (node.get("names") or [])[:8]:
        for rx, what in IOT_HOSTNAMES:
            if rx.search(name):
                reasons.append(f"its host name “{name}” is a {what}'s")
                break
    if trusted_mac and any(str(v).lower().startswith("udhcp") for v in h.get("dhcp_vendor") or []) \
            and node.get("kind") not in ("router", "infra"):
        reasons.append("its DHCP client is BusyBox udhcp, as on embedded firmware")
    for app, label in IOT_APPS.items():
        if app in (apps.get("uses") or {}):
            reasons.append(f"speaks {label}")
    for port, label in IOT_UDP_PORTS.items():
        if str(port) in (h.get("udp_uses") or {}) or str(port) in (h.get("udp_serves") or {}):
            reasons.append(f"uses {label}")
    return list(dict.fromkeys(reasons))


def apps_by_host(sessions: list[dict]) -> dict[str, dict]:
    """ip -> {"uses": {app: sessions}, "serves": {app: sessions}}, from a capture's session index."""
    out: dict[str, dict] = {}
    for rec in sessions:
        app = rec.get("app")
        if not app:
            continue
        for ip, side in ((rec["src_ip"], "uses"), (rec["dst_ip"], "serves")):
            entry = out.setdefault(ip, {"uses": {}, "serves": {}})
            if len(entry[side]) < 32 or app in entry[side]:
                entry[side][app] = entry[side].get(app, 0) + 1
    return out


def build(stats: dict, graph: dict, host_apps: dict | None = None, geo=None, alerts: list | None = None) -> list[dict]:
    hosts = {h["addr"]: h for h in stats.get("hosts") or []}
    macs = {m["mac"]: m for m in stats.get("macs") or []}
    host_apps = host_apps or {}
    alert_count: dict[str, int] = defaultdict(int)
    for a in alerts or []:
        for ip in {a.get("src_ip"), a.get("dst_ip"), a.get("offender")} - {None}:
            alert_count[ip] += 1
    rows = []
    for node in graph.get("nodes") or []:
        ip = node["addr"]
        if node.get("kind") in ("broadcast", "multicast", "unspecified"):
            continue
        if ip.endswith(".255") and not node.get("tx_packets"):
            continue  # a subnet's broadcast address: nothing ever sends from it
        h = hosts.get(ip, {})
        own_macs = node.get("macs") or []
        # The MAC-bound fingerprints (DHCP) are only this host's when every MAC it appeared with is its
        # own: a MAC many addresses use is a router's, and the router's DHCP client isn't this host.
        seen_macs = h.get("macs") or own_macs
        trusted = bool(seen_macs) and len(seen_macs) <= 2 and \
            all((macs.get(m, {}).get("src_ip_count") or 1) <= 2 for m in seen_macs)
        apps = host_apps.get(ip, {})
        family, os_label, os_evidence = os_fingerprint(h, trusted, node.get("scope") != "public")
        iot = iot_evidence(h, node, apps, trusted)
        services = node.get("services") or []
        printer = [PRINTER_PORTS[s["port"]] for s in services if s.get("proto") == "tcp" and s.get("port") in PRINTER_PORTS] or \
            [s for s in h.get("mdns_services") or [] if IOT_MDNS.get(s) == "printer"]
        kind = node.get("kind")
        if node.get("scope") == "public":
            device = "Internet host"
        elif kind == "router":
            device = "Router / gateway"
        elif kind == "infra":
            device = node.get("role") or "Infrastructure server"
        elif printer:
            device = "Printer"
        elif iot:
            device = "IoT / smart device"
        elif family in ("Android",) or (os_label or "").startswith(("iOS", "iPadOS")):
            device = "Phone / tablet"
        elif kind == "server":
            device = node.get("role") or "Server"
        elif family in ("Windows", "Apple", "Linux", "ChromeOS"):
            device = "Computer"
        else:
            device = node.get("role") or "Device"
        g = geo.lookup(ip) if geo is not None and node.get("scope") == "public" else None
        rows.append({
            "ip": ip, "name": node.get("name"), "names": [n for n, _ in node.get("names") or []][:6],
            "macs": own_macs, "vendor": node.get("vendor"), "scope": node.get("scope"), "device": device,
            "role": node.get("role"), "iot": bool(iot), "iot_evidence": iot, "os": os_label, "os_family": family,
            "os_evidence": os_evidence[:6], "services": [f"{s['name']} ({s['proto'].upper()} {s['port']})" for s in services][:12],
            "apps_used": sorted((apps.get("uses") or {}), key=lambda a: -apps["uses"][a])[:10],
            "apps_served": sorted((apps.get("serves") or {}), key=lambda a: -apps["serves"][a])[:10],
            "users": node.get("users") or [], "domains": node.get("domains") or [],
            "mdns_services": h.get("mdns_services") or [], "dhcp_prl": h.get("dhcp_prl") if trusted else None,
            "dhcp_vendor": (h.get("dhcp_vendor") or []) if trusted else [], "syn": h.get("syn"),
            "user_agents": (h.get("user_agents") or [])[:3], "first": node.get("first"), "last": node.get("last"),
            "tx_bytes": node.get("tx_bytes", 0), "rx_bytes": node.get("rx_bytes", 0), "peers": node.get("peers", 0),
            "country": (g or {}).get("country"), "country_name": (g or {}).get("country_name"),
            "asn": (g or {}).get("asn"), "as_name": (g or {}).get("as_name"), "alerts": alert_count.get(ip, 0),
            "device_info": (node.get("device") or {}).get("kind"),
        })
    rows.sort(key=lambda r: (r["scope"] == "public", -(r["tx_bytes"] + r["rx_bytes"])))
    return rows


def geo_summary(stats: dict, geo) -> dict:
    """Traffic per country and per AS, from the capture's endpoints (public addresses only)."""
    countries: dict[str, dict] = {}
    ases: dict[int, dict] = {}
    if geo is None:
        return {"countries": [], "ases": [], "available": False}
    for h in stats.get("hosts") or []:
        ip = h["addr"]
        if netmap.scope_of(ip) != "public":
            continue
        g = geo.lookup(ip)
        if not g:
            continue
        b = int(h.get("tx_bytes", 0)) + int(h.get("rx_bytes", 0))
        p = int(h.get("tx_packets", 0)) + int(h.get("rx_packets", 0))
        c = countries.setdefault(g["country"] or "?", {"country": g["country"], "name": g["country_name"],
                                                       "hosts": 0, "bytes": 0, "packets": 0, "ases": set()})
        c["hosts"] += 1
        c["bytes"] += b
        c["packets"] += p
        c["ases"].add(g["asn"])
        a = ases.setdefault(g["asn"], {"asn": g["asn"], "name": g["as_name"], "country": g["country"],
                                       "hosts": 0, "bytes": 0, "packets": 0, "addresses": []})
        a["hosts"] += 1
        a["bytes"] += b
        a["packets"] += p
        if len(a["addresses"]) < 8:
            a["addresses"].append(ip)
    out_c = sorted(({**c, "ases": len(c["ases"])} for c in countries.values()), key=lambda c: -c["bytes"])
    return {"countries": out_c, "ases": sorted(ases.values(), key=lambda a: -a["bytes"]), "available": True}
