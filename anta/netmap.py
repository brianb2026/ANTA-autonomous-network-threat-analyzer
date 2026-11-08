"""Network map: who talks to whom, and what each address probably is.

Built from the engine's `--stats` evidence: traffic per host, the services it
answered on, names learned from DNS / TLS SNI / HTTP Host / DHCP / NetBIOS,
the MAC addresses and vendors behind it, and DHCP announcements. Every role
comes with the reasons for it, so the map never claims more than the capture
shows.
"""
from __future__ import annotations

import ipaddress
import re

# Ports whose listener tells us what a server is for.
TCP_SERVICES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "RPC", 135: "MS RPC", 139: "NetBIOS", 143: "IMAP", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "Mail submission", 636: "LDAPS", 853: "DNS over TLS", 993: "IMAPS",
    995: "POP3S", 1433: "MS SQL", 1521: "Oracle", 1883: "MQTT", 2049: "NFS", 3128: "HTTP proxy", 3306: "MySQL",
    3389: "Remote Desktop", 5060: "SIP", 5222: "XMPP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
    6379: "Redis", 6443: "Kubernetes API", 8000: "HTTP (alt)", 8080: "HTTP (alt)", 8443: "HTTPS (alt)",
    8883: "MQTT over TLS", 9000: "HTTP (alt)", 9200: "Elasticsearch", 27017: "MongoDB",
}
UDP_SERVICES = {
    53: "DNS", 67: "DHCP", 69: "TFTP", 123: "NTP", 137: "NetBIOS name", 138: "NetBIOS datagram", 161: "SNMP",
    162: "SNMP trap", 443: "QUIC", 500: "IKE (VPN)", 514: "Syslog", 1194: "OpenVPN", 1812: "RADIUS",
    1900: "SSDP / UPnP", 3478: "STUN", 4500: "IPsec NAT-T", 5060: "SIP", 5353: "mDNS", 5355: "LLMNR",
    51820: "WireGuard",
}
SERVER_KINDS = [  # (ports, role) in priority order
    ({53, 853}, "DNS server"),
    ({80, 443, 8000, 8080, 8443, 9000, 3128}, "Web server"),
    ({25, 465, 587, 110, 995, 143, 993}, "Mail server"),
    ({22}, "SSH server"),
    ({21, 20}, "FTP server"),
    ({445, 139, 2049}, "File server"),
    ({1433, 1521, 3306, 5432, 6379, 9200, 27017}, "Database server"),
    ({3389, 5900, 5985}, "Remote access server"),
    ({389, 636}, "Directory server"),
    ({23}, "Telnet server"),
    ({1883, 8883}, "MQTT broker"),
]
MULTICAST_NAMES = {
    "224.0.0.1": "All hosts", "224.0.0.2": "All routers", "224.0.0.5": "OSPF routers", "224.0.0.9": "RIP routers",
    "224.0.0.18": "VRRP", "224.0.0.22": "IGMPv3 reports", "224.0.0.251": "mDNS", "224.0.0.252": "LLMNR",
    "239.255.255.250": "SSDP / UPnP", "255.255.255.255": "Broadcast", "ff02::1": "All nodes", "ff02::2": "All routers",
    "ff02::16": "MLDv2 reports", "ff02::fb": "mDNS", "ff02::1:2": "DHCPv6 servers", "ff02::1:3": "LLMNR",
    "ff02::c": "SSDP / UPnP",
}
# Peer-to-peer discovery: answering these doesn't make a host a server.
DISCOVERY_UDP = {137: "NetBIOS", 138: "NetBIOS", 5353: "mDNS", 5355: "LLMNR", 1900: "SSDP / UPnP"}
# Documentation and benchmarking ranges stand in for internet hosts in examples and labs.
STAND_IN_PUBLIC = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                                     "198.18.0.0/15", "2001:db8::/32")]
# Hardware vendors the engine names (Wireshark's short name -> how the map shows it).
# The engine's table of their IEEE OUIs is generated from this list by
# anta/tools/gen_oui.py.
VENDOR_DISPLAY = {
    "Apple": "Apple", "Intel": "Intel", "IntelWireles": "Intel", "Dell": "Dell", "DellEMC": "Dell",
    "HewlettPacka": "HP", "HP": "HP", "Lenovo": "Lenovo", "LenovoMobile": "Lenovo", "ASUSTekCOMPU": "ASUS",
    "Microsoft": "Microsoft", "Google": "Google", "NestLabs": "Google Nest", "AmazonTechno": "Amazon",
    "SamsungElect": "Samsung", "LGElectronic": "LG", "LGInnotek": "LG Innotek", "Sony": "Sony",
    "SonyInteract": "Sony", "HuaweiTechno": "Huawei", "HuaweiDevice": "Huawei", "XiaomiCommun": "Xiaomi",
    "XiaomiMobile": "Xiaomi", "OppoMobileTe": "OPPO", "vivoMobileCo": "vivo", "OnePlusTechn": "OnePlus",
    "MotorolaMobi": "Motorola", "Nintendo": "Nintendo", "Roku": "Roku", "Sonos": "Sonos", "Ring": "Ring",
    "Cisco": "Cisco", "CiscoMeraki": "Cisco Meraki", "CiscoLinksys": "Linksys", "LinksysGroup": "Linksys",
    "JuniperNetwo": "Juniper", "AristaNetwor": "Arista", "ExtremeNetwo": "Extreme Networks",
    "RuckusWirele": "Ruckus", "Ubiquiti": "Ubiquiti", "Routerboardc": "MikroTik", "Fortinet": "Fortinet",
    "PaloAltoNetw": "Palo Alto Networks", "TpLinkTechno": "TP-Link", "TPLink": "TP-Link", "Netgear": "Netgear",
    "DLinkInterna": "D-Link", "DLink": "D-Link", "ZyxelCommuni": "Zyxel", "BelkinIntern": "Belkin",
    "Synology": "Synology", "QNAP": "QNAP", "SuperMicroCo": "Supermicro", "HikvisionDig": "Hikvision",
    "Canon": "Canon", "SeikoEpson": "Epson", "BrotherIndus": "Brother", "Xerox": "Xerox",
    "RaspberryPiT": "Raspberry Pi", "RaspberryPi": "Raspberry Pi", "Espressif": "Espressif",
    "TexasInstrum": "Texas Instruments", "SiliconLabor": "Silicon Labs", "HonHaiPrecis": "Foxconn",
    "AzureWaveTec": "AzureWave", "MurataManufa": "Murata", "LiteonTechno": "Lite-On", "RealtekSemic": "Realtek",
    "Broadcom": "Broadcom", "Qualcomm": "Qualcomm", "MediaTek": "MediaTek", "NVIDIA": "NVIDIA",
    "VMware": "VMware", "Parallels": "Parallels", "Xensource": "Xen", "PCSSystemtec": "VirtualBox",
}
NETWORK_VENDORS = {"Cisco", "Cisco Meraki", "Linksys", "Juniper", "Arista", "Extreme Networks", "Ruckus", "Ubiquiti",
                   "MikroTik", "Fortinet", "Palo Alto Networks", "TP-Link", "Netgear", "D-Link", "Zyxel", "Huawei"}
# Virtual network adapters, by OUI (Microsoft's other OUIs are real hardware).
VM_OUIS = {"00:15:5d": "Hyper-V virtual machine", "00:05:69": "Virtual machine", "00:0c:29": "Virtual machine",
           "00:1c:14": "Virtual machine", "00:50:56": "Virtual machine", "00:1c:42": "Virtual machine",
           "00:16:3e": "Virtual machine", "08:00:27": "Virtual machine"}


def scope_of(addr: str) -> str:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "unknown"
    if addr == "255.255.255.255":
        return "broadcast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link-local"
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "cgnat"
    if any(ip in net for net in STAND_IN_PUBLIC if net.version == ip.version):
        return "public"
    if ip.is_private:
        return "private"
    return "public"


SCOPE_TEXT = {
    "private": "Private network address", "public": "Public internet address", "link-local": "Link-local address",
    "loopback": "Loopback", "multicast": "Multicast group", "broadcast": "Broadcast", "cgnat": "Carrier-grade NAT",
    "unspecified": "Unconfigured (0.0.0.0)", "unknown": "Address",
}


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.split("%")[0])
        return True
    except ValueError:
        return False


def _ports(d: dict) -> dict[int, int]:
    return {int(k): int(v) for k, v in (d or {}).items()}


WINDOWS_VERSIONS = {"10.0": "Windows 10 or 11 (or Server 2016 and later)", "6.3": "Windows 8.1 / Server 2012 R2",
                    "6.2": "Windows 8 / Server 2012", "6.1": "Windows 7 / Server 2008 R2",
                    "6.0": "Windows Vista / Server 2008", "5.2": "Windows XP x64 / Server 2003", "5.1": "Windows XP"}


def _os_hint(h: dict, local: bool) -> tuple[str | None, str | None]:
    """(guess, reason) from the Windows browser announcement, DHCP vendor class, User-Agent,
    or the IP TTL of a nearby host."""
    winver = h.get("windows_version")
    if winver:
        return WINDOWS_VERSIONS.get(winver, f"Windows {winver}"), f"its Windows browser announcements (version {winver})"
    for v in h.get("dhcp_vendor") or []:
        low = v.lower()
        if low.startswith("msft"):
            return "Windows", f"DHCP vendor class “{v}”"
        if low.startswith("android"):
            return "Android", f"DHCP vendor class “{v}”"
        if low.startswith("dhcpcd") or low.startswith("udhcp"):
            return "Linux", f"DHCP vendor class “{v}”"
    for ua in h.get("user_agents") or []:
        for needle, name in (("Windows NT", "Windows"), ("iPhone", "iOS"), ("iPad", "iPadOS"), ("Android", "Android"),
                             ("Mac OS X", "macOS"), ("CrOS", "ChromeOS"), ("Linux", "Linux")):
            if needle in ua:
                return name, "HTTP User-Agent"
    ttl = int(h.get("ttl") or 0)
    if local and ttl:
        if 32 < ttl <= 64:
            return "Linux, macOS, iOS or Android", f"IP TTL {ttl} (starts at 64)"
        if 64 < ttl <= 128:
            return "Windows", f"IP TTL {ttl} (starts at 128)"
        if ttl > 128:
            return "Network equipment", f"IP TTL {ttl} (starts at 255)"
    return None, None


def build(stats: dict, max_nodes: int = 400) -> dict:
    hosts = stats.get("hosts") or []
    macs = {m["mac"]: m for m in stats.get("macs") or []}

    # Gateways: a MAC that carries traffic for many different IP addresses is a
    # router; its own address is the one it announces in ARP.
    gateway_macs: dict[str, dict] = {}
    for m in macs.values():
        public = [ip for ip in m.get("src_ips") or [] if scope_of(ip) == "public"]
        if m.get("src_ip_count", 0) >= 3 or public:
            gateway_macs[m["mac"]] = m
    gateway_ips: dict[str, str] = {}
    for mac, m in gateway_macs.items():
        own = [ip for ip in m.get("arp_ips") or [] if scope_of(ip) in ("private", "link-local", "cgnat")]
        for ip in own:
            gateway_ips[ip] = (f"its MAC {mac} carries traffic for {m.get('src_ip_count')} addresses"
                               + (" including internet hosts" if any(scope_of(i) == "public"
                                                                     for i in m.get("src_ips") or []) else ""))

    def owns(mac: str, addr: str) -> bool:
        """Whether a MAC is the host's own interface. In a capture taken on a router,
        forwarded packets carry the router's MAC with someone else's IP address."""
        m = macs.get(mac)
        if not m:
            return False
        if m.get("arp_ips"):
            return addr in m["arp_ips"]
        return (m.get("src_ip_count", 0) <= 1 and mac not in gateway_macs
                and scope_of(addr) in ("private", "link-local", "cgnat"))

    # Windows domains seen anywhere: NetBIOS registers their group names, which name no host.
    all_domains = {d.upper() for h in hosts for d in h.get("domains") or []}
    short_domains = all_domains | {d.split(".")[0] for d in all_domains}

    nodes = []
    for h in hosts:
        addr = h["addr"]
        scope = scope_of(addr)
        tx, rx = int(h.get("tx_bytes", 0)), int(h.get("rx_bytes", 0))
        if tx + rx == 0 and scope != "private":
            continue  # only known from a name lookup
        tcp_serves, udp_serves = _ports(h.get("tcp_serves")), _ports(h.get("udp_serves"))
        tcp_uses, udp_uses = _ports(h.get("tcp_uses")), _ports(h.get("udp_uses"))
        roles = h.get("roles") or {}
        reasons: list[str] = []
        tags: list[str] = [SCOPE_TEXT.get(scope, scope)]
        services = []
        for p, n in sorted(tcp_serves.items(), key=lambda kv: -kv[1]):
            if p in TCP_SERVICES or p < 1024:
                services.append({"proto": "tcp", "port": p, "name": TCP_SERVICES.get(p, f"TCP {p}"), "count": n})
        for p, n in sorted(udp_serves.items(), key=lambda kv: -kv[1]):
            if p in DISCOVERY_UDP:
                if DISCOVERY_UDP[p] not in tags:
                    tags.append(DISCOVERY_UDP[p])
            elif p in UDP_SERVICES:
                services.append({"proto": "udp", "port": p, "name": UDP_SERVICES[p], "count": n})
        service_ports = {s["port"] for s in services}

        own_macs = [mac for mac in h.get("macs") or [] if owns(mac, addr)]
        vendor = vm = None
        for mac in own_macs:
            m = macs.get(mac)
            vm = vm or (VM_OUIS.get(mac[:8].lower()) if mac not in gateway_macs else None)
            if m and m.get("vendor") and mac not in gateway_macs:
                vendor = VENDOR_DISPLAY.get(m["vendor"], m["vendor"])
                break
        if not vendor and addr in gateway_ips:
            for mac, m in gateway_macs.items():
                if addr in (m.get("arp_ips") or []) and m.get("vendor"):
                    vendor = VENDOR_DISPLAY.get(m["vendor"], m["vendor"])

        # ---- role, most specific first
        if scope == "broadcast":
            role, kind = "Broadcast", "broadcast"
            reasons.append("the limited broadcast address: every host on the link")
        elif scope == "multicast":
            role, kind = f"Multicast: {MULTICAST_NAMES.get(addr, 'group')}", "multicast"
            reasons.append("a multicast group address")
        elif scope == "unspecified":
            role, kind = "Unconfigured host", "unspecified"
            reasons.append("0.0.0.0 is what a device uses before DHCP gives it an address")
        elif addr in gateway_ips or roles.get("router"):
            role, kind = "Router / gateway", "router"
            if roles.get("router"):
                reasons.append("announced as the router in DHCP")
            if addr in gateway_ips:
                reasons.append(gateway_ips[addr])
        elif roles.get("kdc") or roles.get("domain-controller"):
            role, kind = "Domain controller", "infra"
            if roles.get("kdc"):
                reasons.append("answers Kerberos logons: it is the domain's key distribution center")
            if roles.get("domain-controller"):
                reasons.append("announces itself as a domain controller")
            if roles.get("dns-server"):
                reasons.append("also answers DNS queries")
        elif roles.get("dhcp-server") or 67 in udp_serves:
            role, kind = "DHCP server", "infra"
            reasons.append("answers DHCP requests")
        elif roles.get("dns-server") or 53 in udp_serves or 53 in tcp_serves:
            role, kind = "DNS server", "infra"
            reasons.append("answers DNS queries" if roles.get("dns-server") else "receives DNS queries")
        else:
            role, kind = None, None
            for ports, name in SERVER_KINDS:
                if service_ports & ports:
                    role, kind = name, "server"
                    break
            if role:
                reasons.append("accepts connections on " + ", ".join(
                    f"{s['name']} ({s['proto'].upper()} {s['port']})" for s in services[:4]))
            elif services:
                role, kind = "Server", "server"
                reasons.append("accepts connections on " + ", ".join(
                    f"{s['proto'].upper()} {s['port']}" for s in services[:4]))
            elif scope == "public":
                role, kind = "Internet host", "internet"
                reasons.append("a public internet address")
            elif tcp_uses or udp_uses:
                role, kind = "Client device", "client"
                reasons.append("starts connections to other hosts")
            else:
                role, kind = "Device", "client"
                if tx and rx:
                    reasons.append("exchanged traffic without a recognised service or connection, so its role is unknown")
                elif tx or rx:
                    reasons.append(f"only {'sent' if tx else 'received'} traffic with no recognised service, "
                                   "so its role is unknown")
                else:
                    reasons.append("only seen in name lookups or address announcements")
        if roles.get("dns-server-advertised") and kind != "infra":
            reasons.append("handed out as a DNS server by DHCP")
            if kind in ("client", "internet"):
                role, kind = "DNS server", "infra"
        if vendor in NETWORK_VENDORS and kind in ("client", "server"):
            tags.append("Network equipment vendor")
        if vm:
            tags.append(vm)

        local = scope in ("private", "link-local", "cgnat")
        os_name, os_reason = _os_hint(h, local) if kind in ("client", "server", "infra", "router") else (None, None)

        domains = list(h.get("domains") or [])
        # NetBIOS also registers the domain's group names; they don't name this host.
        names = [n for n, _ in h.get("names") or [] if n.upper() not in short_domains and not _is_ip(n)]
        name_sources = {n: src for n, src in h.get("names") or []}
        # Hostnames a device gives itself beat names others use for it.
        best = None
        for pref in ("DHCP", "Browser", "Kerberos", "NetBIOS", "mDNS", "LLMNR", "TLS SNI", "HTTP Host", "DNS"):
            for n in names:
                if name_sources.get(n) == pref:
                    best = n
                    break
            if best:
                break
        nodes.append({
            "id": addr, "addr": addr, "name": best, "names": [[n, name_sources[n]] for n in names[:8]],
            "role": role, "kind": kind, "scope": scope, "tags": tags, "reasons": reasons,
            "users": list(h.get("users") or [])[:8], "domains": domains[:4],
            "services": services[:12], "vendor": vendor, "os": os_name, "os_reason": os_reason,
            "macs": own_macs[:4], "tx_bytes": tx, "rx_bytes": rx,
            "tx_packets": int(h.get("tx_packets", 0)), "rx_packets": int(h.get("rx_packets", 0)),
            "peers": int(h.get("peers", 0)), "first": h.get("first"), "last": h.get("last"),
        })

    nodes.sort(key=lambda n: -(n["tx_bytes"] + n["rx_bytes"]))
    truncated = len(nodes) > max_nodes
    nodes = nodes[:max_nodes]
    keep = {n["id"] for n in nodes}

    edges = []
    for family in ("ipv4", "ipv6"):
        for row in (stats.get("conversations", {}).get(family, {}) or {}).get("rows", []):
            a, _, b, _, ab_p, ab_b, ba_p, ba_b, start, dur, _, apps = row
            if a not in keep or b not in keep or a == b:
                continue
            edges.append({"a": a, "b": b, "packets": ab_p + ba_p, "bytes": ab_b + ba_b,
                          "a_to_b": ab_b, "b_to_a": ba_b, "start": start, "duration": dur,
                          "apps": apps or {}})
    counts: dict[str, int] = {}
    for n in nodes:
        counts[n["kind"]] = counts.get(n["kind"], 0) + 1
    return {"nodes": nodes, "edges": edges, "truncated": truncated, "kinds": counts,
            "total_hosts": len(hosts)}


_ROUTER_KINDS = re.compile(r"router|Cisco IOS|Juniper")


def annotate_devices(graph: dict, devices: list[dict]) -> dict:
    """The map, with each node a device configuration describes marked as that
    device, and its other addresses listed (a router's interfaces are one box).
    Returns a new dict: the graph may be a cached one."""
    by_addr: dict[str, dict] = {}
    for dev in devices:
        for a in dev.get("addresses") or []:
            if a not in ("127.0.0.1", "::1", "0.0.0.0", "::"):
                by_addr.setdefault(a, dev)
    if not by_addr:
        return graph
    nodes = []
    for n in graph.get("nodes") or []:
        dev = by_addr.get(n.get("addr"))
        if dev:
            n = {**n, "device": dev, "reasons": list(n.get("reasons") or []) +
                 [f"its configuration ({dev.get('source')}) describes {dev.get('kind')} {dev.get('name')}, "
                  f"which also has {', '.join(a for a in dev['addresses'] if a != n.get('addr')) or 'no other address'}"]}
            # The configuration says what the box is better than the services it answered.
            if n.get("kind") in ("infra", "server", "client") and _ROUTER_KINDS.search(dev.get("kind") or ""):
                n["role"], n["kind"] = "Router / gateway", "router"
            if not n.get("name") and dev.get("name"):
                n["name"] = dev["name"]
        nodes.append(n)
    return {**graph, "nodes": nodes}

