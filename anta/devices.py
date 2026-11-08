"""Devices described by files seen in the traffic, and what kind of address is what.

A router or server configuration (an OpenWrt backup, a Cisco IOS running-config,
a Linux interfaces file, `ip addr` output...) copied over the network names every
address the device has, including ones it never uses on the wire (a loopback, a
link to another router). When the capture also shows that device misbehaving,
those are all the addresses of the culprit.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# ------------------------------------------------------------------ addresses

_NETS = [
    ("documentation", ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20"]),
    ("benchmarking", ["198.18.0.0/15", "2001:2::/48"]),
    ("unspecified", ["0.0.0.0/32", "::/128"]),
    ("this-network", ["0.0.0.0/8"]),
    ("loopback", ["127.0.0.0/8", "::1/128"]),
    ("multicast", ["224.0.0.0/4", "ff00::/8"]),
    ("broadcast", ["255.255.255.255/32"]),
    ("reserved", ["240.0.0.0/4"]),
    ("link-local", ["169.254.0.0/16", "fe80::/10"]),
    ("shared", ["100.64.0.0/10"]),
    ("private", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]),
]
_NETS = [(kind, [ipaddress.ip_network(n) for n in nets]) for kind, nets in _NETS]
# No real DNS answer can be one of these.
NEVER_VALID = {"documentation", "benchmarking", "this-network", "multicast", "broadcast", "reserved"}
# What a filtering resolver answers for a blocked name.
SINKHOLE = {"unspecified", "loopback"}
KIND_TEXT = {
    "documentation": "reserved for documentation (RFC 5737/3849): it is never assigned to a real host",
    "benchmarking": "reserved for benchmarking (RFC 2544): it is never a real internet host",
    "this-network": "in 0.0.0.0/8, which no host can have",
    "multicast": "a multicast group, not a host",
    "broadcast": "the broadcast address",
    "reserved": "in the reserved 240.0.0.0/4 block",
    "unspecified": "the unspecified address (how filtering resolvers block a name)",
    "loopback": "a loopback address, so the client would talk to itself",
    "link-local": "a link-local address",
    "shared": "in the carrier-grade NAT range",
    "private": "a private (internal) address",
    "public": "a public address",
}


def address_kind(addr: str) -> str:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "invalid"
    for kind, nets in _NETS:
        if any(ip.version == n.version and ip in n for n in nets):
            return kind
    return "public"


# ------------------------------------------------------------------ devices

@dataclass
class Interface:
    name: str
    address: str
    prefix: int | None = None

    def text(self) -> str:
        return f"{self.address}/{self.prefix}" if self.prefix is not None else self.address


@dataclass
class Device:
    kind: str                                  # "OpenWrt router", "Cisco IOS device", ...
    source: str                                # the file it came from
    hostname: str = ""
    interfaces: list[Interface] = field(default_factory=list)
    dhcp_interfaces: list[str] = field(default_factory=list)   # addresses not in the file
    dns_overrides: list[tuple[str, str]] = field(default_factory=list)  # (name, address) it answers itself

    @property
    def name(self) -> str:
        if self.hostname:
            return self.hostname
        base = re.split(r"[\\/]", self.source)[-1]
        return re.sub(r"(?i)[._-](backup|running|startup|config|conf|cfg|bak)(\.[a-z0-9]+)?$", "", base) or base

    def addresses(self) -> list[str]:
        seen, out = set(), []
        for i in self.interfaces:
            if i.address not in seen:
                seen.add(i.address)
                out.append(i.address)
        return out

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind, "source": self.source, "hostname": self.hostname,
                "interfaces": [{"name": i.name, "address": i.address, "prefix": i.prefix} for i in self.interfaces],
                "dhcp_interfaces": list(self.dhcp_interfaces),
                "dns_overrides": [list(x) for x in self.dns_overrides]}


def _prefix(mask: str | None) -> int | None:
    if not mask:
        return None
    mask = mask.strip()
    if mask[:2].lower() == "0x" and len(mask) <= 10:  # BSD/macOS ifconfig: netmask 0xffffff00
        try:
            bits = int(mask, 16)
        except ValueError:
            return None
        n = bin(bits).count("1")
        return n if bits == (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF else None
    if mask.isdigit():
        return int(mask) if int(mask) <= 128 else None
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def _split(value: str) -> tuple[str, int | None] | None:
    """'10.0.0.1/24' or '10.0.0.1' -> (address, prefix)."""
    value = value.strip().strip("'\"")
    addr, _, pre = value.partition("/")
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    return str(ip), _prefix(pre) if pre else None


def _add(dev: Device, name: str, value: str, mask: str | None = None) -> None:
    sp = _split(value)
    if not sp:
        return
    addr, pre = sp
    if pre is None:
        pre = _prefix(mask)
    if not any(i.address == addr and i.name == name for i in dev.interfaces):
        dev.interfaces.append(Interface(name, addr, pre))


_Q = r"""['"]?([^'"\s]+)['"]?"""


def _openwrt(text: str, source: str) -> Device | None:
    if not re.search(r"(?m)^config[ \t]+\w", text):
        return None
    dev = Device("OpenWrt router", source)
    section, sname, opts = None, "", {}

    def flush():
        if section == "interface":
            for addr in opts.get("ipaddr", []):
                _add(dev, sname, addr, (opts.get("netmask") or [None])[0])
            for addr in opts.get("ip6addr", []):
                _add(dev, sname, addr)
            if opts.get("proto", [""])[0] in ("dhcp", "dhcpv6", "pppoe") and not opts.get("ipaddr"):
                dev.dhcp_interfaces.append(sname)
        elif section == "system" and opts.get("hostname"):
            dev.hostname = opts["hostname"][0]
        elif section in ("dnsmasq", "domain"):
            for spec in opts.get("address", []):  # list address '/name/1.2.3.4'
                m = re.fullmatch(r"/([^/]+)/(.+)", spec)
                if m:
                    dev.dns_overrides.append((m.group(1), m.group(2)))
            if section == "domain" and opts.get("name") and opts.get("ip"):
                dev.dns_overrides.append((opts["name"][0], opts["ip"][0]))

    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"config\s+(\w+)(?:\s+" + _Q + ")?", line)
        if m:
            flush()
            section, sname, opts = m.group(1), m.group(2) or m.group(1), {}
            continue
        m = re.match(r"(option|list)\s+(\w+)\s+(.+)", line)
        if m and section:
            opts.setdefault(m.group(2), []).append(m.group(3).strip().strip("'\""))
    flush()
    return dev


def _cisco(text: str, source: str) -> Device | None:
    if not re.search(r"(?m)^interface[ \t]+\S", text):
        return None
    dev = Device("Cisco IOS device", source)
    iface = ""
    for raw in text.splitlines():
        m = re.match(r"hostname\s+(\S+)", raw)
        if m:
            dev.hostname = m.group(1)
        m = re.match(r"interface\s+(\S+)", raw)
        if m:
            iface = m.group(1)
            continue
        if raw and not raw[0].isspace():  # a top-level line ends the interface block
            iface = ""
        m = re.match(r"\s+ip address\s+(\S+)\s+(\S+)", raw)
        if m and iface:
            _add(dev, iface, m.group(1), m.group(2))
        m = re.match(r"\s+ipv6 address\s+(\S+)", raw)
        if m and iface:
            _add(dev, iface, m.group(1))
        m = re.match(r"ip host\s+(\S+)\s+(\S+)", raw)
        if m:
            dev.dns_overrides.append((m.group(1), m.group(2)))
    return dev if dev.interfaces else None


def _juniper(text: str, source: str) -> Device | None:
    lines = re.findall(r"(?m)^set interfaces (\S+) unit (\d+) family inet6? address (\S+)", text)
    if not lines:
        return None
    dev = Device("Juniper device", source)
    m = re.search(r"(?m)^set system host-name (\S+)", text)
    if m:
        dev.hostname = m.group(1)
    for iface, unit, addr in lines:
        _add(dev, f"{iface}.{unit}", addr)
    return dev


def _mikrotik(text: str, source: str) -> Device | None:
    """A RouterOS export, line by line: "/ip address" then "add address=... interface=..."."""
    if "/ip address" not in text:
        return None
    dev = Device("MikroTik router", source)
    section = ""
    for raw in text.splitlines():
        words = raw.split()
        if words and words[0].startswith("/"):  # "/ip address", maybe with the command on the same line
            n = next((i for i, w in enumerate(words) if w in ("add", "set") or "=" in w), len(words))
            section, words = " ".join(words[:n]), words[n:]
        if not words or words[0] not in ("add", "set"):
            continue
        kv = {k: v.strip("'\"") for k, _, v in (w.partition("=") for w in words[1:] if "=" in w)}
        if section == "/ip address" and kv.get("address"):
            _add(dev, kv.get("interface") or "?", kv["address"])
        elif section == "/system identity" and kv.get("name"):
            dev.hostname = kv["name"]
        elif section == "/ip dns static" and kv.get("name") and kv.get("address"):
            dev.dns_overrides.append((kv["name"], kv["address"]))
    return dev


def _linux(text: str, source: str) -> Device | None:
    """ifupdown, `ip addr`, `ifconfig` and netplan, read line by line (no regex
    that can backtrack badly: this text comes off the wire)."""
    dev = Device("Linux host", source)
    iface = ip_name = cfg_name = plan_name = ""
    plan_list = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        indented = raw[:1].isspace()
        # ifupdown: iface eth0 inet static / address 10.0.0.5 [netmask ...]
        m = re.match(r"iface\s+(\S+)\s+inet6?\s+(\S+)", line)
        if m:
            iface = m.group(1)
            if m.group(2) == "dhcp":
                dev.dhcp_interfaces.append(iface)
            continue
        m = re.match(r"address\s+(\S+)(?:\s+netmask\s+(\S+))?$", line)
        if m and iface and indented:
            _add(dev, iface, m.group(1), m.group(2))
            continue
        m = re.match(r"netmask\s+(\S+)$", line)  # ifupdown's usual form: on a line of its own
        if m and iface and indented:
            last = next((i for i in reversed(dev.interfaces) if i.name == iface), None)
            if last and last.prefix is None:
                last.prefix = _prefix(m.group(1))
            continue
        # `ip addr`: "2: eth0: <...>" then "inet 10.0.0.5/24 ..."
        m = re.match(r"\d+:\s+([^:@\s]+)[@:]", raw)
        if m:
            ip_name = m.group(1)
            continue
        m = re.match(r"inet6?\s+(\S+/\d+)", line)
        if m and ip_name and indented:
            _add(dev, ip_name, m.group(1))
            continue
        # ifconfig: "eth0: flags=..." / "eth0  Link encap" then "inet 10.0.0.5  netmask 255.255.255.0"
        m = re.match(r"([A-Za-z][\w.:-]*?):?\s+(?:flags=|Link encap)", raw)
        if m and not indented:
            cfg_name = m.group(1)
            continue
        m = re.match(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)\s+(?:.*?(?:netmask |Mask:)(\S+))?", line)
        if m and cfg_name and indented:
            _add(dev, cfg_name, m.group(1), m.group(2))
            continue
        # netplan: "eth0:" then "addresses: [10.0.0.5/24]" or a "- 10.0.0.5/24" list
        m = re.match(r"([\w.-]+):$", line)
        if m and indented and m.group(1) not in ("addresses", "routes", "nameservers", "ethernets", "network"):
            plan_name, plan_list = m.group(1), False
            continue
        if plan_name and line.startswith("addresses:"):
            rest = line[len("addresses:"):].strip()
            if rest.startswith("[") and rest.endswith("]"):
                for a in rest[1:-1].split(","):
                    _add(dev, plan_name, a)
            plan_list = not rest
            continue
        if plan_list and line.startswith("- "):
            _add(dev, plan_name, line[2:])
            continue
        plan_list = False
    for raw in text.splitlines():
        line = raw.strip()
        if line[:8] in ("hostname", "HOSTNAME") and line[8:9] in (" ", "\t", "=", ":"):
            value = line[8:].lstrip(" \t=:").split()
            if len(value) == 1:
                dev.hostname = value[0].strip("'\"")
                break
    return dev if dev.interfaces else None


def _windows(text: str, source: str) -> Device | None:
    if "IPv4 Address" not in text and "IP Address" not in text:
        return None
    dev = Device("Windows host", source)
    adapter = ""
    for raw in text.splitlines():
        head = raw.rstrip()
        if raw[:1].strip() and head.endswith(":") and "adapter " in head:  # "Ethernet adapter Ethernet0:"
            adapter = head[:-1].rpartition("adapter ")[2] or adapter
        m = re.search(r"IPv4 Address[ .]*: ([\d.]+)|IP Address[ .]*: ([\d.]+)", raw)
        if m:
            _add(dev, adapter or "?", m.group(1) or m.group(2))
        m = re.search(r"Link-local IPv6 Address[ .]*: ([0-9a-f:]+)", raw)
        if m:
            _add(dev, adapter or "?", m.group(1))
        m = re.search(r"Host Name[ .]*: (\S+)", raw)
        if m:
            dev.hostname = m.group(1)
    return dev if dev.interfaces else None


def _dns_only(text: str, source: str) -> Device | None:
    """dnsmasq `address=/name/ip` rules or a hosts file: names a device answers itself."""
    rules = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("address=/"):
            name, _, rest = line[len("address=/"):].partition("/")
            if name and rest.split():
                rules.append((name, rest.split()[0]))
    if not rules:
        return None
    dev = Device("DNS resolver (dnsmasq)", source)
    dev.dns_overrides.extend(rules)
    return dev


PARSERS = (_openwrt, _cisco, _juniper, _mikrotik, _windows, _linux, _dns_only)


def parse(text: str, source: str) -> Device | None:
    """The device a configuration (or network-status output) describes, if any."""
    if not text or len(text) > 512 * 1024:
        return None
    for parser in PARSERS:
        try:
            dev = parser(text, source)
        except re.error:
            dev = None
        if dev and (dev.interfaces or dev.dns_overrides):
            return dev
    return None
