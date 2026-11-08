"""What a host is, for rules about kinds of hosts ("no Ubuntu hosts on the network", "block
Raspberry Pi devices"): an operating system, a maker, or a kind of device, each recognised from
what the capture shows and said with the evidence that gave it away.

Operating systems are recognised from what their own software says or does: HTTP User-Agents
and Server headers ("Ubuntu; Linux x86_64", "Apache/2.4.52 (Ubuntu)"), the asset inventory's
fingerprint (TCP SYN shape, TTL), and the hosts only that system's own services contact (an
Ubuntu machine checks connectivity-check.ubuntu.com and updates from archive.ubuntu.com). A
browser visiting ubuntu.com proves nothing, so only those service hosts count. Evidence can be
faked: these say what the traffic claims, not what is certain.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

LOCAL = ("private", "link-local", "cgnat")


@dataclass(frozen=True)
class OS:
    key: str
    label: str
    words: str          # how a rule names it (a regex, whole words)
    text: str           # in a User-Agent, Server header, OS guess, name or vendor (case-insensitive regex)
    hosts: tuple        # service hosts only this system contacts
    family: str = ""    # the asset inventory's OS family that also counts
    not_text: str = ""  # text that rules it out (an Android User-Agent also says Linux)


OSES = (
    OS("ubuntu", "Ubuntu", r"ubuntu", r"\bubuntu\b",
       ("connectivity-check.ubuntu.com", "archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com", "changelogs.ubuntu.com",
        "motd.ubuntu.com", "esm.ubuntu.com", "daisy.ubuntu.com", "ntp.ubuntu.com", "api.snapcraft.io", "livepatch.canonical.com",
        "contracts.canonical.com")),
    OS("debian", "Debian", r"debian", r"\bdebian\b(?!.*apt-http)", ("deb.debian.org", "security.debian.org", "ftp.debian.org")),
    OS("fedora", "Fedora", r"fedora", r"\bfedora\b", ("mirrors.fedoraproject.org", "fedoraproject.org")),
    OS("rhel", "Red Hat / CentOS", r"red ?hat|rhel|centos|rocky|alma ?linux", r"red hat|\brhel\b|centos|rocky|almalinux",
       ("cdn.redhat.com", "mirrorlist.centos.org", "mirrors.rockylinux.org", "mirrors.almalinux.org")),
    OS("arch", "Arch Linux", r"arch(?: linux)?", r"arch ?linux", ("archlinux.org",)),
    OS("kali", "Kali Linux", r"kali(?: linux)?", r"\bkali\b", ("http.kali.org", "kali.download", "kali.org")),
    OS("raspbian", "Raspberry Pi OS", r"raspbian|raspberry pi os", r"raspbian", ("raspbian.raspberrypi.org", "archive.raspberrypi.org",
                                                                                  "archive.raspberrypi.com")),
    OS("windows-xp", "Windows XP", r"windows ?xp|xp", r"windows nt 5\.[12]\b", ()),
    OS("windows-7", "Windows 7", r"windows ?7", r"windows nt 6\.1\b", ()),
    OS("windows", "Windows", r"windows|microsoft windows|pcs? running windows", r"windows",
       ("msftconnecttest.com", "msftncsi.com", "windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com"), "Windows"),
    OS("ios", "iOS / iPadOS", r"ios|iphones?|ipads?", r"iphone|ipad|\bios\b", (), not_text=r"mac os x(?!.*mobile)"),
    OS("macos", "macOS", r"mac ?os|macs?|macbooks?|os x", r"macintosh|mac os x|macos", (), not_text=r"iphone|ipad|mobile"),
    OS("android", "Android", r"android", r"android", ("connectivitycheck.android.com", "android.clients.google.com"), "Android"),
    OS("chromeos", "ChromeOS", r"chrome ?os|chromebooks?", r"\bcros\b|chromeos", (), "ChromeOS"),
    OS("linux", "Linux", r"linux", r"linux", (), "Linux", not_text=r"android"),
)
DISTROS = {"ubuntu", "debian", "fedora", "rhel", "arch", "kali", "raspbian"}  # (each also counts as Linux)
VENDORS = {"raspberry pi": "Raspberry Pi", "raspberry pis": "Raspberry Pi", "apple": "Apple", "samsung": "Samsung", "dell": "Dell",
           "hp": "HP", "hewlett packard": "Hewlett Packard", "lenovo": "Lenovo", "cisco": "Cisco", "tp-link": "TP-Link",
           "netgear": "NETGEAR", "ubiquiti": "Ubiquiti", "hikvision": "Hikvision", "dahua": "Dahua", "espressif": "Espressif",
           "amazon": "Amazon", "google": "Google", "sonos": "Sonos", "intel": "Intel", "vmware": "VMware", "microsoft": "Microsoft",
           "brother": "Brother", "canon": "Canon", "epson": "Epson", "xiaomi": "Xiaomi", "huawei": "Huawei", "synology": "Synology",
           "qnap": "QNAP", "roku": "Roku", "nest": "Nest", "ring": "Ring", "wyze": "Wyze", "tuya": "Tuya", "shelly": "Shelly"}
HOST_WORDS = r"(?:hosts?|devices?|machines?|computers?|boxes|systems?|clients?|servers?|pcs?|laptops?|workstations?|things)"


def resolve(words: str) -> dict | None:
    """A kind of host from words like "ubuntu", "ubuntu hosts", "windows xp machines", "raspberry pi devices":
    {"kind": "os"|"vendor", "value", "label"}, or None."""
    w = re.sub(r"^(?:the |any |all |every |our )", "", words.strip().lower())
    w = re.sub(rf"\s+{HOST_WORDS}$", "", w).strip()
    w = re.sub(r"\s+(?:based|running)$", "", w)
    w = re.sub(r"^(?:hosts?|devices?|machines?|computers?) (?:running|with|on) ", "", w)
    for o in OSES:
        if re.fullmatch(o.words, w):
            return {"kind": "os", "value": o.key, "label": f"{o.label} hosts"}
    if w in VENDORS:
        return {"kind": "vendor", "value": VENDORS[w], "label": f"{VENDORS[w]} devices"}
    return None


def _host_of(name: str, hosts: tuple) -> bool:
    name = name.lower().rstrip(".")
    return any(name == h or name.endswith("." + h) for h in hosts)


class Traits:
    """Per local host: the text it presents and the service hosts it contacts, read once."""

    def __init__(self, sessions: list[dict], assets: list[dict] | None, scope_of):
        self.assets = {r["ip"]: r for r in assets or [] if r.get("ip")}
        self.texts: dict[str, list[tuple[str, str]]] = defaultdict(list)   # ip -> [(text, where it came from)]
        self.contacts: dict[str, set[str]] = defaultdict(set)              # ip -> names it reached for
        for s in sessions:
            src, dst = s.get("src_ip"), s.get("dst_ip")
            if scope_of(src or "") in LOCAL:
                for h in s.get("http") or []:
                    if h.get("user_agent"):
                        self.texts[src].append((h["user_agent"], "its HTTP User-Agent"))
                    if h.get("host"):
                        self.contacts[src].add(str(h["host"]).split(":")[0].lower())
                for f in s.get("http_files") or []:
                    if f.get("user_agent"):
                        self.texts[src].append((f["user_agent"], "its HTTP User-Agent"))
                sni = (s.get("tls") or {}).get("sni")
                if sni:
                    self.contacts[src].add(str(sni).lower())
                for q in s.get("dns") or []:
                    if q.get("qname"):
                        self.contacts[src].add(str(q["qname"]).lower().rstrip("."))
            if scope_of(dst or "") in LOCAL:
                server = (s.get("http_response") or {}).get("server")
                if server:
                    self.texts[dst].append((server, "its web server's Server header"))
        for ip, r in self.assets.items():
            if r.get("os"):
                self.texts[ip].append((str(r["os"]), "the Hosts tab's guess (" + "; ".join(r.get("os_evidence") or [])[:160] + ")"))
            for n in r.get("names") or []:
                # A device's own name ("ubuntu-desktop", "raspberrypi.local"), not a website's address: archive.ubuntu.com
                # is a server *for* Ubuntu machines, which says nothing about what it runs.
                if "." not in str(n).rstrip(".") or re.search(r"\.(?:local|lan|home|internal|localdomain)\.?$", str(n), re.I):
                    self.texts[ip].append((str(n), "its name"))
            if r.get("vendor"):
                self.texts[ip].append((str(r["vendor"]), "its network card's maker"))

    def hosts(self) -> set[str]:
        return set(self.texts) | set(self.contacts) | set(self.assets)

    def evidence(self, spec: dict, ip: str) -> str | None:
        """Why this host is of that kind (a short phrase), or None."""
        if spec["kind"] == "vendor":
            vendor = str((self.assets.get(ip) or {}).get("vendor") or "")
            if spec["value"].lower() in vendor.lower():
                return f"its network card is made by {vendor}"
            for text, where in self.texts.get(ip, ()):
                if where == "its name" and spec["value"].lower().replace(" ", "") in text.lower().replace("-", "").replace(" ", ""):
                    return f"{where} is {text}"
            return None
        keys = [spec["value"]] if spec["value"] != "linux" else ["linux", *DISTROS]
        for key in keys:
            o = next(x for x in OSES if x.key == key)
            for text, where in self.texts.get(ip, ()):
                if re.search(o.text, text, re.I) and not (o.not_text and re.search(o.not_text, text, re.I)):
                    return f"{where} says “{text[:90]}”"
            if o.hosts:
                hit = next((n for n in sorted(self.contacts.get(ip, ())) if _host_of(n, o.hosts)), None)
                if hit:
                    return f"it contacted {hit}, which only {o.label}'s own services use"
            fam = (self.assets.get(ip) or {}).get("os_family")
            if o.family and fam == o.family:
                return f"the Hosts tab recognises it as {fam} ({'; '.join((self.assets[ip].get('os_evidence') or [])[:1])})"
        return None
