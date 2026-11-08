"""Network policy tests: rules about how the network should behave, written in plain words
("only 10.0.0.1 answers DNS", "nothing uses Telnet", "printers only talk to 10.0.0.0/24",
"block 10.0.0.5", "no Ubuntu hosts on the network", "don't let router configs be uploaded"),
checked against a capture like unit tests: each rule passes or fails, and a failure lists
the connections that broke it, each with the display filter that shows its packets. Each check
also keeps those connections (check()["_sessions"]): what enforcing the rule would block
(rules.py replays them as a firewall would).

Rules are kept in the data folder (owner-only JSON) and apply to every capture opened.
Everything is checked on this computer, from the capture's sessions.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import re
import tempfile
from collections import defaultdict

from . import geoip, hostkinds, netmap, paths, transfers
from .explain import fmt_bytes

MAX_RULES = 100
MAX_RULE = 300
MAX_GROUPS = 20

# Services as people name them: (pattern, label, TCP/UDP ports, application names from the engine).
SERVICES = [
    (r"dns|name lookups?|name resolution", "DNS", {53}, {"dns"}),
    (r"dhcp|address assignment", "DHCP", {67, 68}, {"dhcp"}),
    (r"ntp|time(?: sync(?:hronization)?)?", "NTP", {123}, {"ntp"}),
    (r"https|tls|ssl", "HTTPS", {443, 8443}, {"tls"}),
    (r"(?:unencrypted |plain |clear ?text )?http(?!s)|plain web", "HTTP", {80, 8080, 8000}, {"http"}),
    (r"web(?: traffic| browsing)?|browsing", "web", {80, 443, 8080, 8443, 8000}, {"http", "tls", "quic"}),
    (r"ssh|secure shell", "SSH", {22}, {"ssh"}),
    (r"telnet", "Telnet", {23}, {"telnet"}),
    (r"ftp|file transfer protocol", "FTP", {20, 21}, {"ftp", "ftp-data"}),
    (r"tftp", "TFTP", {69}, {"tftp"}),
    (r"smb|file shar(?:e|es|ing)|windows shares?|cifs", "SMB file sharing", {445, 139}, {"smb", "smb2", "nbss"}),
    (r"rdp|remote desktop", "Remote Desktop", {3389}, {"rdp"}),
    (r"vnc", "VNC", {5900, 5901}, {"vnc"}),
    (r"e-?mail|mail|smtp", "email (SMTP)", {25, 465, 587}, {"smtp"}),
    (r"imap", "IMAP", {143, 993}, {"imap"}),
    (r"pop3?", "POP", {110, 995}, {"pop"}),
    (r"ldap|active directory|directory", "LDAP", {389, 636, 3268}, {"ldap"}),
    (r"kerberos", "Kerberos", {88}, {"kerberos"}),
    (r"snmp", "SNMP", {161, 162}, {"snmp"}),
    (r"syslog", "syslog", {514}, {"syslog"}),
    (r"mysql", "MySQL", {3306}, {"mysql"}),
    (r"postgres(?:ql)?", "PostgreSQL", {5432}, {"pgsql"}),
    (r"sql server|mssql", "SQL Server", {1433}, {"tds"}),
    (r"databases?", "databases", {3306, 5432, 1433, 1521, 27017, 6379}, {"mysql", "pgsql", "tds"}),
    (r"sip|voip", "SIP", {5060, 5061}, {"sip"}),
    (r"m ?dns|bonjour", "mDNS", {5353}, {"mdns"}),
    (r"llmnr", "LLMNR", {5355}, {"llmnr"}),
    (r"netbios", "NetBIOS", {137, 138, 139}, {"nbns"}),
    (r"upnp|ssdp", "UPnP", {1900}, {"ssdp"}),
    (r"irc", "IRC", {6667}, {"irc"}),
    (r"(?:unencrypted|clear ?text|plain ?text) (?:protocols?|services?)", "unencrypted protocols",
     {20, 21, 23, 80, 110, 143, 161, 8080}, {"telnet", "ftp", "http", "pop", "imap", "snmp"}),
]
# Kinds of device, as the asset inventory names them (anta/assets.py).
CATEGORIES = [
    (r"printers?", "printers", lambda r: r.get("device") == "Printer"),
    (r"cameras?", "cameras", lambda r: r.get("iot") and any("camera" in str(x).lower() for x in
                                                              [*(r.get("iot_evidence") or []), r.get("vendor") or ""])),
    (r"(?:iot|smart|internet of things) (?:devices?|things)|iot", "IoT devices", lambda r: bool(r.get("iot"))),
    (r"phones?|tablets?|mobiles?", "phones", lambda r: r.get("device") == "Phone / tablet"),
    (r"computers?|workstations?|laptops?|desktops?|pcs?", "computers", lambda r: r.get("device") == "Computer"),
    (r"servers?", "servers", lambda r: "server" in str(r.get("device") or "").lower() or
     "server" in str(r.get("role") or "").lower()),
    (r"routers?|gateways?", "routers", lambda r: r.get("device") == "Router / gateway"),
]
EVERYONE = r"nothing|no ?one|nobody|no hosts?|no devices?|no machines?|none of (?:the )?(?:hosts|devices)|no computers?"
# Ways of saying "must not" ("10.0.0.5 cannot talk to 10.0.0.9").
NOT = (r"(?:never|doesn't|does not|don't|do not|must not|mustn't|should not|shouldn't|may not|cannot|can't|can not|"
       r"must never|should never|is not allowed to|isn't allowed to|are not allowed to|aren't allowed to|is never allowed to|"
       r"is forbidden to|is forbidden from|is blocked from|is not permitted to)")
# Talking is either way; connecting is what the device itself starts.
TALK = r"talk(?:s|ing)?|communicat(?:e|es|ing)|exchang(?:e|es|ing) data|chat(?:s|ting)?"
CONNECT = r"connect(?:s|ing)?|go(?:es)?|send(?:s|ing)? data|reach(?:es|ing)?|upload(?:s|ing)?|open(?:s)? connections"
CLOCK = r"\d{1,2}(?::\d{2})?\s*(?:am|pm)?"
ANY_SUBJECT = r"every(?:thing| host| device| machine)|all (?:hosts|devices|machines)|any (?:host|device)|hosts|devices"
UNITS = {"b": 1, "byte": 1, "bytes": 1, "kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3}

ADDR = re.compile(r"^(?:(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:/\d{1,3})?)$")
MAC = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")
DOMAIN = re.compile(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}$")


# Countries by name or code ("russia", "ru", "the united states", "usa").
COUNTRIES = {**{n.lower(): c for c, n in geoip.COUNTRY_NAMES.items()}, **{c.lower(): c for c in geoip.COUNTRY_NAMES},
             "usa": "US", "the united states": "US", "us": "US", "america": "US", "uk": "GB", "britain": "GB",
             "great britain": "GB", "england": "GB", "russia": "RU", "south korea": "KR", "north korea": "KP", "iran": "IR"}


class PolicyError(ValueError):
    pass


# ---------------------------------------------------------------- reading a rule

def _norm(text: str) -> str:
    t = re.sub(r"\s+", " ", str(text or "")).strip().lower().rstrip(".!")
    t = re.sub(r"^(?:make sure (?:that )?|ensure (?:that )?|check (?:that )?|rule:\s*|- |please )", "", t)
    t = t.replace("’", "'")
    # Contractions typed without the apostrophe: dont, cant, shouldnt…
    return re.sub(r"\b(do|does|did|is|are|was|were|should|would|could|must|have|has|ca|wo)nt\b",
                  lambda m: m.group(1) + "n't", t)


def _service(words: str):
    w = words.strip()
    w = re.sub(r"^(?:the |any |a |an )", "", w)
    w = re.sub(r" (?:traffic|servers?|service|protocol|queries|requests|answers|connections)$", "", w)
    for pattern, label, ports, apps in SERVICES:
        if re.fullmatch(pattern, w):
            return {"label": label, "ports": sorted(ports), "apps": sorted(apps)}
    m = re.fullmatch(r"(?:tcp |udp )?ports? (\d{1,5})(?: and (\d{1,5}))?", w)
    if m:
        ports = {int(p) for p in m.groups() if p and 0 < int(p) < 65536}
        if ports:
            return {"label": f"port {', '.join(str(p) for p in sorted(ports))}", "ports": sorted(ports), "apps": []}
    return None


def _split(words: str) -> list[str]:
    return [x.strip() for x in re.split(r",\s*(?:and |or )?|\s+(?:and|or)\s+", words) if x.strip()]


def _places(words: str) -> list[dict]:
    """Where traffic may (or may not) go: addresses, networks, domains, the internet, the
    local network, or countries."""
    out = []
    for tok in _split(re.sub(r"^(?:the )", "", words)):
        tok = re.sub(r"^(?:the |host |hosts |server |servers |address |addresses |network |domain |site )", "", tok)
        if ADDR.match(tok):
            try:
                out.append({"kind": "net", "value": str(ipaddress.ip_network(tok, strict=False)), "label": tok})
                continue
            except ValueError:
                pass
        if MAC.match(tok):
            out.append({"kind": "mac", "value": tok.replace("-", ":"), "label": tok})
        elif re.fullmatch(r"(?:the )?internet|outside|external (?:hosts|addresses|networks?)|public (?:addresses|internet)|"
                          r"anything outside|anywhere outside", tok):
            out.append({"kind": "scope", "value": "public", "label": "the internet"})
        elif re.fullmatch(r"(?:the )?(?:local network|lan|internal (?:hosts|network|addresses)|inside|"
                          r"private (?:addresses|network)|each other|our network|this network)", tok):
            out.append({"kind": "scope", "value": "private", "label": "the local network"})
        elif DOMAIN.match(tok):
            out.append({"kind": "domain", "value": tok.lstrip("*."), "label": tok})
        elif tok.strip() in COUNTRIES:
            out.append({"kind": "country", "value": COUNTRIES[tok.strip()], "label": geoip.country_name(COUNTRIES[tok.strip()])})
        else:
            raise PolicyError(f"I can't tell what “{tok}” is: use an address, a network (10.0.0.0/24), a domain, "
                              "the internet, the local network, or a country's name")
    if not out:
        raise PolicyError("name where it may go")
    return out


def _who(words: str) -> dict:
    """Whom a rule is about: addresses, networks, MACs, or a kind of device."""
    w = re.sub(r"^(?:the |all |every |our |any )", "", words.strip())
    if re.fullmatch(ANY_SUBJECT, words.strip()) or w in ("hosts", "devices"):
        return {"kind": "all", "label": "every host"}
    for pattern, label, _ in CATEGORIES:
        if re.fullmatch(pattern, w):
            return {"kind": "category", "value": label, "label": label}
    spec = hostkinds.resolve(w)
    if spec:
        return {"kind": "trait", "value": spec, "label": spec["label"]}
    nets, macs, labels = [], [], []
    for tok in _split(w):
        tok = re.sub(r"^(?:host |hosts |device |address |network )", "", tok)
        if MAC.match(tok):
            macs.append(tok.replace("-", ":"))
            labels.append(tok)
            continue
        if not ADDR.match(tok):
            raise PolicyError(f"I can't tell who “{tok}” is: use an address, a network, a MAC, a kind of device (printers, "
                              "cameras, IoT devices, phones, computers, servers, routers), an operating system (Ubuntu hosts, "
                              "Windows machines…) or a maker (Raspberry Pi devices)")
        try:
            nets.append(str(ipaddress.ip_network(tok, strict=False)))
        except ValueError as exc:
            raise PolicyError(f"“{tok}” isn't an address") from exc
        labels.append(tok)
    return {"kind": "hosts", "nets": nets, "macs": macs, "label": ", ".join(labels)}


def _cap(s: str) -> str:
    return s[:1].upper() + s[1:]


HOSTS = hostkinds.HOST_WORDS
THIS = r"(?:this|that|the selected|the|it)(?: ip| address| host| device| one| machine| computer| server)?|it"


def _host_kind(words: str) -> dict | None:
    """A kind of host (printers, Ubuntu hosts, Raspberry Pi devices), or None for anything else."""
    w = re.sub(r"^(?:the |all |every |our |any )", "", words.strip())
    for cand in (w, re.sub(rf"\s+{HOSTS}$", "", w), f"{w}s"):
        for pattern, label, _ in CATEGORIES:
            if re.fullmatch(pattern, cand):
                return {"kind": "category", "value": label, "label": label}
    spec = hostkinds.resolve(w)
    return {"kind": "trait", "value": spec, "label": spec["label"]} if spec else None


def _transfer_rule(what: str, verb: str, prep: str | None, where: str | None) -> dict:
    kind = transfers.kind_of(what or "files")
    if not kind:
        raise PolicyError(f"I don't know what “{what}” are: router configs, programs, scripts, archives, documents, "
                          "database dumps, or files")
    v = verb.lower()
    direction = "down" if v.startswith("download") else "either" if v.startswith("transfer") else "up"
    proto, dests = None, None
    if where:
        if prep in ("over", "via", "using", "with"):
            proto = transfers.PROTOCOLS.get(where.strip())
            if not proto:
                raise PolicyError(f"files are followed over FTP, HTTP and SMB, not “{where}”")
        else:
            dests = _places(where)
    noun = transfers.label(kind)
    did = {"up": "uploaded", "down": "downloaded", "either": "transferred"}[direction]
    tail = (f" {'from' if direction == 'down' else 'to'} {', '.join(d['label'] for d in dests)}" if dests else "") + \
        (f" over {proto}" if proto else "")
    return {"kind": "no_transfer", "what": kind, "direction": direction, "proto": proto, "dests": dests,
            "reads": f"No {noun} {'are' if noun.endswith('s') else 'is'} {did}{tail}"}


def _block(x: str) -> dict:
    """"block …" in plain words: an address, a place, a service, a kind of host, or a kind of file."""
    x = x.strip()
    if re.fullmatch(THIS, x):
        raise PolicyError("Which one? Write its address (block 10.0.0.5), or right-click a host anywhere in ANTA and choose "
                          "Block it…")
    m = re.fullmatch(r"(?P<dir>uploads?|downloads?|transfers?)(?: of (?P<what>.+?))?"
                     r"(?: (?P<prep>to|from|over|via|using) (?P<where>.+))?", x)
    if m:
        return _transfer_rule(m.group("what") or "files", m.group("dir"), m.group("prep"), m.group("where"))
    m = re.fullmatch(r"(?P<who>.+?) from (?:talking (?:to|with) |reaching |accessing |connecting to |getting to |going to |"
                     r"using )?(?P<dests>.+)", x)
    if m:
        svc = _service(m.group("who"))
        dests = _places(m.group("dests"))
        if svc:
            return {"kind": "no_destinations", "who": {"kind": "all", "label": "every host"}, "dests": dests, "service": svc,
                    "either": True, "reads": f"Block {svc['label']} with {', '.join(d['label'] for d in dests)} (in either direction)"}
        who = _host_kind(m.group("who")) or _who(m.group("who"))
        return {"kind": "no_destinations", "who": who, "dests": dests, "service": None, "either": True,
                "reads": f"Block {who['label']} from {', '.join(d['label'] for d in dests)} (in either direction)"}
    m = re.fullmatch(r"(?P<svc>.+?)(?: (?:to|towards|on|over|into) (?P<dests>.+))?", x)
    if m and _service(m.group("svc")):
        svc = _service(m.group("svc"))
        if m.group("dests"):
            dests = _places(m.group("dests"))
            return {"kind": "no_destinations", "who": {"kind": "all", "label": "every host"}, "dests": dests, "service": svc,
                    "either": False, "reads": f"Block {svc['label']} to {', '.join(d['label'] for d in dests)}"}
        return {"kind": "no_service", "service": svc, "who": {"kind": "all", "label": "every host"}, "reads": f"Block {svc['label']}"}
    who = _host_kind(x)
    if who:
        return {"kind": "no_hosts", "who": who, "reads": f"Block {who['label']}: none may be on the network"}
    dests = _places(x)
    return {"kind": "no_destinations", "who": {"kind": "all", "label": "every host"}, "dests": dests, "service": None, "either": True,
            "reads": f"Block all traffic with {', '.join(d['label'] for d in dests)} (in either direction)"}


def parse(text: str) -> dict:
    """A rule in plain words -> {kind, ..., reads}: what is checked, said back plainly.
    PolicyError says why a rule couldn't be read."""
    t = _norm(text)
    if not t:
        raise PolicyError("the rule is empty")
    if len(t) > MAX_RULE:
        raise PolicyError(f"a rule is at most {MAX_RULE} characters")

    # Blocking in plain words: "block 10.0.0.5", "block telnet", "block ubuntu hosts", "block printers from the internet".
    m = re.fullmatch(r"(?:block|deny|ban|blacklist|blocklist|cut off|drop|stop|reject|isolate|forbid|prevent|disallow)(?: all)?"
                     r"(?: (?:traffic|connections|access|packets))?(?: (?:to|from|with|for))? (?P<x>.+)", t)
    if m:
        return _block(m.group("x"))

    # Files: "don't let router configs be uploaded", "no programs downloaded from the internet", "no file uploads over FTP".
    m = (re.fullmatch(r"(?:don't|do not|never) (?:let|allow|permit) (?:any )?(?P<what>.+?) (?:to )?(?:be |get )?"
                      r"(?P<dir>uploaded|downloaded|transferred|sent|copied|exfiltrated|taken)"
                      r"(?: (?P<prep>to|from|over|via|using|out of|onto) (?P<where>.+))?", t) or
         re.fullmatch(r"(?:no|never any|zero) (?P<what>.+?) (?:(?:are|is|get|gets|being|ever) )*"
                      r"(?P<dir>uploaded|downloaded|transferred|sent|copied|exfiltrated)"
                      r"(?: (?P<prep>to|from|over|via|using) (?P<where>.+))?", t) or
         re.fullmatch(r"(?P<what>.+?) (?:are|is|get|gets) never (?P<dir>uploaded|downloaded|transferred|sent|copied)"
                      r"(?: (?P<prep>to|from|over|via|using) (?P<where>.+))?", t) or
         re.fullmatch(r"no (?:file |files )?(?P<dir>uploads?|downloads?|transfers?)(?: of (?P<what>.+?))?"
                      r"(?: (?P<prep>to|from|over|via|using) (?P<where>.+))?", t))
    if m and transfers.kind_of(m.group("what") or "files"):
        prep = m.group("prep")
        return _transfer_rule(m.group("what") or "files", m.group("dir"), "over" if prep == "out of" else prep,
                              "the local network" if prep == "out of" else m.group("where"))

    # Passwords in clear text.
    if re.fullmatch(r"(?:no|never any) (?:passwords?|credentials|logins?) (?:are |is )?(?:sent )?(?:in|over) "
                    r"(?:clear|plain) ?text|no (?:clear|plain) ?text (?:passwords?|logins?|credentials)|"
                    r"all logins? (?:are|is|must be|should be) encrypted|(?:passwords?|logins?) (?:are|is) (?:always )?encrypted", t):
        return {"kind": "no_cleartext_logins", "reads": "No login sends its password unencrypted"}

    # "All web traffic is encrypted": the unencrypted form must not be used.
    m = re.fullmatch(r"all (?P<svc>[\w -]+?) (?:traffic |connections )?(?:is|are|must be|should be|stays?) encrypted", t)
    if m:
        unenc = {"web": "http", "http": "http", "email": "email", "mail": "email", "file transfers": "ftp",
                 "remote access": "telnet", "remote logins": "telnet", "traffic": "unencrypted protocols"}
        svc = _service(unenc.get(m.group("svc"), m.group("svc")))
        if not svc:
            raise PolicyError(f"I don't know the service “{m.group('svc')}”")
        if svc["label"] == "email (SMTP)":
            svc = {"label": "unencrypted email", "ports": [25, 110, 143], "apps": ["smtp", "pop", "imap"]}
        return {"kind": "no_service", "service": svc, "who": {"kind": "all", "label": "every host"},
                "reads": f"No one uses {svc['label']} (it isn't encrypted)"}

    # Exclusive servers: "only 10.0.0.1 answers DNS", "DNS only goes to 10.0.0.1", "the only DNS server is 10.0.0.1".
    m = (re.fullmatch(r"only (?P<who>.+?) (?:answers?|serves?|handles?|provides?|runs?|may answer|may serve|can answer|"
                      r"should answer|is allowed to answer|is|are) (?:the )?(?P<svc>.+?)(?: servers?| server)?", t) or
         re.fullmatch(r"(?P<svc>.+?) (?:only )?(?:goes|go|is sent|should go|may go|must go|only goes) (?:only )?to (?P<who>.+)", t) or
         re.fullmatch(r"(?:the )?only (?P<svc>.+?) servers? (?:is|are) (?P<who>.+)", t) or
         re.fullmatch(r"(?P<svc>.+?) servers? (?:is|are) only (?P<who>.+)", t))
    if m and _service(m.group("svc")):
        svc = _service(m.group("svc"))
        who = _who(m.group("who"))
        if who["kind"] != "hosts":
            raise PolicyError("name the servers by address (only 10.0.0.1 answers DNS)")
        return {"kind": "only_servers", "service": svc, "servers": who,
                "reads": f"Only {who['label']} may answer {svc['label']}"}

    # Devices nobody has seen before: "no unknown devices", "only known devices".
    if re.fullmatch(r"(?:no|never any|there are no) (?:unknown|new|unfamiliar|unrecogni[sz]ed|strange) (?:devices?|hosts?|machines?)"
                    r"(?: on the network| appear| join)?|only known (?:devices|hosts|machines)(?: are on the network| may connect| are allowed"
                    r"| join)?|every (?:device|host) is known", t):
        return {"kind": "no_new_devices", "reads": "Every device is one remembered as normal (Hosts → Personalities…)"}

    # Kinds of hosts not allowed: "no ubuntu hosts on the network", "don't let windows xp machines on the network",
    # "raspberry pi devices are not allowed", "keep kali hosts off the network".
    m = (re.fullmatch(r"(?:no|never any|there are no|zero) (?P<x>.+?)(?: (?:are |is )?(?:allowed |permitted )?(?:on|in|joins?|joining|"
                      r"connect(?:s|ed|ing)? to) (?:the |our |this )?(?:network|lan|wi-?fi))?", t) or
         re.fullmatch(r"(?:don't|do not|never) (?:let|allow|permit) (?:any )?(?P<x>.+?) (?:on|onto|in|into|join|connect to|use) "
                      r"(?:the |our |this )?(?:network|lan|wi-?fi)", t) or
         re.fullmatch(r"(?P<x>.+?) (?:are|is) (?:not allowed|forbidden|banned|blocked|not permitted)(?: (?:on|in) (?:the |our )?"
                      r"(?:network|lan|wi-?fi))?", t) or
         re.fullmatch(r"keep (?P<x>.+?) off (?:the |our |this )?(?:network|lan|wi-?fi)", t))
    if m and _host_kind(m.group("x")) and not _service(m.group("x")):
        who = _host_kind(m.group("x"))
        return {"kind": "no_hosts", "who": who, "reads": f"No {who['label']} on the network"}

    # Who may use a service: "only 10.0.0.0/24 may use SSH", "RDP is only used by 10.0.0.5".
    m = (re.fullmatch(r"only (?P<who>.+?) (?:may |can |should |is allowed to |are allowed to )?(?:uses?|connects? (?:with|over|using)) "
                      r"(?P<svc>.+)", t) or
         re.fullmatch(r"(?P<svc>.+?) (?:is|may be|can be|should be|must be) (?:only )?used (?:only )?by (?P<who>.+)", t))
    if m and _service(m.group("svc")):
        svc = _service(m.group("svc"))
        who = _who(m.group("who"))
        return {"kind": "only_clients", "service": svc, "who": who,
                "reads": f"Only {who['label']} may use {svc['label']}"}

    # Forbidden services: "nothing uses Telnet", "no FTP", "Telnet is not used".
    m = (re.fullmatch(rf"(?:{EVERYONE}) (?:uses?|use|speaks?|runs?|connects with|talks) (?P<svc>.+)", t) or
         re.fullmatch(rf"(?:{EVERYONE}) (?:connects?|talks?|goes) (?:to|on|over) (?P<svc>(?:tcp |udp )?ports? \d.*)", t) or
         re.fullmatch(r"(?:no|never any|never) (?P<svc>.+)", t) or
         re.fullmatch(r"(?P<svc>.+?) (?:is|are) (?:never used|not used|not allowed|forbidden|banned|blocked|off|disabled)", t))
    if m and _service(m.group("svc")):
        svc = _service(m.group("svc"))
        return {"kind": "no_service", "service": svc, "who": {"kind": "all", "label": "every host"},
                "reads": f"No one uses {svc['label']}"}

    # Quiet hours: "no traffic between 22:00 and 06:00", "nothing talks at night", "10.0.0.5 is never active on weekends".
    m = re.fullmatch(rf"(?:no traffic|no activity|nothing (?:talks|connects|is active|happens)|no (?:host|device) (?:talks|connects|is active)|"
                     rf"(?P<who>.+?) (?:never talks?|never connects?|(?:is|are) never active|{NOT} (?:{TALK}|{CONNECT}|be active)))"
                     rf"(?: (?:between (?P<a>{CLOCK}) and (?P<b>{CLOCK})|from (?P<c>{CLOCK}) to (?P<d>{CLOCK})|"
                     rf"outside (?:of )?(?P<e>{CLOCK}) ?(?:-|to|and|–) ?(?P<f>{CLOCK})|(?P<night>at night|overnight)|"
                     rf"(?P<weekend>on (?:the )?weekends?|at weekends?)))", t)
    if m:
        who = _who(m.group("who")) if m.group("who") else {"kind": "all", "label": "every host"}
        if m.group("night"):
            span, words = (_minute("22:00"), _minute("06:00")), "at night, 22:00–06:00"
        elif m.group("weekend"):
            span, words = None, "on weekends"
        elif m.group("e"):  # outside working hours: the rest of the day
            span = (_minute(m.group("f")), _minute(m.group("e")))
            words = f"outside {m.group('e')}–{m.group('f')}"
        else:
            start, end = (m.group("a"), m.group("b")) if m.group("a") else (m.group("c"), m.group("d"))
            span, words = (_minute(start), _minute(end)), f"between {start} and {end}"
        return {"kind": "quiet_hours", "who": who, "span": span, "weekend": bool(m.group("weekend")),
                "reads": f"{'Nothing is' if who['kind'] == 'all' else _cap(who['label']) + (' are' if who['kind'] in ('category', 'trait') or ',' in who['label'] else ' is') + ' never'} active {words} "
                         "(in your computer's time zone)"}

    # Two sides that must not talk: "no traffic between 10.0.0.5 and 10.0.0.9", "the cameras and the servers never talk".
    m = (re.fullmatch(r"no (?:traffic|connections?|communication|packets|talking) (?:at all )?between (?P<a>.+?) and (?P<b>.+)", t) or
         re.fullmatch(rf"(?P<a>.+?) and (?P<b>.+?) {NOT} (?:{TALK}|{CONNECT})(?: (?:to|with) each other| together)?", t))
    if m:
        a_, b_ = _who(m.group("a")), _who(m.group("b"))
        return {"kind": "no_between", "a": a_, "b": b_,
                "reads": f"No traffic between {a_['label']} and {b_['label']} (in either direction)"}

    # Data limits: "no host uploads more than 50 MB (to the internet)", "10.0.0.5 never downloads more than 1 GB".
    m = re.fullmatch(rf"(?:{EVERYONE}|(?P<who>.+?) (?:never|{NOT})) (?P<verb>uploads?|sends?|transfers?|downloads?|receives?|pulls?) "
                     rf"(?:out |in )?more than (?P<n>\d+(?:\.\d+)?) ?(?P<u>kb|mb|gb|bytes?|b)(?: of data)?"
                     rf"(?: (?:to|in|into|from) (?P<dests>.+))?", t)
    if m:
        who = _who(m.group("who")) if m.group("who") else {"kind": "all", "label": "every host"}
        unit = m.group("u")
        limit = int(float(m.group("n")) * (1 if unit in ("b", "byte", "bytes") else UNITS[unit]))
        dests = _places(m.group("dests")) if m.group("dests") else None
        down = m.group("verb").startswith(("download", "receive", "pull"))
        where = f" {'from' if down else 'to'} {', '.join(d['label'] for d in dests)}" if dests else ""
        return {"kind": "upload_limit", "who": who, "limit": limit, "dests": dests, "down": down,
                "reads": f"{_cap(who['label'])} {'receives' if down else 'sends'} at most {fmt_bytes(limit)}{where}"}

    # How many hosts one device may reach: "no host talks to more than 50 hosts".
    m = re.fullmatch(rf"(?:{EVERYONE}|(?P<who>.+?) (?:never|{NOT})) (?:{TALK}|{CONNECT}) (?:to |with )?more than (?P<n>\d+) "
                     r"(?:different |distinct |other |unique )?(?:hosts?|devices?|address(?:es)?|ips?|destinations?|servers?|"
                     r"machines?|places?)", t)
    if m:
        who = _who(m.group("who")) if m.group("who") else {"kind": "all", "label": "every host"}
        return {"kind": "peer_limit", "who": who, "limit": int(m.group("n")),
                "reads": f"{_cap(who['label'])} talks to at most {int(m.group('n'))} hosts"}

    # Which services a device may use: "printers only use port 9100", "10.0.0.50 may only use HTTPS and DNS".
    m = re.fullmatch(r"(?P<who>.+?) (?:only|should only|may only|can only|must only) uses? (?P<svcs>.+)", t)
    if m:
        svcs = [_service(x) for x in _split(m.group("svcs"))]
        if all(svcs) and svcs:
            who = _who(m.group("who"))
            return {"kind": "only_services", "who": who, "services": svcs,
                    "reads": f"{_cap(who['label'])} may only use {', '.join(x['label'] for x in svcs)}"}

    # Allowed destinations: "printers only talk to 10.0.0.0/24", "10.0.0.50 only connects to example.com and 10.0.0.1".
    m = (re.fullmatch(r"(?P<who>.+?) (?:only|should only|may only|can only|must only) (?:talks?|connects?|goes|talk|connect|"
                      r"go|sends? data|reaches?|reach) to (?P<dests>.+?)(?: (?:over|using|on|with) (?:only )?(?P<svc>.+))?", t) or
         re.fullmatch(r"(?P<who>.+?) (?:talks?|connects?|goes) (?:only|just) to (?P<dests>.+?)(?: (?:over|using|on|with) "
                      r"(?:only )?(?P<svc>.+))?", t))
    if m:
        who = _who(m.group("who"))
        dests = _places(m.group("dests"))
        svc = _service(m.group("svc")) if m.group("svc") else None
        if m.group("svc") and not svc:
            raise PolicyError(f"I don't know the service “{m.group('svc')}”")
        return {"kind": "only_destinations", "who": who, "dests": dests, "service": svc,
                "reads": f"{_cap(who['label'])} may only connect to {', '.join(d['label'] for d in dests)}"
                         + (f", and only over {svc['label']}" if svc else "")}

    # Forbidden destinations: "nothing talks to 203.0.113.0/24", "no host connects to the internet on port 25".
    m = re.fullmatch(rf"(?:(?:{EVERYONE})|(?P<who>.+?) {NOT}) (?P<verb>{TALK}|{CONNECT}) (?:to|with) (?P<dests>.+?)"
                     r"(?: (?:on|over|using) (?P<svc>.+))?", t)
    if m:
        who = _who(m.group("who")) if m.group("who") else {"kind": "all", "label": "every host"}
        dests = _places(m.group("dests"))
        svc = _service(m.group("svc")) if m.group("svc") else None
        if m.group("svc") and not svc:
            raise PolicyError(f"I don't know the service “{m.group('svc')}”")
        either = bool(re.fullmatch(TALK, m.group("verb")))  # (talking is either way; connecting is the device's own doing)
        over = f" over {svc['label']}" if svc else ""
        verb = "talks with" if either else "connects to"
        return {"kind": "no_destinations", "who": who, "dests": dests, "service": svc, "either": either,
                "reads": f"{'No host' if who['kind'] == 'all' else _cap(who['label'])} "
                         f"{verb if who['kind'] == 'all' else 'must not ' + verb.replace('talks', 'talk').replace('connects', 'connect')} "
                         f"{', '.join(d['label'] for d in dests)}{over}" + (" (in either direction)" if either else "")}

    raise PolicyError("I couldn't read that rule (What can I write? lists every form). Rules like these work: block 10.0.0.5 · "
                      "no ubuntu hosts on the network · don't let router configs be uploaded · nothing uses Telnet · 10.0.0.5 "
                      "cannot talk to 10.0.0.9 · only 10.0.0.1 answers DNS · no traffic between 22:00 and 06:00")


def _minute(clock: str) -> int:
    """Minutes after midnight for 22:00, 9pm, 6, 06:30 am."""
    m = re.fullmatch(r"(\d{1,2})(?::(\d{2}))?\s*(am|pm)?", clock.strip())
    if not m:
        raise PolicyError(f"“{clock}” isn't a time of day")
    h, mi = int(m.group(1)), int(m.group(2) or 0)
    if m.group(3) == "pm" and h < 12:
        h += 12
    if m.group(3) == "am" and h == 12:
        h = 0
    if not (0 <= h < 24 and 0 <= mi < 60):
        raise PolicyError(f"“{clock}” isn't a time of day")
    return h * 60 + mi


# ---------------------------------------------------------------- checking it

def _addr_filter(ip: str) -> str:
    return f"{'ipv6' if ':' in ip else 'ip'}.addr == {ip}"


def _scope(ip: str) -> str:
    kind = netmap.scope_of(ip)
    return "public" if kind == "public" else "private" if kind in ("private", "link-local", "cgnat", "loopback") else kind


class Context:
    """What the checks read: the capture's sessions, and (when a rule needs them) the asset
    inventory, the location table, the logins, the viewer's time zone (minutes behind UTC, as
    browsers give it) and the devices remembered as normal."""

    def __init__(self, sessions: list[dict], assets: list[dict] | None = None, geo=None, logins: dict | None = None,
                 tz_min: int = 0, remembered: dict | None = None):
        self.sessions = [s for s in sessions if s.get("proto") in ("tcp", "udp")]
        self.all_sessions = sessions
        self._traits = None
        self._trait_cache: dict = {}
        self.assets = assets or []
        self.geo = geo
        self.logins = logins
        self.tz_min = tz_min
        self.remembered = remembered
        self.names: dict[str, set[str]] = defaultdict(set)  # address -> names the capture gave it
        for s in sessions:
            for q in s.get("dns") or []:
                for a in q.get("answers") or []:
                    self.names[str(a)].add(str(q.get("qname", "")).lower().rstrip("."))

    @property
    def traits(self) -> hostkinds.Traits:
        if self._traits is None:
            self._traits = hostkinds.Traits(self.all_sessions, self.assets, netmap.scope_of)
        return self._traits

    def why(self, who: dict, ip: str) -> str | None:
        """Why a host is one of `who` (a kind of device, an OS, a maker), or None."""
        if who["kind"] == "trait":
            key = (who["value"]["kind"], who["value"]["value"], ip)
            if key not in self._trait_cache:
                self._trait_cache[key] = self.traits.evidence(who["value"], ip)
            return self._trait_cache[key]
        if who["kind"] == "category":
            row = next((r for r in self.assets if r.get("ip") == ip), None)
            test = next(t for _, label, t in CATEGORIES if label == who["value"])
            return f"the Hosts tab recognises it as {row.get('device') or who['label']}" if row and test(row) else None
        return "named in the rule" if self.members(who)(ip) else None

    def members(self, who: dict):
        if who["kind"] == "all":
            return lambda ip: True
        if who["kind"] == "trait":
            return lambda ip: netmap.scope_of(ip) in hostkinds.LOCAL and self.why(who, ip) is not None
        if who["kind"] == "category":
            test = next(t for _, label, t in CATEGORIES if label == who["value"])
            ips = {r["ip"] for r in self.assets if test(r)}
            return lambda ip: ip in ips
        nets = [ipaddress.ip_network(n) for n in who.get("nets") or []]
        macs = {m.lower() for m in who.get("macs") or []}
        ips = {r["ip"] for r in self.assets if macs & {m.lower() for m in r.get("macs") or []}}

        def test(ip: str) -> bool:
            if ip in ips:
                return True
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                return False
            return any(a.version == n.version and a in n for n in nets)
        return test

    def matches_place(self, s: dict, place: dict, side: str = "dst_ip") -> bool:
        ip = s[side]
        if side != "dst_ip" and place["kind"] == "domain":  # (a name is the server's: the far side of a connection it started)
            return any(n == place["value"] or n.endswith("." + place["value"]) for n in self.names.get(ip, ()))
        if place["kind"] == "scope":
            return _scope(ip) == place["value"]
        if place["kind"] == "net":
            try:
                return ipaddress.ip_address(ip) in ipaddress.ip_network(place["value"])
            except (ValueError, TypeError):
                return False
        if place["kind"] == "mac":
            return any(r["ip"] == ip and place["value"] in [m.lower() for m in r.get("macs") or []] for r in self.assets)
        if place["kind"] == "domain":
            d = place["value"]
            seen = set(self.names.get(ip, ()))
            tls = s.get("tls") or {}
            if tls.get("sni"):
                seen.add(str(tls["sni"]).lower())
            for h in s.get("http") or []:
                if h.get("host"):
                    seen.add(str(h["host"]).split(":")[0].lower())
            for q in s.get("dns") or []:  # (a lookup of the name counts as reaching for it)
                seen.add(str(q.get("qname", "")).lower().rstrip("."))
            return any(n == d or n.endswith("." + d) for n in seen)
        if place["kind"] == "country":
            g = self.geo.lookup(ip) if self.geo is not None and _scope(ip) == "public" else None
            if not g:
                return False
            return g.get("country") == place["value"]
        return False


def _uses(s: dict, svc: dict) -> bool:
    return s.get("dst_port") in svc["ports"] or (s.get("app") or "") in svc["apps"]


def _bytes_out(s: dict) -> int:
    return int((s.get("c2s") or {}).get("payload_bytes") or 0)


def _bytes_all(s: dict) -> int:
    return _bytes_out(s) + int((s.get("s2c") or {}).get("payload_bytes") or 0)


def _group(sessions: list[dict], key, describe, flt) -> list[dict]:
    """Breaking connections grouped (by server, by client and server…), the biggest first."""
    groups: dict = {}
    for s in sessions:
        k = key(s)
        g = groups.setdefault(k, {"sessions": 0, "bytes": 0, "first": s.get("start") or 0, "last": s.get("end") or 0, "s": s})
        g["sessions"] += 1
        g["bytes"] += _bytes_all(s)
        g["first"] = min(g["first"], s.get("start") or 0)
        g["last"] = max(g["last"], s.get("end") or 0)
    out = []
    for k, g in sorted(groups.items(), key=lambda kv: (-kv[1]["sessions"], -kv[1]["bytes"])):
        out.append({"what": describe(k, g["s"]), "sessions": g["sessions"], "bytes": g["bytes"],
                    "first": g["first"], "last": g["last"], "filter": flt(k, g["s"])})
    return out


def _ports_filter(ports) -> str:
    ports = sorted(ports)
    if len(ports) == 1:
        return f"tcp.port == {ports[0]} || udp.port == {ports[0]}"
    return f"tcp.port in {{{', '.join(map(str, ports))}}} || udp.port in {{{', '.join(map(str, ports))}}}"


def check(rule: dict, ctx: Context) -> dict:
    """{status: pass|fail|unknown, violations, groups[{what, sessions, bytes, first, last, filter}], note}."""
    k = rule["kind"]
    groups: list[dict] = []
    note = ""
    if k == "no_cleartext_logins":
        rep = ctx.logins
        if rep is None:
            return {"status": "unknown", "violations": 0, "groups": [], "note": "The logins couldn't be read from this capture."}
        rows = [r for r in rep.get("logins") or [] if not r.get("anonymous")]
        for r in rows[:MAX_GROUPS]:
            groups.append({"what": f"{r['service']} login{f' as {r['user']}' if r.get('user') else ''}: {r['client']} → "
                                   f"{r['server']}:{r['port']} ({r['status']})",
                           "sessions": r["logins"], "bytes": 0, "first": r["first"], "last": r["last"],
                           "filter": f"{_addr_filter(r['client'])} && {_addr_filter(r['server'])} && "
                                     f"tcp.port == {r['port']}" if r.get("client") else ""})
        n = sum(r["logins"] for r in rows)
        keys = {(r.get("client"), r.get("server"), r.get("port")) for r in rows}
        bad = [x for x in ctx.sessions if (x["src_ip"], x["dst_ip"], x.get("dst_port")) in keys]
        return {"status": "fail" if rows else "pass", "violations": n, "groups": groups, "_sessions": bad,
                "note": "Passwords are never shown; the logins view lists the accounts." if rows else ""}
    if k == "only_servers":
        svc = rule["service"]
        allowed = ctx.members(rule["servers"])
        bad = [s for s in ctx.sessions if _uses(s, svc) and not allowed(s["dst_ip"])]
        groups = _group(bad, lambda s: s["dst_ip"],
                        lambda key, s: f"{key} answered {svc['label']}",
                        lambda key, s: f"{_addr_filter(key)} && ({_ports_filter(svc['ports'])})")
    elif k == "no_service":
        svc = rule["service"]
        who = ctx.members(rule["who"])
        bad = [s for s in ctx.sessions if _uses(s, svc) and who(s["src_ip"])]
        groups = _group(bad, lambda s: (s["src_ip"], s["dst_ip"], s["dst_port"]),
                        lambda key, s: f"{key[0]} → {key[1]}:{key[2]} ({(s.get('app_label') or svc['label'])})",
                        lambda key, s: f"{_addr_filter(key[0])} && {_addr_filter(key[1])} && "
                                       f"{'tcp' if s.get('proto') == 'tcp' else 'udp'}.port == {key[2]}")
    elif k == "only_clients":
        svc = rule["service"]
        who = ctx.members(rule["who"])
        bad = [s for s in ctx.sessions if _uses(s, svc) and not who(s["src_ip"])]
        groups = _group(bad, lambda s: (s["src_ip"], s["dst_ip"], s["dst_port"]),
                        lambda key, s: f"{key[0]} used {svc['label']} on {key[1]}:{key[2]}",
                        lambda key, s: f"{_addr_filter(key[0])} && {_addr_filter(key[1])} && "
                                       f"{'tcp' if s.get('proto') == 'tcp' else 'udp'}.port == {key[2]}")
    elif k == "only_services":
        who = ctx.members(rule["who"])
        bad = [s for s in ctx.sessions if who(s["src_ip"]) and netmap.scope_of(s["dst_ip"]) not in ("broadcast", "multicast")
               and not any(_uses(s, svc) for svc in rule["services"])]
        groups = _group(bad, lambda s: (s["src_ip"], s.get("proto"), s["dst_port"]),
                        lambda key, s: f"{key[0]} used {(s.get('app_label') or '').strip() or 'a service'} "
                                       f"({str(key[1]).upper()} {key[2]})",
                        lambda key, s: f"{_addr_filter(key[0])} && {'tcp' if key[1] == 'tcp' else 'udp'}.port == {key[2]}")
    elif k == "no_between":
        side_a, side_b = ctx.members(rule["a"]), ctx.members(rule["b"])
        bad = [s for s in ctx.sessions if (side_a(s["src_ip"]) and side_b(s["dst_ip"])) or (side_b(s["src_ip"]) and side_a(s["dst_ip"]))]
        groups = _group(bad, lambda s: (s["src_ip"], s["dst_ip"]),
                        lambda key, s: f"{key[0]} → {key[1]}",
                        lambda key, s: f"{_addr_filter(key[0])} && {_addr_filter(key[1])}")
    elif k == "peer_limit":
        who = ctx.members(rule["who"])
        peers: dict[str, set] = defaultdict(set)
        for s in ctx.sessions:
            if who(s["src_ip"]) and netmap.scope_of(s["dst_ip"]) not in ("broadcast", "multicast"):
                peers[s["src_ip"]].add(s["dst_ip"])
        over = sorted(((ip, p) for ip, p in peers.items() if len(p) > rule["limit"]), key=lambda x: -len(x[1]))
        for ip, p in over[:MAX_GROUPS]:
            groups.append({"what": f"{ip} talked to {len(p)} hosts", "sessions": len(p), "bytes": 0, "first": 0, "last": 0,
                           "filter": f"{'ipv6' if ':' in ip else 'ip'}.src == {ip}"})
        return {"status": "fail" if over else "pass", "violations": len(over), "groups": groups, "note": note,
                "_sessions": None, "enforce": "A firewall can't count how many hosts a device reaches: this is a test only."}
    elif k == "quiet_hours":
        who = ctx.members(rule["who"])
        tz = dt.timezone(dt.timedelta(minutes=-ctx.tz_min))

        def quiet(t: float) -> bool:
            local = dt.datetime.fromtimestamp(t, tz)
            if rule["weekend"]:
                return local.weekday() >= 5
            minute, (lo, hi) = local.hour * 60 + local.minute, rule["span"]
            return lo <= minute < hi if lo < hi else (minute >= lo or minute < hi)  # (22:00–06:00 wraps midnight)
        bad = [s for s in ctx.sessions if who(s["src_ip"]) and s.get("start") and quiet(float(s["start"]))]
        groups = _group(bad, lambda s: (s["src_ip"], s["dst_ip"]),
                        lambda key, s: f"{key[0]} → {key[1]} at {dt.datetime.fromtimestamp(float(s['start']), tz):%a %H:%M}",
                        lambda key, s: f"{_addr_filter(key[0])} && {_addr_filter(key[1])}")
        for g in groups:  # (only the quiet-time packets)
            g["filter"] = f"{g['filter']} && frame.time_epoch >= {g['first']:.0f} && frame.time_epoch <= {g['last'] + 1:.0f}"
    elif k == "no_new_devices":
        if not ctx.remembered:
            return {"status": "unknown", "violations": 0, "groups": [],
                    "note": "Remember your devices as normal first (Hosts → Personalities… → Remember these as normal)."}
        known = ctx.remembered.get("devices") or {}
        ips = {v.get("ip") for v in known.values()}
        macs = {k[4:] for k in known if k.startswith("mac:")}
        mac_of = {r["ip"]: [m.lower() for m in r.get("macs") or []] for r in ctx.assets}
        seen: dict[str, list] = defaultdict(list)
        for s in ctx.sessions:
            if netmap.scope_of(s["src_ip"]) in ("private", "link-local", "cgnat"):
                seen[s["src_ip"]].append(s)
        new = [ip for ip in seen if ip not in ips and not (set(mac_of.get(ip, [])) & macs)]
        news = set(new)
        bad = [x for x in ctx.sessions if x["src_ip"] in news or x["dst_ip"] in news]
        for ip in sorted(new)[:MAX_GROUPS]:
            ss = seen[ip]
            groups.append({"what": f"{ip}{f' ({mac_of[ip][0]})' if mac_of.get(ip) else ''} isn't one of the remembered devices",
                           "sessions": len(ss), "bytes": sum(_bytes_all(x) for x in ss), "first": min(x.get("start") or 0 for x in ss),
                           "last": max(x.get("end") or 0 for x in ss), "filter": _addr_filter(ip)})
        return {"status": "fail" if new else "pass", "violations": len(new), "groups": groups, "note": note, "_sessions": bad,
                "enforce": "A border firewall can only cut unknown devices off from the internet; keeping them off the network "
                           "takes the switch or the Wi-Fi (802.1X, MAC filtering)."}
    elif k in ("only_destinations", "no_destinations"):
        who = ctx.members(rule["who"])
        if rule["who"]["kind"] == "category" and not any(who(r["ip"]) for r in ctx.assets):
            note = f"No {rule['who']['label']} were recognised in this capture."
        svc = rule.get("service")
        if k == "only_destinations":
            bad = [s for s in ctx.sessions if who(s["src_ip"]) and netmap.scope_of(s["dst_ip"]) not in ("broadcast", "multicast")
                   and not (any(ctx.matches_place(s, p) for p in rule["dests"]) and (svc is None or _uses(s, svc)))]
        else:
            bad = [s for s in ctx.sessions if (svc is None or _uses(s, svc)) and (
                (who(s["src_ip"]) and any(ctx.matches_place(s, p) for p in rule["dests"])) or
                (rule.get("either") and who(s["dst_ip"]) and any(ctx.matches_place(s, p, "src_ip") for p in rule["dests"])))]
        if any(p["kind"] == "country" for p in rule["dests"]) and ctx.geo is None:
            note = "No location table is loaded, so countries can't be told apart."
        groups = _group(bad, lambda s: (s["src_ip"], s["dst_ip"]),
                        lambda key, s: f"{key[0]} → {key[1]}" + (f" ({', '.join(sorted(ctx.names[key[1]])[:2])})"
                                                                  if ctx.names.get(key[1]) else ""),
                        lambda key, s: f"{_addr_filter(key[0])} && {_addr_filter(key[1])}")
    elif k == "upload_limit":
        who = ctx.members(rule["who"])
        down = rule.get("down", False)
        moved: dict[str, list] = defaultdict(list)  # host -> [(bytes it sent or received, the other end, session)]
        for s in ctx.sessions:  # (both the connections it started and those it answered)
            for me, other, mine, side in (("src_ip", "dst_ip", "s2c" if down else "c2s", "dst_ip"),
                                          ("dst_ip", "src_ip", "c2s" if down else "s2c", "src_ip")):
                if who(s[me]) and netmap.scope_of(s[me]) != "public" and \
                        (not rule["dests"] or any(ctx.matches_place(s, p, side) for p in rule["dests"])):
                    moved[s[me]].append((int((s.get(mine) or {}).get("payload_bytes") or 0), s[other], s))
        over = [(ip, xs) for ip, xs in moved.items() if sum(x[0] for x in xs) > rule["limit"]]
        for ip, xs in sorted(over, key=lambda x: -sum(y[0] for y in x[1]))[:MAX_GROUPS]:
            total = sum(x[0] for x in xs)
            top = max(xs, key=lambda x: x[0])
            groups.append({"what": f"{ip} {'received' if down else 'sent'} {fmt_bytes(total)} "
                                   f"(most {'from' if down else 'to'} {top[1]})", "sessions": len(xs),
                           "bytes": total, "first": min(x[2].get("start") or 0 for x in xs),
                           "last": max(x[2].get("end") or 0 for x in xs),
                           "filter": f"{_addr_filter(ip)} && {_addr_filter(top[1])}"})
        return {"status": "fail" if over else "pass", "violations": len(over), "groups": groups, "note": note,
                "_sessions": None, "enforce": "A firewall can't count bytes: this is a test only (a proxy or a data-loss tool "
                                              "could enforce it)."}
    elif k == "no_hosts":
        who = rule["who"]
        hosts: dict[str, list] = defaultdict(list)
        for x in ctx.all_sessions:
            for ip in (x.get("src_ip"), x.get("dst_ip")):
                if ip and netmap.scope_of(ip) in hostkinds.LOCAL:
                    hosts[ip].append(x)
        for r in ctx.assets:
            if netmap.scope_of(r.get("ip") or "") in hostkinds.LOCAL:
                hosts.setdefault(r["ip"], [])
        found = []
        for ip in sorted(h for h in hosts if h):
            reason = ctx.why(who, ip)
            if reason:
                found.append((ip, reason))
        names = {r.get("ip"): r.get("name") for r in ctx.assets}
        for ip, reason in found[:MAX_GROUPS]:
            ss = hosts[ip]
            groups.append({"what": f"{ip}{f' ({names[ip]})' if names.get(ip) else ''}: {reason}", "sessions": len(ss),
                           "bytes": sum(_bytes_all(x) for x in ss), "first": min((x.get("start") or 0 for x in ss), default=0),
                           "last": max((x.get("end") or 0 for x in ss), default=0), "filter": _addr_filter(ip)})
        if not ctx.assets and who["kind"] in ("category", "trait"):
            note = "The Hosts tab's inventory wasn't available: only what the traffic itself says was used."
        keep = {ip for ip, _ in found}
        bad = [x for x in ctx.sessions if x["src_ip"] in keep or x["dst_ip"] in keep]
        return {"status": "fail" if found else "pass", "violations": len(found), "groups": groups, "note": note, "_sessions": bad,
                "enforce": "A border firewall can only cut these hosts off from the internet; keeping them off the network takes "
                           "the switch or the Wi-Fi (802.1X, MAC filtering). The evidence is what their traffic claims, which can "
                           "be faked."}
    elif k == "no_transfer":
        bad, seen = [], set()
        for x in ctx.sessions:
            for f in transfers.files(x):
                if rule["what"] not in f["kinds"] or (rule["proto"] and f["proto"] != rule["proto"]):
                    continue
                if rule["direction"] == "up" and not f["up"] or rule["direction"] == "down" and f["up"]:
                    continue
                client, server = (x["dst_ip"], x["src_ip"]) if f.get("active") else (x["src_ip"], x["dst_ip"])
                if rule["dests"] and not any(ctx.matches_place(x, p, "src_ip" if f.get("active") else "dst_ip")
                                             for p in rule["dests"]):
                    continue
                if id(x) not in seen:
                    seen.add(id(x))
                    bad.append(x)
                if len(groups) < MAX_GROUPS:
                    verb = "uploaded" if f["up"] else "downloaded"
                    groups.append({"what": f"{client} {verb} {f['name']} {'to' if f['up'] else 'from'} {server} over {f['proto']}"
                                           + (f" ({f['why']})" if f["why"] else ""),
                                   "sessions": 1, "bytes": f["size"], "first": x.get("start") or 0, "last": x.get("end") or 0,
                                   "filter": f"{_addr_filter(x['src_ip'])} && {_addr_filter(x['dst_ip'])} && "
                                             f"{'tcp' if x.get('proto') == 'tcp' else 'udp'}.port == {x.get('dst_port')}"})
        return {"status": "fail" if bad else "pass", "violations": len(groups), "groups": groups, "note": note, "_sessions": bad,
                "enforce": "A plain firewall can't see what a transfer carries: enforcing this takes a proxy or an IPS that inspects "
                           "files. Blocking the protocol (nothing uses FTP, nothing uses TFTP) stops these outright."}
    else:
        return {"status": "unknown", "violations": 0, "groups": [], "note": "Unknown rule."}
    total = sum(g["sessions"] for g in groups)
    return {"status": "fail" if groups else "pass", "violations": total, "groups": groups[:MAX_GROUPS], "note": note,
            "_sessions": bad}


def run(texts: list[str], ctx: Context) -> list[dict]:
    out = []
    for text in texts:
        item = {"rule": text}
        try:
            rule = parse(text)
        except PolicyError as exc:
            out.append({**item, "understood": False, "error": str(exc), "status": "unknown"})
            continue
        item.update(understood=True, reads=rule["reads"], kind=rule["kind"])
        item.update({k: v for k, v in check(rule, ctx).items() if not k.startswith("_")})
        if item["groups"]:
            item["filter"] = " || ".join(f"({g['filter']})" for g in item["groups"][:MAX_GROUPS] if g["filter"])
        out.append(item)
    return out


def needs(texts: list[str]) -> set[str]:
    """What the rules need beyond the sessions: "assets", "geo", "logins"."""
    out = set()
    for text in texts:
        try:
            rule = parse(text)
        except PolicyError:
            continue
        if rule["kind"] == "no_new_devices":
            out |= {"assets", "remembered"}
        if rule["kind"] == "quiet_hours":
            out.add("tz")
        for key in ("who", "servers", "a", "b"):
            if (rule.get(key) or {}).get("kind") in ("category", "trait") or (rule.get(key) or {}).get("macs"):
                out.add("assets")
        for p in rule.get("dests") or []:
            if p["kind"] == "country":
                out.add("geo")
            if p["kind"] == "mac":
                out.add("assets")
        if rule["kind"] == "no_cleartext_logins":
            out.add("logins")
    return out


# ---------------------------------------------------------------- the saved rules

def path() -> str:
    return os.path.join(paths.app_data_dir(), "policy.json")


def clean(texts) -> list[str]:
    if not isinstance(texts, list):
        raise PolicyError("rules are a list of lines")
    out = []
    for t in texts[:MAX_RULES]:
        if not isinstance(t, str):
            continue
        t = re.sub(r"[\x00-\x1f\x7f]+", " ", t).strip()[:MAX_RULE]
        if t and not t.startswith("#") and t not in out:
            out.append(t)
    return out


def load() -> list[str]:
    try:
        with open(path(), encoding="utf-8") as fh:
            return clean(json.load(fh).get("rules"))
    except (OSError, ValueError, TypeError, AttributeError, PolicyError):
        return []


PLACEMENTS = ("border", "host")


def load_placement() -> str:
    """Where the rules are enforced in a dry run: at the border, or on every device."""
    try:
        with open(path(), encoding="utf-8") as fh:
            value = json.load(fh).get("placement")
    except (OSError, ValueError, TypeError, AttributeError):
        return "border"
    return value if value in PLACEMENTS else "border"


def save(texts: list[str], placement: str | None = None) -> list[str]:
    rules = clean(texts)
    placement = placement if placement in PLACEMENTS else load_placement()
    directory = os.path.dirname(path())
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".policy-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"rules": rules, "placement": placement}, fh, indent=1)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return rules
