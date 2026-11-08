"""Firewall dry run: firewall rules you are thinking of adding, replayed against the capture
before you apply them. Every connection in the capture is judged as the firewall would judge it
(stateful: the rule decides the connection, replies follow it), and the result says what would
have been blocked, which ordinary traffic would break ("printing would stop"), and which of the
capture's alerts would still have got through.

Rules can be written in plain words or pasted from a firewall, one per line:
    block in tcp to any port 23                       plain words (allow/block, in/out, from, to, port)
    iptables -A INPUT -p tcp --dport 23 -j DROP       iptables (INPUT/OUTPUT/FORWARD, -s/-d, --dport, multiport, -P)
    ufw deny 23/tcp   /   ufw default deny incoming   ufw
    block in quick proto tcp from any to any port 23  pf (last match wins unless quick)
    access-list 101 deny tcp any any eq 23            Cisco ACLs (with the implicit deny at the end)

Where the firewall sits decides what it sees: at the border (between the local network and the
internet: "in" is from the internet, "out" is to it; traffic inside the network never crosses
it), or on every device (each connection is outgoing for its sender and incoming for its
receiver, judged by the same rules on both).
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field

from . import netmap, policy

MAX_RULES = 300
MAX_LINE = 400
MAX_GROUPS = 40

PORT_NAMES = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "dns": 53, "bootps": 67, "dhcp": 67,
    "bootpc": 68, "tftp": 69, "http": 80, "www": 80, "kerberos": 88, "pop3": 110, "ntp": 123, "netbios-ns": 137,
    "netbios-dgm": 138, "netbios-ssn": 139, "imap": 143, "snmp": 161, "ldap": 389, "https": 443, "smb": 445,
    "microsoft-ds": 445, "smtps": 465, "syslog": 514, "printer": 515, "submission": 587, "ipp": 631, "ldaps": 636,
    "imaps": 993, "pop3s": 995, "mssql": 1433, "ssdp": 1900, "mysql": 3306, "rdp": 3389, "ms-wbt-server": 3389,
    "sip": 5060, "mdns": 5353, "llmnr": 5355, "postgresql": 5432, "postgres": 5432, "vnc": 5900, "irc": 6667,
    "jetdirect": 9100,
}
EXTRA_SERVICES = {631: "printing (IPP)", 515: "printing (LPD)", 9100: "printing (JetDirect)", 1900: "UPnP discovery"}
LOCAL_WORDS = {"local", "lan", "localnet", "the local network", "local network", "internal"}
INTERNET_WORDS = {"internet", "the internet", "wan", "outside", "external"}
ALLOW = {"allow", "accept", "pass", "permit"}
BLOCK = {"block", "deny", "drop", "reject"}


class FirewallError(ValueError):
    pass


@dataclass
class Addr:
    nets: list = field(default_factory=list)   # ip_network; empty with neither flag = any
    local: bool = False                        # the local network (private addresses)
    internet: bool = False                     # anything outside it

    def any(self) -> bool:
        return not self.nets and not self.local and not self.internet

    def match(self, ip, is_local: bool) -> bool:
        if self.any():
            return True
        if self.local and is_local or self.internet and not is_local:
            return True
        return any(ip.version == n.version and ip in n for n in self.nets)

    def text(self) -> str:
        if self.any():
            return "anywhere"
        parts = [str(n.network_address) if n.num_addresses == 1 else str(n) for n in self.nets]
        parts += (["the local network"] if self.local else []) + (["the internet"] if self.internet else [])
        return ", ".join(parts)


@dataclass
class Rule:
    line: int
    text: str
    action: str                     # allow or block
    direction: str = "any"          # in, out or any
    proto: str = "any"              # tcp, udp, icmp or any
    src: Addr = field(default_factory=Addr)
    dst: Addr = field(default_factory=Addr)
    sport: list | None = None       # [(lo, hi)]; None = any
    dport: list | None = None
    quick: bool = False
    syntax: str = "words"
    family: int = 0                 # 4, 6 or 0 (both)

    def reads(self) -> str:
        what = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}.get(self.proto, "connections")
        where = {"in": " coming in", "out": " going out"}.get(self.direction, "")
        s = f"{'Allow' if self.action == 'allow' else 'Block'} {what}{where}"
        if not self.src.any():
            s += f" from {self.src.text()}"
        if not self.dst.any():
            s += f" to {self.dst.text()}"
        if self.dport:
            s += f" on port {_ports_text(self.dport)}"
        if self.sport:
            s += f" from port {_ports_text(self.sport)}"
        if self.family:
            s += f" (IPv{self.family} only)"
        return s + (" (stops here: quick)" if self.quick else "")


def _ports_text(ports: list) -> str:
    return ", ".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ports)


# ------------------------------------------------------------------ parsing pieces

def _port_value(tok: str) -> int:
    tok = tok.strip().lower()
    if tok in PORT_NAMES:
        return PORT_NAMES[tok]
    if not tok.isdigit() or not 0 <= int(tok) <= 65535:
        raise FirewallError(f"{tok!r} isn't a port number or a known service name")
    return int(tok)


def _ports(text: str) -> list:
    """22 · 22,80 · 1000:2000 · 1000-2000 · ssh · {22 80}"""
    out = []
    for part in re.split(r"[,\s]+", text.strip().strip("{}").strip()):
        if not part:
            continue
        m = re.fullmatch(r"([\w-]+)[:-](\w+)", part) if part.lower() not in PORT_NAMES else None
        if m and m.group(1).isdigit():
            lo, hi = _port_value(m.group(1)), _port_value(m.group(2))
            out.append((min(lo, hi), max(lo, hi)))
        else:
            v = _port_value(part)
            out.append((v, v))
    if not out:
        raise FirewallError("no port given")
    return out


def _addr(tokens: list[str]) -> Addr:
    """any · 10.0.0.0/24 · 10.0.0.5 · {a, b} · the internet · the local network"""
    text = " ".join(tokens).strip().strip("{}").strip().lower()
    if text in ("any", "all", "anywhere", "0.0.0.0/0", "::/0", "*"):
        return Addr()
    if text in LOCAL_WORDS:
        return Addr(local=True)
    if text in INTERNET_WORDS:
        return Addr(internet=True)
    nets = []
    for part in re.split(r"[,\s]+", text):
        if not part:
            continue
        if part.startswith(("<", "(", "!")):
            raise FirewallError(f"{part!r}: tables, interface addresses and negation aren't supported in a dry run")
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            raise FirewallError(f"{part!r} isn't an address or a network") from None
    return Addr(nets=nets)


def _proto(tok: str) -> str:
    tok = tok.lower()
    if tok in ("tcp", "udp", "icmp"):
        return tok
    if tok in ("ip", "all", "any", "ipv4", "ipv6"):
        return "any"
    if tok in ("icmpv6", "ipv6-icmp"):
        return "icmp"
    raise FirewallError(f"protocol {tok!r} isn't one a dry run can judge (tcp, udp, icmp or any)")


# ------------------------------------------------------------------ the syntaxes

def _words_or_pf(line: int, text: str, toks: list[str]) -> Rule:
    """allow|block|pass|deny [in|out] [quick] [log] [on IF] [inet|inet6] [proto] [P] [from X [port N]] [to Y [port N]] [port N]"""
    action_word = toks[0].lower()
    r = Rule(line, text, "allow" if action_word in ALLOW else "block", syntax="pf" if action_word == "pass" else "words")
    i = 1
    stop = {"from", "to", "port", "proto", "in", "out", "quick", "log", "on", "inet", "inet6", "all", "keep", "flags", "modulate"}
    while i < len(toks):
        t = toks[i].lower()
        if t in ("in", "out"):
            r.direction = t
        elif t == "quick":
            r.quick, r.syntax = True, "pf"
        elif t in ("log", "all", "return", "drop"):
            pass
        elif t == "on":
            i += 1  # (the interface: one firewall here, so any)
            r.syntax = "pf"
        elif t in ("inet", "inet6"):
            r.family = 4 if t == "inet" else 6
        elif t == "proto":
            i += 1
            r.proto = _proto(toks[i]) if i < len(toks) else "any"
        elif t in ("tcp", "udp", "icmp", "ip") or (t == "any" and i + 1 < len(toks) and toks[i + 1].lower() in ("from", "to")):
            r.proto = _proto(t)
        elif t in ("from", "to"):
            j = i + 1
            if j < len(toks) and toks[j].startswith("{"):
                while j < len(toks) and not toks[j].endswith("}"):
                    j += 1
            elif j < len(toks) and toks[j].lower() == "the":
                j += 1
            if j >= len(toks):
                raise FirewallError(f"'{t}' needs an address")
            # (“the local network” / “the internet” are several words)
            end = j + 1
            while end < len(toks) and toks[end].lower() not in stop:
                end += 1
            addr = _addr(toks[i + 1:end])
            ports = None
            if end + 1 < len(toks) and toks[end].lower() == "port":
                k = end + 1
                if toks[k].startswith("{"):
                    while k < len(toks) and not toks[k].endswith("}"):
                        k += 1
                ports = _ports(" ".join(toks[end + 1:k + 1]))
                end = k + 1
            if t == "from":
                r.src, r.sport = addr, ports or r.sport
            else:
                r.dst, r.dport = addr, ports or r.dport
            i = end
            continue
        elif t == "port":
            k = i + 1
            if k < len(toks) and toks[k].startswith("{"):
                while k < len(toks) and not toks[k].endswith("}"):
                    k += 1
            if k >= len(toks):
                raise FirewallError("'port' needs a number")
            r.dport = _ports(" ".join(toks[i + 1:k + 1]))
            i = k + 1
            continue
        elif t in ("keep", "state", "flags", "modulate", "synproxy"):
            break  # (pf's state options: every rule is judged statefully here anyway)
        else:
            raise FirewallError(f"didn't understand {toks[i]!r}")
        i += 1
    return r


def _iptables(line: int, text: str, toks: list[str], defaults: dict) -> Rule | None:
    if toks and toks[0] in ("iptables", "ip6tables", "sudo"):
        family = 6 if "ip6tables" in toks[:2] else 4
        toks = [t for t in toks if t not in ("iptables", "ip6tables", "sudo")]
    else:
        family = 0
    opts: dict[str, str] = {}
    i = 0
    chain = ""
    while i < len(toks):
        t = toks[i]
        if t == "!":
            raise FirewallError("negation (!) isn't supported in a dry run")
        if t in ("-A", "--append", "-I", "--insert"):
            chain = toks[i + 1] if i + 1 < len(toks) else ""
            i += 2
            if i < len(toks) and toks[i].isdigit():
                i += 1
            continue
        if t in ("-P", "--policy"):
            if i + 2 >= len(toks):
                raise FirewallError("-P needs a chain and a policy")
            ch, pol = toks[i + 1].upper(), toks[i + 2].upper()
            action = "allow" if pol == "ACCEPT" else "block"
            for d in {"INPUT": ["in"], "OUTPUT": ["out"], "FORWARD": ["in", "out", "internal"]}.get(ch, []):
                defaults[d] = (action, f"iptables -P {ch} {pol}")
            return None
        if t.startswith("-") and i + 1 < len(toks):
            opts[t] = toks[i + 1]
            i += 2
            continue
        i += 1
    if not chain:
        raise FirewallError("an iptables rule needs -A CHAIN (or -P CHAIN POLICY)")
    target = opts.get("-j", opts.get("--jump", "")).upper()
    if target in ("ACCEPT",):
        action = "allow"
    elif target in ("DROP", "REJECT"):
        action = "block"
    elif target == "LOG":
        raise FirewallError("-j LOG only logs: it doesn't allow or block")
    else:
        raise FirewallError(f"-j {target or '(none)'}: only ACCEPT, DROP and REJECT can be judged (not jumps to other chains)")
    state = opts.get("--state") or opts.get("--ctstate")
    if state and "NEW" not in state.upper().split(","):
        raise FirewallError("a rule for ESTABLISHED/RELATED traffic only: replies always follow their connection here")
    direction = {"INPUT": "in", "OUTPUT": "out", "FORWARD": "any"}.get(chain.upper())
    if direction is None:
        raise FirewallError(f"chain {chain!r}: only INPUT, OUTPUT and FORWARD are judged")
    r = Rule(line, text, action, direction=direction, syntax="iptables", family=family)
    if "-p" in opts or "--protocol" in opts:
        r.proto = _proto(opts.get("-p") or opts["--protocol"])
    for key, side in (("-s", "src"), ("--source", "src"), ("-d", "dst"), ("--destination", "dst")):
        if key in opts:
            setattr(r, side, _addr([opts[key].replace(",", " ")]))
    for key, side in (("--dport", "dport"), ("--destination-port", "dport"), ("--dports", "dport"),
                      ("--sport", "sport"), ("--source-port", "sport"), ("--sports", "sport")):
        if key in opts:
            setattr(r, side, _ports(opts[key]))
    return r


def _ufw(line: int, text: str, toks: list[str], defaults: dict) -> Rule | None:
    toks = [t for t in toks if t not in ("sudo", "ufw")]
    if not toks:
        raise FirewallError("an empty ufw command")
    if toks[0].lower() == "default":
        if len(toks) < 2:
            raise FirewallError("ufw default needs allow, deny or reject")
        action = "allow" if toks[1].lower() in ALLOW else "block"
        which = toks[2].lower() if len(toks) > 2 else "incoming"
        for d in {"incoming": ["in"], "outgoing": ["out"], "routed": ["in", "out", "internal"]}.get(which, ["in"]):
            defaults[d] = (action, " ".join(["ufw", *toks]))
        return None
    if toks[0].lower() in ("insert", "prepend"):
        toks = toks[2:] if toks[0].lower() == "insert" else toks[1:]
    action_word = toks[0].lower()
    if action_word == "limit":
        raise FirewallError("ufw limit only slows repeated connections: it doesn't block them outright")
    if action_word not in ALLOW | BLOCK:
        raise FirewallError(f"ufw {toks[0]}: only allow, deny and reject can be judged")
    rest = toks[1:]
    # ufw deny 23/tcp, ufw allow ssh, ufw deny out 25
    simple = [t for t in rest if t.lower() not in ("in", "out")]
    if len(simple) == 1 and not simple[0].lower().startswith(("from", "to")):
        port, _, proto = simple[0].partition("/")
        r = Rule(line, text, "allow" if action_word in ALLOW else "block", syntax="ufw")
        r.direction = "out" if "out" in [t.lower() for t in rest] else "in"
        r.dport = _ports(port)
        r.proto = _proto(proto) if proto else "any"
        return r
    r = _words_or_pf(line, text, [action_word] + [t for t in rest])
    r.syntax = "ufw"
    if r.direction == "any":
        r.direction = "in"  # (ufw rules are incoming unless they say out)
    return r


def _cisco(line: int, text: str, toks: list[str]) -> Rule:
    if toks[0].lower() == "access-list":
        toks = toks[2:]  # (the list's number or name)
    if toks and toks[0].isdigit():
        toks = toks[1:]  # (a sequence number in a named list)
    if not toks or toks[0].lower() not in ("permit", "deny"):
        raise FirewallError("an access list entry is permit or deny")
    r = Rule(line, text, "allow" if toks[0].lower() == "permit" else "block", syntax="cisco")
    if len(toks) < 2:
        raise FirewallError("permit/deny needs a protocol")
    r.proto = _proto(toks[1])
    i = 2

    def address():
        nonlocal i
        if i >= len(toks):
            raise FirewallError("an address is missing")
        t = toks[i].lower()
        if t == "any":
            i += 1
            return Addr()
        if t == "host":
            i += 2
            return _addr([toks[i - 1]])
        ip = toks[i]
        if i + 1 < len(toks) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", toks[i + 1]):
            wild = int(ipaddress.ip_address(toks[i + 1]))
            inv = (~wild) & 0xFFFFFFFF
            prefix = bin(inv).count("1")
            if inv != ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF):
                raise FirewallError(f"wildcard {toks[i + 1]} isn't a contiguous mask")
            i += 2
            return Addr(nets=[ipaddress.ip_network(f"{ip}/{prefix}", strict=False)])
        i += 1
        return _addr([ip])

    def ports():
        nonlocal i
        if i >= len(toks):
            return None
        op = toks[i].lower()
        if op == "eq":
            i += 2
            return [(_port_value(toks[i - 1]),) * 2]
        if op == "range":
            i += 3
            lo, hi = _port_value(toks[i - 2]), _port_value(toks[i - 1])
            return [(lo, hi)]
        if op == "gt":
            i += 2
            return [(_port_value(toks[i - 1]) + 1, 65535)]
        if op == "lt":
            i += 2
            return [(0, _port_value(toks[i - 1]) - 1)]
        if op == "neq":
            i += 2
            v = _port_value(toks[i - 1])
            return [(0, v - 1), (v + 1, 65535)]
        return None

    r.src = address()
    r.sport = ports()
    r.dst = address()
    r.dport = ports()
    extra = [t.lower() for t in toks[i:]]
    if extra and not set(extra) <= {"log", "established", "log-input"}:
        raise FirewallError(f"didn't understand {' '.join(toks[i:])!r}")
    if "established" in extra:
        raise FirewallError("'established' matches replies only: replies always follow their connection here")
    return r


def parse(text: str) -> dict:
    """{"rules": [Rule], "defaults": {direction: (action, why)}, "errors": [{line, text, error}], "semantics"}"""
    if not isinstance(text, str):
        raise FirewallError("the rules are text, one per line")
    rules: list[Rule] = []
    errors: list[dict] = []
    defaults: dict[str, tuple[str, str]] = {}
    cisco = False
    lines = text.splitlines()[:MAX_RULES]
    for n, raw in enumerate(lines, 1):
        line = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", raw).strip()[:MAX_LINE]
        if not line or line.startswith(("#", "!", "//")) or line.lower().startswith(("ip access-list", "interface ", "exit")):
            continue
        line = line.split(" #", 1)[0].strip()
        toks = line.replace("{", " { ").replace("}", " } ").split()
        toks = _join_braces(toks)
        head = toks[0].lower()
        try:
            if head in ("iptables", "ip6tables", "sudo") and "ufw" not in toks[:2] or head.startswith("-"):
                r = _iptables(n, line, toks, defaults)
            elif head == "ufw" or (head == "sudo" and "ufw" in toks[:2]):
                r = _ufw(n, line, toks, defaults)
            elif head == "access-list" or head in ("permit", "deny") and len(toks) > 2 and toks[2].lower() in ("any", "host") \
                    or (head.isdigit() and len(toks) > 1 and toks[1].lower() in ("permit", "deny")):
                r = _cisco(n, line, toks)
                cisco = True
            elif head == "default":
                if len(toks) < 2 or toks[1].lower() not in ALLOW | BLOCK:
                    raise FirewallError("default allow or default block")
                action = "allow" if toks[1].lower() in ALLOW else "block"
                which = toks[2].lower() if len(toks) > 2 else "all"
                which_dirs = {"in": ["in"], "incoming": ["in"], "out": ["out"], "outgoing": ["out"]}
                for d in which_dirs.get(which, ["in", "out", "internal"]):
                    defaults[d] = (action, line)
                r = None
            elif head in ALLOW | BLOCK:
                r = _words_or_pf(n, line, toks)
            else:
                raise FirewallError("start with allow or block (or paste iptables, ufw, pf or Cisco access-list lines)")
        except (FirewallError, IndexError) as exc:
            why = str(exc) if isinstance(exc, FirewallError) else "the line ends too soon"
            errors.append({"line": n, "text": line, "error": why})
            continue
        if r is not None:
            rules.append(r)
    pf = any(r.syntax == "pf" for r in rules)
    if cisco and not any(r.action == "allow" and r.src.any() and r.dst.any() and r.proto == "any" and not r.dport for r in rules):
        for d in ("in", "out", "internal"):
            defaults.setdefault(d, ("block", "the implicit “deny any” at the end of every Cisco access list"))
    return {"rules": rules, "defaults": defaults, "errors": errors,
            "semantics": ("pf: the last matching rule wins, unless a quick rule matches first" if pf
                          else "the first matching rule wins")}


def _join_braces(toks: list[str]) -> list[str]:
    out, buf = [], None
    for t in toks:
        if t == "{":
            buf = []
        elif t == "}" and buf is not None:
            out.append("{" + " ".join(buf) + "}")
            buf = None
        elif buf is not None:
            buf.append(t.strip(","))
        else:
            out.append(t)
    return out + (buf or [])


# ------------------------------------------------------------------ judging the capture

LOCAL_SCOPES = {"private", "link-local", "cgnat", "loopback", "multicast", "broadcast", "unspecified"}


def _is_local(ip) -> bool:
    """On the local network (as the map counts it: documentation ranges stand in for the internet)."""
    return netmap.scope_of(str(ip)) in LOCAL_SCOPES


def _service(port: int, app: str | None) -> str:
    if port in EXTRA_SERVICES:
        return EXTRA_SERVICES[port]
    for _, name, ports, apps in policy.SERVICES:
        if name in ("web", "databases", "unencrypted protocols"):
            continue
        if port in ports or (app and app in apps):
            return name
    return f"port {port}"


def _in_ports(port: int, ranges: list | None) -> bool:
    return ranges is None or any(lo <= port <= hi for lo, hi in ranges)


def _matches(r: Rule, direction: str, proto: str, src, dst, src_local: bool, dst_local: bool, sport: int, dport: int) -> bool:
    if r.direction != "any" and r.direction != direction:
        return False
    if r.proto != "any" and r.proto != proto:
        return False
    if r.family and src.version != r.family:
        return False
    return (r.src.match(src, src_local) and r.dst.match(dst, dst_local)
            and _in_ports(sport, r.sport) and _in_ports(dport, r.dport))


def _decide(parsed: dict, direction: str, *args) -> tuple[str, Rule | None, str]:
    """(action, deciding rule or None, why) for one direction of one connection."""
    rules = parsed["rules"]
    pf = parsed["semantics"].startswith("pf")
    chosen = None
    for r in rules:
        if _matches(r, direction, *args):
            chosen = r
            if not pf or r.quick:
                break
    if chosen:
        return chosen.action, chosen, f"line {chosen.line}"
    action, why = parsed["defaults"].get(direction, ("allow", "nothing matched, and a firewall passes what no rule blocks"))
    return action, None, why


def crossing(s: dict, placement: str) -> str | None:
    """How a connection meets the firewall: "in", "out", "both" (on every device), "unseen" (a border
    firewall never sees it: inside the network, or between two outside hosts) or None (not TCP/UDP)."""
    if s.get("proto") not in ("tcp", "udp"):
        return None
    try:
        sl, dl = _is_local(ipaddress.ip_address(s["src_ip"])), _is_local(ipaddress.ip_address(s["dst_ip"]))
    except (KeyError, ValueError):
        return None
    if placement == "host":
        return "both"
    return "out" if sl and not dl else "in" if dl and not sl else "unseen"


def judge(parsed: dict, s: dict, placement: str) -> tuple[str, Rule | None, str]:
    """(allow|block, the deciding rule or None, why) for one connection the firewall sees."""
    src, dst = ipaddress.ip_address(s["src_ip"]), ipaddress.ip_address(s["dst_ip"])
    args = (s["proto"], src, dst, _is_local(src), _is_local(dst), int(s.get("src_port") or 0), int(s.get("dst_port") or 0))
    if placement == "border":
        return _decide(parsed, crossing(s, placement), *args)
    action, rule, why = _decide(parsed, "out", *args)  # (the same rules on every device: outgoing at the sender,
    if action == "allow":                               # incoming at the receiver)
        action, rule, why = _decide(parsed, "in", *args)
    return action, rule, why


def _size(s: dict) -> int:
    return int((s.get("c2s") or {}).get("payload_bytes", 0)) + int((s.get("s2c") or {}).get("payload_bytes", 0))


def consequences(sessions: list[dict], blocked: dict[int, str], placement: str, alerts: list[dict] | None = None) -> dict:
    """What blocking some connections would do: `blocked` maps id(session) to what blocked it.
    Totals, the blocked connections grouped, what would break (by service), and the alerts stopped,
    still getting through, or out of a border firewall's sight."""
    totals = {"connections": 0, "bytes": 0, "blocked": 0, "blocked_bytes": 0, "unseen": 0, "not_judged": 0}
    groups: dict[tuple, dict] = {}
    services: dict[str, dict] = {}
    verdicts: dict[tuple, list[bool]] = defaultdict(list)
    unseen: set[tuple] = set()
    for s in sessions:
        how = crossing(s, placement)
        if how is None:
            totals["not_judged"] += 1
            continue
        dport, proto = int(s.get("dst_port") or 0), s["proto"]
        if how == "unseen":
            totals["unseen"] += 1
            unseen.add((s["src_ip"], s["dst_ip"], dport))
            continue
        size = _size(s)
        totals["connections"] += 1
        totals["bytes"] += size
        by = blocked.get(id(s))
        verdicts[(s["src_ip"], s["dst_ip"], dport, proto)].append(by is not None)
        if by is None:
            continue
        totals["blocked"] += 1
        totals["blocked_bytes"] += size
        name = _service(dport, s.get("app"))
        key = (s["src_ip"], s["dst_ip"], dport, proto)
        g = groups.get(key)
        if g is None:
            v = "ipv6" if ":" in s["src_ip"] else "ip"
            g = groups[key] = {"what": f"{s['src_ip']} \u2192 {s['dst_ip']}:{dport} ({name})", "service": name, "sessions": 0,
                               "bytes": 0, "by": by,
                               "filter": f"{v}.addr == {s['src_ip']} && {v}.addr == {s['dst_ip']} && {proto}.port == {dport}"}
        g["sessions"] += 1
        g["bytes"] += size
        sv = services.setdefault(name, {"service": name, "sessions": 0, "bytes": 0, "devices": set(), "example": g["what"]})
        sv["sessions"] += 1
        sv["bytes"] += size
        sv["devices"].update(x for x in (s["src_ip"], s["dst_ip"]) if _is_local(ipaddress.ip_address(x)))
    ordered = sorted(groups.values(), key=lambda g: (-g["sessions"], -g["bytes"]))
    breaks = sorted(({**v, "devices": len(v["devices"])} for v in services.values()), key=lambda v: -v["sessions"])
    stopped, through, inside = [], [], []
    for a in alerts or []:
        if (a.get("triage") or {}).get("status") == "false_positive" or a.get("severity") not in ("critical", "high", "medium"):
            continue

        def same(src, dst, port, a=a):
            return src == a.get("src_ip") and dst == a.get("dst_ip") and (not a.get("dst_port") or port == a.get("dst_port"))
        vs = [v for (src, dst, port, _), xs in verdicts.items() for v in xs if same(src, dst, port)]
        entry = {"id": a["id"], "title": a.get("title"), "severity": a.get("severity"),
                 "what": f"{a.get('src_ip')} \u2192 {a.get('dst_ip')}" + (f":{a['dst_port']}" if a.get("dst_port") else ""),
                 "blocked": sum(vs), "connections": len(vs)}
        if vs:
            (stopped if all(vs) else through).append(entry)
        elif any(same(*u) for u in unseen):
            inside.append(entry)
    return {"totals": totals, "blocked": ordered[:MAX_GROUPS], "blocked_groups": len(ordered), "breaks": breaks[:20],
            "alerts": {"stopped": stopped, "through": through, "inside": inside}}


def run(text: str, sessions: list[dict], alerts: list[dict] | None = None, placement: str = "border") -> dict:
    """The firewall lines alone, replayed (rules.py combines them with the plain-words rules)."""
    if placement not in ("border", "host"):
        raise FirewallError("the firewall sits at the border or on every device")
    parsed = parse(text)
    hits: dict[int, int] = defaultdict(int)
    blocked: dict[int, str] = {}
    for s in sessions:
        if crossing(s, placement) in (None, "unseen"):
            continue
        action, rule, why = judge(parsed, s, placement)
        if rule:
            hits[rule.line] += 1
        if action == "block":
            blocked[id(s)] = f"line {rule.line}" if rule else why
    rules_out = [{"line": r.line, "text": r.text, "reads": r.reads(), "syntax": r.syntax, "hits": hits.get(r.line, 0)}
                 for r in parsed["rules"]]
    return {"placement": placement, "semantics": parsed["semantics"], "rules": rules_out, "errors": parsed["errors"],
            "defaults": {d: {"action": a, "why": w} for d, (a, w) in parsed["defaults"].items()},
            **consequences(sessions, blocked, placement, alerts)}
