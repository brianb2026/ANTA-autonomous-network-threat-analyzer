"""Network rules: the policy tests and the firewall dry run in one list. Each line is a rule in
plain words ("block 10.0.0.5", "no ubuntu hosts on the network", "don't let router configs be
uploaded", "only 10.0.0.1 answers DNS") or a firewall line (plain firewall words, iptables,
ufw, pf, Cisco access lists). Every rule is both:

  a test: does this capture break it? (the connections or hosts that do, each with its packets)
  a firewall rule: enforced, what would it block? All the rules are enforced together, and the
  summary says what would be blocked, what would break, and which alerts would be stopped.

Some rules can't be enforced by a firewall (a byte count, a number of hosts) and say so; some
need more than a firewall (keeping hosts off the network takes the switch; reading what a file
transfer carries takes a proxy) and say that too. Nothing touches a real firewall.
"""
from __future__ import annotations

import re
from collections import defaultdict

from . import firewall, policy

FIREWALL_HEADS = {"iptables", "ip6tables", "ufw", "sudo", "access-list", "pass", "permit", "default"}

# Everything a rule can say, by topic: the in-app guide ("What can I write?"), the examples menu,
# and the "Did you mean…" suggestions all come from this list.
REFERENCE: list[tuple[str, str, list[tuple[str, str]]]] = [
    ("Block things", "Everything to and from something, in either direction.", [
        ("block 10.0.0.5", "an address"), ("block 10.0.0.0/24", "a network"), ("block example.com", "a site, by name"),
        ("block China", "a country (the location table)"), ("block telnet", "a service"), ("block port 4444", "a port"),
        ("block smb to the internet", "a service, only towards somewhere"), ("block 10.0.0.5 from the internet", "a host from somewhere"),
        ("block printers from the internet", "a kind of device from somewhere"), ("block ubuntu hosts", "every host of a kind"),
        ("block uploads of router configs", "a kind of file"),
    ]),
    ("Keep devices off the network", "Hosts recognised by their system, maker or kind.", [
        ("no ubuntu hosts on the network", "an operating system"), ("don't let windows xp machines on the network", "an old system"),
        ("keep kali hosts off the network", "a hacking distribution"), ("no raspberry pi devices", "a maker"),
        ("no iot devices on the network", "a kind of device"), ("no unknown devices", "anything not remembered as normal"),
    ]),
    ("Files", "What connections carried: router configurations, programs, scripts, archives, documents, database dumps, files.", [
        ("don't let router configs be uploaded", "configurations backed up off the device"),
        ("no programs downloaded from the internet", "executables"), ("no files uploaded to the internet", "anything going out"),
        ("no database dumps uploaded", "SQL dumps and backups"), ("no file uploads over ftp", "one protocol"),
        ("no scripts downloaded", "PowerShell, batch, shortcuts"),
    ]),
    ("Who may talk to whom", "Addresses, networks, kinds of devices, systems, sites, the internet, countries.", [
        ("10.0.0.5 cannot talk to 10.0.0.9", "either direction"), ("10.0.0.5 cannot connect to 10.0.0.9", "only what 10.0.0.5 starts"),
        ("no traffic between 10.0.0.0/24 and 10.0.1.0/24", "two networks"), ("printers only talk to 10.0.0.0/24", "allowed places only"),
        ("ubuntu hosts cannot talk to the internet", "a kind of host"), ("nothing talks to 203.0.113.0/24", "a place nobody may reach"),
        ("no device connects to North Korea", "a country"),
    ]),
    ("Services", "DNS, DHCP, NTP, HTTP(S), SSH, Telnet, FTP, TFTP, SMB, RDP, VNC, email, LDAP, SNMP, databases, ports…", [
        ("nothing uses telnet", "a service nobody may use"), ("only 10.0.0.1 answers DNS", "the only allowed server"),
        ("only 10.0.0.0/24 may use SSH", "the only allowed users"), ("printers only use port 9100", "a device's only services"),
        ("no host connects to the internet over SMB", "a service towards somewhere"), ("nothing connects to port 4444", "a port"),
    ]),
    ("Encryption", "", [("all web traffic is encrypted", "no plain HTTP"), ("no passwords in clear text", "logins sent unencrypted")]),
    ("How much", "Tests only: a firewall can't count bytes or hosts.", [
        ("no host uploads more than 100 MB to the internet", "data out"), ("no host downloads more than 2 GB", "data in"),
        ("no host talks to more than 50 hosts", "spread"),
    ]),
    ("When", "In your computer's time zone.", [
        ("no traffic between 22:00 and 06:00", "a span of the day"), ("nothing talks at night", "22:00 to 06:00"),
        ("servers are never active on weekends", "Saturday and Sunday"), ("no traffic outside 7:00-19:00", "working hours only"),
    ]),
    ("Firewall lines", "Ordered: the first matching line wins (pf: the last, unless quick). Allow lines make exceptions.", [
        ("block in tcp to any port 23", "plain firewall words: allow/block, in/out, tcp/udp, from, to, port"),
        ("allow out to the internet port 443", "an allow line"), ("default block in", "what happens when no line matches"),
        ("iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT", "iptables (INPUT, OUTPUT, FORWARD)"),
        ("iptables -P INPUT DROP", "an iptables chain's policy"), ("ufw deny 23/tcp", "ufw"), ("ufw default deny incoming", "ufw's default"),
        ("block in quick proto tcp from any to any port {22 3389}", "pf"), ("access-list 101 deny tcp any any eq 23", "a Cisco access list"),
    ]),
]


def reference() -> list[dict]:
    return [{"group": g, "about": about, "examples": [{"text": t, "means": m} for t, m in items]} for g, about, items in REFERENCE]


def _words(text: str) -> set[str]:
    t = re.sub(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?", " ADDR ", text.lower())
    return {w for w in re.findall(r"[a-z]+|ADDR", t) if w not in ("the", "a", "an", "to", "of", "on", "be", "is", "are")}


def suggest(text: str, n: int = 2) -> list[str]:
    """The examples closest to a line that couldn't be read, with its own address put in."""
    mine = _words(text)
    if not mine:
        return []
    addr = re.search(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?", text)
    scored = []
    for _, _, items in REFERENCE:
        for example, _ in items:
            theirs = _words(example)
            score = len(mine & theirs) / len(mine | theirs)
            if score > 0.15:
                if addr:
                    example = re.sub(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?", addr.group(0), example, count=1)
                scored.append((score, example))
    return [e for _, e in sorted(scored, key=lambda x: -x[0])[:n]]


def classify(text: str) -> tuple[str, dict | str | None]:
    """("firewall", None), ("words", the parsed rule), ("note", None) or ("error", why)."""
    t = text.strip()
    if not t or t.startswith("#"):
        return "note", None
    fw = firewall.parse(t)
    if fw["rules"] or (fw["defaults"] and not fw["errors"]):
        return "firewall", None
    try:
        return "words", policy.parse(t)
    except policy.PolicyError as exc:
        head = t.split()[0].lower()
        if (head in FIREWALL_HEADS or head.startswith("-")) and fw["errors"]:
            return "error", fw["errors"][0]["error"]
        return "error", str(exc)


def _group(sessions: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for s in sessions:
        key = (s["src_ip"], s["dst_ip"], s.get("dst_port"), s.get("proto"))
        g = groups.get(key)
        if g is None:
            v = "ipv6" if ":" in s["src_ip"] else "ip"
            g = groups[key] = {"what": f"{s['src_ip']} → {s['dst_ip']}:{s.get('dst_port')} "
                                       f"({firewall._service(int(s.get('dst_port') or 0), s.get('app'))})",
                               "sessions": 0, "bytes": 0, "first": s.get("start") or 0, "last": s.get("end") or 0,
                               "filter": f"{v}.addr == {s['src_ip']} && {v}.addr == {s['dst_ip']} && "
                                         f"{s.get('proto')}.port == {s.get('dst_port')}"}
        g["sessions"] += 1
        g["bytes"] += firewall._size(s)
        g["first"] = min(g["first"], s.get("start") or 0)
        g["last"] = max(g["last"], s.get("end") or 0)
    return sorted(groups.values(), key=lambda g: (-g["sessions"], -g["bytes"]))[:policy.MAX_GROUPS]


def evaluate(lines: list[str], ctx: policy.Context, alerts: list[dict] | None = None, placement: str = "border") -> tuple[list, dict]:
    """(results per line, what enforcing them all would do)."""
    if placement not in policy.PLACEMENTS:
        placement = "border"
    kinds = [classify(line) for line in lines]
    parsed = firewall.parse("\n".join(line if k == "firewall" else "" for line, (k, _) in zip(lines, kinds, strict=True)))
    has_fw = bool(parsed["rules"] or parsed["defaults"])
    blocked: dict[int, str] = {}
    fw_hits: dict[int, list[dict]] = defaultdict(list)
    if has_fw:
        for s in ctx.sessions:
            if firewall.crossing(s, placement) in (None, "unseen"):
                continue
            action, rule, why = firewall.judge(parsed, s, placement)
            if rule:
                fw_hits[rule.line].append(s)
            if action == "block":
                blocked[id(s)] = f"line {rule.line}" if rule else f"no line matched: {why}"
    results = []
    for n, (line, (kind, payload)) in enumerate(zip(lines, kinds, strict=True), 1):
        if kind == "note":
            continue
        item: dict = {"rule": line, "line": n}
        if kind == "error":
            item.update(understood=False, error=payload, status="unknown", suggestions=suggest(line))
        elif kind == "firewall":
            fr = next((r for r in parsed["rules"] if r.line == n), None)
            if fr is None:
                item.update(understood=True, kind="firewall", syntax="default", status="pass", violations=0, groups=[],
                            reads="What happens when no firewall line matches (see the summary)",
                            enforce={"blocks": 0})
            else:
                hit = fw_hits.get(n, [])
                block = fr.action == "block"
                item.update(understood=True, kind="firewall", syntax=fr.syntax, reads=fr.reads(),
                            status="fail" if block and hit else "pass", violations=len(hit) if block else 0,
                            groups=_group(hit) if block else [],
                            enforce={"blocks": len(hit)} if block else {"allows": len(hit)})
        else:
            res = policy.check(payload, ctx)
            bad = res.pop("_sessions", None)
            note = res.pop("enforce", "")
            item.update(understood=True, reads=payload["reads"], kind=payload["kind"], **res)
            if bad is None:
                item["enforce"] = {"test_only": note}
            else:
                stoppable = [s for s in bad if firewall.crossing(s, placement) not in (None, "unseen")]
                for s in stoppable:
                    blocked.setdefault(id(s), f"line {n}")
                item["enforce"] = {"blocks": len(stoppable), "inside": len(bad) - len(stoppable), "note": note}
        if item.get("groups"):
            item["filter"] = " || ".join(f"({g['filter']})" for g in item["groups"][:policy.MAX_GROUPS] if g.get("filter"))
        results.append(item)
    summary = firewall.consequences(ctx.all_sessions, blocked, placement, alerts)
    summary.update(placement=placement, semantics=parsed["semantics"] if has_fw else "",
                   defaults={d: {"action": a, "why": w} for d, (a, w) in parsed["defaults"].items()})
    return results, summary
