"""Indicator sweep: look for a list of indicators of compromise in every session of
a capture and say where each one turned up.

Indicators are pasted the way threat reports print them, one or several per line,
defanged or not: IPv4/IPv6 addresses (optionally with a port), networks in CIDR
form, domains (a domain also matches its subdomains), URLs, SHA-256 file hashes,
JA3 and JA4 TLS fingerprints, and file names (prefixed `file:`). Everything is
matched locally against the capture's session index; nothing is looked up online.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

MAX_INDICATORS = 500
MAX_ROWS = 50          # example sessions kept per indicator
MAX_FILTER_FLOWS = 20  # flows a "show packets" filter names

_DEFANG = [(re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
           (re.compile(r"\[:\]"), ":"), (re.compile(r"\[/\]"), "/"),
           (re.compile(r"^hxxp", re.I), "http"), (re.compile(r"^fxp", re.I), "ftp")]
_HEX = re.compile(r"[0-9a-fA-F]+")
_JA4 = re.compile(r"[tqd]\d{2}[di]\d{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}")
_DOMAIN = re.compile(r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}")
_IP_PORT = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})|\[([0-9a-fA-F:]+)\]:(\d{1,5})")

KIND_TEXT = {"ip": "address", "net": "network", "domain": "domain", "url": "URL", "sha256": "SHA-256",
             "ja3": "JA3 (or MD5)", "ja4": "JA4", "file": "file name"}


def refang(s: str) -> str:
    s = s.strip().strip("'\"<>")
    for pattern, repl in _DEFANG:
        s = pattern.sub(repl, s)
    return s


def classify(token: str) -> tuple[dict | None, str | None]:
    """One indicator -> ({value, kind, ...}, None), or (None, why it isn't one)."""
    raw = token
    token = refang(token)
    if not token:
        return None, "empty"
    low = token.lower()
    if low.startswith("file:"):
        name = token[5:].strip()
        return ({"raw": raw, "kind": "file", "value": name.lower()}, None) if name else (None, "no file name")
    m = _IP_PORT.fullmatch(token)
    if m:
        ip, port = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        try:
            addr = str(ipaddress.ip_address(ip))
        except ValueError:
            return None, "not an IP address"
        if not 0 < int(port) < 65536:
            return None, "bad port"
        return {"raw": raw, "kind": "ip", "value": addr, "port": int(port)}, None
    if "/" in token and "://" not in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
            return {"raw": raw, "kind": "net", "value": str(net)}, None
        except ValueError:
            pass
    try:
        return {"raw": raw, "kind": "ip", "value": str(ipaddress.ip_address(token))}, None
    except ValueError:
        pass
    if _HEX.fullmatch(token):
        n = len(token)
        if n == 64:
            return {"raw": raw, "kind": "sha256", "value": low}, None
        if n == 32:
            return {"raw": raw, "kind": "ja3", "value": low}, None
        if n == 40:
            return None, "SHA-1: ANTA hashes files with SHA-256 only"
        return None, f"a {n}-digit hex string isn't a hash ANTA knows"
    if _JA4.fullmatch(low):
        return {"raw": raw, "kind": "ja4", "value": low}, None
    if "://" in token:
        scheme, _, rest = token.partition("://")
        host, slash, path = rest.partition("/")
        host = host.rsplit("@", 1)[-1].split(":")[0].lower().strip("[]")
        if not host:
            return None, "URL without a host"
        return {"raw": raw, "kind": "url", "value": low, "host": host, "path": (slash + path) or "/",
                "scheme": scheme.lower()}, None
    domain = low.rstrip(".").removeprefix("*.")
    if _DOMAIN.fullmatch(domain):
        return {"raw": raw, "kind": "domain", "value": domain}, None
    return None, "not an address, network, domain, URL, hash or fingerprint"


def parse(text: str) -> tuple[list[dict], list[dict]]:
    """Indicators from pasted text; unrecognised tokens are returned with a reason."""
    found, rejected, seen = [], [], set()
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0] if not line.lstrip().lower().startswith(("http", "hxxp")) else line
        for token in re.split(r"[\s,;]+", line.strip()):
            if not token:
                continue
            ind, why = classify(token)
            if ind is None:
                if len(rejected) < 100:
                    rejected.append({"raw": token[:200], "reason": why})
                continue
            key = (ind["kind"], ind["value"], ind.get("port"))
            if key in seen:
                continue
            seen.add(key)
            found.append(ind)
            if len(found) >= MAX_INDICATORS:
                return found, rejected
    return found, rejected


# ----------------------------------------------------------------- matching

def _flow(s: dict) -> str:
    return f"{6 if s['proto'] == 'tcp' else 17},{s['src_ip']},{s['src_port']},{s['dst_ip']},{s['dst_port']}"


def _session_text(s: dict) -> str:
    return f"{s['proto'].upper()} {s['src_ip']}:{s['src_port']} → {s['dst_ip']}:{s['dst_port']}"


def _addr_filter(ip: str) -> str:
    return f"{'ipv6' if ':' in ip else 'ip'}.addr == {ip}"


def flow_filter(flows: list[str]) -> str:
    """A display filter selecting these flows (\"proto,ipA,portA,ipB,portB\"), and the ICMP errors about them."""
    parts = []
    for spec in flows[:MAX_FILTER_FLOWS]:
        proto, a, pa, b, pb = spec.split(",")
        l4 = "tcp" if proto == "6" else "udp"
        parts.append(f"({_addr_filter(a)} && {_addr_filter(b)} && {l4}.port == {pa} && {l4}.port == {pb})")
    return " || ".join(parts)


class Index:
    """Lookups over a capture's sessions, built once per sweep."""

    def __init__(self, sessions: list[dict]):
        self.sessions = sessions
        self.by_ip: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self.names: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self.answers: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self.hashes: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self.files: list[tuple[int, str, str]] = []
        self.ja3: dict[str, list[int]] = defaultdict(list)
        self.ja4: dict[str, list[int]] = defaultdict(list)
        self.urls: list[tuple[int, str, str]] = []  # (session, host, uri)
        for i, s in enumerate(sessions):
            self.by_ip[s["src_ip"]].append((i, "source"))
            self.by_ip[s["dst_ip"]].append((i, "destination"))
            for q in s.get("dns") or []:
                name = str(q.get("qname", "")).lower().rstrip(".")
                if name:
                    self.names[name].append((i, "DNS query"))
                for a in q.get("answers") or []:
                    try:
                        self.answers[str(ipaddress.ip_address(a))].append((i, name))
                    except ValueError:  # a CNAME: the name the query was pointed at
                        target = str(a).lower().rstrip(".")
                        if target:
                            self.names[target].append((i, f"DNS answer (CNAME of {name})"))
            tls = s.get("tls") or {}
            if tls.get("sni"):
                self.names[tls["sni"].lower()].append((i, "TLS server name"))
            if tls.get("ja3"):
                self.ja3[tls["ja3"].lower()].append(i)
            if tls.get("ja4"):
                self.ja4[tls["ja4"].lower()].append(i)
            for h in s.get("http") or []:
                host = str(h.get("host", "")).split(":")[0].lower()
                if host:
                    self.names[host].append((i, "HTTP Host"))
                    self.urls.append((i, host, str(h.get("uri", ""))))
            for f in s.get("http_files") or []:
                name = f.get("filename") or str(f.get("uri", "")).split("?")[0].rsplit("/", 1)[-1]
                self._file(i, f.get("sha256"), name, "HTTP download")
            for f in s.get("smb_files") or []:
                self._file(i, f.get("sha256"), str(f.get("name", "")).replace("\\", "/").rsplit("/", 1)[-1],
                           "SMB " + ("upload" if f.get("op") == "write" else "download"))
            d = s.get("ftp_data")
            if d and d.get("name"):
                self._file(i, d.get("sha256"), str(d["name"]).rsplit("/", 1)[-1],
                           "FTP " + ("upload" if d.get("upload") else "download"))

    def _file(self, i: int, sha: str | None, name: str, how: str) -> None:
        if sha:
            self.hashes[sha.lower()].append((i, f"{name or 'file'} ({how})"))
        if name:
            self.files.append((i, name.lower(), how))

    def matches(self, ind: dict) -> list[tuple[int, str]]:
        kind, value = ind["kind"], ind["value"]
        hits: list[tuple[int, str]] = []
        if kind in ("ip", "net"):
            if kind == "ip":
                ips = [value]
            else:
                net = ipaddress.ip_network(value)
                ips = [ip for ip in set(self.by_ip) | set(self.answers)
                       if ipaddress.ip_address(ip).version == net.version and ipaddress.ip_address(ip) in net]
            for ip in ips:
                for i, role in self.by_ip.get(ip, []):
                    s = self.sessions[i]
                    port = ind.get("port")
                    if port and port not in (s["src_port"], s["dst_port"]):
                        continue
                    hits.append((i, f"{role} address {ip}"))
                if not ind.get("port"):
                    hits += [(i, f"DNS answer {ip} for {name}") for i, name in self.answers.get(ip, [])]
        elif kind == "domain":
            for name, where in self.names.items():
                if name == value or name.endswith("." + value):
                    hits += [(i, f"{w}: {name}") for i, w in where]
        elif kind == "url":
            for i, host, uri in self.urls:
                if (host == ind["host"] or host.endswith("." + ind["host"])) and \
                        (ind["path"] == "/" or uri.lower().startswith(ind["path"])):
                    hits.append((i, f"HTTP request http://{host}{uri[:200]}"))
        elif kind == "sha256":
            hits = [(i, f"file {what}") for i, what in self.hashes.get(value, [])]
        elif kind == "ja3":
            hits = [(i, "JA3 of the client hello") for i in self.ja3.get(value, [])]
        elif kind == "ja4":
            hits = [(i, "JA4 of the client hello") for i in self.ja4.get(value, [])]
        elif kind == "file":
            hits = [(i, f"file {name} ({how})") for i, name, how in self.files
                    if name == value or name.endswith("/" + value)]
        return hits


def _filter_for(ind: dict, flows: list[str]) -> str:
    kind, value = ind["kind"], ind["value"]
    if kind == "ip":
        f = _addr_filter(value)
        if ind.get("port"):
            return f"{f} && (tcp.port == {ind['port']} || udp.port == {ind['port']})"
        return f"{f} || {'dns.aaaa' if ':' in value else 'dns.a'} == {value}"
    if kind == "net":
        return _addr_filter(value)
    if kind == "domain":
        rx = "(^|\\\\.)" + re.escape(value).replace("\\", "\\\\") + "$"
        return " || ".join(f'{field} matches "{rx}"' for field in
                           ("dns.qry.name", "tls.handshake.extensions_server_name", "http.host"))
    return flow_filter(flows)


def _alert_terms(alert: dict) -> set[str]:
    terms = {alert.get("src_ip"), alert.get("dst_ip"), str(alert.get("target") or "").rsplit(":", 1)[0]}
    terms.update(alert.get("addresses") or [])
    f = alert.get("file") or {}
    terms.add(str(f.get("sha256") or "").lower())
    d = alert.get("dns") or {}
    terms.add(str(d.get("name") or "").lower())
    terms.update(d.get("answers") or [])
    stream = alert.get("stream") or {}
    for key in ("sni", "ja3", "ja4"):
        terms.add(str(stream.get(key) or "").lower())
    return {t for t in terms if t}


def _alert_hit(ind: dict, terms: set[str]) -> bool:
    kind, value = ind["kind"], ind["value"]
    if kind == "domain":
        return any(t == value or t.endswith("." + value) for t in terms)
    if kind == "net":
        net = ipaddress.ip_network(value)
        for t in terms:
            try:
                if ipaddress.ip_address(t) in net:
                    return True
            except ValueError:
                continue
        return False
    if kind == "url":
        return ind["host"] in terms
    return value in terms


def sweep(text: str, sessions: list[dict], alerts: list[dict] | None = None) -> dict:
    indicators, rejected = parse(text)
    index = Index(sessions)
    alert_terms = [(a["id"], a.get("title", ""), _alert_terms(a)) for a in alerts or []]
    results = []
    for ind in indicators:
        hits = index.matches(ind)
        by_session: dict[int, list[str]] = defaultdict(list)
        for i, where in hits:
            if where not in by_session[i]:
                by_session[i].append(where)
        order = sorted(by_session, key=lambda i: sessions[i]["start"])
        flows = list(dict.fromkeys(_flow(sessions[i]) for i in order))
        hosts = sorted({h for i in order for h in (sessions[i]["src_ip"], sessions[i]["dst_ip"])})
        rows = [{"ts": sessions[i]["start"], "session": _session_text(sessions[i]), "where": "; ".join(by_session[i]),
                 "flow": _flow(sessions[i])} for i in order[:MAX_ROWS]]
        results.append({
            "indicator": ind["raw"], "kind": ind["kind"], "kind_text": KIND_TEXT[ind["kind"]], "value": ind["value"],
            "hits": len(order), "first": sessions[order[0]]["start"] if order else None,
            "last": max(sessions[i]["end"] for i in order) if order else None,
            "hosts": hosts[:50], "rows": rows,
            "filter": _filter_for(ind, flows) if order or ind["kind"] in ("ip", "net", "domain") else "",
            "alerts": [{"id": aid, "title": title} for aid, title, terms in alert_terms if _alert_hit(ind, terms)],
        })
    results.sort(key=lambda r: (r["hits"] == 0 and not r["alerts"], r["first"] or 0))
    return {"indicators": len(indicators), "matched": sum(1 for r in results if r["hits"] or r["alerts"]),
            "sessions": len(sessions), "results": results, "rejected": rejected}
