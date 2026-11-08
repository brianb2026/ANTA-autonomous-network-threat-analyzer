"""Quick look: what ANTA already knows about something an analyst points at (an address, a
domain name, a MAC address, a file hash, a TLS fingerprint, a URL or a file name), for the
right-click menu and its Quick look card. Read only, from the analysis already done
(the analyzer's state, and the capture's statistics and session index when they have been
read): nothing is looked up outside this computer.
"""
from __future__ import annotations

import ipaddress
import re

from . import devices
from .intel import SOURCES, _norm_url

MAC = re.compile(r"^[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}$", re.I)
HEX = re.compile(r"^[0-9a-f]+$", re.I)
JA4 = re.compile(r"^[tqd][0-9a-z]{2}[di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$", re.I)
JA4S = re.compile(r"^[tqd][0-9a-z]{2}\d{2}[0-9a-z]{2}_[0-9a-f]{4}_[0-9a-f]{12}$", re.I)
DOMAIN = re.compile(r"^(?=.{3,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$", re.I)
# A name ending in one of these is more likely a file than a domain.
FILE_EXT = {"exe", "dll", "js", "vbs", "ps1", "bat", "cmd", "msi", "scr", "jar", "zip", "rar", "7z", "gz", "tar", "iso",
            "img", "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf", "txt", "csv", "log",
            "html", "htm", "php", "asp", "aspx", "json", "xml", "png", "jpg", "jpeg", "gif", "svg", "bin", "dat",
            "tmp", "lnk", "hta", "pcap", "pcapng", "py", "sh", "apk", "dmg", "pkg", "deb", "rpm"}
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SCOPE_TEXT = {"private": "An address on your network", "link-local": "A link-local address (this network segment only)",
              "loopback": "This computer (loopback)", "multicast": "A multicast group", "broadcast": "Broadcast",
              "shared": "A carrier-grade NAT address", "unspecified": "An unconfigured address (0.0.0.0)",
              "documentation": "A documentation address (not routed on the internet)"}


def classify(q: str) -> str:
    q = q.strip()
    try:
        ipaddress.ip_address(q)
        return "ip"
    except ValueError:
        pass
    if MAC.match(q):
        return "mac"
    if HEX.match(q) and len(q) in (32, 40, 64):
        return {32: "md5", 40: "sha1", 64: "sha256"}[len(q)]
    if JA4.match(q):
        return "ja4"
    if JA4S.match(q):
        return "ja4s"
    if re.match(r"^https?://\S+$", q, re.I):
        return "url"
    if DOMAIN.match(q):
        return "filename" if q.rsplit(".", 1)[1].lower() in FILE_EXT else "domain"
    return "text"


def _feed(fid: str) -> str:
    return SOURCES.get(fid, {}).get("name", fid)


def _intel(analyzer, kind: str, value: str) -> list[str]:
    index = getattr(analyzer.intel, "index", None) if getattr(analyzer, "intel", None) is not None else None
    hits = (index or {}).get(kind, {}).get(value) or []
    return [f"Threat intel: {_feed(h.get('feed', ''))}: {h.get('reason', '')}".rstrip(": ") for h in hits[:3]]


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def _list(values, n: int = 3) -> str:
    values = [str(v) for v in values if v]
    return ", ".join(values[:n]) + (f" and {len(values) - n:,} more" if len(values) > n else "")


def alerts_involving(analyzer, q: str, limit: int = 8) -> list[dict]:
    """The alerts that name `q` (an address, a domain, a hash): most severe first."""
    q_low = q.lower()
    out = []
    for a in list(analyzer.alerts.values()):
        m = a.get("metrics") or {}
        values = {str(v).lower() for v in (a.get("src_ip"), a.get("dst_ip"), a.get("target"), m.get("domain"),
                                            m.get("sha256"), m.get("sni")) if v}
        values |= {str(v).lower() for v in a.get("addresses") or []}
        target = str(a.get("target") or "").lower()
        if q_low in values or (len(q_low) > 3 and target.endswith("." + q_low)):
            out.append({"id": a["id"], "title": a["title"], "severity": a["severity"]})
    out.sort(key=lambda x: SEVERITY.get(x["severity"], 9))
    return out[:limit]


def _alert_line(alerts: list[dict]) -> str:
    if not alerts:
        return ""
    worst = alerts[0]["severity"]
    same = sum(1 for a in alerts if a["severity"] == worst)
    return f"{_plural(len(alerts), 'alert')} ({same} {worst}): {alerts[0]['title']}"


def _sessions_where(sessions, test) -> list[dict]:
    return [s for s in sessions or [] if test(s)]


def lookup(q: str, ctx, analyzer, nodes: list | None = None, sessions: list | None = None,
           objects: list | None = None) -> dict:
    """Facts about `q` as short lines of plain text, its alerts, and what kind of thing it is.
    `nodes` (the network map's hosts), `sessions` (the session index) and `objects` (the
    files list) are used when they have been read already."""
    q = q.strip()
    kind = classify(q)
    lines: list[str] = []
    out = {"q": q, "kind": kind, "lines": lines, "alerts": []}
    if kind == "ip":
        dest, host = ctx.destination_profile(q), ctx.host_profile(q)
        node = next((n for n in nodes or [] if n.get("addr") == q), None)
        scope = devices.address_kind(q)
        ident = [x for x in ((node or {}).get("name"), (node or {}).get("role"), (node or {}).get("vendor"),
                             (node or {}).get("os")) if x and x != q]
        if not ident and dest.get("dns_name"):
            ident = [dest["dns_name"]]
        if ident:
            lines.append(" · ".join(dict.fromkeys(ident)))
        loc = dest.get("location") or {}
        if loc:
            lines.append(" · ".join(x for x in (loc.get("country"), f"AS{loc['asn']}" if loc.get("asn") else "",
                                                 loc.get("org")) if x))
        elif scope in SCOPE_TEXT:
            lines.append(SCOPE_TEXT[scope])
        users = (node or {}).get("users") or []
        if users:
            lines.append(f"Signed-in user{'s' if len(users) > 1 else ''}: {_list(users)}")
        act = []
        if dest.get("internal_host_count"):
            act.append(f"used by {_plural(dest['internal_host_count'], 'of your hosts', 'of your hosts')}"
                       + (f" on port {_list(dest.get('ports_used') or [])}" if dest.get("ports_used") else ""))
        if host.get("destinations_contacted"):
            act.append(f"contacted {_plural(host['destinations_contacted'], 'destination')}")
        if host.get("serves"):
            act.append(f"serves {_list(host['serves'])}")
        elif host.get("uses"):
            act.append(f"uses {_list(host['uses'])}")
        if act:
            lines.append(act[0][0].upper() + "; ".join(act)[1:])
        lines += _intel(analyzer, "ip", q)
        out["internal"] = scope in ("private", "link-local", "loopback", "shared")
    elif kind == "domain":
        name = q.lower().rstrip(".")
        dest = ctx.destination_profile(name)
        if dest.get("addresses"):
            lines.append(f"Resolved to {_list(dest['addresses'])}")
        if dest.get("internal_host_count"):
            lines.append(f"Looked up or used by {_plural(dest['internal_host_count'], 'of your hosts', 'of your hosts')}: "
                         f"{_list(dest.get('internal_hosts') or [])}")
        used = _sessions_where(sessions, lambda s: name in (((s.get("tls") or {}).get("sni") or "").lower(),
                                                           *((h.get("host") or "").lower() for h in s.get("http") or [])))
        if used:
            lines.append(f"Named in {_plural(len(used), 'session')} (TLS server name or HTTP host)")
        if dest.get("registered_domain") and dest["registered_domain"] != name:
            lines.append(f"Part of {dest['registered_domain']}")
        labels = name.split(".")
        for i in range(len(labels) - 1):
            lines += _intel(analyzer, "domain", ".".join(labels[i:]))
    elif kind == "mac":
        mac = q.lower().replace("-", ":")
        owners = [n for n in nodes or [] if mac in [m.lower() for m in n.get("macs") or []]]
        for n in owners[:3]:
            lines.append(" · ".join(x for x in (n.get("addr"), n.get("name"), n.get("vendor")) if x))
        if not owners:
            lines.append("No address in the statistics uses it (open Statistics once to read them)" if nodes is None
                         else "No address in this capture uses it")
    elif kind in ("sha256", "sha1", "md5"):
        h = q.lower()
        files = [o for o in objects or [] if (o.get("sha256") or "").lower() == h]
        for f in files[:3]:
            lines.append(f"File {f.get('name')} ({f.get('proto')}, {f.get('size', 0):,} bytes) "
                         f"from {f.get('server')} to {f.get('client')}")
        if kind == "sha256":
            lines += _intel(analyzer, "sha256", h)
        if kind == "md5":  # (an MD5 is also how JA3 fingerprints are written)
            hellos = _sessions_where(sessions, lambda s: (s.get("tls") or {}).get("ja3") == h)
            if hellos:
                clients = sorted({s["src_ip"] for s in hellos})
                lines.append(f"JA3 of {_plural(len(hellos), 'TLS session')} from {_list(clients)}")
            lines += _intel(analyzer, "ja3", h)
        if not lines and objects is None and sessions is None:
            lines.append("Open the Files tab once to match it against the capture's files")
    elif kind in ("ja4", "ja4s"):
        key = "ja4" if kind == "ja4" else "ja4s"
        hellos = _sessions_where(sessions, lambda s: (s.get("tls") or {}).get(key) == q)
        if hellos:
            clients = sorted({s["src_ip"] for s in hellos})
            servers = sorted({(s.get("tls") or {}).get("sni") or s["dst_ip"] for s in hellos})
            lines.append(f"{_plural(len(hellos), 'TLS session')} from {_list(clients)} to {_list(servers)}")
        elif sessions is None:
            lines.append("Open Statistics → TLS fingerprints once to match it against the capture")
        if kind == "ja4":
            lines += _intel(analyzer, "ja4", q)
    elif kind == "url":
        norm = _norm_url(q)
        hits = []
        for s in sessions or []:
            for r in s.get("http") or []:
                if _norm_url(f"{r.get('host', '')}{r.get('uri', '')}") == norm:
                    hits.append(s)
        if hits:
            lines.append(f"Requested in {_plural(len(hits), 'session')} by {_list(sorted({s['src_ip'] for s in hits}))}")
        lines += _intel(analyzer, "url", norm)
    elif kind == "filename":
        files = [o for o in objects or [] if (o.get("name") or "").lower() == q.lower()]
        for f in files[:3]:
            lines.append(f"{f.get('proto')} {f.get('direction')}, {f.get('size', 0):,} bytes, from {f.get('server')} "
                         f"to {f.get('client')}" + (f", SHA-256 {f['sha256'][:16]}…" if f.get("sha256") else ""))
    out["alerts"] = alerts_involving(analyzer, q)
    if out["alerts"]:
        lines.append(_alert_line(out["alerts"]))
    if not lines:
        lines.append("Nothing else is known about it in this capture")
    return out
