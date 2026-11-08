"""Threat-intelligence feeds: known-bad addresses, domains, URLs, file hashes and TLS
fingerprints, matched against every session.

The built-in sources are abuse.ch's free lists (CC0): Feodo Tracker (botnet C2
addresses), SSLBL (JA3 fingerprints of malware), URLhaus (malware URLs), ThreatFox
(indicators of every kind) and MalwareBazaar (malware file hashes). ANTA only
downloads them when the user clicks Update; any other list can be imported as a
file (abuse.ch CSVs are recognised, anything else is read one indicator per line,
as the indicator sweep reads them). Feeds are stored owner-only in the data folder.
"""
from __future__ import annotations

import contextlib
import csv
import io
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
import urllib.request
from collections import defaultdict

from . import hunt, paths

MAX_FEED_BYTES = 64 * 1024 * 1024
USER_AGENT = "ANTA threat-intel updater"

SOURCES = {
    "feodo": {"name": "Feodo Tracker: botnet C2 servers", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
              "about": "Command-and-control servers of Emotet, QakBot, Dridex and other banking/loader botnets."},
    "sslbl_ja3": {"name": "SSLBL: malware JA3 fingerprints", "url": "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
                  "about": "TLS client fingerprints of malware families. No longer updated by abuse.ch (2021), and "
                           "common TLS libraries can share a JA3: matches are leads, not proof."},
    "urlhaus": {"name": "URLhaus: malware URLs (recent)", "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
                "about": "Addresses serving malware in the last 30 days."},
    "threatfox": {"name": "ThreatFox: indicators (recent)", "url": "https://threatfox.abuse.ch/export/csv/recent/",
                  "about": "C2 addresses, domains, URLs and payload hashes reported in the last 48 hours."},
    "bazaar": {"name": "MalwareBazaar: malware hashes (recent)", "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
               "about": "SHA-256 hashes of malware samples submitted in the last 48 hours."},
}

KINDS = ("ip", "ip_port", "domain", "url", "sha256", "ja3", "ja4")


def _hit(feed: str, reason: str, first_seen: str = "", extra: str = "") -> dict:
    return {"feed": feed, "reason": reason[:120], "first_seen": first_seen[:32], "extra": extra[:200]}


def _rows(text: str):
    """CSV rows of an abuse.ch export: '#' comment lines dropped, the header too."""
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    yield from csv.reader(io.StringIO("\n".join(lines)), skipinitialspace=True)


def parse(feed_id: str, text: str) -> dict[str, dict[str, list]]:
    """Indicators of one feed: {kind: {value: [hit, ...]}}."""
    out: dict[str, dict[str, list]] = {k: defaultdict(list) for k in KINDS}
    head = text[:4096]
    if "Feodo Tracker" in head:
        for r in _rows(text):
            if len(r) >= 6 and r[1] and r[1] != "dst_ip":
                out["ip_port"][f"{r[1]}:{r[2]}"].append(_hit(feed_id, f"{r[5]} C2 ({r[3]})", r[0]))
                out["ip"][r[1]].append(_hit(feed_id, f"{r[5]} C2", r[0], f"port {r[2]}"))
    elif "JA3 Fingerprint Blacklist" in head:
        for r in _rows(text):
            if len(r) >= 4 and re.fullmatch(r"[0-9a-f]{32}", r[0]):
                out["ja3"][r[0]].append(_hit(feed_id, r[3], r[1]))
    elif "URLhaus" in head:
        for r in _rows(text):
            if len(r) >= 7 and r[2].startswith(("http://", "https://")):
                out["url"][_norm_url(r[2])].append(_hit(feed_id, f"{r[5]} ({r[6]})" if r[6] != "None" else r[5], r[1]))
    elif "ThreatFox" in head:
        for r in _rows(text):
            if len(r) < 8:
                continue
            value, kind, threat, malware = r[2], r[3], r[4], r[7]
            reason = f"{malware} {threat.replace('_', ' ')}".strip()
            if kind == "ip:port" and ":" in value:
                ip, _, port = value.rpartition(":")
                out["ip_port"][f"{ip}:{port}"].append(_hit(feed_id, reason, r[0]))
                out["ip"][ip].append(_hit(feed_id, reason, r[0], f"port {port}"))
            elif kind == "domain":
                out["domain"][value.lower().rstrip(".")].append(_hit(feed_id, reason, r[0]))
            elif kind == "url":
                out["url"][_norm_url(value)].append(_hit(feed_id, reason, r[0]))
            elif kind == "sha256_hash":
                out["sha256"][value.lower()].append(_hit(feed_id, reason, r[0]))
    elif "MalwareBazaar" in head:
        for line in text.splitlines():
            line = line.strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", line):
                out["sha256"][line].append(_hit(feed_id, "malware sample (MalwareBazaar)"))
    else:  # anything else: one indicator per line, read like the indicator sweep
        found, _ = hunt.parse(text)
        for ind in found:
            k, v = ind["kind"], ind["value"]
            reason = "listed"
            if k == "ip" and ind.get("port"):
                out["ip_port"][f"{v}:{ind['port']}"].append(_hit(feed_id, reason))
            elif k == "ip":
                out["ip"][v].append(_hit(feed_id, reason))
            elif k == "url":
                out["url"][_norm_url(v)].append(_hit(feed_id, reason))
            elif k in ("domain", "sha256", "ja3", "ja4"):
                out[k][v].append(_hit(feed_id, reason))
    return {k: dict(v) for k, v in out.items()}


def _norm_url(url: str) -> str:
    """scheme-less, lower-case host, default port dropped: what an HTTP request line gives us."""
    url = url.strip()
    rest = url.split("://", 1)[-1]
    host, slash, path = rest.partition("/")
    host = host.lower()
    if host.endswith(":80"):
        host = host[:-3]
    elif host.endswith(":443"):  # HTTPS read with a key log gives the same scheme-less form
        host = host[:-4]
    return host + slash + path


class IntelStore:
    """Feeds on disk (owner-only), merged into one index for matching."""

    def __init__(self, directory: str | None = None):
        self.dir = directory or os.path.join(paths.app_data_dir(), "intel")
        self._lock = threading.Lock()
        self.index: dict[str, dict[str, list]] = {k: {} for k in KINDS}
        self.meta: dict[str, dict] = {}
        self.version = 0
        self.load()

    # ------------------------------------------------------------ storage
    def _meta_path(self) -> str:
        return os.path.join(self.dir, "feeds.json")

    def _ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)
        if os.name != "nt":
            os.chmod(self.dir, 0o700)

    def load(self) -> None:
        try:
            with open(self._meta_path(), encoding="utf-8") as fh:
                meta = json.load(fh)
        except (OSError, ValueError):
            meta = {}
        index: dict[str, dict[str, list]] = {k: defaultdict(list) for k in KINDS}
        for fid, m in list(meta.items()):
            if not re.fullmatch(r"[a-z0-9_-]{1,40}", fid) or not m.get("enabled", True):
                continue
            try:
                with open(os.path.join(self.dir, f"{fid}.txt"), encoding="utf-8", errors="replace") as fh:
                    parsed = parse(fid, fh.read())
            except OSError:
                continue
            for k, entries in parsed.items():
                for v, hits in entries.items():
                    index[k][v].extend(hits)
        with self._lock:
            self.meta = meta
            self.index = {k: dict(v) for k, v in index.items()}
            self.version += 1

    def _save_meta(self) -> None:
        self._ensure_dir()
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".feeds-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self.meta, fh, indent=1)
        os.replace(tmp, self._meta_path())

    def _store(self, fid: str, text: str, name: str, source: str) -> dict:
        parsed = parse(fid, text)
        count = sum(len(v) for v in parsed.values())
        if not count:
            raise ValueError("no indicators found in it (is it the right file?)")
        self._ensure_dir()
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=f".{fid}-", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, os.path.join(self.dir, f"{fid}.txt"))
        by_kind = {k: len(v) for k, v in parsed.items() if v}
        self.meta[fid] = {"name": name, "source": source, "updated": time.time(), "entries": count,
                          "by_kind": by_kind, "enabled": True}
        self._save_meta()
        self.load()
        return self.meta[fid]

    # ------------------------------------------------------------ feeds
    def feeds(self) -> list[dict]:
        out = []
        for fid, src in SOURCES.items():
            m = self.meta.get(fid, {})
            out.append({"id": fid, "name": src["name"], "about": src["about"], "url": src["url"], "builtin": True,
                        "installed": fid in self.meta, **{k: m.get(k) for k in ("updated", "entries", "by_kind")},
                        "enabled": m.get("enabled", True)})
        for fid, m in self.meta.items():
            if fid not in SOURCES:
                out.append({"id": fid, "name": m.get("name", fid), "about": "Imported file", "url": None,
                            "builtin": False, "installed": True,
                            **{k: m.get(k) for k in ("updated", "entries", "by_kind")}, "enabled": m.get("enabled", True)})
        return out

    def update(self, fid: str) -> dict:
        """Download a built-in feed (https only, size-capped) and replace the stored copy."""
        src = SOURCES.get(fid)
        if not src:
            raise ValueError("unknown feed")
        # Only the fixed https:// addresses in SOURCES are ever fetched.
        req = urllib.request.Request(src["url"], headers={"User-Agent": USER_AGENT})  # noqa: S310
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            data = resp.read(MAX_FEED_BYTES + 1)
        if len(data) > MAX_FEED_BYTES:
            raise ValueError("the feed is larger than expected; not stored")
        return self._store(fid, data.decode("utf-8", "replace"), src["name"], src["url"])

    def import_text(self, name: str, text: str) -> dict:
        if len(text) > MAX_FEED_BYTES:
            raise ValueError("the file is too large")
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:30] or "list"
        return self._store(f"custom-{slug}", text, name[:80] or "Imported list", "imported file")

    def remove(self, fid: str) -> None:
        if fid in self.meta:
            del self.meta[fid]
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(self.dir, f"{fid}.txt"))
            self._save_meta()
            self.load()

    def set_enabled(self, fid: str, enabled: bool) -> None:
        if fid in self.meta:
            self.meta[fid]["enabled"] = bool(enabled)
            self._save_meta()
            self.load()

    def size(self) -> int:
        return sum(len(v) for v in self.index.values())

    # ------------------------------------------------------------ matching
    def match_session(self, rec: dict) -> list[dict]:
        """Every listed indicator a session touches: [{kind, value, where, hits}]."""
        if not self.size():
            return []
        idx = self.index
        found: list[dict] = []
        seen = set()

        def add(kind, value, where, hits):
            if hits and (kind, value) not in seen:
                seen.add((kind, value))
                found.append({"kind": kind, "value": value, "where": where, "hits": hits[:5]})

        for ip, port, role in ((rec["dst_ip"], rec["dst_port"], "destination"), (rec["src_ip"], rec["src_port"], "source")):
            add("ip_port", f"{ip}:{port}", f"{role} {ip}:{port}", idx["ip_port"].get(f"{ip}:{port}"))
            if (("ip_port", f"{ip}:{port}")) not in seen:
                add("ip", ip, f"{role} address {ip}", idx["ip"].get(ip))
        names = set()
        for q in rec.get("dns") or []:
            names.add((str(q.get("qname", "")).lower().rstrip("."), "DNS query"))
            for a in q.get("answers") or []:
                with contextlib.suppress(ValueError):
                    ipaddress.ip_address(a)
                    add("ip", a, f"DNS answer {a} for {q.get('qname')}", idx["ip"].get(a))
        tls = rec.get("tls") or {}
        if tls.get("sni"):
            names.add((tls["sni"].lower(), "TLS server name"))
        scheme = "https" if tls.get("decrypted") else "http"  # HTTPS read with the user's key log
        for h in rec.get("http") or []:
            host = str(h.get("host", "")).split(":")[0].lower()
            if host:
                names.add((host, "HTTP Host"))
                url = _norm_url(f"{host}{h.get('uri', '')}")
                add("url", url, f"{scheme.upper()} request {scheme}://{url}", idx["url"].get(url))
        for name, where in names:
            labels = name.split(".")
            for i in range(len(labels) - 1):  # the name itself, then each parent domain
                parent = ".".join(labels[i:])
                if idx["domain"].get(parent):
                    add("domain", parent, f"{where}: {name}", idx["domain"][parent])
                    break
        for key, label in (("http_files", "HTTP download"), ("smb_files", "SMB file")):
            for f in rec.get(key) or []:
                sha = str(f.get("sha256") or "").lower()
                if sha:
                    add("sha256", sha, f"{label} {f.get('filename') or f.get('name') or f.get('uri') or ''}".strip(),
                        idx["sha256"].get(sha))
        d = rec.get("ftp_data") or {}
        if d.get("sha256"):
            add("sha256", d["sha256"], f"FTP file {d.get('name', '')}", idx["sha256"].get(d["sha256"]))
        if tls.get("ja3"):
            add("ja3", tls["ja3"], "JA3 of the TLS client", idx["ja3"].get(tls["ja3"]))
        if tls.get("ja4"):
            add("ja4", tls["ja4"], "JA4 of the TLS client", idx["ja4"].get(tls["ja4"]))
        return found
