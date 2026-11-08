"""Flow logs: one line of metadata per session (who talked to whom, when, how much,
over what, with the names, fingerprints and files involved), the way Zeek's conn.log
and NetFlow keep it. Lines are small enough to keep for months, while the packets
themselves live in the rolling capture buffer for a few hours or days.

Files are JSON lines, one per day (flows-YYYY-MM-DD.jsonl), owner-only, in the data
folder; old days are deleted past the retention period or the size cap.
"""
from __future__ import annotations

import contextlib
import datetime
import json
import os
import re
import threading

from . import paths

FILE_RE = re.compile(r"flows-(\d{4}-\d{2}-\d{2})\.jsonl")


def log_dir() -> str:
    d = os.path.join(paths.app_data_dir(), "flows")
    os.makedirs(d, exist_ok=True)
    if os.name != "nt":
        os.chmod(d, 0o700)
    return d


def conn_state(rec: dict) -> str:
    """Zeek's conn_state, approximately, from what the engine saw."""
    if rec.get("proto") != "tcp":
        return "SF" if rec["s2c"]["packets"] else "S0"
    t = rec.get("tcp") or {}
    if not t.get("handshake"):
        if t.get("rst") and not rec["s2c"]["payload_bytes"]:
            return "REJ"
        return "S0" if not rec["s2c"]["packets"] else "OTH"
    if t.get("rst"):
        return "RSTO"
    return "SF" if t.get("closed") else "S1"


def record(rec: dict, geo=None) -> dict:
    """A session as one flow-log line."""
    out = {
        "ts": rec["start"], "uid": f"F{rec.get('flow_id', 0)}-{int(rec['start'] * 1e6) % 1_000_000_000:09d}",
        "proto": rec["proto"], "service": rec.get("app") or "", "src": rec["src_ip"], "sport": rec["src_port"],
        "dst": rec["dst_ip"], "dport": rec["dst_port"], "duration": round(rec["end"] - rec["start"], 6),
        "orig_bytes": rec["c2s"]["payload_bytes"], "resp_bytes": rec["s2c"]["payload_bytes"],
        "orig_pkts": rec["c2s"]["packets"], "resp_pkts": rec["s2c"]["packets"],
        "orig_ip_bytes": rec["c2s"]["bytes"], "resp_ip_bytes": rec["s2c"]["bytes"], "conn_state": conn_state(rec),
    }
    if rec.get("app_expected") is not None:
        out["service_expected"] = rec["app_expected"]
    if rec.get("dns"):
        out["dns"] = [{"query": q.get("qname"), "qtype": q.get("qtype"), "rcode": q.get("rcode"),
                       "answers": (q.get("answers") or [])[:8]} for q in rec["dns"][:8]]
    tls = rec.get("tls") or {}
    if tls:
        out["tls"] = {k: tls.get(k) for k in ("sni", "ja3", "ja4", "ja3s", "ja4s") if tls.get(k)}
    if rec.get("http"):
        out["http"] = [{k: h.get(k) for k in ("method", "host", "uri", "user_agent") if h.get(k)} for h in rec["http"][:8]]
    files = []
    for f in rec.get("http_files") or []:
        files.append({"proto": "http", "name": f.get("filename") or f.get("uri"), "sha256": f.get("sha256"), "size": f.get("size")})
    for f in rec.get("smb_files") or []:
        files.append({"proto": "smb", "name": f.get("name"), "sha256": f.get("sha256"), "size": f.get("size")})
    if rec.get("ftp_data") and rec["ftp_data"].get("size"):
        d = rec["ftp_data"]
        files.append({"proto": "ftp", "name": d.get("name"), "sha256": d.get("sha256"), "size": d.get("size")})
    if files:
        out["files"] = files
    if geo is not None:
        for side, ip in (("src", rec["src_ip"]), ("dst", rec["dst_ip"])):
            g = geo.lookup(ip) if ip else None
            if g:
                out[f"{side}_country"] = g["country"]
                out[f"{side}_asn"] = g["asn"]
    if rec.get("capture"):
        out["capture"] = rec["capture"]
    return out


class FlowLog:
    def __init__(self, directory: str | None = None, days: int = 30, max_mb: int = 1024):
        self.dir = directory or log_dir()
        self.days = days
        self.max_mb = max_mb
        self._lock = threading.Lock()
        self._fh = None
        self._day = None
        self.written = 0

    def configure(self, days: int, max_mb: int) -> None:
        self.days, self.max_mb = days, max_mb
        self.prune()

    def write(self, rec: dict, geo=None) -> None:
        line = json.dumps(record(rec, geo), separators=(",", ":"), default=str) + "\n"
        day = datetime.datetime.fromtimestamp(rec["start"], tz=datetime.timezone.utc).strftime("%Y-%m-%d")
        with self._lock:
            if day != self._day:
                self._close()
                os.makedirs(self.dir, mode=0o700, exist_ok=True)
                p = os.path.join(self.dir, f"flows-{day}.jsonl")
                fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                self._fh = os.fdopen(fd, "a", encoding="utf-8")
                self._day = day
            self._fh.write(line)
            self.written += 1
            if self.written % 500 == 0:
                self._fh.flush()

    def _close(self) -> None:
        if self._fh:
            with contextlib.suppress(OSError):
                self._fh.close()
        self._fh = None
        self._day = None

    def flush(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.flush()

    def close(self) -> None:
        with self._lock:
            self._close()

    def files(self) -> list[dict]:
        out = []
        if not os.path.isdir(self.dir):
            return out
        for name in sorted(os.listdir(self.dir)):
            m = FILE_RE.fullmatch(name)
            if not m:
                continue
            st = os.stat(os.path.join(self.dir, name))
            out.append({"name": name, "day": m.group(1), "size": st.st_size, "modified": st.st_mtime})
        return out

    def prune(self, today: datetime.date | None = None) -> list[str]:
        """Delete days past the retention period, then the oldest days past the size cap."""
        today = today or datetime.datetime.now(datetime.timezone.utc).date()
        removed = []
        files = self.files()
        for f in files:
            age = (today - datetime.date.fromisoformat(f["day"])).days
            if age > self.days and f["day"] != self._day:
                with contextlib.suppress(OSError):
                    os.unlink(os.path.join(self.dir, f["name"]))
                removed.append(f["name"])
        files = [f for f in self.files()]
        total = sum(f["size"] for f in files)
        for f in files:  # oldest first
            if total <= self.max_mb * 1024 * 1024 or f["day"] == self._day:
                break
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(self.dir, f["name"]))
            total -= f["size"]
            removed.append(f["name"])
        return removed
