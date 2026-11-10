"""Security helpers: private runtime directory, record validation, safe JSON."""
from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import stat
import sys

# Unix socket paths are limited to sizeof(sun_path) - 1 bytes (103 on macOS, 107 on Linux).
MAX_SOCKET_PATH = 103


def runtime_dir() -> str:
    """Owner-only directory for IPC endpoints and export temp files.

    Sockets live here rather than in a shared /tmp so no other local user can
    connect to them (injecting fake alerts) or pre-create them (hijacking).
    """
    if os.environ.get("ANTA_RUNTIME_DIR"):
        base = os.environ["ANTA_RUNTIME_DIR"]
    elif sys.platform == "win32":
        root = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        base = os.path.join(root, "ANTA", "run")
    else:
        base = os.path.join(os.path.expanduser("~"), ".anta", "run")
    os.makedirs(base, mode=0o700, exist_ok=True)
    st = os.lstat(base)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"{base} must be a real directory, not a symlink")
    if hasattr(os, "getuid"):  # POSIX ownership/mode checks; Windows profile dirs are ACL-protected
        if st.st_uid != os.getuid():
            raise RuntimeError(f"{base} is owned by uid {st.st_uid}, not you; refusing to use it")
        if st.st_mode & 0o077:
            os.chmod(base, 0o700)
    return base


def socket_path(name: str) -> str:
    path = os.path.join(runtime_dir(), name)
    if len(path.encode()) > MAX_SOCKET_PATH:
        raise RuntimeError(f"socket path {path!r} exceeds {MAX_SOCKET_PATH} bytes; set ANTA_RUNTIME_DIR to a shorter path")
    return path


# ------------------------------------------------------------------ JSON

def _finite(o):
    if isinstance(o, float):
        return o if math.isfinite(o) else None
    if isinstance(o, dict):
        return {k: _finite(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_finite(v) for v in o]
    return o


def dumps(obj) -> str:
    """JSON for the browser: NaN/Infinity (invalid JSON) become null."""
    try:
        return json.dumps(obj, allow_nan=False, default=float)
    except ValueError:
        return json.dumps(_finite(obj), allow_nan=False, default=float)


# ------------------------------------------------------------ validation

class InvalidRecord(ValueError):
    pass


LIMITS = {"str": 2048, "events": 5000, "dns": 128, "http": 32, "rate": 256, "answers": 16}


def _num(v, name, lo=-math.inf, hi=math.inf):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not lo <= v <= hi:
        raise InvalidRecord(f"{name}: bad number {v!r}")
    return v


def _str(v, name, limit=LIMITS["str"]):
    if v is None:
        return ""
    if not isinstance(v, str):
        raise InvalidRecord(f"{name}: expected string")
    return v[:limit]


def _ip(v, name):
    try:
        return str(ipaddress.ip_address(v))
    except (ValueError, TypeError):
        raise InvalidRecord(f"{name}: bad IP {v!r}") from None


def validate_session(rec: dict) -> dict:
    """Type- and range-check a session record from the engine or stdin.

    Records can come from external telemetry, so nothing downstream (detectors,
    export command lines, the browser) should see unchecked fields.
    """
    if rec.get("proto") not in ("tcp", "udp"):
        raise InvalidRecord("proto must be tcp or udp")
    out = dict(rec)
    out["flow_id"] = int(_num(rec.get("flow_id", 0), "flow_id", 0, 2**63))
    out["src_ip"] = _ip(rec.get("src_ip"), "src_ip")
    out["dst_ip"] = _ip(rec.get("dst_ip"), "dst_ip")
    out["src_port"] = int(_num(rec.get("src_port"), "src_port", 0, 65535))
    out["dst_port"] = int(_num(rec.get("dst_port"), "dst_port", 0, 65535))
    out["start"] = float(_num(rec.get("start"), "start", 0, 2**40))
    out["end"] = float(_num(rec.get("end"), "end", out["start"], 2**40))
    out["final"] = bool(rec.get("final", True))
    out["capture"] = _str(rec.get("capture"), "capture", 4096)
    for d in ("c2s", "s2c"):
        side = rec.get(d) or {}
        if not isinstance(side, dict):
            raise InvalidRecord(f"{d}: expected object")
        out[d] = {k: int(_num(side.get(k, 0), f"{d}.{k}", 0, 2**62)) for k in ("packets", "bytes", "payload_bytes")}

    events = rec.get("events") or []
    if not isinstance(events, list):
        raise InvalidRecord("events: expected list")
    clean = []
    for e in events[: LIMITS["events"]]:
        if not (isinstance(e, list) and len(e) == 2):
            raise InvalidRecord("events: expected [ms, bytes] pairs")
        clean.append([float(_num(e[0], "event.t", 0, 2**40)), int(_num(e[1], "event.len", -(2**31), 2**31))])
    out["events"] = clean

    rate = rec.get("rate")
    if isinstance(rate, dict):
        out["rate"] = {
            "bucket_ms": float(_num(rate.get("bucket_ms", 1000), "rate.bucket_ms", 0.001, 2**40)),
            "out": [int(_num(v, "rate.out", 0, 2**62)) for v in (rate.get("out") or [])[: LIMITS["rate"]]],
            "in": [int(_num(v, "rate.in", 0, 2**62)) for v in (rate.get("in") or [])[: LIMITS["rate"]]],
        }
    else:
        out.pop("rate", None)

    if isinstance(rec.get("tls"), dict):
        t = rec["tls"]
        out["tls"] = {k: _str(t.get(k), f"tls.{k}", 1024) for k in ("sni", "ja3", "ja3_string", "ja4", "ja3s", "ja4s")}
        out["tls"]["ja3_string"] = _str(t.get("ja3_string"), "tls.ja3_string", 4096)
        out["tls"]["ja3s_string"] = _str(t.get("ja3s_string"), "tls.ja3s_string", 4096)
        for k in ("ja3", "ja3s"):
            if not re.fullmatch(r"(?:[0-9a-f]{32})?", out["tls"][k]):
                raise InvalidRecord(f"tls.{k}: expected an MD5 hex digest")
        out["tls"]["alpn"] = [_str(a, "tls.alpn", 64) for a in (t.get("alpn") or [])[:8]]
        if t.get("decrypted"):
            out["tls"]["decrypted"] = True  # read with the user's TLS key log
    else:
        out.pop("tls", None)

    if isinstance(rec.get("dns"), list):
        out["dns"] = [{
            "qname": _str(q.get("qname"), "dns.qname", 512),
            "qtype": int(_num(q.get("qtype", 0), "dns.qtype", 0, 65535)),
            "answered": bool(q.get("answered", False)),
            "rcode": int(_num(q.get("rcode", 0), "dns.rcode", 0, 15)),
            "txt_bytes": int(_num(q.get("txt_bytes", 0), "dns.txt_bytes", 0, 2**31)),
            "answers": [_str(a, "dns.answer", 256) for a in (q.get("answers") or [])[: LIMITS["answers"]]],
        } for q in rec["dns"][: LIMITS["dns"]] if isinstance(q, dict)]
    else:
        out.pop("dns", None)

    if isinstance(rec.get("http"), list):
        out["http"] = [{
            "method": _str(r.get("method"), "http.method", 16),
            "host": _str(r.get("host"), "http.host", 256),
            "uri": _str(r.get("uri"), "http.uri", 1024),
            "user_agent": _str(r.get("user_agent"), "http.user_agent", 512),
            "content_length": int(_num(r.get("content_length", 0), "http.content_length", 0, 2**62)),
        } for r in rec["http"][: LIMITS["http"]] if isinstance(r, dict)]
    else:
        out.pop("http", None)

    if isinstance(rec.get("http_response"), dict):
        r = rec["http_response"]
        out["http_response"] = {"status": int(_num(r.get("status", 0), "http.status", 0, 999)),
                                "server": _str(r.get("server"), "http.server", 256),
                                "content_type": _str(r.get("content_type"), "http.content_type", 256)}
        if r.get("powered_by"):
            out["http_response"]["powered_by"] = _str(r.get("powered_by"), "http.powered_by", 128)
    else:
        out.pop("http_response", None)

    # Software greetings (an SSH identification line, a server's "220 (vsFTPd 3.0.5)"): printable text only.
    if isinstance(rec.get("banner"), dict):
        b = {k: _str(rec["banner"].get(k), f"banner.{k}", 128) for k in ("client", "server") if rec["banner"].get(k)}
        if any(not re.fullmatch(r"[ -~]*", v) for v in b.values()):
            raise InvalidRecord("banner: expected printable text")
        if b:
            out["banner"] = b
        else:
            out.pop("banner", None)
    else:
        out.pop("banner", None)

    if isinstance(rec.get("http_files"), list):
        files = []
        for f in rec["http_files"][:64]:
            if not isinstance(f, dict):
                continue
            sha = _str(f.get("sha256"), "http_files.sha256", 64)
            magic = _str(f.get("magic"), "http_files.magic", 32)
            if not re.fullmatch(r"[0-9a-f]{64}", sha) or not re.fullmatch(r"[0-9a-f]*", magic):
                raise InvalidRecord("http_files: bad hash or magic")
            files.append({
                "n": int(_num(f.get("n", 0), "http_files.n", 0, 2**32)),
                "method": _str(f.get("method"), "http_files.method", 16),
                "host": _str(f.get("host"), "http_files.host", 256),
                "uri": _str(f.get("uri"), "http_files.uri", 1024),
                "user_agent": _str(f.get("user_agent"), "http_files.user_agent", 512),
                "status": int(_num(f.get("status", 0), "http_files.status", 0, 999)),
                "content_type": _str(f.get("content_type"), "http_files.content_type", 256),
                "content_encoding": _str(f.get("content_encoding"), "http_files.content_encoding", 64),
                "filename": _str(f.get("filename"), "http_files.filename", 255),
                "declared_length": int(_num(f.get("declared_length", 0), "http_files.declared_length", 0, 2**62)),
                "size": int(_num(f.get("size", 0), "http_files.size", 0, 2**62)),
                "encoded_size": int(_num(f.get("encoded_size", 0), "http_files.encoded_size", 0, 2**62)),
                "magic": magic,
                "sha256": sha,
                "complete": bool(f.get("complete", False)),
                "ts": float(_num(f.get("ts", 0), "http_files.ts", 0, 2**40)),
            })
        out["http_files"] = files
    else:
        out.pop("http_files", None)

    if isinstance(rec.get("smb_files"), list):
        files = []
        for f in rec["smb_files"][:64]:
            if not isinstance(f, dict):
                continue
            sha = _str(f.get("sha256"), "smb_files.sha256", 64)
            magic = _str(f.get("magic"), "smb_files.magic", 32)
            if not re.fullmatch(r"(?:[0-9a-f]{64})?", sha) or not re.fullmatch(r"[0-9a-f]*", magic):
                raise InvalidRecord("smb_files: bad hash or magic")
            files.append({
                "name": _str(f.get("name"), "smb_files.name", 1024),
                "share": _str(f.get("share"), "smb_files.share", 512),
                "op": "write" if f.get("op") == "write" else "read",
                "n": int(_num(f.get("n", 0), "smb_files.n", 0, 2**32)),
                "size": int(_num(f.get("size", 0), "smb_files.size", 0, 2**62)),
                "end_of_file": int(_num(f.get("end_of_file", 0), "smb_files.end_of_file", 0, 2**62)),
                "magic": magic,
                "sha256": sha,
                "complete": bool(f.get("complete", False)),
                "ts": float(_num(f.get("ts", 0), "smb_files.ts", 0, 2**40)),
            })
        out["smb_files"] = files
    else:
        out.pop("smb_files", None)
    if rec.get("http2"):
        out["http2"] = True
    if "smb_encrypted" in rec:
        out["smb_encrypted"] = bool(rec.get("smb_encrypted"))

    if isinstance(rec.get("ftp"), dict):
        c = rec["ftp"]
        cmds = c.get("commands") if isinstance(c.get("commands"), list) else []
        out["ftp"] = {"user": _str(c.get("user"), "ftp.user", 256), "tls_refused": bool(c.get("tls_refused", False)),
                      "commands": [_str(x, "ftp.commands", 512) for x in cmds[:64]]}
    else:
        out.pop("ftp", None)
    if isinstance(rec.get("ftp_data"), dict):
        d = rec["ftp_data"]
        sha = _str(d.get("sha256"), "ftp_data.sha256", 64)
        magic = _str(d.get("magic"), "ftp_data.magic", 32)
        if not re.fullmatch(r"(?:[0-9a-f]{64})?", sha) or not re.fullmatch(r"[0-9a-f]*", magic):
            raise InvalidRecord("ftp_data: bad hash or magic")
        out["ftp_data"] = {
            "command": _str(d.get("command"), "ftp_data.command", 8).upper(),
            "name": _str(d.get("name"), "ftp_data.name", 1024),
            "user": _str(d.get("user"), "ftp_data.user", 256),
            "upload": bool(d.get("upload", False)),
            "active": bool(d.get("active", False)),
            "control": _str(d.get("control"), "ftp_data.control", 128),
            "reply": _str(d.get("reply"), "ftp_data.reply", 256),
            "size": int(_num(d.get("size", 0), "ftp_data.size", 0, 2**62)),
            "magic": magic,
            "sha256": sha,
            "complete": bool(d.get("complete", False)),
            "tls_refused": bool(d.get("tls_refused", False)),
            "side": 1 if d.get("side") == 1 else 0,
            "text": _str(d.get("text"), "ftp_data.text", 64 * 1024),
        }
    else:
        out.pop("ftp_data", None)

    # Logins sent in clear text: the account and whether it was accepted, never a password.
    if isinstance(rec.get("logins"), list):
        logins = []
        for l in rec["logins"][:32]:
            if not isinstance(l, dict):
                continue
            accepted = l.get("accepted")
            logins.append({
                "proto": _str(l.get("proto"), "logins.proto", 16),
                "method": _str(l.get("method"), "logins.method", 32),
                "user": _str(l.get("user"), "logins.user", 256),
                "accepted": accepted if isinstance(accepted, bool) else None,
                "anonymous": bool(l.get("anonymous", False)),
                "default_secret": bool(l.get("default_secret", False)),
                "ts": float(_num(l.get("ts", 0), "logins.ts", 0, 2**40)),
            })
        out["logins"] = logins
    else:
        out.pop("logins", None)

    if isinstance(rec.get("stream_head"), dict):
        h = rec["stream_head"]
        heads = {d: _str(h.get(d), f"stream_head.{d}", 32) for d in ("c2s", "s2c")}
        if not all(re.fullmatch(r"[0-9a-f]*", v) for v in heads.values()):
            raise InvalidRecord("stream_head: expected hex")
        first = h.get("first")
        out["stream_head"] = {**heads, "c2s_from_start": bool(h.get("c2s_from_start")),
                              "s2c_from_start": bool(h.get("s2c_from_start")),
                              "first": first if first in ("client", "server") else ""}
    else:
        out.pop("stream_head", None)

    # The application: from the first bytes (DPI) or the port; and what the port should carry.
    for k in ("app", "app_expected", "app_source"):
        v = rec.get(k)
        if v is None:
            out.pop(k, None)
        elif not isinstance(v, str) or not re.fullmatch(r"[a-z0-9-]{0,24}", v):
            raise InvalidRecord(f"{k}: expected a short protocol name")
    if "app_label" in rec:
        out["app_label"] = _str(rec.get("app_label"), "app_label", 64)

    if isinstance(rec.get("tcp"), dict):
        t = rec["tcp"]
        out["tcp"] = {k: bool(t.get(k, False)) for k in ("handshake", "closed", "rst")}
        out["tcp"].update({k: int(_num(t.get(k, 0), f"tcp.{k}", 0, 2**62))
                           for k in ("retransmissions", "out_of_order", "gap_bytes", "zero_window", "null_flags")})
        for k in ("syn_rtt_ms", "ack_rtt_ms"):  # the handshake's timing (the speed-of-light check)
            if t.get(k) is not None:
                out["tcp"][k] = float(_num(t[k], f"tcp.{k}", 0, 86_400_000))
        if isinstance(t.get("clock"), dict):  # each side's TCP timestamp clock: [t0, TSval0, t1, TSval1, readings]
            clock = {}
            for d in ("c2s", "s2c"):
                c = t["clock"].get(d)
                if isinstance(c, list) and len(c) == 5:
                    clock[d] = [float(_num(c[0], "clock.t0", 0, 2**40)), int(_num(c[1], "clock.v0", 0, 2**32 - 1)),
                                float(_num(c[2], "clock.t1", 0, 2**40)), int(_num(c[3], "clock.v1", 0, 2**32 - 1)),
                                int(_num(c[4], "clock.n", 0, 2**62))]
            if clock:
                out["tcp"]["clock"] = clock
    else:
        out.pop("tcp", None)

    pe = rec.get("payload_entropy")
    if isinstance(pe, dict):
        out["payload_entropy"] = {d: (float(_num(pe[d], "entropy", 0, 8)) if pe.get(d) is not None else None)
                                  for d in ("c2s", "s2c")}
    else:
        out.pop("payload_entropy", None)
    return out
