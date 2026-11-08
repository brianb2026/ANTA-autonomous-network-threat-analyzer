"""Export Objects: every file a capture carries (HTTP bodies, SMB2 reads and
writes, FTP transfers), listed from the session index. Each has an id the engine
uses to write that file out again (`--object FLOW:KIND:N`), and the SHA-256 the
copy must have."""
from __future__ import annotations

import re

from . import filetypes

OBJECT_ID = re.compile(r"(\d{1,19}):([hsf]):(\d{1,10})")


def _base(path: str) -> str:
    return re.split(r"[\\/]", path.split("?", 1)[0].rstrip("/\\"))[-1]


def list_objects(sessions: list[dict]) -> list[dict]:
    out = []
    for s in sessions:
        flow = s["flow_id"]
        https = bool((s.get("tls") or {}).get("decrypted"))  # read with the user's TLS key log
        scheme = "https" if https else "http"
        for f in s.get("http_files") or []:
            uri = f.get("uri") or ""
            # A response whose request wasn't read (the key log had only the server's secret)
            # still has the TLS server name.
            host = f.get("host") or (s.get("tls") or {}).get("sni") or s["dst_ip"]
            out.append({
                "id": f"{flow}:h:{f['n']}", "proto": "HTTPS" if https else "HTTP", "direction": "download",
                "name": f.get("filename") or _base(uri) or "(index)",
                "location": f"{scheme}://{host}{uri}" if uri else f"{scheme}://{host}/",
                "client": s["src_ip"], "server": s["dst_ip"], "size": f["size"], "magic": f["magic"],
                "sha256": f["sha256"], "complete": f["complete"], "ts": f.get("ts") or s["start"],
                "detail": f.get("content_type") or "",
            })
        for f in s.get("smb_files") or []:
            out.append({
                "id": f"{flow}:s:{f['n']}", "proto": "SMB", "direction": "upload" if f["op"] == "write" else "download",
                "name": _base(f["name"]) or f["name"], "location": f"{f['share']}\\{f['name']}",
                "client": s["src_ip"], "server": s["dst_ip"], "size": f["size"], "magic": f["magic"],
                "sha256": f["sha256"], "complete": f["complete"], "ts": f.get("ts") or s["start"], "detail": "",
            })
        d = s.get("ftp_data")
        if d and d["size"]:
            control = d.get("control") or ""
            client, _, server = control.partition(" -> ")
            client = client.rsplit(":", 1)[0] or s["src_ip"]
            server = server.rsplit(":", 1)[0] or s["dst_ip"]
            listing = d["command"] in ("LIST", "NLST", "MLSD")
            out.append({
                "id": f"{flow}:f:{d['side']}", "proto": "FTP", "direction": "upload" if d["upload"] else "download",
                "name": _base(d["name"]) if d["name"] else ("directory listing" if listing else "data"),
                "location": f"ftp://{server}/{d['name'].lstrip('/')}" if d["name"] else f"ftp://{server}/ ({d['command']})",
                "client": client, "server": server, "size": d["size"], "magic": d["magic"], "sha256": d["sha256"],
                "complete": d["complete"], "ts": s["start"], "detail": f"user {d['user']}" if d.get("user") else "",
            })
    for o in out:
        desc, kind = filetypes.describe(o["magic"])
        # What the bytes are; failing that, for HTTP, what the server said it sent.
        o["type"] = desc or _text_type(o["magic"]) or (o["detail"].split(";")[0] if o["proto"].startswith("HTTP") else "")
        o["program"] = kind in ("executable", "script")
    out.sort(key=lambda o: o["ts"])
    return out


def _text_type(magic_hex: str) -> str:
    """'text' when the first bytes are printable ASCII (configurations, listings, scripts without #!)."""
    try:
        head = bytes.fromhex(magic_hex)
    except ValueError:
        return ""
    return "text" if head and all(b in (9, 10, 13) or 32 <= b < 127 for b in head) else ""


def safe_name(name: str, fallback: str = "file") -> str:
    """A file name that is safe on every platform: no paths, no control or reserved characters."""
    base = _base(name or "")
    base = re.sub(r'[\x00-\x1f<>:"/\\|?*]+', "_", base).strip(" .")
    if base.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)),
                                      *(f"LPT{i}" for i in range(10))}:
        base = "_" + base
    return base[:120] or fallback
