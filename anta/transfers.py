"""The files a connection carried, and what kind each is: for rules like "don't let router configs
be uploaded" or "no programs downloaded from the internet".

FTP transfers keep their text, so a configuration is recognised by reading it (devices.parse
knows Cisco, Juniper, MikroTik, OpenWrt, pfSense and other formats) as well as by its name.
HTTP and SMB transfers are judged by name, type and first bytes. TFTP, the other way routers
back up their configuration, isn't followed: a rule can forbid TFTP itself.
"""
from __future__ import annotations

import re

from . import devices, filetypes

CONFIG_NAME = re.compile(r"(?:^|[/_.-])(?:startup|running)-config|\.(?:cfg|conf|config|rsc|backup)$|(?:^|[/_.-])(?:config|backup)"
                         r"(?:[_.-]|$)|router|switch|firewall|cisco|mikrotik|openwrt|pfsense|fortigate", re.I)
DBDUMP_NAME = re.compile(r"\.(?:sql|dump|bak|db|sqlite3?|mdb|accdb)(?:\.gz|\.zip|\.7z)?$|(?:^|[/_.-])(?:dump|db_?backup)", re.I)

KINDS = {
    "config": ("router configurations", r"(?:(?:router|switch|firewall|device|network|cisco|juniper|mikrotik|openwrt)s?'? )?"
                                        r"(?:config(?:uration)?s?|config(?:uration)? (?:files?|backups?|dumps?)|backups? of "
                                        r"(?:the )?(?:router|switch|firewall)s?'? config(?:uration)?s?)|(?:router|switch|firewall|device) "
                                        r"backups?"),
    "program": ("programs", r"programs?|executables?|exe files?|binaries|binary files?|apps?|applications?|installers?|malware"),
    "script": ("scripts", r"scripts?|powershell scripts?|batch files?|macros?"),
    "archive": ("archives", r"archives?|zip files?|zips?|compressed files?|rar files?"),
    "document": ("documents", r"documents?|office (?:files|documents)|pdfs?|spreadsheets?|word documents?"),
    "dbdump": ("database dumps", r"database (?:dumps?|backups?|exports?|files?)|sql (?:dumps?|files?)|db (?:dumps?|backups?)"),
    "any": ("files", r"(?:any |all )?files?|anything|data|any data"),
}
PROTOCOLS = {"ftp": "FTP", "http": "HTTP", "https": "HTTP", "web": "HTTP", "smb": "SMB", "windows shares": "SMB", "file shares": "SMB"}


def kind_of(words: str) -> str | None:
    w = re.sub(r"^(?:the |any |a |an |our )", "", words.strip().lower())
    for key, (_, pattern) in KINDS.items():
        if re.fullmatch(pattern, w):
            return key
    return None


def label(kind: str) -> str:
    return KINDS[kind][0]


def files(s: dict) -> list[dict]:
    """The files a session carried: {name, up (towards the server), proto, kinds:set, why}."""
    out = []
    d = s.get("ftp_data")
    if d:
        name = d.get("name") or ""
        desc, ftype = filetypes.describe(d.get("magic") or "")
        kinds = {"any", *_by_type(ftype, name)}
        why = desc
        dev = devices.parse(d.get("text") or "", name) if d.get("text") else None
        if dev is not None:
            kinds.add("config")
            article = "an" if dev.kind[:1].lower() in "aeiou" else "a"
            why = f"{article} {dev.kind} configuration" + (f" ({dev.name})" if getattr(dev, "name", "") else "")
        elif CONFIG_NAME.search(name):
            kinds.add("config")
            why = why or "named like a configuration"
        out.append({"name": name or "(unnamed)", "up": bool(d.get("upload")), "proto": "FTP", "kinds": kinds, "why": why,
                    "size": int(d.get("size") or 0), "active": bool(d.get("active"))})
    for f in s.get("http_files") or []:
        name = filetypes.name_of(f.get("uri"), f.get("filename")) or f.get("uri") or "(unnamed)"
        desc, ftype = filetypes.describe(f.get("magic") or "")
        kinds = {"any", *_by_type(ftype, name)}
        if CONFIG_NAME.search(name):
            kinds.add("config")
        up = not f.get("status") and (f.get("method") or "").upper() in ("POST", "PUT", "PATCH")
        out.append({"name": name, "up": up, "proto": "HTTP", "kinds": kinds, "why": desc, "size": int(f.get("size") or 0)})
    for f in s.get("smb_files") or []:
        name = (f.get("name") or "").replace("\\", "/").rsplit("/", 1)[-1] or "(unnamed)"
        desc, ftype = filetypes.describe(f.get("magic") or "")
        kinds = {"any", *_by_type(ftype, name)}
        if CONFIG_NAME.search(name):
            kinds.add("config")
        out.append({"name": name, "up": f.get("op") == "write", "proto": "SMB", "kinds": kinds, "why": desc, "size": int(f.get("size") or 0)})
    return out


def _by_type(ftype: str, name: str) -> set[str]:
    ext = filetypes.extension(name)
    kinds = set()
    if ftype == "executable" or ext in filetypes.EXEC_EXT:
        kinds.add("program")
    if ftype == "script" or ext in filetypes.SCRIPT_EXT:
        kinds.add("script")
    if ftype == "archive":
        kinds.add("archive")
    if ftype == "document" or ext in ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "rtf"):
        kinds.add("document")
    if DBDUMP_NAME.search(name):
        kinds.add("dbdump")
    return kinds
