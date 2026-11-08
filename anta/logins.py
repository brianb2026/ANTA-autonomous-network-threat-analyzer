"""Logins sent in clear text, from the capture's session index: like Wireshark's Tools >
Credentials, but never the password. For each client, server and account: the service, how
it logged in, how often, whether the server accepted it, and the encrypted form of the
service to move to. What it is for: the list of passwords to change.
"""
from __future__ import annotations

from .explain import SAFER_SERVICE


def report(sessions: list[dict]) -> dict:
    rows: dict[tuple, dict] = {}
    for rec in sessions:
        for l in rec.get("logins") or []:
            key = (rec["src_ip"], rec["dst_ip"], rec["dst_port"], l["proto"], l["method"], l["user"])
            r = rows.get(key)
            if r is None:
                r = rows[key] = {
                    "client": rec["src_ip"], "server": rec["dst_ip"], "port": rec["dst_port"],
                    "service": l["proto"], "method": l["method"], "user": l["user"],
                    "anonymous": l["anonymous"], "default_secret": l["default_secret"],
                    "logins": 0, "accepted": 0, "refused": 0, "unknown": 0,
                    "first": l["ts"], "last": l["ts"], "safer": SAFER_SERVICE.get(l["proto"], ""),
                    "seen": set(),
                }
            mark = (rec["flow_id"], l["ts"])
            if mark in r["seen"]:
                continue
            r["seen"].add(mark)
            r["logins"] += 1
            r["accepted" if l["accepted"] else "unknown" if l["accepted"] is None else "refused"] += 1
            r["default_secret"] |= l["default_secret"]
            r["first"], r["last"] = min(r["first"], l["ts"]), max(r["last"], l["ts"])
            if r["last"] == l["ts"]:  # the latest session: what "show packets" opens
                r["flow"] = {"src": rec["src_ip"], "dst": rec["dst_ip"], "proto": rec["proto"],
                             "sport": rec["src_port"], "dport": rec["dst_port"]}
    out = []
    for r in rows.values():
        del r["seen"]
        r["status"] = ("accepted" if r["accepted"] == r["logins"] else "refused" if r["refused"] == r["logins"]
                       else "unknown" if r["unknown"] == r["logins"] else "mixed")
        out.append(r)
    # Logins that worked first (those passwords certainly need changing), then the latest.
    out.sort(key=lambda r: (r["anonymous"], r["accepted"] == 0, -r["last"]))
    exposed = {(r["server"], r["service"], r["user"]) for r in out if not r["anonymous"]}
    return {
        "logins": out[:5000],
        "total": sum(r["logins"] for r in out),
        "accounts": len(exposed),
        "accepted": len({(r["server"], r["service"], r["user"]) for r in out if r["accepted"] and not r["anonymous"]}),
        "services": sorted({r["service"] for r in out}),
    }
