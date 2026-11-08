"""What to look at first: up to five things in the capture, worst first, each with why it
matters and the next step. Built from what ANTA already found (the alerts linked into
device stories, passwords sent in clear text, programs downloaded) and, when that is
little, from the traffic itself (the largest upload to the internet).

Everything here is read from the capture on this computer. Account names are listed;
passwords never are (ANTA never keeps them).
"""
from __future__ import annotations

from . import netmap
from .explain import fmt_bytes

RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MAX_ITEMS = 5
BIG_UPLOAD = 1_000_000  # bytes up to one internet address before it's worth a glance


def _addr_filter(ip: str) -> str:
    return f"{'ipv6' if ':' in ip else 'ip'}.addr == {ip}"


def _who(ip: str, names: dict) -> str:
    n = names.get(ip)
    return f"{ip} ({n})" if n and n != ip else ip


def build(stories: list[dict], logins_report: dict | None, files: list[dict] | None, stats: dict | None,
          alerts: list[dict], names: dict | None = None, broken_rules: list[dict] | None = None,
          changed: list[dict] | None = None) -> list[dict]:
    names = names or {}
    items: list[dict] = []

    # The devices whose alerts tell a story, worst first (storyline.build sorts them).
    for s in stories[:3]:
        if RANK.get(s["severity"], 9) > RANK["medium"]:
            continue
        worst = min(s["steps"], key=lambda x: (RANK.get(x["severity"], 9), x["first_seen"]))
        actions = [{"label": "Open the alert", "do": "alert", "id": worst["id"]},
                   {"label": "Host details", "do": "host", "addr": s["device"]}]
        items.append({"severity": s["severity"], "title": f"{_who(s['device'], names)}: {worst['title']}",
                      "why": s.get("summary") or worst.get("headline") or "", "actions": actions})

    # Passwords anyone on the path could read.
    if logins_report and logins_report.get("total"):
        rows = [r for r in logins_report.get("logins") or [] if not r.get("anonymous")]
        worked = [r for r in rows if r.get("accepted")]
        services = sorted({r["service"] for r in rows}) or logins_report.get("services") or []
        accounts = logins_report.get("accounts") or 0
        if accounts:
            title = (f"{accounts} account{'s' if accounts != 1 else ''} logged in without encryption "
                     f"({', '.join(services[:4])})")
            why = ("Their passwords crossed the network in clear text; anyone on the path could read them. "
                   + (f"{len(worked)} of the logins worked, so those passwords are real: change them, " if worked else "Change them, ")
                   + "and move to the encrypted form of the service.")
            items.append({"severity": "high" if worked else "medium", "title": title, "why": why,
                          "actions": [{"label": "The logins", "do": "stats", "tool": "logins"}]})

    # Programs and scripts that arrived over the network.
    programs = [f for f in files or [] if f.get("program")]
    if programs:
        names_list = ", ".join(sorted({f["name"] for f in programs})[:3])
        more = len({f["name"] for f in programs}) - 3
        items.append({"severity": "high", "title": f"{len(programs)} program{'s' if len(programs) != 1 else ''} or "
                                                   f"script{'s' if len(programs) != 1 else ''} downloaded: {names_list}"
                                                   + (f" and {more} more" if more > 0 else ""),
                      "why": "Executable files carried in the traffic. Check where each came from and its SHA-256; "
                             "never run one to find out.",
                      "actions": [{"label": "The files", "do": "files", "programs": True},
                                  {"label": "Host details", "do": "host", "addr": programs[0]["client"]}]})

    # The network's own rules (policy tests) that the capture breaks.
    for r in (broken_rules or [])[:2]:
        first = (r.get("groups") or [{}])[0]
        items.append({"severity": "medium", "title": f"Rule broken: {r['rule']}",
                      "why": f"{r['violations']:,} connection{'s' if r['violations'] != 1 else ''} break it"
                             + (f", first {first['what']}." if first.get("what") else "."),
                      "actions": [a for a in ({"label": "Show them", "do": "packets", "filter": r.get("filter")}
                                              if r.get("filter") else None,
                                              {"label": "Network rules", "do": "policy"}) if a]})

    # Devices behaving differently from what was remembered as normal.
    for d in (changed or [])[:2]:
        first = next(c for c in d["changes"] if c["notable"])
        new = first["what"].startswith("A device that wasn't on the network")
        items.append({"severity": "medium", "title": f"{_who(d['ip'], names)} " + ("is new on the network" if new else
                                                                                    "changed its behavior"),
                      "why": f"{first['what']} Now: {d['sentence']}",
                      "actions": [a for a in ({"label": "Show it", "do": "packets", "filter": first["filter"]}
                                              if first.get("filter") else None,
                                              {"label": "Host details", "do": "host", "addr": d["ip"]},
                                              {"label": "All devices", "do": "personalities"}) if a]})

    # The largest upload to the internet, when no alert already covers that pair.
    if stats and len(items) < MAX_ITEMS:
        alerted = {frozenset((a.get("src_ip"), a.get("dst_ip"))) for a in alerts}
        best = None
        for fam in ("ipv4", "ipv6"):
            for r in ((stats.get("conversations") or {}).get(fam) or {}).get("rows") or []:
                a, b = r[0], r[2]
                sa, sb = netmap.scope_of(a), netmap.scope_of(b)
                if sa == "private" and sb == "public":
                    inside, outside, up, down = a, b, r[5], r[7]
                elif sb == "private" and sa == "public":
                    inside, outside, up, down = b, a, r[7], r[5]
                else:
                    continue
                if up >= BIG_UPLOAD and up > down and frozenset((inside, outside)) not in alerted and \
                        (best is None or up > best[2]):
                    best = (inside, outside, up, down)
        if best:
            inside, outside, up, down = best
            items.append({"severity": "info", "title": f"Largest upload to the internet: {_who(inside, names)} → "
                                                       f"{_who(outside, names)}, {fmt_bytes(up)}",
                          "why": f"It sent {fmt_bytes(up)} and received {fmt_bytes(down)}. Uploads this size are backups and "
                                 "file sharing, or data leaving: worth a glance at where it went.",
                          "actions": [{"label": "Show its packets", "do": "packets",
                                       "filter": f"{_addr_filter(inside)} && {_addr_filter(outside)}"},
                                      {"label": "Host details", "do": "host", "addr": outside}]})

    items.sort(key=lambda it: RANK.get(it["severity"], 9))
    return items[:MAX_ITEMS]
