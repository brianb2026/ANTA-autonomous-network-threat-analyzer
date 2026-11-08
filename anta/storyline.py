"""Attack storyline: the alerts about one device linked into one story, in time order and
attack stage (scouting, getting in the middle, delivery, calling home, spreading, data
leaving), with a plain-words account of what happened and where it went next.

Each alert is filed under the device it is about: the device ANTA names as the culprit
(offender), else the internal end of it. An alert that moves to another internal device
(a program copied over SMB) appears in both stories and links them. Alerts an analyst
marked false positive, and low-severity shared traffic, are left out.
"""
from __future__ import annotations

from . import devices

STAGES = [
    ("recon", "Scouting the network"),
    ("position", "Getting in the middle"),
    ("delivery", "Malware delivered"),
    ("c2", "Calling home"),
    ("lateral", "Spreading inside"),
    ("exfil", "Data leaving"),
    ("other", "Other unusual activity"),
]
STAGE_LABEL = dict(STAGES)
STAGE_ORDER = {k: i for i, (k, _) in enumerate(STAGES)}
KIND_STAGE = {
    "scan": "recon",
    "arp_spoof": "position", "dns_poison": "position",
    "download": "delivery",
    "beacon": "c2", "dga": "c2", "tls_port": "c2", "port_mismatch": "c2",
    "smb_file": "lateral", "compromised_device": "lateral",
    "exfil": "exfil", "dns_tunnel": "exfil", "ftp_file": "exfil",
    "anomaly": "other", "baseline": "other", "crafted_tcp": "other", "agent": "other", "intel_match": "c2",
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
# Common cloud traffic many hosts share, and passwords sent in clear text (a habit to fix, not an
# attack step): noise in a story.
SKIP_KINDS = {"shared", "cleartext_login"}
INTERNAL = {"private", "link-local", "loopback", "shared"}


def _internal(ip) -> bool:
    return bool(ip) and devices.address_kind(str(ip)) in INTERNAL


def _subject(a: dict) -> str | None:
    """The device an alert is about."""
    if a.get("offender"):
        return str(a["offender"]).split(",")[0].strip()
    if a.get("kind") == "compromised_device" and a.get("addresses"):
        return a["addresses"][0]
    for ip in (a.get("src_ip"), a.get("dst_ip")):
        if _internal(ip):
            return ip
    return a.get("src_ip")


def _stage(a: dict) -> str:
    if a.get("kind") == "intel_match":  # a known-bad file or download is delivery; an address or domain, calling home
        m = a.get("metrics") or {}
        if str(m.get("indicator_kind") or m.get("kind") or "").lower() in ("sha256", "url", "file"):
            return "delivery"
    return KIND_STAGE.get(a.get("kind"), "other")


def _peer(a: dict, subject: str) -> str:
    for v in (a.get("target"), a.get("dst_ip") if a.get("dst_ip") != subject else a.get("src_ip")):
        if v and v != subject:
            return str(v)
    return ""


def _clock(ts: float) -> str:
    import datetime as dt
    return dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else ""


PHRASES = {  # what a step says in the story's one-paragraph account
    "recon": "scanned the network",
    "position": "put itself in the middle of other devices' traffic",
    "delivery": "received suspicious software",
    "c2": "started calling home",
    "lateral": "spread to another device",
    "exfil": "sent data out",
    "other": "behaved unusually",
}


def _sentence(subject: str, steps: list[dict]) -> str:
    """One paragraph in time order: each stage once, at the time it first happened."""
    seen, parts = set(), []
    for s in steps:
        if s["stage"] in seen:
            continue
        seen.add(s["stage"])
        peer = f" ({s['peer']})" if s["peer"] and s["stage"] in ("c2", "lateral", "exfil", "delivery") else ""
        parts.append(f"{PHRASES[s['stage']]}{peer} at {_clock(s['first_seen'])}")
    if not parts:
        return ""
    if len(parts) == 1:
        body = parts[0]
    else:
        body = ", then ".join(parts[:-1]) + ", and then " + parts[-1]
    return f"{subject} {body}."


def build(alerts: list[dict], names: dict[str, str] | None = None) -> dict:
    names = names or {}
    stories: dict[str, dict] = {}

    def story(ip: str) -> dict:
        if ip not in stories:
            stories[ip] = {"device": ip, "name": names.get(ip, ""), "internal": _internal(ip), "steps": [], "links": set()}
        return stories[ip]

    for a in alerts:
        if a.get("kind") in SKIP_KINDS or ((a.get("triage") or {}).get("status") == "false_positive"):
            continue
        subject = _subject(a)
        if not subject:
            continue
        stage = _stage(a)
        step = {"id": a["id"], "kind": a.get("kind"), "stage": stage, "stage_label": STAGE_LABEL[stage],
                "title": a.get("title"), "headline": a.get("headline", ""), "severity": a.get("severity"),
                "first_seen": a.get("first_seen") or 0, "last_seen": a.get("last_seen") or 0,
                "peer": _peer(a, subject), "verdict": (a.get("triage") or {}).get("status") or "new"}
        story(subject)["steps"].append(step)
        # Spreading: the device it reached gets the step too, and the two stories link.
        if stage == "lateral" and step["peer"] and _internal(step["peer"]) and step["peer"] != subject:
            target = story(step["peer"])
            target["steps"].append({**step, "stage": "delivery", "stage_label": STAGE_LABEL["delivery"],
                                    "peer": subject, "received_from": subject})
            story(subject)["links"].add(step["peer"])
            target["links"].add(subject)

    out = []
    for s in stories.values():
        steps = sorted(s["steps"], key=lambda x: (x["first_seen"], STAGE_ORDER[x["stage"]]))
        reached = sorted({x["stage"] for x in steps}, key=STAGE_ORDER.get)
        worst = min((x["severity"] for x in steps), key=lambda v: SEVERITY_RANK.get(v, 9))
        out.append({
            "device": s["device"], "name": s["name"], "internal": s["internal"], "steps": steps,
            "stages": reached, "attack_stages": [x for x in reached if x != "other"],
            "severity": worst, "first_seen": steps[0]["first_seen"], "last_seen": max(x["last_seen"] for x in steps),
            "links": sorted(s["links"]), "summary": _sentence(s["name"] or s["device"], steps),
        })
    # The worst first: severity, how far the attack got, then the earliest.
    out.sort(key=lambda s: (SEVERITY_RANK.get(s["severity"], 9), -len(s["attack_stages"]), s["first_seen"]))
    return {"stories": out, "stages": [{"id": k, "label": v} for k, v in STAGES if k != "other"]}
