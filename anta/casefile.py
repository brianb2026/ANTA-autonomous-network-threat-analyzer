"""An investigation: the analyst's notes, the answers they pinned, their verdicts on the
alerts and the focus they were working in, saved to a file and opened again later (on the
same capture; the file names it). The file is plain JSON and holds no packets, only what the
analyst wrote and what ANTA answered.

A file opened here is untrusted input: every field is checked, cut to size and stripped of
control characters, and anything malformed is dropped rather than trusted.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
import time

FORMAT = "anta-investigation"
VERSION = 1
MAX_FILE = 5 * 1024 * 1024
MAX_PINS = 200
MAX_NOTES = 50_000
VERDICTS = ("investigating", "confirmed", "false_positive")
CAPTURE_EXT = (".pcap", ".pcapng", ".cap")

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]+")


class CaseError(ValueError):
    pass


def _text(v, limit: int, lines: bool = False) -> str:
    if not isinstance(v, str):
        return ""
    v = _CTRL.sub(" ", v) if lines else re.sub(r"[\x00-\x1f\x7f]+", " ", v)
    return v.strip()[:limit]


def _table(t) -> dict | None:
    if not isinstance(t, dict) or not isinstance(t.get("rows"), list):
        return None
    cols = [_text(c, 60) for c in (t.get("columns") or [])[:8] if isinstance(c, str)]
    rows = []
    for r in t["rows"][:25]:
        if not isinstance(r, dict) or not isinstance(r.get("cells"), list):
            continue
        rows.append({"cells": [_text(c, 300) for c in r["cells"][:8]], "filter": _text(r.get("filter"), 4096)})
    return {"columns": cols, "rows": rows, "note": _text(t.get("note"), 300), "facts": bool(t.get("facts"))}


def pin(data) -> dict:
    """A pinned answer, checked: {kind, question, summary, lines, table, filter}."""
    if not isinstance(data, dict):
        raise CaseError("a pin is an object")
    out = {
        "id": _text(data.get("id"), 24) or secrets.token_urlsafe(6),
        "kind": data.get("kind") if data.get("kind") in ("ask", "host", "note") else "ask",
        "question": _text(data.get("question"), 500),
        "summary": _text(data.get("summary"), 300),
        "lines": [_text(x, 500) for x in (data.get("lines") or [])[:12] if isinstance(x, str)],
        "table": _table(data.get("table")),
        "filter": _text(data.get("filter"), 4096),
        "pinned": float(data["pinned"]) if isinstance(data.get("pinned"), (int, float)) else time.time(),
    }
    if not (out["question"] or out["summary"] or out["lines"]):
        raise CaseError("a pin needs a question, a summary or an answer")
    return out


def signature(alert: dict) -> tuple:
    """What identifies an alert across two readings of the same capture (its number doesn't)."""
    return (alert.get("kind") or "", alert.get("src_ip") or "", alert.get("dst_ip") or "", alert.get("offender") or "")


def export(capture: dict, notes: str, pins: list[dict], alerts: list[dict], focus) -> str:
    verdicts = []
    for a in alerts:
        t = a.get("triage") or {}
        if t.get("status") in VERDICTS or t.get("note"):
            kind, src, dst, offender = signature(a)
            verdicts.append({"kind": kind, "src_ip": src, "dst_ip": dst, "offender": offender, "title": a.get("title") or "",
                             "status": t.get("status") or "new", "note": t.get("note") or ""})
    levels = []
    for f in (focus or [])[:16]:
        if isinstance(f, dict) and isinstance(f.get("filter"), str) and f["filter"].strip():
            levels.append({"label": _text(f.get("label"), 200), "filter": f["filter"][:200_000]})
    doc = {"format": FORMAT, "version": VERSION,
           "saved": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
           "capture": capture, "notes": notes, "pins": pins, "verdicts": verdicts, "focus": levels}
    return json.dumps(doc, indent=1, ensure_ascii=False)


def load(content) -> dict:
    """An investigation file's content, checked (CaseError if it isn't one)."""
    if not isinstance(content, str) or len(content.encode("utf-8", "replace")) > MAX_FILE:
        raise CaseError("that file is empty or larger than 5 MB")
    try:
        doc = json.loads(content)
    except ValueError as exc:
        raise CaseError("that file isn't an ANTA investigation (it isn't JSON)") from exc
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise CaseError("that file isn't an ANTA investigation")
    if not isinstance(doc.get("version"), int) or doc["version"] > VERSION:
        raise CaseError("that investigation was saved by a newer ANTA")
    cap = doc.get("capture") if isinstance(doc.get("capture"), dict) else {}
    path = _text(cap.get("path"), 4096)
    capture = {"name": _text(cap.get("name"), 255), "path": path if os.path.isabs(path) else "",
               "size": cap.get("size") if isinstance(cap.get("size"), int) else None,
               "packets": cap.get("packets") if isinstance(cap.get("packets"), int) else None}
    pins = []
    for p in (doc.get("pins") or [])[:MAX_PINS] if isinstance(doc.get("pins"), list) else []:
        try:
            pins.append(pin(p))
        except (CaseError, TypeError, ValueError):
            continue
    verdicts = []
    for v in (doc.get("verdicts") or [])[:5000] if isinstance(doc.get("verdicts"), list) else []:
        if not isinstance(v, dict) or v.get("status") not in ("new", *VERDICTS):
            continue
        verdicts.append({"kind": _text(v.get("kind"), 40), "src_ip": _text(v.get("src_ip"), 200),
                         "dst_ip": _text(v.get("dst_ip"), 200), "offender": _text(v.get("offender"), 200),
                         "title": _text(v.get("title"), 200), "status": v["status"], "note": _text(v.get("note"), 4000, True)})
    focus = []
    for f in (doc.get("focus") or [])[:16] if isinstance(doc.get("focus"), list) else []:
        if isinstance(f, dict) and isinstance(f.get("filter"), str) and f["filter"].strip() and len(f["filter"]) <= 200_000 \
                and not any(c in f["filter"] for c in "\x00\r\n"):
            focus.append({"label": _text(f.get("label"), 200), "filter": f["filter"]})
    return {"capture": capture, "notes": _text(doc.get("notes"), MAX_NOTES, True), "pins": pins, "verdicts": verdicts,
            "focus": focus, "saved": _text(doc.get("saved"), 40)}


def same_capture(saved: dict, current: dict) -> bool:
    """Whether the investigation was made on the capture that is open (its name and size)."""
    if not saved.get("name") or not current.get("name"):
        return False
    return saved["name"] == current["name"] and (saved.get("size") is None or saved.get("size") == current.get("size"))


def openable(path: str) -> bool:
    """A capture path from a file that may be offered to open: an existing capture file."""
    return bool(path) and os.path.isabs(path) and path.lower().endswith(CAPTURE_EXT) and os.path.isfile(path)
