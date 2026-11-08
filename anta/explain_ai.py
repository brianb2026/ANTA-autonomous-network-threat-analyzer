"""Explain with AI: a selection of packets (or a conversation, or an alert's connections)
explained in plain words by the AI model set up under Detection…, when the user asks.

What is sent is evidence about the packets, never the packets: one summary line per
packet (number, time, the two ends, protocol, length, and the Info column with anything
secret taken out), the selection's statistics (protocols, conversations, expert notes,
names looked up, server names), ANTA's own rule-based findings and the alerts about it.
Never packet bytes. Passwords, logins' secrets, query strings, cookies and long encoded
strings are removed from every line; internal addresses and hardware addresses become
internal-host-N and mac-N unless the user allowed sharing them, and are put back in the
answer. The page shows exactly this text before anything is sent.
"""
from __future__ import annotations

import re

MAX_ROWS_HEAD, MAX_ROWS_TAIL = 80, 40
MAX_CHARS = 30_000
ASSESSMENTS = ("normal", "worth a look", "suspicious", "malicious", "unclear")

SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "2 to 4 sentences: what these packets show, for an analyst"},
        "assessment": {"type": "string", "enum": list(ASSESSMENTS)},
        "observations": {"type": "array", "items": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "one fact or inference, in plain words"},
                           "frames": {"type": "array", "items": {"type": "integer"},
                                      "description": "the frame numbers it rests on"}},
            "required": ["text", "frames"], "additionalProperties": False}},
        "next_steps": {"type": "array", "items": {"type": "string"},
                       "description": "what to check next (observation and defence only)"},
        "confidence": {"type": "number", "description": "0 to 1: how sure you are of the assessment"},
    },
    "required": ["summary", "assessment", "observations", "next_steps", "confidence"],
    "additionalProperties": False,
}

SYSTEM = """You are the analyst's assistant inside ANTA, a passive network analyzer like Wireshark, \
used on a network its owner runs. You are given evidence about packets the analyst selected: one summary \
line per packet (frame number, seconds since the capture started, source → destination, protocol, length, \
the Info column), the selection's statistics, ANTA's own rule-based findings and any alerts about it. You \
never see packet bytes; secrets were removed (shown as [hidden]), and addresses on the analyst's network may \
appear as internal-host-N or mac-N.

Explain what these packets show: what the devices were doing, in what order, and why it most likely \
happened. Say what is normal and what isn't. Cite the frame numbers each observation rests on. Separate \
what the packets show from what you infer, and say so when the evidence is too thin to tell. Be \
calibrated: most traffic is benign; call it malicious only on real evidence. Suggest next steps an \
analyst can take to check or defend (filters to apply, things to look at, settings to fix), never \
actions against other systems.

Answer with only the JSON object."""

# Secrets that can show in a packet's Info column, and what they become.
_REDACT = [
    (re.compile(r"(?i)\b(PASS|PASSWORD)\b(\s+)\S.*"), r"\1\2[hidden]"),
    (re.compile(r'(?i)\b(LOGIN)(\s+)("[^"]*"|\S+)\s+\S.*'), r"\1\2\3 [hidden]"),
    (re.compile(r"(?i)\b(AUTH(?:ENTICATE)?\s+(?:PLAIN|LOGIN|CRAM-MD5|DIGEST-MD5|XOAUTH2|OAUTHBEARER|NTLM|GSSAPI))\s+\S+"),
     r"\1 [hidden]"),
    (re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|token|secret|api[_-]?key|access[_-]?token|auth|sessionid|session|sid|"
                r"key|code)=([^&\s;]+)"), r"\1=[hidden]"),
    (re.compile(r"(?i)\b(cookie|set-cookie|authorization|proxy-authorization):?\s+\S.*"), r"\1: [hidden]"),
    (re.compile(r"\?[^\s\"']+"), "?[query removed]"),
    # A long encoded string (base64 credentials, tokens), but not a dotted name or a hash.
    (re.compile(r"(?<![.\w])(?=[A-Za-z0-9+/_=-]*[+/=])[A-Za-z0-9+/_-]{20,}={0,2}(?![.\w])"), "[data]"),
]


# A line that is one base64 token: what a client sends after SMTP's or POP's AUTH LOGIN, or
# IMAP's AUTHENTICATE (the user name, then the password).
_B64_LINE = re.compile(r"^((?:[CS]:|Request:|Response:)\s+)?([A-Za-z0-9+/]{4,}={0,2})\s*$")


def redact(text: str) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text or ""))
    m = _B64_LINE.match(text.strip())
    if m and len(m.group(2)) % 4 == 0 and not m.group(2).isdigit() and not m.group(2).isalpha():
        return f"{m.group(1) or ''}[hidden]"
    for pattern, repl in _REDACT:
        text = pattern.sub(repl, text)
    return text[:300]


def _rows(rows: list[dict], t0: float | None, total: int | None) -> list[str]:
    def line(p):
        t = f"{p['ts'] - t0:.6f}" if t0 is not None and p.get("ts") is not None else "?"
        return f"#{p['n']}  {t}s  {p.get('src') or '?'} → {p.get('dst') or '?'}  {p.get('proto') or ''}  " \
               f"{p.get('len') or 0}B  {redact(p.get('info') or '')}"
    if len(rows) <= MAX_ROWS_HEAD + MAX_ROWS_TAIL:
        out = [line(p) for p in rows]
    else:
        out = [line(p) for p in rows[:MAX_ROWS_HEAD]]
        out.append(f"… {len(rows) - MAX_ROWS_HEAD - MAX_ROWS_TAIL:,} packets not shown …")
        out += [line(p) for p in rows[-MAX_ROWS_TAIL:]]
    if total is not None and total > len(rows):
        out.append(f"(the lines above cover the first {len(rows):,} of {total:,} packets)")
    return out


def evidence(label: str, rows: list[dict], total: int | None, t0: float | None, stats: dict | None,
             diagnosis: dict | None, alerts: list[dict]) -> str:
    """The text the model is sent (before pseudonyms): headed sections, plain lines."""
    out = [f"SELECTION: {label}"]
    s = stats or {}
    p = s.get("properties") or {}
    if p:
        out.append(f"{p.get('frames', 0):,} packets, {p.get('bytes', 0):,} bytes over {p.get('duration') or 0:.3f} s.")
    protos = sorted(s.get("protocols") or [], key=lambda r: -r.get("frames", 0))
    if protos:
        out.append("\nPROTOCOLS (packets containing each, by layer):")
        out += [f"  {r['path'].removeprefix('frame/')}: {r['frames']:,}" for r in protos[:20] if r.get("path") != "frame"]
    def end(addr, port):
        return f"[{addr}]:{port}" if ":" in str(addr) else f"{addr}:{port}"
    conv = []
    for kind in ("tcp", "udp"):
        for r in ((s.get("conversations") or {}).get(kind) or {}).get("rows") or []:
            conv.append((r[5] + r[7], f"  {kind.upper()} {end(r[0], r[1])} ↔ {end(r[2], r[3])}: {r[4]:,} packets/{r[5]:,} B A→B, "
                                      f"{r[6]:,}/{r[7]:,} B B→A, {r[9]:.3f} s"))
    if conv:
        out.append("\nCONVERSATIONS (largest first):")
        out += [c[1] for c in sorted(conv, key=lambda c: -c[0])[:12]]
    expert = sorted(s.get("expert") or [], key=lambda e: -e.get("count", 0))
    if expert:
        out.append("\nEXPERT NOTES (as Wireshark's Expert Information):")
        out += [f"  {e['severity']}: {redact(e['summary'])} ×{e['count']} (e.g. frame {(e.get('frames') or ['?'])[0]})"
                for e in expert[:15]]
    for title, pairs in (("DNS NAMES QUERIED", ((s.get("dns") or {}).get("names") or [])),
                         ("TLS SERVER NAMES", ((s.get("tls") or {}).get("server_names") or [])),
                         ("HTTP HOSTS", ((s.get("http") or {}).get("hosts") or [])),
                         ("HTTP STATUS CODES", ((s.get("http") or {}).get("status") or []))):
        if pairs:
            out.append(f"\n{title}:")
            out += [f"  {redact(k)}: {v:,}" for k, v in pairs[:15]]
    if diagnosis and diagnosis.get("conversations"):
        out.append("\nANTA'S RULE-BASED FINDINGS:")
        for c in diagnosis["conversations"][:6]:
            out.append(f"  [{c.get('status')}] {c.get('title')}: {redact(c.get('summary') or '')}")
    if alerts:
        out.append("\nANTA ALERTS ABOUT THESE PACKETS:")
        out += [f"  {a.get('severity', '').upper()} {a.get('title')}: {redact(a.get('headline') or '')}" for a in alerts[:6]]
    out.append("\nPACKETS:")
    out += _rows(rows, t0, total)
    text = "\n".join(out)
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + "\n… (cut to fit)"
    return text


def clean(data: dict, names) -> dict:
    """A model's answer, checked and with the pseudonyms it used turned back into addresses."""
    if not isinstance(data, dict):
        raise ValueError("not an object")

    def txt(v, n=1200):
        return names.restore(re.sub(r"[\x00-\x08\x0b-\x1f\x7f]+", " ", str(v or "")))[:n]
    obs = []
    for o in (data.get("observations") or [])[:14]:
        if isinstance(o, dict) and o.get("text"):
            frames = [int(f) for f in (o.get("frames") or []) if isinstance(f, int) and not isinstance(f, bool) and f > 0]
            obs.append({"text": txt(o["text"], 800), "frames": sorted(set(frames))[:20]})
    try:
        conf = max(0.0, min(1.0, float(data.get("confidence") or 0)))
    except (TypeError, ValueError):
        conf = 0.0
    assessment = data.get("assessment") if data.get("assessment") in ASSESSMENTS else "unclear"
    return {"summary": txt(data.get("summary"), 2000), "assessment": assessment, "observations": obs,
            "next_steps": [txt(x, 500) for x in (data.get("next_steps") or [])[:10] if x], "confidence": conf}
