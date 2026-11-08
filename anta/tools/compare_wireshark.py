"""Compare ANTA's packet list against Wireshark's (tshark) for a capture.

  python -m anta.tools.compare_wireshark capture.pcap [--show 20] [--proto TCP] [--keylog FILE]

Reports per-column agreement for Source, Destination, Protocol, Length and
Info, and lists the most common mismatches. Needs tshark (ships with
Wireshark; on macOS /Applications/Wireshark.app/Contents/MacOS/tshark).
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def find_tshark() -> str | None:
    for candidate in (shutil.which("tshark"), "/Applications/Wireshark.app/Contents/MacOS/tshark",
                      r"C:\Program Files\Wireshark\tshark.exe"):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def unescape(field: str) -> str:
    """tshark -T fields escapes backslashes (and a few separators) in values."""
    return re.sub(r"\\(.)", lambda m: {"t": "\t", "n": "\n", "r": "\r"}.get(m.group(1), m.group(1)), field)


def wireshark_rows(tshark: str, path: str, two_pass: bool = True, keylog: str | None = None) -> dict[int, dict]:
    # Two-pass matches the Wireshark window (cross-references like "reply in N").
    keys = ["-o", f"tls.keylog_file:{keylog}"] if keylog else []
    out = subprocess.run([tshark, *(["-2"] if two_pass else []), *keys, "-r", path, "-T", "fields", "-E", "separator=\x1f", "-E", "quote=n",
                          "-e", "frame.number", "-e", "_ws.col.def_src", "-e", "_ws.col.def_dst",
                          "-e", "_ws.col.protocol", "-e", "frame.len", "-e", "_ws.col.info"],
                         capture_output=True, text=True, check=True).stdout
    rows = {}
    for line in out.splitlines():
        parts = line.split("\x1f")
        if len(parts) < 6:
            continue
        rows[int(parts[0])] = {"src": parts[1], "dst": parts[2], "proto": parts[3], "len": int(parts[4]),
                               "info": unescape(parts[5])}
    return rows


def anta_rows(engine: str, path: str, two_pass: bool = True, keylog: str | None = None) -> dict[int, dict]:
    rows: dict[int, dict] = {}
    start = 1
    while True:  # the engine pages at most 100000 rows at a time
        cmd = [engine, "--packets", "-r", path, "--from", str(start), "--limit", "100000"]
        if not two_pass:
            cmd.append("--single-pass")
        if keylog:
            cmd += ["--keylog", keylog]
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
        nxt = None
        for line in out.splitlines():
            rec = json.loads(line)
            if rec.get("type") == "packet":
                rows[rec["n"]] = {"src": rec["src"], "dst": rec["dst"], "proto": rec["proto"], "len": rec["len"],
                                  "info": rec["info"]}
            elif rec.get("type") == "page":
                nxt = rec.get("next")
        if not nxt:
            return rows
        start = nxt


def normalise(s: str) -> str:
    return " ".join(s.split())  # Wireshark pads some Info strings with runs of spaces


def compare(path: str, engine: str, tshark: str, show: int = 15, proto: str | None = None,
            two_pass: bool = True, keylog: str | None = None) -> dict:
    ws, an = wireshark_rows(tshark, path, two_pass, keylog), anta_rows(engine, path, two_pass, keylog)
    frames = sorted(set(ws) & set(an))
    if proto:
        frames = [n for n in frames if ws[n]["proto"] == proto]
    scores = {}
    mismatches = collections.defaultdict(collections.Counter)
    examples = {}
    for col in ("src", "dst", "proto", "len", "info"):
        ok = 0
        for n in frames:
            a, b = ws[n][col], an[n][col]
            same = normalise(str(a)) == normalise(str(b))
            ok += same
            if not same:
                key = (ws[n]["proto"], col)
                sample = f"WS: {str(a)[:110]}\n      ANTA: {str(b)[:110]}"
                mismatches[key][sample] += 1
                examples.setdefault(key, n)
        scores[col] = ok / len(frames) if frames else 1.0
    full = sum(all(normalise(str(ws[n][c])) == normalise(str(an[n][c])) for c in ("src", "dst", "proto", "len", "info"))
               for n in frames)
    print(f"{os.path.basename(path)}: {len(frames)} frames compared (Wireshark {len(ws)}, ANTA {len(an)})")
    for col, s in scores.items():
        print(f"  {col:6} {s:7.2%}")
    print(f"  all columns identical: {full}/{len(frames)} ({full / max(1, len(frames)):.2%})")
    if show:
        ranked = sorted(mismatches.items(), key=lambda kv: -sum(kv[1].values()))
        for (wproto, col), samples in ranked[:show]:
            total = sum(samples.values())
            sample, _ = samples.most_common(1)[0]
            print(f"\n  [{wproto} / {col}] {total} mismatches, e.g. frame {examples[(wproto, col)]}:\n      {sample}")
    return {"frames": len(frames), "scores": scores, "identical": full}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("captures", nargs="+")
    ap.add_argument("--engine", default=os.path.join(ROOT, "build", "anta-engine"))
    ap.add_argument("--show", type=int, default=15)
    ap.add_argument("--proto", help="only frames Wireshark labels with this protocol")
    ap.add_argument("--one-pass", action="store_true",
                    help="compare the single-pass views (what a live capture shows) instead of the file view")
    ap.add_argument("--keylog", help="a TLS key log (SSLKEYLOGFILE) both sides decrypt with")
    args = ap.parse_args()
    tshark = find_tshark()
    if not tshark:
        print("tshark not found (install Wireshark)", file=sys.stderr)
        return 2
    for path in args.captures:
        compare(path, args.engine, tshark, args.show, args.proto, not args.one_pass, args.keylog)
    return 0


if __name__ == "__main__":
    sys.exit(main())
