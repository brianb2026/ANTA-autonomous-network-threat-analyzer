"""The tamper seal: was this capture edited, spliced or cut, and has it changed since you
sealed it?

Two kinds of evidence:

  The seal itself: the file's SHA-256, recorded on request (seals.json in the app's data
  directory). Opening the file later says whether a single byte changed since; a hash someone
  gave you can be compared too.

  Internal consistency, for a file that was never sealed: what a capture tool writes can't
  contradict itself, and editing tends to leave contradictions behind.
    - Record headers: a stored length longer than the file's snap length or than the packet
      itself, a microsecond field of a million or more, a file that ends mid-record.
    - pcapng blocks: a block whose closing length disagrees with its opening one, several
      sections (files joined together), the program that last wrote it (editcap, mergecap,
      TraceWrangler and friends rewrite captures), the capture tool's own count of drops.
    - Time: packets that go backwards in time, times in the future, times after the file was
      last saved, a clock that was never set (1970).
    - Checksums: IPv4, TCP and UDP checksums are computed by the sender and don't survive a
      changed byte. A computer that captures its own traffic often hands checksums to its
      network card ("offloading"), so wrong checksums on one host's sent packets are normal;
      wrong ones from other hosts mean the bytes changed after they were sent.
    - Missing packets: TCP says when bytes were acknowledged that the capture never saw. Losses
      scattered through the file are the capture dropping packets; losses in many connections
      at once, right after a silence, look like a stretch was cut out.

None of this proves a file is untouched (a careful forger recomputes checksums); it finds the
contradictions that ordinary editing leaves.
"""
from __future__ import annotations

import contextlib
import gzip
import hashlib
import json
import os
import struct
import tempfile
import time
from collections import Counter, defaultdict

from . import paths

PCAP_MAGIC = {0xA1B2C3D4: ("<", 1e-6), 0xD4C3B2A1: (">", 1e-6), 0xA1B23C4D: ("<", 1e-9), 0x4D3CB2A1: (">", 1e-9)}
PCAPNG_SHB = 0x0A0D0D0A
EDITORS = ("editcap", "mergecap", "tracewrangler", "tcprewrite", "bittwiste", "text2pcap", "pcapfix", "reordercap",
           "scapy", "netsniff", "pcap-ng-edit", "tshark -w", "dumpcap merge")
MAX_LIST = 20
SEV = {"fail": 0, "note": 1, "pass": 2}


def seals_path() -> str:
    return os.path.join(paths.app_data_dir(), "seals.json")


def _open(path: str):
    with open(path, "rb") as fh:
        head = fh.read(2)
    return gzip.open(path, "rb") if head == b"\x1f\x8b" else open(path, "rb")  # noqa: SIM115


def file_hash(path: str) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


# ---------------------------------------------------------------- reading the file's structure

class Walk:
    """Every record's time and length, and every contradiction in the file's own structure."""

    def __init__(self, base: int = 0):
        self.frame = base
        self.format = ""
        self.writer = ""
        self.os = ""
        self.hardware = ""
        self.sections = 0
        self.interfaces: list[dict] = []
        self.issues: dict[str, list] = defaultdict(list)   # id -> [frame or detail]
        self.counts: Counter = Counter()
        self.first = None
        self.last = None
        self.prev: dict[int, float] = {}       # interface -> last time
        self.back: list[tuple[int, float]] = []  # (frame, how far back in seconds)
        self.gaps: list[tuple[float, int, float]] = []  # (seconds, frame after the gap, time)
        self.last_any = None
        self.prev_bytes: bytes | None = None
        self.prev_ts = 0.0
        self.whole_seconds = 0
        self.drops = 0
        self.comments = 0
        self.secrets = 0

    def issue(self, key: str, item) -> None:
        self.counts[key] += 1
        if len(self.issues[key]) < MAX_LIST:
            self.issues[key].append(item)

    def packet(self, iface: int, ts: float, caplen: int, origlen: int, snaplen: int, data: bytes) -> None:
        self.frame += 1
        n = self.frame
        if snaplen and caplen > snaplen:
            self.issue("over_snaplen", n)
        if caplen > origlen:
            self.issue("over_origlen", n)
        if ts < 315532800:  # (before 1980: the capturing device's clock was never set)
            self.issue("clock_unset", n)
        elif ts > time.time() + 86400:
            self.issue("future", n)
        prev = self.prev.get(iface)
        if prev is not None and ts < prev:
            if len(self.back) < 5000:
                self.back.append((n, prev - ts))
            self.counts["backwards"] += 1
        self.prev[iface] = max(ts, prev) if prev is not None else ts
        if self.last_any is not None and ts - self.last_any > 0:
            gap = ts - self.last_any
            if len(self.gaps) < 64 or gap > self.gaps[-1][0]:
                self.gaps.append((gap, n, ts))
                self.gaps.sort(reverse=True)
                del self.gaps[64:]
        self.last_any = ts if self.last_any is None else max(self.last_any, ts)
        if ts == int(ts):
            self.whole_seconds += 1
        if self.prev_bytes is not None and data == self.prev_bytes and abs(ts - self.prev_ts) < 0.001:
            self.issue("duplicate", n)
        self.prev_bytes, self.prev_ts = data, ts
        self.first = ts if self.first is None else min(self.first, ts)
        self.last = ts if self.last is None else max(self.last, ts)

    # ---- classic pcap
    def pcap(self, fh, head: bytes) -> None:
        order, unit = PCAP_MAGIC[struct.unpack("<I", head[:4])[0]]
        self.format = "pcap (nanosecond times)" if unit == 1e-9 else "pcap"
        rest = fh.read(20)
        if len(rest) < 20:
            self.issue("ends_midway", "the file header")
            return
        _maj, _min, _tz, _sig, snaplen, link = struct.unpack(order + "HHiIII", rest)
        self.interfaces.append({"link": link & 0xFFFF, "snaplen": snaplen})
        limit = 1_000_000_000 if unit == 1e-9 else 1_000_000
        while True:
            rec = fh.read(16)
            if not rec:
                return
            if len(rec) < 16:
                self.issue("ends_midway", f"after frame {self.frame}")
                return
            sec, frac, caplen, origlen = struct.unpack(order + "IIII", rec)
            if frac >= limit:
                self.issue("bad_fraction", self.frame + 1)
            if caplen > 0x4000000:
                self.issue("ends_midway", f"frame {self.frame + 1} claims {caplen:,} bytes")
                return
            data = fh.read(caplen)
            if len(data) < caplen:
                self.issue("ends_midway", f"inside frame {self.frame + 1}")
                return
            self.packet(0, sec + frac * unit, caplen, origlen, snaplen, data)

    # ---- pcapng
    def pcapng(self, fh, head: bytes) -> None:
        self.format = "pcapng"
        order = "<"
        buf = head
        tsres: list[float] = []
        snaps: list[int] = []
        while True:
            hdr = buf if len(buf) >= 8 else buf + fh.read(8 - len(buf))
            buf = b""
            if not hdr:
                return
            if len(hdr) < 8:
                self.issue("ends_midway", f"after frame {self.frame}")
                return
            btype = struct.unpack(order + "I", hdr[:4])[0]
            if btype == PCAPNG_SHB:
                bom = fh.read(4)
                if len(bom) < 4:
                    self.issue("ends_midway", "a section header")
                    return
                order = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                total = struct.unpack(order + "I", hdr[4:8])[0]
                body = bom + fh.read(max(0, total - 16))
                tsres, snaps = [], []
                self.sections += 1
            else:
                total = struct.unpack(order + "I", hdr[4:8])[0]
                if total < 12 or total > 0x4000000 or total % 4:
                    self.issue("bad_block", f"after frame {self.frame} (a block of {total} bytes)")
                    return
                body = fh.read(total - 12)
            trailer = fh.read(4)
            if len(body) < total - 12 or len(trailer) < 4:
                self.issue("ends_midway", f"after frame {self.frame}")
                return
            if struct.unpack(order + "I", trailer)[0] != total:
                self.issue("bad_block", f"after frame {self.frame}")
            if btype == PCAPNG_SHB:
                for code, val in _options(body[16:], order):
                    text = val.decode("utf-8", "replace").strip("\x00")[:120]
                    if code == 2:
                        self.hardware = text
                    elif code == 3:
                        self.os = text
                    elif code == 4:
                        self.writer = text
                    elif code == 1:
                        self.comments += 1
            elif btype == 1 and len(body) >= 8:  # interface
                link, _, snap = struct.unpack(order + "HHI", body[:8])
                res = 1e-6
                for code, val in _options(body[8:], order):
                    if code == 9 and val:
                        v = val[0]
                        res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                tsres.append(res)
                snaps.append(snap)
                self.interfaces.append({"link": link, "snaplen": snap})
            elif btype == 6 and len(body) >= 20:  # enhanced packet
                iface, hi, lo, caplen, origlen = struct.unpack(order + "IIIII", body[:20])
                if iface >= len(tsres):
                    self.issue("bad_interface", self.frame + 1)
                    res, snap = 1e-6, 0
                else:
                    res, snap = tsres[iface], snaps[iface]
                data = body[20:20 + caplen]
                if len(data) < caplen:
                    self.issue("bad_block", f"frame {self.frame + 1} is longer than its block")
                self.packet(iface, ((hi << 32) | lo) * res, caplen, origlen, snap, data)
                for code, _ in _options(body[20 + ((caplen + 3) & ~3):], order):
                    if code == 1:
                        self.comments += 1
            elif btype == 3 and len(body) >= 4:  # simple packet: no time
                origlen = struct.unpack(order + "I", body[:4])[0]
                self.packet(0, self.last_any or 0.0, min(origlen, len(body) - 4), origlen, snaps[0] if snaps else 0, body[4:])
            elif btype == 5 and len(body) >= 12:  # interface statistics: the capture's own count of drops
                for code, val in _options(body[12:], order):
                    if code == 5 and len(val) >= 8:
                        self.drops += struct.unpack(order + "Q", val[:8])[0]
            elif btype == 0x0000000A:
                self.secrets += 1


def _options(raw: bytes, order: str):
    pos = 0
    while pos + 4 <= len(raw):
        code, length = struct.unpack(order + "HH", raw[pos:pos + 4])
        if code == 0:
            return
        yield code, raw[pos + 4:pos + 4 + length]
        pos += 4 + ((length + 3) & ~3)


def walk(path: str, base: int = 0) -> Walk:
    w = Walk(base)
    with _open(path) as fh:
        head = fh.read(4)
        if len(head) < 4:
            w.issue("ends_midway", "the file header")
            return w
        magic = struct.unpack("<I", head)[0]
        if magic in PCAP_MAGIC:
            w.pcap(fh, head)
        elif magic == PCAPNG_SHB:
            w.pcapng(fh, head)
        else:
            w.format = "unknown"
            w.issue("unknown_format", "not pcap or pcapng")
    return w


# ---------------------------------------------------------------- seals

def load_seals() -> dict:
    try:
        with open(seals_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_seal(key: str, record: dict) -> None:
    seals = load_seals()
    seals[key] = record
    if len(seals) > 2000:  # (the oldest go first)
        for k in sorted(seals, key=lambda k: seals[k].get("sealed", 0))[: len(seals) - 2000]:
            del seals[k]
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(seals_path()), prefix=".seals-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(seals, fh)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, seals_path())
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def seal_key(files: list[str]) -> str:
    return "\n".join(os.path.realpath(f) for f in files)


def fingerprint(files: list[str]) -> dict:
    """SHA-256 of each file and of them together (one value to keep)."""
    parts = []
    total = 0
    for f in files:
        digest, size = file_hash(f)
        parts.append({"name": os.path.basename(f), "sha256": digest, "size": size})
        total += size
    whole = parts[0]["sha256"] if len(parts) == 1 else hashlib.sha256("".join(p["sha256"] for p in parts).encode()).hexdigest()
    return {"sha256": whole, "size": total, "files": parts}


# ---------------------------------------------------------------- the verdict

def _cluster(times: list[tuple], gaps: list[tuple]) -> list[dict]:
    """Missing-packet reports bunched in time across several connections, with the silence before them."""
    by_second: dict[int, set] = defaultdict(set)
    first: dict[int, float] = {}
    for row in times:  # (time, source, destination, length[, frame, TCP stream])
        ts = row[0]
        b = int(ts // 2)
        by_second[b].add(row[5] if len(row) > 5 and row[5] != "" else tuple(sorted((row[1], row[2]))))
        first[b] = min(first.get(b, ts), ts)
    out = []
    for b, convs in by_second.items():
        if len(convs) < 3:
            continue
        t = first[b]
        gap = next((g for g in gaps if g[2] <= t + 2 and g[2] >= t - 2 and g[0] >= 1.0), None)
        if gap:
            out.append({"at": gap[2], "frame": gap[1], "silence": gap[0], "connections": len(convs)})
    return sorted(out, key=lambda c: -c["connections"])[:5]


def report(files: list[tuple[str, int]], bad_checksums: list[tuple], missing: list[tuple], counts: dict,
           sealed: dict | None, live: bool = False, sent: dict | None = None) -> dict:
    """The verdict and every check, from the files, the engine's checksum and loss findings,
    and the recorded seal (if any). `bad_checksums`/`missing` are (time, source, destination, length)."""
    walks = [walk(p, base) for p, base in files]
    fp = fingerprint([p for p, _ in files])
    checks: list[dict] = []

    def check(cid, title, status, what, why="", frames=None, flt=""):
        checks.append({"id": cid, "title": title, "status": status, "what": what, "why": why,
                       "frames": [f for f in (frames or []) if isinstance(f, int)][:MAX_LIST], "filter": flt})

    def frames_filter(frames):
        frames = [f for f in frames if isinstance(f, int)][:MAX_LIST]
        return f"frame.number in {{{' '.join(map(str, frames))}}}" if frames else ""

    # -- the seal
    matches = None
    if sealed:
        matches = sealed.get("sha256") == fp["sha256"]
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(sealed.get("sealed", 0)))
        if matches:
            check("seal", "Unchanged since you sealed it", "pass", f"Its SHA-256 is the one recorded on {when}: not one byte changed.")
        else:
            check("seal", "Changed since you sealed it", "fail",
                  f"Its SHA-256 differs from the one recorded on {when} ({sealed.get('size', 0):,} bytes then, "
                  f"{fp['size']:,} now). Something rewrote the file after it was sealed.",
                  "A capture that changed after it was sealed can't be trusted as the original.")
    if live:
        check("live", "Still being recorded", "note", "A live capture keeps growing, so its seal changes until it stops.")

    # -- structure
    def merged(key):
        out = []
        for w in walks:
            out += w.issues.get(key, [])
        return out[:MAX_LIST], sum(w.counts[key] for w in walks)

    frames, n = merged("over_snaplen")
    if n:
        check("snaplen", "Packets longer than the file allows", "fail", f"{n:,} packets store more bytes than the file's own "
              "snap length permits; no capture tool writes that.", "Bytes were added after capture.", frames, frames_filter(frames))
    frames, n = merged("over_origlen")
    if n:
        check("origlen", "More bytes stored than were on the wire", "fail", f"{n:,} packets store more bytes than their own "
              "recorded length.", "The record was rewritten by hand or by a careless tool.", frames, frames_filter(frames))
    frames, n = merged("bad_fraction")
    if n:
        check("fraction", "Impossible times", "fail", f"{n:,} packets have a fraction of a second of one second or more.",
              "Times were written by something other than a capture tool.", frames, frames_filter(frames))
    items, n = merged("ends_midway")
    if n:
        check("ends", "The file ends in the middle of a packet", "note", f"It stops {items[0]}: cut off when copied, or still "
              "being written when it was read.", "The packets before are fine; the last one is missing.")
    items, n = merged("bad_block")
    if n:
        check("blocks", "Broken pcapng blocks", "fail", f"{n:,} blocks whose length at the end disagrees with the start "
              f"({items[0]}).", "Bytes were inserted or removed inside the file.")
    frames, n = merged("bad_interface")
    if n:
        check("iface", "Packets from an interface the file never described", "fail", f"{n:,} packets.",
              "Packets were pasted in from another capture.", frames, frames_filter(frames))
    sections = sum(w.sections for w in walks)
    if sections > 1:
        check("sections", "Several captures joined together", "note", f"The file has {sections} sections: separate captures "
              "were joined into it (mergecap, or files appended).", "Times and interfaces may not line up between the parts.")
    writers = sorted({w.writer for w in walks if w.writer})
    edited_by = [x for x in writers if any(e in x.lower() for e in EDITORS)]
    if edited_by:
        check("writer", "Last written by an editing tool", "note", f"The file says it was written by “{edited_by[0]}”, a program "
              "that rewrites captures (cuts, merges, changes times or addresses).", "It isn't the capture tool's original file.")
    elif writers:
        check("writer", "Written by a capture tool", "pass", f"The file says it was written by “{writers[0]}”.")
    drops = sum(w.drops for w in walks)
    if drops:
        check("drops", "The capture tool says it dropped packets", "note", f"Its own statistics count {drops:,} packets it "
              "didn't record (too busy).", "Packets missing for this reason aren't tampering.")
    if any(w.secrets for w in walks):
        check("secrets", "The file carries decryption keys", "note", "It contains a Decryption Secrets block (TLS or other keys "
              "embedded by the capture tool).", "Anyone with the file can decrypt what those keys cover; share it with care.")

    # -- time
    back = [b for w in walks for b in w.back]
    nback = sum(w.counts["backwards"] for w in walks)
    if nback:
        big = [b for b in back if b[1] >= 0.01]
        frames = [b[0] for b in (big or back)][:MAX_LIST]
        worst = max(b[1] for b in back)
        if big:
            check("backwards", "Time goes backwards", "fail", f"{nback:,} packets are earlier than the one before them on the same "
                  f"interface, by up to {_dur(worst)}.", "Capture tools write packets in the order they arrive; reordered or "
                  "re-timed packets were edited (or files were joined badly).", frames, frames_filter(frames))
        else:
            check("backwards", "Small steps back in time", "note", f"{nback:,} packets are up to {_dur(worst)} earlier than the "
                  "one before them.", "Normal for captures taken on several CPU queues; not on its own a sign of editing.",
                  frames, frames_filter(frames))
    frames, n = merged("future")
    if n:
        check("future", "Times in the future", "fail", f"{n:,} packets are dated after today.",
              "The times were changed, or the capturing device's clock was badly wrong.", frames, frames_filter(frames))
    frames, n = merged("clock_unset")
    if n:
        check("clock", "The capturing device's clock wasn't set", "note", f"{n:,} packets are dated before 1980.",
              "Common on devices without a clock battery; times are only relative.", frames, frames_filter(frames))
    last = max((w.last for w in walks if w.last is not None), default=None)
    for p, _ in files:
        with contextlib.suppress(OSError):
            mtime = os.path.getmtime(p)
            if last is not None and last > mtime + 300 and last > 315532800:
                check("mtime", "Packets dated after the file was saved", "fail", f"The last packet is {_dur(last - mtime)} later than "
                      f"{os.path.basename(p)} was last saved.", "A file can't hold packets from after it was written: the times "
                      "were changed, or a clock was wrong.")
    whole = sum(w.whole_seconds for w in walks)
    total = sum(w.frame - base for w, (_, base) in zip(walks, files, strict=True))
    if total >= 20 and whole == total:
        check("whole", "Every time is a whole second", "note", "No packet has a fraction of a second.",
              "Some tools round times; capture tools don't. The times may have been rewritten.")
    frames, n = merged("duplicate")
    if n:
        check("dupes", "Packets recorded twice", "note", f"{n:,} packets are exact copies of the one just before.",
              "Usual when a mirrored switch port sends both directions; on its own not editing.", frames, frames_filter(frames))
    if not any(c["id"] in ("backwards", "future", "mtime", "fraction") for c in checks) and total:
        check("time", "Times run forward", "pass", "Every packet is at or after the one before it, and none is in the future.")

    # -- checksums
    if bad_checksums:
        senders = Counter(r[1] for r in bad_checksums)
        flt = "ip.checksum_bad || tcp.checksum_bad || udp.checksum_bad"
        sent = sent or {}
        # Offloading spoils nearly every packet the capturing computer sends; an edit spoils a few.
        offload = [s for s, c in senders.items() if c >= 10 and sent.get(s) and c / sent[s] >= 0.5]
        edited = {s: c for s, c in senders.items() if s not in offload}
        n_bad = counts.get("bad_checksums", len(bad_checksums))
        if len(offload) == 1 and not edited:
            share = senders[offload[0]] / sent[offload[0]]
            check("checksums", "Wrong checksums from one computer", "note",
                  f"{n_bad:,} packets sent by {offload[0]} ({share:.0%} of what it sent) have wrong checksums; no one else's do.",
                  "That's the capturing computer handing checksums to its network card (offloading): its packets are recorded "
                  "before the card fills them in. Normal.", [], flt)
        else:
            who = ", ".join(f"{s} ({c})" for s, c in sorted(edited.items(), key=lambda x: -x[1])[:5]) or ", ".join(offload)
            frames = list(counts.get("bad_frames") or [])[:MAX_LIST]
            check("checksums", "Wrong checksums", "fail",
                  f"{sum(edited.values()) or n_bad:,} packets have checksums that don't match their bytes, sent by {who}.",
                  "A checksum is computed by the sender: a wrong one means the packet's bytes changed after it was sent "
                  "(edited, or damaged on the way)." + (f" ({', '.join(offload)} also looks like checksum offloading.)"
                                                        if offload and edited else ""), frames, flt)
    else:
        check("checksums", "Checksums are right", "pass", "Every IPv4 header, TCP and UDP checksum that could be checked is "
              "correct: no byte was changed after it was sent (unless the checksum was recomputed too).")

    # -- missing packets
    nmiss = counts.get("missing", len(missing))
    if nmiss:
        gaps = sorted((g for w in walks for g in w.gaps), reverse=True)
        cuts = _cluster(missing, gaps)
        flt = "tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment"
        if cuts:
            c = cuts[0]
            check("cut", "A stretch looks cut out", "fail",
                  f"After {_dur(c['silence'])} of silence at frame {c['frame']:,}, {c['connections']} connections at once "
                  "continue past bytes the capture never saw.", "Ordinary drops are scattered; many connections losing data "
                  "at the same moment, right after a silence, is what removing a stretch of packets looks like.",
                  [x["frame"] for x in cuts], flt)
        else:
            check("missing", "Some packets are missing", "note", f"{nmiss:,} places where TCP acknowledged or continued past bytes "
                  "the capture never recorded, scattered through the file.", "Scattered losses are the capture dropping packets "
                  "(a busy computer or switch port), not a cut.", [], flt)
    else:
        check("missing", "Nothing missing in TCP", "pass", "Every TCP connection's bytes follow on from the ones before.")

    checks.sort(key=lambda c: SEV[c["status"]])
    fails = [c for c in checks if c["status"] == "fail"]
    if sealed and not matches:
        verdict, headline = "changed", "Changed since you sealed it"
    elif fails:
        verdict, headline = "edited", "Signs of editing"
    elif sealed and matches:
        verdict, headline = "sealed", "Unchanged since you sealed it"
    else:
        verdict, headline = "consistent", "No signs of editing"
    w0 = walks[0] if walks else None
    return {"verdict": verdict, "headline": headline, "checks": checks, "fingerprint": fp,
            "sealed": sealed, "matches": matches,
            "format": w0.format if w0 else "", "writer": writers[0] if writers else "",
            "os": next((w.os for w in walks if w.os), ""), "hardware": next((w.hardware for w in walks if w.hardware), ""),
            "packets": total, "first": min((w.first for w in walks if w.first is not None), default=None), "last": last,
            "comments": sum(w.comments for w in walks)}


def _dur(s: float) -> str:
    s = abs(s)
    if s < 1:
        return f"{s * 1000:.0f} ms" if s >= 0.001 else f"{s * 1e6:.0f} µs"
    if s < 120:
        return f"{s:.1f} s"
    if s < 7200:
        return f"{s / 60:.0f} minutes"
    if s < 172800:
        return f"{s / 3600:.0f} hours"
    return f"{s / 86400:.0f} days"
