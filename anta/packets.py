"""Packet viewer back end.

Two sources, one numbering (frames counted from 1 across the whole capture):
  * the session's capture file(s): a file being analysed, or the recording of a
    live capture (PATH and its rotated predecessor PATH.1). Pages and full
    decodes come from the engine (`--packets`, `--packet-detail`), so a capture
    of any size is browsed without loading it into memory.
  * the live feed: rate-limited per-packet summaries the engine streams while
    capturing, kept in a small ring buffer and pushed to "follow" viewers.
"""
from __future__ import annotations

import asyncio
import collections
import contextlib
import json
import os
import re
import tempfile

from . import netmap
from .objects import OBJECT_ID, list_objects
from .security import InvalidRecord, runtime_dir, validate_session
from .sessions import _spawn_kwargs

FLOW_SPEC = re.compile(r"(6|17),[0-9a-fA-F:.]+,\d{1,5},[0-9a-fA-F:.]+,\d{1,5}")
MAX_PAGE = 1000
MAX_FILTER_LEN = 512
# Display filters: a selection of packets in the list is a long one (frame.number in {…}).
MAX_DFILTER = 8 * 1024 * 1024
# Longer than this, a filter goes to the engine in a file: Windows caps a command line at 32 K.
ARG_FILTER_LIMIT = 8000
FEED_BUFFER = 5000
MAX_RULES = 64
COLOR = re.compile(r"#[0-9a-fA-F]{6}")
FIELD_NAME = re.compile(r"[a-z0-9][a-z0-9_.\-]{0,79}")
MAX_COLUMNS = 12
FRAMES = re.compile(r"\d{1,12}(?:-\d{1,12})?(?:,\d{1,12}(?:-\d{1,12})?)*")
DEFAULT_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "colorfilters.json")


def _clean_text(value: str, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit or any(c in value for c in "\x00\r\n"):
        raise PacketError("invalid filter")
    return value.strip()


def _filter_string(value: str) -> str:
    """A value inside a display filter's double-quoted string."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


class PacketError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class CaptureFiles:
    """Maps global frame numbers onto a capture and its rotated predecessor."""

    def __init__(self, path: str | None = None, live: bool = False):
        self.path = path
        self.live = live
        self.base = 0              # frames before `path`
        self.previous_base: int | None = None  # frames before `path.1` (after a rotation)

    def rotated(self, base: int, previous_base: int) -> None:
        self.base, self.previous_base = base, previous_base

    def inputs(self) -> list[tuple[str, int]]:
        if not self.path:
            return []
        out = []
        older = self.path + ".1"
        if self.previous_base is not None and os.path.exists(older):
            out.append((older, self.previous_base))
        if os.path.exists(self.path):
            out.append((self.path, self.base))
        return out


class PacketService:
    def __init__(self, engine: str):
        self.engine = engine
        self.keylog: str | None = None   # path to a TLS key log, for decrypting the user's own TLS
        self.files = CaptureFiles()
        self.feed: collections.deque = collections.deque(maxlen=FEED_BUFFER)
        self.pending: list[dict] = []
        self.feed_first_ts: float | None = None
        self.slots = asyncio.Semaphore(3)
        self._fields: list[dict] | None = None
        self._stats_cache: collections.OrderedDict = collections.OrderedDict()
        self._index: tuple[str, list[dict]] | None = None  # (file state, sessions)
        self._index_lock = asyncio.Lock()

    def reset(self, path: str | None = None, live: bool = False) -> None:
        self.files = CaptureFiles(path, live)
        self._stats_cache.clear()
        self._index = None
        self.feed.clear()
        self.pending.clear()
        self.feed_first_ts = None

    def on_packet(self, rec: dict) -> None:
        """Live feed record from the engine (already rate-limited there)."""
        summary = {k: rec.get(k) for k in ("n", "ts", "len", "cap", "src", "dst", "proto", "info")}
        if not isinstance(summary["n"], int) or not isinstance(summary["ts"], (int, float)):
            return
        for key in ("src", "dst", "proto", "info"):
            summary[key] = str(summary[key] or "")[:300]
        if self.feed_first_ts is None:
            self.feed_first_ts = summary["ts"]
        self.feed.append(summary)
        self.pending.append(summary)
        if len(self.pending) > 2000:
            del self.pending[:-2000]

    def take_pending(self, limit: int = 400) -> tuple[list[dict], int]:
        batch, skipped = self.pending[-limit:], max(0, len(self.pending) - limit)
        self.pending = []
        return batch, skipped

    def status(self) -> dict:
        return {"files": bool(self.files.inputs()), "live": self.files.live, "feed": len(self.feed),
                "first_ts": self.feed_first_ts}

    # ------------------------------------------------------------- engine

    def _input_args(self) -> list[str]:
        inputs = self.files.inputs()
        if not inputs:
            raise PacketError("this session has no capture file to browse (live capture without recording)", 409)
        args = []
        for path, base in inputs:
            args += ["-r", path, "--frame-base", str(base)]
        return args

    def _decrypt_args(self) -> list[str]:
        """The TLS key log, if the user loaded one, so the packet view decrypts their own TLS."""
        return ["--keylog", self.keylog] if self.keylog else []

    async def _engine(self, args: list[str], timeout: float = 90) -> list[dict]:
        long_filter = None
        if "-Y" in args:  # (a long display filter is read from a private file instead)
            i = args.index("-Y")
            if i + 1 < len(args) and len(args[i + 1]) > ARG_FILTER_LIMIT:
                fd, long_filter = tempfile.mkstemp(prefix="anta_filter_", suffix=".txt", dir=runtime_dir())
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(args[i + 1])
                args = [*args[:i], "--display-filter-file", long_filter, *args[i + 2:]]
        try:
            return await self._run_engine(args, timeout)
        finally:
            if long_filter:
                with contextlib.suppress(OSError):
                    os.unlink(long_filter)

    async def _run_engine(self, args: list[str], timeout: float) -> list[dict]:
        async with self.slots:
            proc = await asyncio.create_subprocess_exec(
                self.engine, *args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, limit=64 * 1024 * 1024, **_spawn_kwargs())
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except TimeoutError:
                proc.kill()
                raise PacketError("the packet query took too long; narrow it with a filter", 504) from None
        if proc.returncode == 1:
            raise PacketError(err.decode(errors="replace").replace("anta-engine: ", "").strip() or "not found", 404)
        if proc.returncode != 0:
            msg = err.decode(errors="replace").replace("anta-engine: ", "").strip()
            raise PacketError(msg or "packet query failed", 400)
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    async def page(self, start: int, limit: int, bpf: str = "", flows: list[str] | None = None,
                   count: bool = False, dfilter: str = "", colors: list[str] | None = None,
                   columns: list[str] | None = None) -> dict:
        if start < 1:
            start = 1
        limit = max(1, min(int(limit), MAX_PAGE))
        bpf = _clean_text(bpf, MAX_FILTER_LEN)
        dfilter = _clean_text(dfilter, MAX_DFILTER)
        flows = [f for f in (flows or []) if FLOW_SPEC.fullmatch(f)][:200]
        colors = [c for c in (colors or []) if c][:MAX_RULES]

        if not self.files.inputs():
            if not self.files.live and not self.feed:
                raise PacketError("no capture loaded", 409)
            # Live capture without a recording: the feed's ring buffer is all there is.
            if bpf or flows or dfilter:
                raise PacketError("filters need a recorded capture; enable recording for live captures", 409)
            rows = [p for p in self.feed if p["n"] >= start][:limit]
            return {"packets": rows, "next": None, "matched_total": len(self.feed), "matched_before": 0,
                    "first_ts": self.feed_first_ts, "source": "feed"}

        args = ["--packets", *self._input_args(), *self._decrypt_args(), "--from", str(start), "--limit", str(limit)]
        if count:
            args.append("--count")
        if bpf:
            args += ["-f", bpf]
        for spec in flows:
            args += ["--flow", spec]
        if dfilter:
            args += ["-Y", dfilter]
        for rule in colors:
            args += ["--color-rule", rule]
        columns = [c for c in (columns or []) if FIELD_NAME.fullmatch(c)][:MAX_COLUMNS]
        if columns:  # custom columns: each row carries those fields' values ("f")
            args += ["--fields", ",".join(columns)]
        records = await self._engine(args)
        page = next((r for r in records if r.get("type") == "page"), {})
        return {"packets": [r for r in records if r.get("type") == "packet"], "next": page.get("next"),
                "matched_total": page.get("matched_total"), "matched_before": page.get("matched_before", 0),
                "last_frame": page.get("last_frame"), "first_ts": page.get("first_ts") or self.feed_first_ts,
                "source": "capture"}

    async def find(self, mode: str, text: str, where: str = "list", start: int = 0, backwards: bool = False,
                   bpf: str = "", flows: list[str] | None = None, dfilter: str = "") -> dict:
        """Find Packet (Wireshark's Ctrl+F): the next (or previous) frame after `start`, among the
        frames the list shows (its display or capture filter, an alert's flows), that matches a
        display filter, shows some text (in the list's columns or the detail tree), holds some
        bytes (text, hex or a regular expression). Wraps around the capture's end, like Wireshark."""
        text = _clean_text(text, 1024)
        if not text:
            raise PacketError("say what to find")
        dfilter = _clean_text(dfilter, MAX_DFILTER)
        find_text = None
        if mode == "filter":
            expr = text
        elif mode == "text" and where in ("list", "details"):
            expr, find_text = "", text
        elif mode == "text":  # the packet bytes, any case
            expr = f'frame matches "(?i){_filter_string(re.escape(text))}"'
        elif mode == "hex":
            digits = re.sub(r"[\s:.\-]|0x", "", text, flags=re.I)
            if not digits or len(digits) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", digits):
                raise PacketError("hex bytes look like 47 45 54 or 474554")
            expr = "frame contains " + ":".join(digits[i:i + 2] for i in range(0, len(digits), 2)).lower()
        elif mode == "regex":
            expr = f'frame matches "{_filter_string(text)}"'
        else:
            raise PacketError("find a display filter, text, hex bytes or a regular expression")
        parts = [f"({x})" for x in (dfilter, expr) if x]

        async def query(extra: str, start_at: int, last: bool) -> int | None:
            terms = parts + ([extra] if extra else [])
            args = ["--packets", *self._input_args(), *self._decrypt_args(), "--from", str(start_at), "--limit", "1"]
            if terms:
                args += ["-Y", " && ".join(terms)]
            if find_text is not None:
                args += ["--find-text", find_text, "--find-in", where]
            if last:
                args.append("--last")
            if bpf:
                args += ["-f", _clean_text(bpf, MAX_FILTER_LEN)]
            for spec in [f for f in (flows or []) if FLOW_SPEC.fullmatch(f)][:200]:
                args += ["--flow", spec]
            hit = next((r for r in await self._engine(args, timeout=600) if r.get("type") == "packet"), None)
            return hit["n"] if hit else None

        if not backwards:
            n = await query("", start + 1, False)
            wrapped = n is None and start > 0
            if wrapped:
                n = await query(f"frame.number <= {start}", 1, False)
        else:
            n = await query(f"frame.number < {start}", 1, True) if start > 1 else None
            wrapped = n is None
            if wrapped:
                n = await query(f"frame.number >= {max(start, 1)}", 1, True)
        return {"frame": n, "wrapped": bool(wrapped and n is not None)}

    async def check_filters(self, filters: list[str]) -> list[dict]:
        filters = [_clean_text(f, 4096) for f in filters[:MAX_RULES + 1]]
        if not filters:
            return []
        args = []
        for f in filters:
            args += ["--check-filter", f]
        return await self._engine(args)

    async def filter_fields(self) -> list[dict]:
        if self._fields is None:
            self._fields = [{k: r[k] for k in ("name", "kind", "desc")} for r in await self._engine(["--filter-fields"])]
        return self._fields

    async def stats(self, dfilter: str = "", bpf: str = "", interval: float = 0,
                    series: list[str] | None = None, counts: list[str] | None = None) -> dict:
        """Statistics and the network map for the capture, cached per file state and query.
        `counts`: display filters counted over the whole capture (stats["counts"], in order)."""
        dfilter = _clean_text(dfilter, MAX_DFILTER)
        bpf = _clean_text(bpf, MAX_FILTER_LEN)
        series = [_clean_text(x, 4096) for x in (series or []) if x][:8]
        counts = [_clean_text(x, 4096) for x in (counts or []) if x][:256]
        interval = float(interval or 0)
        if interval and not 0.000001 <= interval <= 86400:
            raise PacketError("the I/O interval must be between 1 µs and 1 day")
        inputs = self.files.inputs()
        if not inputs:
            raise PacketError("statistics need a capture file (or a recorded live capture)", 409)
        state = []
        for path, base in inputs:
            try:
                st = os.stat(path)
            except OSError:
                continue
            state.append((path, base, st.st_size, st.st_mtime_ns))
        key = json.dumps([state, dfilter, bpf, interval, series, counts])
        if key in self._stats_cache:
            self._stats_cache.move_to_end(key)
            return self._stats_cache[key]
        args = ["--stats", *self._input_args()]
        if dfilter:
            args += ["-Y", dfilter]
        if bpf:
            args += ["-f", bpf]
        if interval:
            args += ["--io-interval", repr(interval)]
        for x in series:
            args += ["--io-series", x]
        for x in counts:
            args += ["--count-filter", x]
        records = await self._engine(args, timeout=600)
        stats = next((r for r in records if r.get("type") == "stats"), None)
        if stats is None:
            raise PacketError("statistics failed", 500)
        result = {"stats": stats, "map": netmap.build(stats)}
        self._stats_cache[key] = result
        while len(self._stats_cache) > 6:
            self._stats_cache.popitem(last=False)
        return result

    async def packet_times(self, dfilter: str, limit: int, frames: bool = False) -> list[tuple]:
        """(time, source, destination, length) of the packets a display filter selects, in order,
        at most `limit` of them: what the map's replay draws as arrows. frames=True adds each
        one's frame number."""
        dfilter = _clean_text(dfilter, MAX_DFILTER)
        limit = max(1, min(int(limit), 100_000))
        records = await self._engine(["--packets", *self._input_args(), "--from", "1", "--limit", str(limit), "-Y", dfilter],
                                     timeout=600)
        return [(float(r["ts"]), str(r.get("src") or ""), str(r.get("dst") or ""), int(r.get("len") or 0),
                 *((int(r.get("n") or 0),) if frames else ()))
                for r in records if r.get("type") == "packet"]

    def peek(self) -> tuple[dict | None, list[dict] | None]:
        """The capture's statistics and session index, if they were already read for the
        capture as it is now (nothing is run): for answers that must come at once."""
        stats = self._stats_cache.get(json.dumps([json.loads(self._file_state()), "", "", 0.0, [], []]))
        state = json.dumps([self._file_state(), self.keylog])
        return stats, (self._index[1] if self._index and self._index[0] == state else None)

    def _file_state(self) -> str:
        state = []
        for path, base in self.files.inputs():
            try:
                st = os.stat(path)
            except OSError:
                continue
            state.append((path, base, st.st_size, st.st_mtime_ns))
        return json.dumps(state)

    def _plain_inputs(self) -> list[str]:
        inputs = self.files.inputs()
        if not inputs:
            raise PacketError("this needs a capture file (or a recorded live capture)", 409)
        args = []
        for path, _ in inputs:
            args += ["-r", path]
        return args

    def source_stem(self) -> str:
        inputs = self.files.inputs()
        stem = os.path.splitext(os.path.basename(inputs[-1][0]))[0] if inputs else "capture"
        return re.sub(r"[^A-Za-z0-9._-]+", "_", stem)[:80] or "capture"

    async def index(self) -> list[dict]:
        """Every session of the capture (compact, validated), cached per file state.
        The file list and indicator sweeps read it."""
        async with self._index_lock:
            state = json.dumps([self._file_state(), self.keylog])  # decrypted HTTPS changes with the key log
            if self._index and self._index[0] == state:
                return self._index[1]
            records = await self._engine(["--index", *self._plain_inputs(), *self._decrypt_args()], timeout=900)
            sessions = []
            for rec in records:
                if rec.get("type") != "session":
                    continue
                try:
                    sessions.append(validate_session(rec))
                except (InvalidRecord, TypeError, ValueError):
                    continue
            self._index = (state, sessions)
            return sessions

    async def objects(self) -> list[dict]:
        return list_objects(await self.index())

    def _temp(self, suffix: str) -> str:
        fd, path = tempfile.mkstemp(prefix="anta_save_", suffix=suffix, dir=runtime_dir())
        os.close(fd)
        return path

    async def save_packets(self, dfilter: str = "", frames: str = "", bpf: str = "",
                           flows: list[str] | None = None, safe: dict | None = None) -> dict:
        """Export Specified Packets: the whole capture, the frames the packet list shows
        (display filter, capture filter, an alert's flows), or listed frames, as a new
        pcap. Returns its path and packet count. With `safe` ({keep_payload, shift_time}),
        a share-safe copy: stand-in addresses and contents cut; `key_path` then holds the
        address key (real -> stand-in, CSV), the user's alone."""
        dfilter = _clean_text(dfilter, MAX_DFILTER)
        bpf = _clean_text(bpf, MAX_FILTER_LEN)
        flows = [f for f in (flows or []) if FLOW_SPEC.fullmatch(f)][:200]
        frames = (frames or "").replace(" ", "")
        if frames and (len(frames) > 400_000 or not FRAMES.fullmatch(frames)):
            raise PacketError("frames must look like 1-20,35,40-41")
        path = self._temp(".pcap")
        args = ["--packets", *self._input_args(), "--save", path]
        if dfilter:
            args += ["-Y", dfilter]
        if frames:
            args += ["--frames", frames]
        if bpf:
            args += ["-f", bpf]
        for spec in flows:
            args += ["--flow", spec]
        key_path = None
        if safe is not None:
            key_path = self._temp(".csv")
            args += ["--sanitize", "--sanitize-key", key_path]
            if safe.get("keep_payload"):
                args.append("--sanitize-keep-payload")
            if safe.get("shift_time"):
                args.append("--sanitize-shift-time")
        try:
            records = await self._engine(args, timeout=900)
        except BaseException:
            for p in (path, key_path):
                with contextlib.suppress(OSError, TypeError):
                    os.unlink(p)
            raise
        saved = next((r for r in records if r.get("type") == "saved"), {})
        out = {"path": path, "packets": int(saved.get("packets", 0)), "first": saved.get("first"),
               "last": saved.get("last"), "skipped_link_type": int(saved.get("skipped_link_type", 0))}
        if safe is not None:
            s = saved.get("sanitized") or {}
            out["key_path"] = key_path
            out["sanitized"] = {k: int(s.get(k) or 0) for k in ("ipv4", "ipv6", "mac", "bytes_cut", "unsupported")}
            out["sanitized"].update(keep_payload=bool(s.get("keep_payload")), shift_time=bool(s.get("shift_time")))
        return out

    async def extract_object(self, object_id: str) -> str:
        """Write one transferred file (an id from objects()) to a private temp file."""
        if not OBJECT_ID.fullmatch(object_id or ""):
            raise PacketError("bad object id")
        path = self._temp(".bin")
        try:
            await self._engine(["--object", object_id, "--object-out", path, *self._plain_inputs(),
                                *self._decrypt_args()], timeout=900)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(path)
            raise
        return path

    async def frames_with_fields(self, dfilter: str, fields: str, limit: int) -> list[dict]:
        """Frames a display filter selects, each with the named fields' values (engine --fields)."""
        dfilter = _clean_text(dfilter, MAX_DFILTER)
        if not dfilter:
            raise PacketError("a display filter is needed")
        return await self._engine(["--packets", *self._input_args(), *self._decrypt_args(), "-Y", dfilter, "--limit", str(limit),
                                   "--fields", fields], timeout=600)

    TCP_GRAPH_FIELDS = ("frame.time_relative,ip.src,ipv6.src,tcp.srcport,tcp.dstport,tcp.seq,tcp.ack,tcp.len,"
                        "tcp.window_size,tcp.flags.syn,tcp.flags.fin,tcp.flags.reset,tcp.flags.ack,tcp.analysis.*")
    TCP_FLAGS = {"tcp.flags.syn": 1, "tcp.flags.fin": 2, "tcp.flags.reset": 4, "tcp.analysis.retransmission": 8,
                 "tcp.analysis.fast_retransmission": 8, "tcp.analysis.spurious_retransmission": 8,
                 "tcp.analysis.duplicate_ack": 16, "tcp.analysis.zero_window": 32, "tcp.analysis.lost_segment": 64,
                 "tcp.analysis.out_of_order": 128}

    async def tcp_graph(self, stream: int, limit: int = 100_000, dfilter: str = "") -> dict:
        """One TCP stream for Wireshark's TCP Stream Graphs: per segment, [frame, time, direction
        (0: from the side that opened it), relative seq, length, relative ack, window, the
        ACK's measured RTT (or null), flags (1 SYN, 2 FIN, 4 RST, 8 retransmission, 16 dup
        ACK, 32 zero window, 64 a segment before it wasn't captured, 128 out of order)]."""
        if not 0 <= stream < 2**40:
            raise PacketError("a TCP stream number is needed")
        flt = f"tcp.stream eq {stream}" + (f" && ({dfilter})" if dfilter else "")  # (within a selection)
        rows = [r for r in await self.frames_with_fields(flt, self.TCP_GRAPH_FIELDS, limit) if r.get("type") == "packet"]
        if not rows:
            raise PacketError(f"TCP stream {stream} has no packets {'in the selection' if dfilter else 'here'}", 404)

        def first(f, name, cast=float):
            v = (f.get(name) or [None])[0]
            try:
                return cast(v) if v not in (None, "") else None
            except ValueError:
                return None

        def end(f):
            return f"{first(f, 'ip.src', str) or first(f, 'ipv6.src', str)}:{first(f, 'tcp.srcport', int)}"

        opener = next((r for r in rows if first(r.get("f") or {}, "tcp.flags.syn", int) and
                       not first(r.get("f") or {}, "tcp.flags.ack", int)), rows[0])
        a = end(opener.get("f") or {})
        points, b = [], None
        for r in rows:
            f = r.get("f") or {}
            src = end(f)
            if src != a and b is None:
                b = src
            flags = 0
            for name, bit in self.TCP_FLAGS.items():
                if name in f and (name.startswith("tcp.analysis.") or first(f, name, int)):
                    flags |= bit
            points.append([r["n"], first(f, "frame.time_relative") or 0.0, 0 if src == a else 1,
                           first(f, "tcp.seq", int) or 0, first(f, "tcp.len", int) or 0, first(f, "tcp.ack", int) or 0,
                           first(f, "tcp.window_size", int), first(f, "tcp.analysis.ack_rtt"), flags])
        if b is None:
            f = opener.get("f") or {}
            ip = first(f, "ip.src", str) or first(f, "ipv6.src", str)
            b = f"{'?' if not ip else '…'}:{first(f, 'tcp.dstport', int)}"
        return {"stream": stream, "a": a, "b": b, "points": points, "truncated": len(rows) >= limit}

    async def follow(self, proto: str, stream: int, h2_stream: int | None = None) -> dict:
        """Follow a TCP or UDP stream; or, with the user's key log, a TCP stream's
        decrypted TLS data ("tls") or one HTTP/2 stream inside it ("http2")."""
        if proto not in ("tcp", "udp", "tls", "http2") or not 0 <= stream < 2**40:
            raise PacketError("follow needs proto tcp, udp, tls or http2 and a stream number")
        spec = f"{proto},{stream}"
        if proto == "http2":
            if h2_stream is None or not 0 < h2_stream < 2**31:
                raise PacketError("following HTTP/2 needs the HTTP/2 stream id")
            spec += f",{h2_stream}"
        if proto == "tls" and not self.keylog:
            raise PacketError("load your TLS key log (Decrypt TLS…) to follow the decrypted stream", 409)
        args = ["--follow", spec, *self._input_args(), *(self._decrypt_args() if proto in ("tls", "http2") else [])]
        records = await self._engine(args, timeout=300)
        result = next((r for r in records if r.get("type") == "follow"), None)
        if not result or not result.get("found"):
            raise PacketError(f"{'TCP' if proto != 'udp' else 'UDP'} stream {stream} not found", 404)
        result["decrypt_available"] = bool(self.keylog)
        return result

    async def detail(self, frame: int) -> dict:
        if frame < 1:
            raise PacketError("frame numbers start at 1", 404)
        records = await self._engine(["--packet-detail", str(frame), *self._input_args(), *self._decrypt_args()])
        if not records:
            raise PacketError("frame not found", 404)
        return records[0]


class ColorRules:
    """Coloring rules, Wireshark-style: the first enabled rule a packet matches colors
    its row. Kept owner-only in the app's data folder; Wireshark's defaults otherwise."""

    def __init__(self, path: str):
        self.path = path

    @staticmethod
    def defaults() -> list[dict]:
        with open(DEFAULT_RULES_PATH, encoding="utf-8") as fh:
            return json.load(fh)

    def load(self) -> list[dict]:
        try:
            with open(self.path, encoding="utf-8") as fh:
                return self.validate(json.load(fh))
        except (OSError, ValueError, PacketError):
            return self.defaults()

    @staticmethod
    def validate(rules) -> list[dict]:
        if not isinstance(rules, list) or len(rules) > MAX_RULES:
            raise PacketError(f"expected a list of at most {MAX_RULES} rules")
        out = []
        for i, r in enumerate(rules, 1):
            if not isinstance(r, dict):
                raise PacketError(f"rule {i} is not an object")
            name, flt = r.get("name"), r.get("filter")
            if not isinstance(name, str) or not name.strip() or len(name) > 80:
                raise PacketError(f"rule {i}: the name must be 1-80 characters")
            if not isinstance(flt, str) or not flt.strip() or len(flt) > 2048 or any(c in flt for c in "\x00\r\n"):
                raise PacketError(f"rule {i}: the filter must be 1-2048 characters on one line")
            bg, fg = r.get("bg"), r.get("fg")
            if not (isinstance(bg, str) and COLOR.fullmatch(bg) and isinstance(fg, str) and COLOR.fullmatch(fg)):
                raise PacketError(f"rule {i}: colors must look like #rrggbb")
            out.append({"name": name.strip(), "filter": flt.strip(), "bg": bg.lower(), "fg": fg.lower(),
                        "enabled": bool(r.get("enabled", True))})
        return out

    def save(self, rules: list[dict]) -> None:
        directory = os.path.dirname(self.path)
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".colorfilters-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(rules, fh, indent=1)
            if os.name != "nt":
                os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
