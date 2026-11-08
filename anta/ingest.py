"""Record sources feeding the analyzer.

All sources carry the engine's JSON records:
  {"type": "hello", ...}    once per engine run
  {"type": "session", ...}  one per finished (final=true) or long-lived (final=false) session
  {"type": "stats", ...}    periodic capture counters

Transports
  zmq   ZeroMQ PULL socket (ipc:// or tcp://); the engine PUSHes with ZMTP 3.0
  unix  newline-delimited JSON over a Unix stream socket
  stdin newline-delimited JSON read with sys.stdin.readline()
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from collections.abc import Callable

Record = dict
Sink = Callable[[Record], None]

MAX_RECORD_BYTES = 16 * 1024 * 1024  # engine records are < 64 KB; anything bigger is hostile or broken


def parse_line(line: str | bytes) -> Record | None:
    line = line.strip()
    if not line:
        return None
    if len(line) > MAX_RECORD_BYTES:
        print("anta: skipping oversized record", file=sys.stderr)
        return None
    try:
        rec = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        preview = line[:80] if isinstance(line, str) else line[:80].decode("utf-8", "replace")
        print(f"anta: skipping malformed record: {preview!r}", file=sys.stderr)
        return None
    return rec if isinstance(rec, dict) else None


def read_stdin(sink: Sink) -> int:
    """CLI ingestion mode: one line at a time via sys.stdin.readline().

    Deliberately not `sys.stdin.read()` / `readlines()`: memory stays flat no
    matter how large the piped history is, and records are analysed as soon as
    each line arrives from a live producer.
    """
    count = 0
    while True:
        line = sys.stdin.readline()
        if not line:  # EOF
            break
        rec = parse_line(line)
        if rec is not None:
            sink(rec)
            count += 1
    return count


def start_stdin_thread(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue) -> threading.Thread:
    """Run read_stdin() in a thread and hand records to the event loop.

    The reader blocks until the queue has room, so a fast producer is slowed
    down (pipe backpressure) instead of records being dropped.
    """
    def put(rec):
        asyncio.run_coroutine_threadsafe(queue.put(rec), loop).result()

    def run():
        read_stdin(put)
        asyncio.run_coroutine_threadsafe(queue.put({"type": "eof", "source": "stdin"}), loop).result()

    t = threading.Thread(target=run, name="stdin-reader", daemon=True)
    t.start()
    return t


async def _discard_until_newline(reader: asyncio.StreamReader) -> bool:
    """Skip the rest of an oversized line. Returns False at EOF."""
    while True:
        try:
            await reader.readuntil(b"\n")
            return True
        except asyncio.LimitOverrunError as exc:
            await reader.readexactly(exc.consumed)
        except asyncio.IncompleteReadError:
            return False


async def serve_unix_socket(path: str, queue: asyncio.Queue) -> asyncio.AbstractServer:
    """Listen for engine connections (newline JSON) on an owner-only Unix socket."""
    if os.path.lexists(path):
        os.unlink(path)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        print("anta: engine connected (unix socket)", file=sys.stderr)
        while True:
            try:
                line = await reader.readuntil(b"\n")
            except asyncio.LimitOverrunError:
                print("anta: skipping oversized record", file=sys.stderr)
                if not await _discard_until_newline(reader):
                    break
                continue
            except asyncio.IncompleteReadError:
                break
            rec = parse_line(line)
            if rec is not None:
                await queue.put(rec)
        print("anta: engine disconnected", file=sys.stderr)
        writer.close()

    old = os.umask(0o177)  # socket file is created 0600 atomically: no window for other users
    try:
        server = await asyncio.start_unix_server(handle, path=path, limit=MAX_RECORD_BYTES)
    finally:
        os.umask(old)
    os.chmod(path, 0o600)
    return server


class ZmqSource:
    """ZeroMQ PULL socket the engine PUSHes records to."""

    def __init__(self, endpoint: str, queue: asyncio.Queue):
        import zmq
        import zmq.asyncio

        self.endpoint = endpoint
        self.queue = queue
        self.ctx = zmq.asyncio.Context.instance()
        self.sock = self.ctx.socket(zmq.PULL)
        self.sock.setsockopt(zmq.MAXMSGSIZE, MAX_RECORD_BYTES)  # libzmq drops the peer on bigger frames
        self.sock.setsockopt(zmq.RCVHWM, 100_000)
        self.sock.setsockopt(zmq.LINGER, 0)
        if endpoint.startswith("ipc://"):
            path = endpoint[len("ipc://"):]
            if os.path.lexists(path):
                os.unlink(path)
            old = os.umask(0o177)
            try:
                self.sock.bind(endpoint)
            finally:
                os.umask(old)
            os.chmod(path, 0o600)
        else:
            self.sock.bind(endpoint)
        self.task = asyncio.get_running_loop().create_task(self._run())

    async def _run(self):
        while True:
            msg = await self.sock.recv()
            rec = parse_line(msg)
            if rec is not None:
                await self.queue.put(rec)

    def close(self):
        self.task.cancel()
        self.sock.close(0)


async def spawn_engine(engine: str, args: list[str], endpoint: str) -> asyncio.subprocess.Process:
    """Launch the C++ engine pointed at our endpoint."""
    return await asyncio.create_subprocess_exec(engine, *args, "-u", endpoint)


async def paced(queue_in: asyncio.Queue, queue_out: asyncio.Queue, speed: float) -> None:
    """Replay records at `speed`x real time based on their session end time."""
    loop = asyncio.get_running_loop()
    base_wall = base_ts = None
    while True:
        rec = await queue_in.get()
        ts = rec.get("end") if rec.get("type") == "session" else None
        if speed > 0 and isinstance(ts, (int, float)):
            if base_ts is None:
                base_wall, base_ts = loop.time(), ts
            delay = min((ts - base_ts) / speed - (loop.time() - base_wall), 60.0)
            if delay > 0:
                await asyncio.sleep(delay)
        await queue_out.put(rec)
