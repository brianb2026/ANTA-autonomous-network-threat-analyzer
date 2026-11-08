"""Capture session lifecycle for the app: open a file, capture live, run the demo.

The engine is always a child process. How it is launched depends on whether the
current user may already capture:

  direct    the user can open the device (Windows with Npcap, macOS with BPF access,
            Linux with CAP_NET_RAW, or any file). Records come over the child's stdout
            pipe: private by construction, no socket to protect. Closing its stdin
            stops it cleanly on every OS.
  elevated  macOS / Linux without capture rights. The OS's own password prompt
            (osascript "with administrator privileges" / polkit pkexec) starts the
            engine as root; it opens the device, then immediately drops to the user's
            account. Records arrive on a per-session ZeroMQ socket in the private
            runtime directory; the engine is stopped by signalling its (now
            unprivileged) PID, which it reports in its hello record.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import secrets
import shlex
import signal
import sys
import time
from collections.abc import Callable

from . import ingest, paths, settings
from .security import socket_path

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
MAX_FILTER_LEN = 1024
CREATE_NO_WINDOW = 0x08000000  # Windows: don't flash a console for the engine


def elevated_engine_args(engine: str, args: list[str], endpoint: str) -> list[str]:
    """The command run as root through the OS password prompt. It drops to the account
    this app runs as (from the real uid: environment variables like USER can say
    anything) and stops by itself if the app goes away without stopping it."""
    if paths.IS_WINDOWS:
        raise SessionError("elevated capture is not used on Windows")
    import pwd
    uid = os.getuid()
    if uid == 0:
        raise SessionError("ANTA is running as root; run it as your own account instead")
    return [engine, *args, "-u", endpoint, "--user", pwd.getpwuid(uid).pw_name, "--parent-pid", str(os.getpid())]


def _spawn_kwargs() -> dict:
    return {"creationflags": CREATE_NO_WINDOW} if paths.IS_WINDOWS else {}


def is_capture_file(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return os.path.isfile(path) and fh.read(4) in PCAP_MAGIC
    except OSError:
        return False


def applescript_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


VIRTUAL_PREFIXES = ("awdl", "llw", "utun", "anpi", "ap", "bridge", "gif", "stf", "docker", "veth", "virbr", "vmnet",
                    "vboxnet", "tun", "tap", "ciscodump", "dbus", "nflog", "nfqueue", "bluetooth", "usbmon",
                    "randpkt", "sshdump", "udpdump", "etwdump")


def _interface_rank(d: dict) -> int:
    """Put the interface a user most likely means (the real network) first."""
    addrs = d.get("addresses") or []
    ipv4 = [a for a in addrs if "." in a and not a.startswith("169.254.")]
    name = (d.get("name") or "").lower()
    desc = (d.get("description") or "").lower()
    score = 8 * bool(ipv4) + 2 * bool(addrs) + 2 * bool(d.get("up")) + bool(d.get("running"))
    if d.get("loopback") or "loopback" in desc:
        score -= 10
    if name.startswith(VIRTUAL_PREFIXES) or any(w in desc for w in ("virtual", "vpn", "miniport", "hyper-v")):
        score -= 6
    return score


class SessionError(Exception):
    pass


class SessionManager:
    def __init__(self, engine: str, on_record: Callable, on_reset: Callable, on_state: Callable,
                 trust_capture: Callable[[str], None], on_capture: Callable[[str | None, bool], None] | None = None,
                 keylog: Callable[[], str | None] | None = None):
        self.engine = engine
        self.keylog = keylog or (lambda: None)  # the user's TLS key log, if loaded: HTTPS is analysed decrypted
        self.on_record = on_record          # async (generation, record)
        self.on_reset = on_reset            # sync: start a fresh analyzer
        self.on_state = on_state            # async (state dict)
        self.trust_capture = trust_capture  # allow exports from a recording we created
        self.on_capture = on_capture or (lambda path, live: None)  # packet viewer: which file to browse
        self.generation = 0
        self.proc: asyncio.subprocess.Process | None = None
        self.tasks: list[asyncio.Task] = []
        self.zmq: ingest.ZmqSource | None = None
        self.engine_pid: int | None = None
        self.elevated = False
        self.stderr_tail: list[str] = []
        self.state = {"state": "idle", "mode": None, "source": None, "message": "", "elevated": False,
                      "started": None}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------ queries

    async def interfaces(self) -> list[dict]:
        proc = await asyncio.create_subprocess_exec(self.engine, "--list-interfaces", stdin=asyncio.subprocess.DEVNULL,
                                                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                                                    **_spawn_kwargs())
        out, err = await asyncio.wait_for(proc.communicate(), timeout=15)
        if proc.returncode != 0:
            msg = err.decode(errors="replace").strip()
            if paths.IS_WINDOWS:
                msg += " — is Npcap installed? Get it from https://npcap.com"
            raise SessionError(msg or "could not list interfaces")
        devices = json.loads(out)
        devices.sort(key=lambda d: (-_interface_rank(d), d.get("name", "")))
        return devices

    async def _can_capture(self, iface: str) -> tuple[bool, str]:
        proc = await asyncio.create_subprocess_exec(self.engine, "--check-capture", iface,
                                                    stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
                                                    stderr=asyncio.subprocess.PIPE, **_spawn_kwargs())
        _, err = await asyncio.wait_for(proc.communicate(), timeout=15)
        if proc.returncode == 0:
            return True, ""
        if proc.returncode == 3:
            return False, "permission"
        raise SessionError(err.decode(errors="replace").strip() or f"cannot capture on {iface}")

    # ------------------------------------------------------------ control

    async def start_file(self, path: str, speed: float = 0.0, label: str | None = None) -> dict:
        path = os.path.abspath(os.path.expanduser(path))
        if not is_capture_file(path):
            raise SessionError("not a pcap/pcapng capture file")
        async with self._lock:
            await self._stop_locked()
            self._begin("file", label or os.path.basename(path))
            self.trust_capture(path)
            replay = speed > 0
            self.on_capture(path, replay)
            self.state["feed"] = replay  # a paced replay streams packets like a live capture
            keylog = self.keylog()
            await self._launch_direct(["-r", path] + (["--keylog", keylog] if keylog else []) +
                                      (["--packet-feed", "400"] if replay else []), speed)
            return self.state

    async def start_live(self, iface: str, bpf: str = "", record: bool = True) -> dict:
        names = {d["name"] for d in await self.interfaces()}
        if iface not in names:
            raise SessionError("unknown interface")
        if len(bpf) > MAX_FILTER_LEN or any(c in bpf for c in "\x00\r\n"):
            raise SessionError("invalid capture filter")
        async with self._lock:
            await self._stop_locked()
            args = ["-i", iface, "--packet-feed", "400"]  # live packet view, rate-limited in the engine
            if bpf:
                args += ["-f", bpf]
            capture = None
            if record:
                capture = os.path.join(paths.captures_dir(), f"live-{time.strftime('%Y%m%d-%H%M%S')}.pcap")
                ring = settings.load()  # the rolling buffer: segment size x segments kept
                args += ["-w", capture, "--write-max-mb", str(ring["ring_segment_mb"]),
                         "--write-keep", str(ring["ring_segments"])]
                self.trust_capture(capture)
            self._begin("live", iface)
            self.state["feed"] = True
            self.on_capture(capture, True)
            ok, why = await self._can_capture(iface)
            if ok:
                await self._launch_direct(args, 0.0)
            elif why == "permission" and not paths.IS_WINDOWS:
                await self._launch_elevated(args, iface)
            else:
                await self._finish("error", "Npcap denied access. Reinstall Npcap without 'Restrict to "
                                            "administrators', or run ANTA as administrator.")
            return self.state

    async def start_demo(self) -> dict:
        target = os.path.join(paths.samples_dir(), "demo.pcap")
        if not is_capture_file(target):
            await self.on_state(dict(self.state, state="preparing", message="Generating demo traffic…"))
            await asyncio.to_thread(_generate_demo, target)
        return await self.start_file(target, speed=30.0, label="Demo traffic (5 attacks, 30× replay)")

    async def stop(self) -> dict:
        async with self._lock:
            await self._stop_locked()
            return self.state

    # ----------------------------------------------------------- internals

    def _begin(self, mode: str, source: str) -> None:
        self.generation += 1
        self.on_reset()
        self.stderr_tail = []
        self.engine_pid = None
        self.elevated = False
        self.state = {"state": "starting", "mode": mode, "source": source, "message": "", "elevated": False,
                      "started": time.time(), "feed": False}

    async def _set(self, **changes) -> None:
        self.state = dict(self.state, **changes)
        await self.on_state(self.state)

    async def _finish(self, state: str, message: str = "") -> None:
        await self._set(state=state, message=message)

    async def _launch_direct(self, args: list[str], speed: float) -> None:
        gen = self.generation
        self.proc = await asyncio.create_subprocess_exec(
            self.engine, *args, "--stop-on-stdin-eof", "-u", "stdout",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            limit=ingest.MAX_RECORD_BYTES, **_spawn_kwargs())
        self.engine_pid = self.proc.pid
        await self._set(state="running")
        reader = asyncio.create_task(self._read_stdout(self.proc, gen, speed))
        self.tasks = [reader, asyncio.create_task(self._read_stderr(self.proc.stderr)),
                      asyncio.create_task(self._watch(self.proc, gen, reader))]

    async def _launch_elevated(self, args: list[str], iface: str) -> None:
        gen = self.generation
        st = os.stat(self.engine)
        if st.st_mode & 0o022:
            raise SessionError("refusing to run a group/world-writable engine binary with administrator rights")
        sock = socket_path(f"capture-{secrets.token_hex(4)}.ipc")
        engine_args = elevated_engine_args(self.engine, args, f"zmq+ipc://{sock}")
        queue: asyncio.Queue = asyncio.Queue(maxsize=50_000)
        self.zmq = ingest.ZmqSource(f"ipc://{sock}", queue)
        log = os.path.join(paths.logs_dir(), "engine-elevated.log")
        with open(log, "a"):
            os.chmod(log, 0o600)  # created by us, so the root engine appends to a user-owned file
        self.elevated = True
        await self._set(state="authorizing", elevated=True,
                        message="Waiting for administrator approval to open the capture device…")

        if paths.IS_MAC:
            command = shlex.join(engine_args) + f" >/dev/null 2>>{shlex.quote(log)} &"
            prompt = f"ANTA needs administrator access to capture packets on {iface}. " \
                     f"Capture then continues under your own account."
            script = f"do shell script {applescript_string(command)} with prompt {applescript_string(prompt)} " \
                     f"with administrator privileges"
            proc = await asyncio.create_subprocess_exec("osascript", "-e", script, stdin=asyncio.subprocess.DEVNULL,
                                                        stdout=asyncio.subprocess.DEVNULL,
                                                        stderr=asyncio.subprocess.PIPE)
            _, err = await proc.communicate()
            if proc.returncode != 0:
                self._close_zmq()
                declined = b"-128" in err
                await self._finish("error", "Administrator access was declined." if declined
                                   else f"Could not start capture: {err.decode(errors='replace').strip()}")
                return
        else:
            pkexec = "/usr/bin/pkexec" if os.path.exists("/usr/bin/pkexec") else None
            if not pkexec:
                self._close_zmq()
                await self._finish("error", "No polkit agent (pkexec) found. Grant capture rights once with: "
                                            f"sudo setcap cap_net_raw,cap_net_admin=eip {shlex.quote(self.engine)}")
                return
            self.proc = await asyncio.create_subprocess_exec(pkexec, *engine_args, stdin=asyncio.subprocess.DEVNULL,
                                                             stdout=asyncio.subprocess.DEVNULL,
                                                             stderr=asyncio.subprocess.PIPE)
            self.tasks.append(asyncio.create_task(self._read_stderr(self.proc.stderr)))
            self.tasks.append(asyncio.create_task(self._watch(self.proc, gen)))

        self.tasks.append(asyncio.create_task(self._forward_zmq(queue, gen)))

    async def _forward_zmq(self, queue: asyncio.Queue, gen: int) -> None:
        deadline = time.time() + 120
        while True:
            try:
                rec = await asyncio.wait_for(queue.get(), timeout=1.0)
            except TimeoutError:
                if self.engine_pid is None and time.time() > deadline and gen == self.generation:
                    await self._finish("error", "The capture engine never connected (authorization timed out?).")
                    return
                continue
            if rec.get("type") == "hello":
                self.engine_pid = rec.get("pid") if isinstance(rec.get("pid"), int) else None
                await self._set(state="running", message="Capturing as your user account (root dropped).")
            elif rec.get("type") == "stats" and rec.get("final") and gen == self.generation:
                await self.on_record(gen, rec)
                await self._finish("stopped" if self.state["state"] == "stopping" else "finished")
                self._close_zmq()
                return
            await self.on_record(gen, rec)

    async def _read_stdout(self, proc, gen: int, speed: float) -> None:
        base_wall = base_ts = None
        loop = asyncio.get_running_loop()
        while True:
            try:
                line = await proc.stdout.readline()
            except (asyncio.LimitOverrunError, ValueError):
                continue
            if not line:
                return
            rec = ingest.parse_line(line)
            if rec is None:
                continue
            kind = rec.get("type")
            ts = rec.get("end") if kind == "session" else rec.get("ts") if kind == "packet" else None
            if speed > 0 and isinstance(ts, (int, float)):
                if base_ts is None:
                    base_wall, base_ts = loop.time(), ts
                delay = min((ts - base_ts) / speed - (loop.time() - base_wall), 30.0)
                if delay > 0:
                    await asyncio.sleep(delay)
            if gen != self.generation:
                return
            await self.on_record(gen, rec)

    async def _read_stderr(self, stream) -> None:
        while True:
            line = await stream.readline()
            if not line:
                return
            text = line.decode(errors="replace").rstrip()
            self.stderr_tail = (self.stderr_tail + [text])[-6:]
            print(text, file=sys.stderr)

    async def _watch(self, proc, gen: int, reader: asyncio.Task | None = None) -> None:
        code = await proc.wait()
        if reader is not None:
            # The engine can finish long before a paced replay has delivered its records.
            with contextlib.suppress(asyncio.CancelledError):
                await reader
        if gen != self.generation:
            return
        if self.state["state"] == "stopping":
            await self._finish("stopped")
        elif code == 0:
            await self._finish("finished" if self.state["mode"] != "live" else "stopped")
        elif not self.elevated or self.engine_pid is None:
            detail = next((ln for ln in reversed(self.stderr_tail) if "anta-engine:" in ln), "")
            await self._finish("error", detail.replace("anta-engine: ", "") or f"engine exited with code {code}")

    async def _stop_locked(self) -> None:
        if self.state["state"] in ("running", "starting", "authorizing", "preparing"):
            await self._set(state="stopping")
        proc = self.proc
        if proc is not None and proc.returncode is None and not self.elevated:
            with contextlib.suppress(Exception):
                proc.stdin.close()  # engine sees EOF and stops cleanly
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except TimeoutError:
                proc.kill()
                await proc.wait()
        elif self.elevated and self.engine_pid:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(self.engine_pid, signal.SIGTERM)
            if proc is not None:  # pkexec parent
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(proc.wait(), timeout=5)
            else:
                await asyncio.sleep(1.0)
        for task in self.tasks:
            task.cancel()
        self.tasks = []
        self.proc = None
        self._close_zmq()  # removing the session's socket also tells an elevated engine to stop
        message = ""
        if self.elevated and self.engine_pid and not await _exited(self.engine_pid, 5.0):
            message = "The capture engine didn't stop. Quit ANTA to stop it."
        if self.state["state"] == "stopping":
            await self._finish("stopped", message)

    def _close_zmq(self) -> None:
        if self.zmq is not None:
            path = self.zmq.endpoint[len("ipc://"):] if self.zmq.endpoint.startswith("ipc://") else None
            self.zmq.close()
            self.zmq = None
            if path:
                with contextlib.suppress(OSError):
                    os.unlink(path)


async def _exited(pid: int, timeout: float) -> bool:
    """Whether process `pid` (not our child: started through the password prompt) is gone
    within `timeout` seconds."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass  # still there (and not ours to signal)
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(0.2)


def _generate_demo(target: str) -> None:
    import datetime as dt

    from .tools.gen_traffic import Scenario

    os.makedirs(os.path.dirname(target), exist_ok=True)
    t0 = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).timestamp() - 600
    demo = Scenario(seed=2, t0=t0)
    demo.benign(clients=14, duration=600, v6_clients=2)
    demo.c2_beacon()
    demo.c2_jittered()
    demo.dns_tunnel()
    demo.exfil()
    demo.http_keepalive_beacon()
    tmp = target + ".tmp"
    demo.w.save(tmp)
    os.replace(tmp, target)
