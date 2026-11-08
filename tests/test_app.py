"""App-mode session control: start/stop over the API, input validation, CSRF, isolation."""
import asyncio
import contextlib
import os
import subprocess
import sys
import tempfile
import time

import pytest
from aiohttp.test_utils import TestClient, TestServer

from anta.analyzer import Analyzer
from anta.server import Dashboard, allowed_hosts_for
from anta.sessions import SessionManager, _interface_rank, applescript_string, elevated_engine_args, is_capture_file
from conftest import ENGINE

TOKEN = "app-test-token-0123456789"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
JSON = {**AUTH, "Content-Type": "application/json"}


class Client(TestClient):
    async def close(self):
        await self.dash.sessions.stop()
        for t in self.tasks:
            t.cancel()
        self.dash.cleanup()
        await super().close()


async def make_client():
    dash = Dashboard(Analyzer(), ENGINE, TOKEN, allowed_hosts_for("127.0.0.1", []), set())
    queue = asyncio.Queue()
    dash.attach_sessions(queue)
    client = Client(TestServer(dash.app(), host="127.0.0.1"))
    client.dash = dash
    client.tasks = [asyncio.create_task(dash.consume(queue)), asyncio.create_task(dash.flusher())]
    await client.start_server()
    return client


async def wait_done(c, timeout=60):
    for _ in range(int(timeout / 0.2)):
        state = await (await c.get("/api/session", headers=AUTH)).json()
        if state["state"] not in ("starting", "running", "preparing", "stopping"):
            return state
        await asyncio.sleep(0.2)
    raise AssertionError("session did not finish")


def test_file_session_analyses_and_finishes(engine, data_dir):
    async def go():
        c = await make_client()
        try:
            r = await c.post("/api/session", headers=JSON,
                             json={"mode": "file", "path": os.path.join(data_dir, "mixed_demo.pcap")})
            assert r.status == 200, await r.text()
            state = await wait_done(c)
            assert state["state"] == "finished" and state["source"] == "mixed_demo.pcap"
            await asyncio.sleep(0.5)  # consumer drains the queue
            summary = await (await c.get("/api/summary", headers=AUTH)).json()
            assert summary["sessions"] > 2000 and summary["by_severity"].get("critical", 0) >= 3
            # The file this session read is trusted for export.
            alerts = await (await c.get("/api/alerts", headers=AUTH)).json()
            r = await c.get(f"/api/export/{alerts[0]['id']}", headers=AUTH)
            assert r.status == 200
        finally:
            await c.close()
    asyncio.run(go())


def test_new_session_starts_from_a_clean_slate(engine, data_dir):
    async def go():
        c = await make_client()
        try:
            await c.post("/api/session", headers=JSON, json={"mode": "file", "path": os.path.join(data_dir, "mixed_demo.pcap")})
            await wait_done(c)
            await asyncio.sleep(0.5)
            await c.post("/api/session", headers=JSON, json={"mode": "file", "path": os.path.join(data_dir, "edge_cases.pcap")})
            await wait_done(c)
            await asyncio.sleep(0.5)
            summary = await (await c.get("/api/summary", headers=AUTH)).json()
            assert summary["sessions"] == 6 and summary["alerts"] == 0  # nothing carried over
        finally:
            await c.close()
    asyncio.run(go())


def test_stop_ends_a_paced_replay(engine, data_dir):
    async def go():
        c = await make_client()
        try:
            await c.post("/api/session", headers=JSON,
                         json={"mode": "file", "path": os.path.join(data_dir, "mixed_demo.pcap"), "speed": 1})
            await asyncio.sleep(1.0)
            r = await c.delete("/api/session", headers=JSON)
            assert (await r.json())["state"] == "stopped"
        finally:
            await c.close()
    asyncio.run(go())


def test_session_input_validation_and_csrf(engine, tmp_path):
    async def go():
        c = await make_client()
        try:
            secret = tmp_path / "secret.txt"
            secret.write_text("not a capture")
            cases = [
                ({"mode": "file", "path": str(secret)}, 400),           # not a pcap: refused
                ({"mode": "file", "path": "/nonexistent.pcap"}, 400),
                ({"mode": "live", "iface": "eth0; rm -rf ~"}, 400),     # not a listed interface
                ({"mode": "live", "iface": "lo0", "filter": "x" * 5000}, 400),
                ({"mode": "nope"}, 400),
            ]
            for body, status in cases:
                r = await c.post("/api/session", headers=JSON, json=body)
                assert r.status == status, (body, r.status)
            # Cross-site form posts can't change state (no JSON content type, or foreign Origin).
            assert (await c.post("/api/session", headers=AUTH, data="mode=demo")).status == 403
            r = await c.post("/api/session", headers={**JSON, "Origin": "http://attacker.example"}, json={"mode": "demo"})
            assert r.status == 403
            assert (await c.post("/api/session", json={"mode": "demo"})).status == 401
            # Quit is only exposed in browser-fallback mode.
            assert (await c.post("/api/quit", headers=JSON, json={})).status == 404
        finally:
            await c.close()
    asyncio.run(go())


def test_interface_listing_and_ranking(engine):
    async def nop(*a):
        pass
    m = SessionManager(ENGINE, nop, lambda: None, nop, lambda p: None)
    devices = asyncio.run(m.interfaces())
    assert devices and all("name" in d for d in devices)
    ranked = sorted([
        {"name": "lo0", "loopback": True, "up": True, "addresses": ["127.0.0.1"]},
        {"name": "awdl0", "up": True, "addresses": ["fe80::1"]},
        {"name": "en0", "up": True, "running": True, "addresses": ["fe80::2", "192.168.1.20"]},
    ], key=lambda d: -_interface_rank(d))
    assert ranked[0]["name"] == "en0"  # the real network first; loopback/virtual adapters after


def test_helpers():
    assert applescript_string('a "b" \\ c') == '"a \\"b\\" \\\\ c"'
    assert not is_capture_file(__file__)


@pytest.mark.skipif(sys.platform == "win32", reason="no elevated capture on Windows")
def test_elevated_engine_drops_to_the_real_account_and_follows_the_app(monkeypatch):
    import pwd
    monkeypatch.setenv("USER", "root")  # the environment must not decide who the engine becomes
    monkeypatch.setenv("LOGNAME", "root")
    args = elevated_engine_args("/x/anta-engine", ["-i", "en0"], "zmq+ipc:///tmp/s.ipc")
    assert args[args.index("--user") + 1] == pwd.getpwuid(os.getuid()).pw_name != "root"
    assert args[args.index("--parent-pid") + 1] == str(os.getpid())


@pytest.mark.skipif(sys.platform == "win32", reason="--parent-pid is for elevated capture (macOS/Linux)")
def test_engine_stops_when_the_app_that_started_it_is_gone(engine, data_dir, tmp_path):
    gone = subprocess.Popen([sys.executable, "-c", "pass"])
    gone.wait()  # a PID that no longer exists
    # Nothing listens on the socket: without the watchdog the engine would wait for it forever.
    start = time.monotonic()
    out = subprocess.run([engine, "-r", os.path.join(data_dir, "mixed_demo.pcap"), "-u",
                          f"unix:{tmp_path / 'nobody.sock'}", "--parent-pid", str(gone.pid)],
                         capture_output=True, text=True, timeout=60)
    assert time.monotonic() - start < 30
    assert "has exited; stopping" in out.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="--parent-pid is for elevated capture (macOS/Linux)")
def test_engine_stops_when_the_app_removes_the_session_socket(engine):
    """Stopping an elevated capture removes its socket: the engine stops capturing even if
    no stop signal reaches it (the app is still running, so the watchdog doesn't fire)."""
    import socket
    import struct
    import threading
    from anta.tools import samples
    work = tempfile.mkdtemp(prefix="anta-stop-", dir="/tmp")  # (Unix socket paths must be short)
    fifo, sock_path = os.path.join(work, "cap.pcap"), os.path.join(work, "s.sock")
    os.mkfifo(fifo)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    done = threading.Event()

    def feed():  # a capture that never ends by itself
        frame = samples.udp("10.1.0.1", "10.1.0.2", 4000, 5000, b"x" * 64)
        with contextlib.suppress(BrokenPipeError), open(fifo, "wb", buffering=0) as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            i = 0
            while not done.is_set():
                fh.write(struct.pack("<IIII", 1_700_000_000 + i, 0, len(frame), len(frame)) + frame)
                i += 1
                time.sleep(0.01)

    def drain():  # the app's end: read whatever the engine sends
        with contextlib.suppress(OSError):
            conn, _ = server.accept()
            while conn.recv(65536):
                pass

    threading.Thread(target=feed, daemon=True).start()
    threading.Thread(target=drain, daemon=True).start()
    proc = subprocess.Popen([engine, "-r", fifo, "-u", f"unix:{sock_path}", "--parent-pid", str(os.getpid())],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(1.5)
        assert proc.poll() is None  # capturing
        start = time.monotonic()
        server.close()
        os.unlink(sock_path)  # what the app does when the user presses Stop
        proc.wait(timeout=20)
        assert time.monotonic() - start < 5
        assert "the app stopped this capture; stopping" in proc.stderr.read()
    finally:
        done.set()
        if proc.poll() is None:
            proc.kill()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_engine_always_ends_after_sigterm(engine, data_dir):
    # A reader that never reads keeps the engine blocked on output; a stop request
    # must still end it (the hard deadline is 15 s), never leave it running.
    r, w = os.pipe()
    proc = subprocess.Popen([engine, "-r", os.path.join(data_dir, "mixed_demo.pcap")], stdout=w,
                            stderr=subprocess.DEVNULL)
    os.close(w)
    try:
        time.sleep(1.5)  # the pipe fills and the engine blocks
        assert proc.poll() is None
        start = time.monotonic()
        proc.terminate()
        proc.wait(timeout=40)
        assert time.monotonic() - start < 25
    finally:
        if proc.poll() is None:
            proc.kill()
        os.close(r)
