"""ANTA desktop application.

Runs the dashboard server on a background thread (loopback only, random port,
fresh session token) and shows it in a native window via pywebview: WebKit on
macOS, WebView2 on Windows, Qt/GTK WebKit on Linux. If no native web view is
available it opens the default browser instead and adds a Quit button.
"""
from __future__ import annotations

import asyncio
import os
import re
import secrets
import sys
import threading
import webbrowser

from . import paths
from .analyzer import Analyzer, Config


def _redirect_output() -> str:
    """Windowed builds have no console (sys.stderr is None on Windows): log to a file."""
    log = os.path.join(paths.logs_dir(), "anta.log")
    if os.path.exists(log) and os.path.getsize(log) > 5 * 1024 * 1024:
        os.replace(log, log + ".1")
    if paths.frozen() or sys.stderr is None or sys.stdout is None:
        fh = open(log, "a", buffering=1, encoding="utf-8", errors="replace")  # noqa: SIM115 (lives for the process)
        if not paths.IS_WINDOWS:
            os.chmod(log, 0o600)
        sys.stdout = sys.stderr = fh
    return log


def _load_model(model_dir: str):
    from .model import AnomalyModel

    try:
        return AnomalyModel(model_dir) if AnomalyModel.available(model_dir) else None
    except Exception as exc:  # a broken user model must not stop the app
        print(f"anta: model unavailable ({exc}); rule-based detectors only", file=sys.stderr)
        return None


class ServerThread:
    """The aiohttp dashboard + session manager on its own event loop."""

    def __init__(self, analyzer: Analyzer, engine: str, port: int):
        from .server import Dashboard, allowed_hosts_for

        self.token = secrets.token_urlsafe(32)
        self.dash = Dashboard(analyzer, engine, self.token, allowed_hosts_for("127.0.0.1", []), set())
        self.requested_port = port
        self.port = 0
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.error: BaseException | None = None
        self._stop: asyncio.Event | None = None
        self.thread = threading.Thread(target=self._run, name="anta-server", daemon=True)

    def start(self) -> str:
        self.thread.start()
        if not self.ready.wait(30) or self.error:
            raise RuntimeError(f"dashboard failed to start: {self.error}")
        return f"http://127.0.0.1:{self.port}/?token={self.token}"

    def stop(self) -> None:
        if self._stop is not None and self.loop.is_running():
            self.loop.call_soon_threadsafe(self._stop.set)
        self.thread.join(timeout=15)

    def wait(self) -> None:
        while self.thread.is_alive():
            self.thread.join(timeout=0.5)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._main())
        except BaseException as exc:  # surface startup failures to the UI thread
            self.error = exc
            self.ready.set()

    async def _main(self) -> None:
        from .server import purge_stale_exports, start_dashboard

        purge_stale_exports()
        self._stop = asyncio.Event()
        queue: asyncio.Queue = asyncio.Queue(maxsize=50_000)
        sessions = self.dash.attach_sessions(queue)
        self.dash.quit_callback = self._stop.set
        tasks = [asyncio.create_task(self.dash.consume(queue)), asyncio.create_task(self.dash.flusher())]
        runner, self.port = await start_dashboard(self.dash, "127.0.0.1", self.requested_port)
        self.ready.set()
        try:
            await self._stop.wait()
        finally:
            await sessions.stop()
            for task in tasks:
                task.cancel()
            self.dash.cleanup()
            await runner.cleanup()


class Bridge:
    """The window functions the page asks for, through the dashboard's API (`/api/native/…`):
    pywebview's own script bridge builds its functions with eval, which our CSP forbids."""

    def __init__(self, server: ServerThread | None = None, base: str = ""):
        self._window = None  # underscore: pywebview does not expose private attributes to JS
        self._server = server
        self._base = base  # http://127.0.0.1:PORT
        self._popouts: list = []

    def pop_out(self, query, title="ANTA"):
        """Open one view in a window of its own (statistics, a chart, the map…), side by side
        with the main one. It signs in with a single-use ticket, not the session token."""
        import webview
        from urllib.parse import parse_qsl

        from .server import popout_query

        q = popout_query(dict(parse_qsl(str(query or "")[:512])))
        if not q or self._server is None:
            return False
        # On macOS a window made in private mode wipes the shared website data, the main
        # window's session cookie with it. The main window already wiped it at start, so
        # later windows join that store as they are, and nothing is kept that wasn't before.
        if paths.IS_MAC:
            webview._state["private_mode"] = False
        name = re.sub(r"[\x00-\x1f]", "", str(title or "ANTA"))[:80]
        window = webview.create_window(f"{name} — ANTA", f"{self._base}/?ticket={self._server.dash.issue_ticket()}&{q}",
                                       width=1100, height=760, min_size=(480, 320), background_color="#ECECEC")
        self._popouts.append(window)
        return True

    def _close_popouts(self):
        for window in self._popouts:
            try:
                window.destroy()
            except Exception:  # noqa: BLE001 - already closed by the user
                pass
        self._popouts.clear()

    def choose_capture(self):
        import webview

        kind = webview.FileDialog.OPEN if hasattr(webview, "FileDialog") else webview.OPEN_DIALOG
        result = self._window.create_file_dialog(
            kind, allow_multiple=False,
            file_types=("Packet captures (*.pcap;*.pcapng;*.cap)", "All files (*.*)"))
        return result[0] if result else None

    def reveal_captures(self):
        folder = paths.captures_dir()
        if paths.IS_WINDOWS:
            os.startfile(folder)  # noqa: S606 - opens Explorer on our own folder
        else:
            import subprocess
            subprocess.Popen(["open" if paths.IS_MAC else "xdg-open", folder])  # noqa: S603
        return folder


def _native_window(server: ServerThread, url: str) -> bool:
    try:
        import webview
    except ImportError:
        return False
    bridge = Bridge(server, url.split("/?", 1)[0])
    # Saving (captures, files, CSV, reports, alert exports) is a download from our own
    # server; with this on, the window asks where to put it with the system Save dialog.
    if hasattr(webview, "settings"):
        webview.settings["ALLOW_DOWNLOADS"] = True
    try:
        window = webview.create_window("ANTA — Network Threat Analyzer", url, width=1440, height=900,
                                       min_size=(900, 600), background_color="#ECECEC")
        bridge._window = window
        server.dash.native = bridge
        window.events.closed += lambda: bridge._close_popouts()  # the app ends with its main window
        server.dash.app_info["native"] = True
        webview.start(private_mode=True)  # blocks until the window closes
        return True
    except Exception as exc:
        print(f"anta: native window unavailable ({exc}); using the browser", file=sys.stderr)
        server.dash.app_info["native"] = False
        return False


def run(headless: bool = False, browser: bool = False, port: int = 0, engine: str | None = None,
        model: str | None = None, config: str | None = None, url_file: str | None = None) -> int:
    console = sys.stderr if headless and sys.stderr is not None and not paths.frozen() else None
    log = _redirect_output()
    engine = os.path.abspath(engine if engine and os.path.exists(engine) else paths.engine_path())
    model_dir = model if model and os.path.exists(os.path.join(model, "model.onnx")) else paths.models_dir()
    analyzer = Analyzer(_load_model(model_dir), Config.load(config or paths.config_path()))
    server = ServerThread(analyzer, engine, port)
    url = server.start()
    print(f"anta: app started (engine {engine}, model {model_dir}, log {log})", file=sys.stderr)

    if url_file:  # lets scripts (and the CI smoke test) find a windowed/headless app's dashboard
        fd = os.open(url_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(url + "\n")
    try:
        if headless:
            for stream in {console, sys.__stderr__} - {None}:
                print(f"ANTA dashboard: {url}", file=stream, flush=True)
            server.wait()
        elif browser or not _native_window(server, url):
            server.dash.app_info["can_quit"] = True
            webbrowser.open(url)
            server.wait()  # until Quit in the page (or Ctrl-C)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


def main() -> None:
    """Entry point for the packaged application."""
    if paths.frozen() and len(sys.argv) > 1 and sys.argv[1] in ("analyze", "serve", "train", "--help", "-h"):
        from .__main__ import main as cli_main  # the bundle doubles as the CLI
        sys.exit(cli_main())
    import argparse

    ap = argparse.ArgumentParser(prog="ANTA", description="ANTA desktop application")
    ap.add_argument("--headless", action="store_true", help="no window; serve the dashboard until killed")
    ap.add_argument("--browser", action="store_true", help="use the default browser instead of a native window")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--url-file", help="write the dashboard URL (with its token) to this file, mode 0600")
    args, _ = ap.parse_known_args()  # tolerate launcher-added arguments (e.g. macOS -psn_…)
    sys.exit(run(headless=args.headless, browser=args.browser, port=args.port, url_file=args.url_file))


if __name__ == "__main__":
    main()
