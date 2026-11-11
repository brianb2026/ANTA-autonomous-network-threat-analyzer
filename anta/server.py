"""Dashboard server: WebSocket alert feed, REST API and per-stream pcap export.

Security model
  * Binds to loopback by default. Every API/WebSocket request needs the session
    token (printed once at startup, exchanged for an HttpOnly SameSite=Strict
    cookie), so other local users and web pages can't read alerts.
  * Host header allowlist blocks DNS-rebinding; WebSocket Origin must match the
    host so a malicious page can't open a cross-site socket with the cookie.
  * Strict CSP (self only, no inline script), no framing, no referrers.
  * Exports only read capture files announced by the engine or given on the
    command line, only regular pcap/pcapng files, and only the alert's flows.
"""
from __future__ import annotations

import asyncio
import contextlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import signal
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from urllib.parse import parse_qsl, urlencode, urlsplit

from aiohttp import WSMsgType, web

from . import (apps, ask, ask_answers, assets, before, casefile, diagnose, explain_ai, flowlog, geoip, hunt, ignore,
               ingest, lint, logins, moves, netmap, paths, personality, physics, policy, quicklook, quiet, rhythm, rules,
               scopes, seal, settings, software, storyline, timeline, triage)
from .agent import PROVIDERS, AgentError, AgentSettings, Reviewer
from .agent_context import AgentContext
from .analyzer import TITLES, TRIAGE_STATUSES, Analyzer, alert_summary
from .features import FEATURE_NAMES
from .intel import SOURCES as INTEL_SOURCES
from .intel import IntelStore
from .modelstore import AGENT, BUILTIN, ModelError, ModelStore
from .objects import OBJECT_ID, list_objects, safe_name
from .objects import list_objects as files_in
from .packets import ColorRules, PacketError, PacketService
from .security import InvalidRecord, dumps, runtime_dir, socket_path, validate_session
from .sessions import SessionError, SessionManager

WEB_DIR = paths.web_dir()
COOKIE = "anta_session"

# Pop-out windows: the views one can open on its own, and the plain values its other
# parameters may take (they come back from a URL, so nothing else is let through).
POPOUT_VIEWS = ("alerts", "alert", "story", "packets", "stats", "hosts", "map", "assets", "files")
_POPOUT_VALUE = re.compile(r"[A-Za-z0-9_-]{1,40}")
TICKET_TTL = 60.0


def popout_query(params) -> str | None:
    """The query string of a pop-out window, from untrusted parameters; None if invalid."""
    view = params.get("popout")
    if view not in POPOUT_VIEWS:
        return None
    out = {"popout": view}
    for key in ("tool", "id", "card"):
        value = params.get(key)
        if value is not None:
            if not isinstance(value, str) or not _POPOUT_VALUE.fullmatch(value):
                return None
            out[key] = value
    return urlencode(out)
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
              b"\x0a\x0d\x0d\x0a"}  # pcap (both endiannesses, us/ns) and pcapng
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def json_response(obj, status=200) -> web.Response:
    return web.Response(text=dumps(obj), status=status, content_type="application/json")


class Dashboard:
    def __init__(self, analyzer: Analyzer, engine_path: str, token: str, allowed_hosts: set[str],
                 trusted_captures: set[str], prefs_dir: str | None = None):
        self.analyzer = analyzer
        self.analyzer.set_ignored(ignore.load(TITLES))  # (alert sources the analyst chose to ignore)
        self.engine_path = engine_path
        self.token = token
        self.allowed_hosts = allowed_hosts
        self.trusted_captures = {os.path.realpath(p) for p in trusted_captures}
        self.clients: set[web.WebSocketResponse] = set()
        self.pending: dict[str, dict] = {}
        self.retracted: set[str] = set()
        self.case: dict = {"notes": "", "pins": []}  # the investigation: notes and pinned answers (casefile.py)
        self._keylog_scan: dict | None = None        # checking the HTTPS a loaded key log made readable
        self._keylog_task: asyncio.Task | None = None
        self.export_slots = asyncio.Semaphore(2)
        self.temp_files: set[str] = set()
        # Single-use tickets that let a pop-out window in (the app makes them; a window
        # whose cookie store is its own can't share the main window's session).
        self._tickets: dict[str, float] = {}
        self._ticket_lock = threading.Lock()
        self.downloads: dict[str, dict] = {}  # token -> a prepared file the page may download once or twice
        self.queue: asyncio.Queue | None = None
        self.sessions: SessionManager | None = None
        self.packets = PacketService(os.path.abspath(engine_path))
        self.color_rules = ColorRules(os.path.join(prefs_dir or paths.app_data_dir(), "colorfilters.json"))
        self.followers: set[web.WebSocketResponse] = set()
        self.app_info = {"platform": sys.platform, "native": False, "can_quit": False}
        # The desktop app's own window functions (pop-out windows, the system file
        # dialog), set by the app: the page asks for them here rather than through
        # pywebview's script bridge, which needs eval and so can't run under our CSP.
        self.native = None
        self.quit_callback = None
        # Shared context: offline GeoIP, threat-intel feeds, flow logs and the user's settings.
        self.prefs_dir = prefs_dir or paths.app_data_dir()
        self.settings = settings.load()
        self.geo = geoip.default()
        self.geo.start()
        self.intel = IntelStore(os.path.join(self.prefs_dir, "intel"))
        self.flowlog = flowlog.FlowLog(os.path.join(self.prefs_dir, "flows"), self.settings["flowlog_days"],
                                       self.settings["flowlog_max_mb"])
        with contextlib.suppress(OSError):
            os.makedirs(self.flowlog.dir, mode=0o700, exist_ok=True)
            self.flowlog.prune()
        self.analyzer.intel = self.intel
        self.analyzer.geo = self.geo
        # Detection: the model ANTA started with (built in), a model the user added, or the
        # detection agent instead of a model.
        self.builtin_model = analyzer.model
        self.models = ModelStore(builtin_model=self.builtin_model)
        self.agent_settings = AgentSettings(command=analyzer.cfg.agent_command)
        self.agent_context = AgentContext(lambda: self.analyzer, lambda: self.builtin_model)
        self.reviewer = Reviewer(self.agent_settings, self.agent_context, self._on_agent_verdict)
        self.ask_times: list[float] = []  # questions sent to the AI model in the last hour
        self.scopes = scopes.ScopeStore()  # packet selections the analysis can be limited to
        self.model_error = ""
        self._apply_detector()

    def attach_sessions(self, queue: asyncio.Queue) -> SessionManager:
        """Let the dashboard start/stop engine sessions itself (app mode, `serve --pcap`)."""
        self.queue = queue

        async def on_record(gen, rec):
            await queue.put((gen, rec))

        async def on_state(state):
            await self.broadcast({"type": "session", "session": state})

        def trust(path):
            self.trusted_captures.add(os.path.realpath(path))

        self.sessions = SessionManager(os.path.abspath(self.engine_path), on_record, self.reset, on_state, trust,
                                       on_capture=self.packets.reset, keylog=lambda: self.packets.keylog)
        return self.sessions

    def _apply_detector(self) -> None:
        """Put the chosen detection model (or the agent) to work on the analyzer."""
        active = self.models.active()
        self.model_error = ""
        if active == AGENT:
            self.analyzer.model = None
            self.analyzer.agent_submit = self.reviewer.submit
            return
        self.analyzer.agent_submit = None
        if active == BUILTIN:
            self.analyzer.model = self.builtin_model
            return
        try:
            self.analyzer.model = self.models.load(active)
        except Exception as exc:  # noqa: BLE001 - a broken model file falls back to the built-in one
            self.model_error = f"couldn't load that model ({str(exc)[:200]}); using the built-in one"
            self.analyzer.model = self.builtin_model

    def _on_agent_verdict(self, rec: dict, verdict: dict) -> None:
        alert = self.analyzer.agent_alert(rec, verdict)
        if alert is not None:
            self.pending[alert["id"]] = alert

    def reset(self) -> None:
        """Fresh analyzer for a new session; the browser clears its feed."""
        rules = self.analyzer.ignoring.rules
        self.analyzer = Analyzer(self.analyzer.model, self.analyzer.cfg, intel=self.intel, geo=self.geo)
        self.analyzer.set_ignored(rules)
        self.analyzer.agent_submit = self.reviewer.submit if self.models.active() == AGENT else None
        self.packets.reset()
        self.scopes = scopes.ScopeStore()  # (selections belong to the capture they were made in)
        self.case = {"notes": "", "pins": []}  # (an investigation is about one capture; saved ones can be opened again)
        self.pending.clear()
        self.retracted.clear()
        if self._keylog_task and not self._keylog_task.done():
            self._keylog_task.cancel()  # it was checking the previous capture
        self._keylog_scan = None  # a new capture is analysed with the key log from the start
        asyncio.get_running_loop().create_task(self.broadcast({"type": "reset"}))

    # --------------------------------------------------------- pipeline

    async def consume(self, queue: asyncio.Queue) -> None:
        while True:
            item = await queue.get()
            if isinstance(item, tuple):  # (session generation, record) from the SessionManager
                gen, rec = item
                if self.sessions is None or gen != self.sessions.generation:
                    continue  # a stopped session's stragglers must not leak into the new one
            else:
                rec = item
            if not isinstance(rec, dict):
                continue
            kind = rec.get("type")
            if kind == "session" and rec.get("final"):
                self._log_flow(rec)
            if kind == "packet":  # live packet view feed
                self.packets.on_packet(rec)
                continue
            if kind == "capture_rotated":
                if isinstance(rec.get("base"), int) and isinstance(rec.get("previous_base"), int):
                    self.packets.files.rotated(rec["base"], rec["previous_base"])
                continue
            if kind == "hello" and not isinstance(item, tuple) and isinstance(rec.get("capture"), str):
                # An engine we didn't start (CLI listener): browse what it reads/records.
                self.packets.reset(rec["capture"] or None, bool(rec.get("live")))
            if rec.get("type") == "eof":
                await self.broadcast({"type": "status", "message": f"input finished ({rec.get('source')})"})
                continue
            if rec.get("type") == "hello" and isinstance(rec.get("capture"), str):
                # Only captures announced over the authenticated IPC channel become exportable.
                self.trusted_captures.add(os.path.realpath(rec["capture"]))
            try:
                for alert in self.analyzer.ingest(rec):
                    if alert.get("retracted"):
                        self.pending.pop(alert["id"], None)
                        self.retracted.add(alert["id"])
                    else:
                        self.pending[alert["id"]] = alert
            except Exception as exc:  # one bad record must not stop the pipeline
                print(f"anta: failed to analyse record: {exc!r}", file=sys.stderr)

    def _log_flow(self, rec: dict) -> None:
        """One flow-log line per finished session, for live captures (and opened files, if set)."""
        mode = (self.sessions.state.get("mode") if self.sessions else "live") or "live"
        if not self.settings["flowlog_live" if mode == "live" else "flowlog_files"]:
            return
        try:
            self.flowlog.write(validate_session(rec), self.geo)
        except (InvalidRecord, TypeError, ValueError, OSError) as exc:
            print(f"anta: flow log: {exc}", file=sys.stderr)

    async def flusher(self) -> None:
        """Coalesce alert updates so a busy channel doesn't flood the browser."""
        last_summary = 0.0
        while True:
            await asyncio.sleep(0.25)
            if self.pending or self.retracted:
                batch = [alert_summary(a) for a in self.pending.values()]
                gone = sorted(self.retracted)
                self.pending.clear()
                self.retracted.clear()
                await self.broadcast({"type": "alerts", "alerts": batch, "retracted": gone})
            batch, skipped = self.packets.take_pending()
            if batch and self.followers:
                await self.broadcast({"type": "packets", "packets": batch, "skipped": skipped,
                                      "first_ts": self.packets.feed_first_ts}, only=self.followers)
            if time.time() - last_summary > 1.0:
                last_summary = time.time()
                await self.broadcast({"type": "summary", "summary": self.analyzer.summary()})

    async def broadcast(self, msg: dict, only: set | None = None) -> None:
        targets = self.clients if only is None else (only & self.clients)
        if not targets:
            return
        data = dumps(msg)
        for ws in list(targets):
            try:
                await ws.send_str(data)
            except (ConnectionResetError, RuntimeError):
                self.clients.discard(ws)

    # -------------------------------------------------------- pop-out tickets

    def issue_ticket(self) -> str:
        """A ticket a new window exchanges once, within a minute, for the session cookie.
        Called by the desktop app (another thread), never over HTTP."""
        ticket = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._ticket_lock:
            for t in [t for t, expiry in self._tickets.items() if expiry < now]:
                del self._tickets[t]
            while len(self._tickets) >= 32:
                self._tickets.pop(next(iter(self._tickets)))
            self._tickets[ticket] = now + TICKET_TTL
        return ticket

    def _take_ticket(self, presented: str) -> bool:
        now = time.monotonic()
        with self._ticket_lock:
            match = next((t for t in self._tickets if hmac.compare_digest(t.encode(), presented.encode())), None)
            expiry = self._tickets.pop(match, 0.0) if match else 0.0
        return expiry >= now

    # -------------------------------------------------------- middleware

    def _authorized(self, request: web.Request) -> bool:
        presented = request.cookies.get(COOKIE, "")
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            presented = auth[7:]
        return bool(presented) and hmac.compare_digest(presented.encode(), self.token.encode())

    @web.middleware
    async def guard(self, request: web.Request, handler):
        host = (request.host or "").lower()
        hostname = urlsplit(f"//{host}").hostname or ""
        if hostname not in self.allowed_hosts:
            # Unknown Host header: DNS-rebinding attempt or wrong address.
            return web.Response(status=421, text="misdirected request")
        path = request.path
        if path.startswith("/static/") or path == "/favicon.ico":
            resp = await handler(request)
        elif path == "/":
            ticket = request.query.get("ticket")
            if ticket is not None:
                if not self._take_ticket(ticket):
                    return self._harden(web.Response(status=403, text="invalid or expired ticket"))
                # A pop-out window: the session cookie, then its view (rebuilt from checked values).
                query = popout_query(request.query)
                resp = web.Response(status=303, headers={"Location": "/?" + query if query else "/"})
                resp.set_cookie(COOKIE, self.token, httponly=True, samesite="Strict", path="/",
                                secure=request.secure)
                return self._harden(resp)
            token = request.query.get("token")
            if token is not None:
                if not hmac.compare_digest(token.encode(), self.token.encode()):
                    return web.Response(status=403, text="invalid token")
                # Swap the URL token for a cookie and drop it from the address bar/history.
                resp = web.Response(status=303, headers={"Location": "/"})
                resp.set_cookie(COOKIE, self.token, httponly=True, samesite="Strict", path="/",
                                secure=request.secure)
                return self._harden(resp)
            if not self._authorized(request):
                resp = web.FileResponse(os.path.join(WEB_DIR, "locked.html"), status=401)
            else:
                resp = await handler(request)
        else:
            if not self._authorized(request):
                return self._harden(json_response({"error": "unauthorized"}, status=401))
            if request.method not in ("GET", "HEAD"):
                # State-changing calls: JSON only (a cross-site form can't send it without a CORS
                # preflight we never answer) and, when the browser says, from our own origin.
                origin = request.headers.get("Origin")
                if request.content_type != "application/json" or (
                        origin is not None and (urlsplit(origin).hostname or "") not in self.allowed_hosts):
                    return self._harden(json_response({"error": "forbidden"}, status=403))
            if path == "/ws":
                origin = request.headers.get("Origin")
                if origin is not None and (urlsplit(origin).hostname or "") not in self.allowed_hosts:
                    return self._harden(web.Response(status=403, text="cross-origin WebSocket refused"))
            resp = await handler(request)
        return self._harden(resp)

    @staticmethod
    def _harden(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    # ------------------------------------------------------------ routes

    async def index(self, request: web.Request) -> web.FileResponse:
        return web.FileResponse(os.path.join(WEB_DIR, "index.html"))

    async def websocket(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=20, max_msg_size=4096)  # the client never needs to send much
        await ws.prepare(request)
        self.clients.add(ws)
        print(f"anta: dashboard connected ({len(self.clients)} open)", file=sys.stderr)
        await ws.send_str(dumps({"type": "snapshot",
                                 "alerts": [alert_summary(a) for a in self.analyzer.alerts.values()],
                                 "summary": self.analyzer.summary(),
                                 "session": self.sessions.state if self.sessions else None,
                                 "app": self.app_info}))
        try:
            async for msg in ws:
                if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
                if msg.type == WSMsgType.TEXT:
                    try:
                        cmd = json.loads(msg.data)
                    except ValueError:
                        continue
                    if isinstance(cmd, dict) and cmd.get("type") == "follow":
                        (self.followers.add if cmd.get("on") else self.followers.discard)(ws)
        finally:
            self.clients.discard(ws)
            self.followers.discard(ws)
        return ws

    async def list_alerts(self, request: web.Request) -> web.Response:
        return json_response([alert_summary(a) for a in self.analyzer.alerts.values()])

    async def get_alert(self, request: web.Request) -> web.Response:
        alert = self.analyzer.alerts.get(request.match_info["id"])
        if not alert:
            raise web.HTTPNotFound(text="unknown alert")
        return json_response(alert)

    async def summary(self, request: web.Request) -> web.Response:
        return json_response(self.analyzer.summary())

    # ----------------------------------------------------- session control

    def _need_sessions(self) -> SessionManager:
        if self.sessions is None:
            raise web.HTTPConflict(text="session control is not enabled for this server")
        return self.sessions

    async def interfaces(self, request: web.Request) -> web.Response:
        try:
            return json_response(await self._need_sessions().interfaces())
        except SessionError as exc:
            return json_response({"error": str(exc)}, status=503)

    async def get_session(self, request: web.Request) -> web.Response:
        return json_response(self._need_sessions().state)

    async def start_session(self, request: web.Request) -> web.Response:
        sessions = self._need_sessions()
        try:
            body = await request.json()
        except ValueError:
            return json_response({"error": "invalid JSON"}, status=400)
        if not isinstance(body, dict):
            return json_response({"error": "invalid request"}, status=400)
        mode = body.get("mode")
        try:
            if mode == "file" and isinstance(body.get("path"), str):
                speed = body.get("speed", 0)
                speed = float(speed) if isinstance(speed, (int, float)) and 0 <= speed <= 1000 else 0.0
                state = await sessions.start_file(body["path"], speed)
            elif mode == "live" and isinstance(body.get("iface"), str):
                bpf = body.get("filter") or ""
                if not isinstance(bpf, str):
                    return json_response({"error": "invalid filter"}, status=400)
                state = await sessions.start_live(body["iface"], bpf, bool(body.get("record", True)))
            elif mode == "demo":
                state = await sessions.start_demo()
            else:
                return json_response({"error": "mode must be file, live or demo"}, status=400)
        except SessionError as exc:
            return json_response({"error": str(exc)}, status=400)
        return json_response(state)

    # ------------------------------------------------------- packet viewer

    async def list_packets(self, request: web.Request) -> web.Response:
        q = request.query
        try:
            start = int(q.get("from", "1"))
            limit = int(q.get("limit", "200"))
        except ValueError:
            return json_response({"error": "from/limit must be integers"}, status=400)
        flows: list[str] = []
        if q.get("alert"):
            info = self.analyzer.export_index.get(q["alert"])
            if not info:
                return json_response({"error": "unknown alert"}, status=404)
            flows = info["flows"] or ["6,0.0.0.0,0,0.0.0.0,0"]  # an alert with no flows matches nothing
        colorize = q.get("colorize") == "1"
        rules = [r for r in self.color_rules.load() if r["enabled"]] if colorize else []
        # "Colorize conversation" rules from the viewer go first; the response's color
        # index counts them before the saved rules.
        temporary = q.getall("tmpcolor", [])[:16] if colorize else []
        scope = self._scope(q.get("scope"))
        try:
            page = await self.packets.page(start, limit, q.get("filter", "").strip(), flows,
                                           count=q.get("count") == "1",
                                           dfilter=self._within(scope, q.get("dfilter", "")),
                                           colors=temporary + [r["filter"] for r in rules], columns=q.getall("col", []))
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        page["status"] = self.packets.status()
        page["colors"] = [{"name": r["name"], "bg": r["bg"], "fg": r["fg"]} for r in rules]
        return json_response(page)

    async def tcp_graph(self, request: web.Request) -> web.Response:
        try:
            stream = int(request.query.get("stream", ""))
        except ValueError:
            return json_response({"error": "stream must be a number"}, status=400)
        scope = self._scope(request.query.get("scope"))
        try:
            return json_response(await self.packets.tcp_graph(stream, dfilter=scope["filter"] if scope else ""))
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)

    def _names(self) -> dict[str, str]:
        """Names the capture gives addresses: DNS answers, and the names hosts announce (once
        the statistics are read)."""
        names: dict[str, str] = {}
        for ip, r in list(self.analyzer.resolved.items())[:100_000]:
            if isinstance(r, dict) and r.get("domain"):
                names[ip] = str(r["domain"]).rstrip(".")[:120]
        stats, _ = self.packets.peek()
        for n in ((stats or {}).get("map") or {}).get("nodes") or []:
            if n.get("name") and n.get("addr") and n["name"] != n["addr"]:
                names[n["addr"]] = str(n["name"])[:120]  # (a host's own name wins over a reverse lookup)
        return names

    # ------------------------------------------------- selections (scopes)

    def _capture_id(self) -> str:
        gen = self.sessions.generation if self.sessions else 0
        return f"{gen}|{self.packets.files.path or ''}"

    def _alert_flow_filter(self, alert_id: str) -> str:
        info = self.analyzer.export_index.get(alert_id)
        if not info:
            raise scopes.ScopeError("that alert is no longer in the list")
        return hunt.flow_filter(info["flows"][:200]) if info["flows"] else "frame.number == 0"

    def _scope(self, sid) -> dict | None:
        """The selection a request names (`scope`), or None; a stale one is an error the page
        explains (it was made in another capture, or is long gone)."""
        if not sid:
            return None
        scope = self.scopes.get(str(sid), self._capture_id())
        if scope is None:
            raise web.HTTPGone(text=json.dumps({"error": "That selection belongs to another capture or has expired: "
                                                         "select the packets again.", "scope_gone": True}),
                               content_type="application/json")
        return scope

    @staticmethod
    def _within(scope: dict | None, dfilter: str = "") -> str:
        """A display filter limited to a selection."""
        dfilter = (dfilter or "").strip()
        if not scope:
            return dfilter
        return f"({scope['filter']}) && ({dfilter})" if dfilter else scope["filter"]

    async def _connections(self, scope: dict) -> dict:
        """The connections, addresses and time window in a selection (from its statistics)."""
        if scope.get("conn") is None:
            result = await self.packets.stats(scope["filter"], "", 0, [])
            scope["conn"] = scopes.connections(result["stats"])
        return scope["conn"]

    def _scope_info(self, scope: dict) -> dict:
        flt = scope["filter"]
        return {"id": scope["id"], "label": scope["label"], "count": scope["count"], "parent": scope.get("parent"),
                "filter": flt if len(flt) <= 4000 else flt[:4000] + " …", "filter_length": len(flt),
                "filter_full": flt if len(flt) <= 200_000 else None}

    async def create_scope(self, request: web.Request) -> web.Response:
        """A selection of packets to limit the analysis to: {parts: [{filter, alert, frames}],
        within: an outer selection's id, label} -> {id, label, count, filter}."""
        body = await self._body(request)
        try:
            outer = self._scope(body.get("within"))
            flt = scopes.build_filter(body.get("parts"), self._alert_flow_filter)
        except scopes.ScopeError as exc:
            return json_response({"error": str(exc)}, status=400)
        flt = self._within(outer, flt) if outer else flt
        try:
            page = await self.packets.page(1, 1, count=True, dfilter=flt)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        count = page.get("matched_total")
        if not count:
            return json_response({"error": "None of those packets are in the capture."}, status=409)
        label = body.get("label") if isinstance(body.get("label"), str) else ""
        label = re.sub(r"[\x00-\x1f\x7f]+", " ", label).strip()[:200] or scopes.label_for(body["parts"])
        scope = self.scopes.add(flt, body["parts"], label, count, self._capture_id())
        scope["parent"] = outer["id"] if outer else None
        return json_response(self._scope_info(scope))

    async def get_scope(self, request: web.Request) -> web.Response:
        return json_response(self._scope_info(self._scope(request.match_info["id"])))

    async def scope_alerts(self, request: web.Request) -> web.Response:
        """The alerts about a selection's connections (or, for alerts without any, its addresses)."""
        scope = self._scope(request.match_info["id"])
        try:
            conn = await self._connections(scope)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        ids = [a["id"] for a in self.analyzer.alerts.values()
               if scopes.alert_in(a, (self.analyzer.export_index.get(a["id"]) or {}).get("flows") or [], conn)]
        return json_response({"alerts": ids, "complete": conn["complete"]})

    async def storyline(self, request: web.Request) -> web.Response:
        """The alerts linked into one story per device: stages, a timeline, an account."""
        alerts = list(self.analyzer.alerts.values())
        scope = self._scope(request.query.get("scope"))
        if scope:
            try:
                conn = await self._connections(scope)
            except PacketError as exc:
                return json_response({"error": str(exc)}, status=exc.status)
            alerts = [a for a in alerts
                      if scopes.alert_in(a, (self.analyzer.export_index.get(a["id"]) or {}).get("flows") or [], conn)]
        return json_response(storyline.build(alerts, self._names()))

    async def rhythm_view(self, request: web.Request) -> web.Response:
        """When each client-to-server channel was active over the capture, and how steady
        its rhythm is: timers (beacons) show as evenly spaced stripes."""
        snap = rhythm.snapshot(self.analyzer.channels)  # (copied here, where the analyzer runs)
        scope = self._scope(request.query.get("scope"))
        if scope:
            try:
                snap = scopes.rhythm_snapshot(snap, await self._connections(scope))
            except PacketError as exc:
                return json_response({"error": str(exc)}, status=exc.status)
        alerts = list(self.analyzer.alerts.values())
        return json_response(await asyncio.get_running_loop().run_in_executor(
            None, rhythm.build, snap, self._names(), alerts))

    # ------------------------------------------------------------- ask the capture

    FILTER_SYNTAX = re.compile(r"==|!=|&&|\|\||>=|<=|\bcontains\b|\bmatches\b|\bin \{|\[\d")

    async def _question(self, request: web.Request) -> tuple[str, int]:
        body = await self._body(request)
        q = body.get("q")
        if not isinstance(q, str) or not q.strip() or len(q) > ask.MAX_QUESTION or any(c in q for c in "\x00\r\n"):
            raise web.HTTPBadRequest(text=json.dumps({"error": f"ask a question of 1 to {ask.MAX_QUESTION} characters"}),
                                     content_type="application/json")
        tz = body.get("tz")
        tz = int(tz) if isinstance(tz, int) and not isinstance(tz, bool) and -1440 <= tz <= 1440 else 0
        return q.strip(), tz

    async def _filter_check(self, flt: str) -> dict:
        try:
            [check] = await self.packets.check_filters([flt])
            return {"ok": bool(check.get("ok")), "error": check.get("error", "")}
        except (PacketError, ValueError):
            return {"ok": False, "error": "the filter couldn't be checked"}

    def _host_names(self) -> dict[str, str]:
        """The names hosts on the network announced (DHCP, NetBIOS, mDNS…), lower case ->
        address: so a question can name a host the way the packet list shows it."""
        stats, _ = self.packets.peek()
        out: dict[str, str] = {}
        for n in ((stats or {}).get("map") or {}).get("nodes") or []:
            if n.get("scope") == "public" or not n.get("addr"):
                continue
            for name, src in n.get("names") or []:
                if src not in ("DNS", "TLS SNI", "HTTP Host") and name and name != n["addr"]:
                    out.setdefault(str(name).lower().rstrip("."), n["addr"])
        return out

    async def ask_question(self, request: web.Request) -> web.Response:
        """A question in plain words -> a display filter and/or the view that answers it,
        read by rules here (nothing leaves this computer), with what ANTA already knows."""
        q, tz = await self._question(request)
        scope = self._scope(request.query.get("scope"))
        plan = None
        fields = None
        with contextlib.suppress(PacketError):
            fields = {f["name"] for f in await self.packets.filter_fields()}
        dotted = re.findall(r"\b[a-z][a-z0-9_-]*\.[a-z0-9_.]+\b", q.lower())
        if self.FILTER_SYNTAX.search(q) or (fields and any(d in fields for d in dotted)):
            check = await self._filter_check(q)
            if check["ok"]:  # it's a display filter already
                plan = {"question": q, "understood": True, "filter": q, "summary": "That is a display filter already.",
                        "parts": [], "action": {"kind": "packets"}, "also": None, "intent": None, "source": "filter"}
        if plan is None:
            hosts = self._host_names()
            plan = ask.parse(q, None, tz, hosts)
            if plan["needs_times"]:
                with contextlib.suppress(PacketError, KeyError, TypeError):
                    props = (await self.packets.stats(self._within(scope, ""), "", 0, []))["stats"]["properties"]
                    plan = ask.parse(q, {"first": float(props["first"]), "last": float(props["last"]),
                                         "duration": float(props["duration"])}, tz, hosts)
        if plan["filter"] and plan["source"] == "rules":
            plan["check"] = await self._filter_check(plan["filter"])
        about = plan.get("about")
        if about and about.get("filter") and about["filter"] != plan["filter"]:
            if not (await self._filter_check(about["filter"]))["ok"]:
                plan.pop("about")  # (its numbers would come from a filter the engine refuses)
        if plan.get("check", {"ok": True})["ok"]:
            found = await self._ask_answer(plan, tz, scope)
            plan["answer"], plan["table"] = found["lines"], found.get("table")
        else:
            plan["answer"], plan["table"] = [], None
        plan["scoped"] = bool(scope)
        provider = self.agent_settings.values["provider"]
        plan["model"] = (self.reviewer.backend().name if provider in PROVIDERS and self.reviewer.ready() else None)
        return json_response(plan)

    async def _ask_stats(self, flt: str) -> dict:
        return (await self.packets.stats(flt, "", 0, []))["stats"]

    async def _ask_answer(self, plan: dict, tz: int = 0, scope: dict | None = None) -> dict:
        """What ANTA already knows that answers the question: {"lines", "table"} (a table
        whose rows open their packets, when a list answers better)."""
        intent, out = plan.get("intent"), []
        about = plan.get("about")
        addr = (about or {}).get("subject") or ""  # the address the question is about, if it names one
        for p in plan.get("parts") or [] if not addr else []:
            word = p["label"].split(" ", 1)[-1]
            if not p["negate"] and p["label"].startswith(("from ", "to ", "involving ")):
                with contextlib.suppress(ValueError):
                    addr = str(ipaddress.ip_address(word))
                    break
        try:
            if about:
                whole = await self._ask_stats(self._within(scope, ""))
                names = self._names()  # (after the statistics: they hold the names hosts announced)
                flt = self._within(scope, about.get("filter") or "")
                stats = whole if flt == self._within(scope, "") else await self._ask_stats(flt)
                props = whole.get("properties") or {}
                ctx = ask_answers.Ctx(names=names, tz_min=tz, start=float(props["first"]) if props.get("frames") else None,
                                      geo=self.geo, alerts=list(self.analyzer.alerts.values()),
                                      resolved=self.analyzer.resolved, scoped=bool(scope))
                if about["kind"] == "identity":
                    ctx.assets = await self._asset_rows(scope)
                if about["kind"] == "apps":  # (named applications: from the sessions, not the statistics)
                    found = ask_answers.apps(about, await self._apps(await self.packets.index()), ctx)
                    if scope:
                        found["lines"] = list(found["lines"]) + ["Counted over the whole capture (not only the focus)."]
                    return found
                subject_stats = None
                if about["kind"] == "pair" and not about.get("other") and about.get("subject"):
                    subject_stats = await self._ask_stats(self._within(scope, ask_answers.addr_filter(about["subject"])))
                found = await asyncio.get_running_loop().run_in_executor(
                    None, ask_answers.answer, about, stats, ctx, whole, subject_stats)
                if scope:
                    found["lines"] = list(found["lines"]) + ["Counted within the focused packets."]
                return found
            names = self._names()
            if intent == "logins":
                rep = logins.report(await self.packets.index())
                rows = [r for r in rep["logins"] if not addr or addr in (r["client"], r["server"])]
                if addr:
                    out.append(f"{len(rows)} clear-text logins involve {addr}." if rows else f"No clear-text logins involve {addr}.")
                else:
                    out.append(f"{rep['total']} logins sent in clear text; {rep['accepted']} accounts' passwords worked."
                               if rep["total"] else "No logins were sent in clear text.")
                out += [f"{r['service']} login as {r['user'] or '(no user name)'}: {r['client']} → {r['server']} ({r['status']})"
                        for r in rows[:3]]  # (the account names only; never a password)
            elif intent == "rhythm":
                built = rhythm.build(rhythm.snapshot(self.analyzer.channels), {}, list(self.analyzer.alerts.values()))
                beacons = [a for a in self.analyzer.alerts.values() if a["kind"] == "beacon"
                           and (not addr or addr in (a.get("src_ip"), a.get("dst_ip")))]
                out.append(f"{built['steady']} channels check in on a steady timer; {len(beacons)} were raised as "
                           "beacons.")
                out += [a["headline"] for a in beacons[:3]]
            elif intent == "story":
                stories = storyline.build(list(self.analyzer.alerts.values()), names)["stories"]
                if addr:  # the device asked about: its own story, and the ones it links to
                    stories = [s for s in stories if s["device"] == addr or addr in s["links"]]
                out += [s["summary"] for s in stories[:3]] or \
                    [f"No alerts make up a story about {addr}." if addr else "No alerts make up a story yet."]
            elif intent == "alerts":
                alerts = [a for a in self.analyzer.alerts.values()
                          if not addr or addr in (a.get("src_ip"), a.get("dst_ip"), a.get("offender"))]
                by: dict[str, int] = {}
                for a in alerts:
                    by[a["severity"]] = by.get(a["severity"], 0) + 1
                out.append(", ".join(f"{by[k]} {k}" for k in ("critical", "high", "medium", "low") if by.get(k))
                           or (f"No alerts about {addr}." if addr else "No alerts."))
                if not addr and alerts and re.search(r"\b(?:most|top|which|who|whom)\b", plan["question"].lower()):
                    per: dict[str, int] = {}
                    for a in alerts:
                        who = a.get("offender") or a.get("src_ip")
                        if who:
                            per[who] = per.get(who, 0) + 1
                    out += [f"{names.get(k) and f'{k} ({names[k]})' or k}: {v} alerts"
                            for k, v in sorted(per.items(), key=lambda kv: -kv[1])[:3]]
                else:
                    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                    out += [a["headline"] for a in sorted(alerts, key=lambda a: sev.get(a["severity"], 4))[:3]]
            elif intent == "files":
                files = [o for o in await self.packets.objects() if not addr or addr in (o["client"], o["server"])]
                out.append(f"{len(files):,} files {'involving ' + addr + ' ' if addr else ''}were carried in the capture.")
                out += [f"{o['name']} ({o['proto']}, {o['type'] or 'unknown type'}, {o['size']:,} bytes): "
                        f"{o['server']} → {o['client']}" for o in files[:3]]
            elif intent == "devices":
                nodes = ((await self.packets.stats(self._within(scope, ""), "", 0, [])).get("map") or {}).get("nodes") or []
                out.append(f"{len(nodes):,} addresses on the network map.")
        except (PacketError, KeyError, TypeError, IndexError, ValueError):
            pass
        return {"lines": out[:5], "table": None}

    # ------------------------------------------------------------- one host, at a glance

    async def host_info(self, request: web.Request) -> web.Response:
        """Everything about one address (or MAC) in one place: what it is, who it talked to,
        its alerts, files and clear-text logins (the host panel)."""
        addr = (request.query.get("addr") or "").strip().lower()
        mac = False
        try:
            addr = str(ipaddress.ip_address(addr))
        except ValueError:
            if not re.fullmatch(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", addr):
                return json_response({"error": "give an IP address or a MAC address"}, status=400)
            addr, mac = addr.replace("-", ":"), True
        tz = request.query.get("tz", "0")
        tz = int(tz) if re.fullmatch(r"-?\d{1,4}", tz) and abs(int(tz)) <= 1440 else 0
        scope = self._scope(request.query.get("scope"))
        flt = ask_answers.addr_filter(addr)
        try:
            whole = await self._ask_stats(self._within(scope, ""))
            stats = await self._ask_stats(self._within(scope, flt))
            assets_rows = await self._asset_rows(scope)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        names = self._names()
        props = whole.get("properties") or {}
        ctx = ask_answers.Ctx(names=names, tz_min=tz, start=float(props["first"]) if props.get("frames") else None,
                              geo=self.geo, assets=assets_rows, alerts=list(self.analyzer.alerts.values()),
                              resolved=self.analyzer.resolved, scoped=bool(scope))
        loop = asyncio.get_running_loop()
        ident = await loop.run_in_executor(None, ask_answers.identity, {"subject": addr}, stats, ctx)
        talk = await loop.run_in_executor(None, ask_answers.peers, {"subject": addr, "filter": flt, "dir": "any", "rank": "bytes",
                                                                    "order": "most", "n": 8, "scope": None}, stats, ctx)
        ip = addr if not mac else \
            next((r["ip"] for r in assets_rows if addr in [m.lower() for m in r.get("macs") or []]), "")  # (a MAC's address)
        sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        alerts = sorted(([{"id": a["id"], "severity": a["severity"], "title": a["title"], "headline": a.get("headline", ""),
                           "verdict": (a.get("triage") or {}).get("status") or "new"}
                          for a in self.analyzer.alerts.values()
                          if ip and ip in (a.get("src_ip"), a.get("dst_ip"), a.get("offender"), *(a.get("victims") or []))]),
                        key=lambda a: (sev.get(a["severity"], 9), a["id"]))
        files, logins_n = [], 0
        with contextlib.suppress(PacketError):
            if ip:
                files = [{"id": o["id"], "name": o["name"], "proto": o["proto"], "direction": o["direction"],
                          "size": o["size"], "type": o["type"], "program": o["program"],
                          "peer": o["server"] if o["client"] == ip else o["client"]}
                         for o in await self.packets.objects() if ip in (o["client"], o["server"])][:30]
                rep = logins.report(await self.packets.index())
                logins_n = sum(r["logins"] for r in rep["logins"] if ip in (r["client"], r["server"]))
        row = next((r for r in assets_rows if r["ip"] == ip), None) if ip else None
        used, persona, sw = [], None, []
        with contextlib.suppress(PacketError):
            if ip and not scope:
                used = (await self._apps(await self.packets.index()))["devices"].get(ip, [])[:8]
                persona = next((d for d in (await self._personalities())["report"]["devices"] if d["ip"] == ip), None)
                inv = await self._software(await self.packets.index())
                sw = next((h["software"] for h in inv["hosts"] if h["ip"] == ip), [])[:10]
        return json_response({
            "addr": addr, "ip": ip, "name": (row or {}).get("name") or names.get(ip, ""),
            "kind": netmap.scope_of(ip) if ip else "mac", "device": (row or {}).get("device"),
            "lines": ident.get("lines") or [], "facts": [r["cells"] for r in (ident.get("table") or {}).get("rows") or []],
            "peers": talk.get("table"), "peer_lines": talk.get("lines") or [], "peer_count": talk.get("count", 0),
            "alerts": alerts[:50], "files": files, "apps": used, "software": sw,
            "personality": {"sentence": persona["sentence"], "changes": persona["changes"]} if persona else None,
            "logins": logins_n, "filter": ask_answers.addr_filter(ip) if ip else flt, "scoped": bool(scope)})

    async def triage_list(self, request: web.Request) -> web.Response:
        """What to look at first: up to five findings, worst first, with the next step for each."""
        scope = self._scope(request.query.get("scope"))
        alerts = list(self.analyzer.alerts.values())
        stats = None
        try:
            if scope:
                conn = await self._connections(scope)
                alerts = [a for a in alerts
                          if scopes.alert_in(a, (self.analyzer.export_index.get(a["id"]) or {}).get("flows") or [], conn)]
            stats = await self._ask_stats(self._within(scope, ""))
        except PacketError:
            pass
        names = self._names()
        stories = storyline.build(alerts, names)["stories"]
        rep, files = None, []
        with contextlib.suppress(PacketError):
            index = await self.packets.index()
            rep = logins.report(index)
            files = list_objects(index)
        changed = []
        with contextlib.suppress(PacketError):  # (devices that behave differently from what was remembered as normal)
            if not scope and personality.load():
                changed = [d for d in (await self._personalities())["report"]["devices"] if d["notable"]]
        broken = []
        with contextlib.suppress(PacketError):  # (a broken network policy rule is worth a look too)
            results, _, _ = await self._policy_results(policy.load(), self._tz(request.query.get("tz")))
            broken = [r for r in results or [] if r.get("status") == "fail"]
        items = await asyncio.get_running_loop().run_in_executor(
            None, triage.build, stories, rep, files, stats, alerts, names, broken, changed)
        return json_response({"items": items, "alerts": len(alerts)})

    async def timeline_packets(self, request: web.Request) -> web.Response:
        """The packets of a stretch of the capture (seconds from its start), for the replay's arrows:
        {start, packets: [[t, source, destination, length]], hosts, complete}."""
        q = request.query
        try:
            t0, t1 = float(q.get("from", "0")), float(q.get("to", "0"))
            limit = int(q.get("max", "20000"))
        except ValueError:
            return json_response({"error": "from, to and max must be numbers"}, status=400)
        if not (0 <= t0 < t1) or t1 - t0 > 86400:
            return json_response({"error": "from must be before to, at most a day apart"}, status=400)
        scope = self._scope(q.get("scope"))
        try:
            props = (await self.packets.stats(self._within(scope, ""), "", 0, []))["stats"]["properties"]
            start = float(props.get("first") or 0)
            rows = await self.packets.packet_times(
                self._within(scope, f"frame.time_relative >= {t0:.6f} && frame.time_relative < {t1:.6f}"), min(limit, 50_000))
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        hosts: dict[str, int] = {}
        out = []
        for ts, src, dst, length in rows:
            for h in (src, dst):
                if h not in hosts:
                    hosts[h] = len(hosts)
            out.append([round(ts - start, 6), hosts[src], hosts[dst], length])
        return json_response({"start": start, "from": t0, "to": t1, "packets": out, "hosts": list(hosts),
                              "complete": len(out) < min(limit, 50_000)})

    # ------------------------------------------------------------- device personalities and drift

    async def _personalities(self) -> dict:
        """The open capture's device profiles against what was remembered as normal."""
        sessions = await self.packets.index()
        usage = await self._apps(sessions)
        key = (id(sessions), len(sessions))
        cached = getattr(self, "_profile_cache", None)
        if cached and cached[0] == key:
            current = cached[1]
        else:
            rows = await self._asset_rows(None)
            current = await asyncio.get_running_loop().run_in_executor(None, personality.profiles, sessions, usage, rows)
            self._profile_cache = (key, current)
        filters = {a["app"]: a["filter"] for a in usage["apps"] if a["filter"]}
        report = personality.report(current, personality.load(), filters)
        # The devices in serious alerts (not dismissed as false positives): the page marks them in red.
        serious: dict[str, list] = defaultdict(list)
        for a in self.analyzer.alerts.values():
            if a.get("severity") in ("critical", "high") and (a.get("triage") or {}).get("status") != "false_positive":
                for ip in {a.get("src_ip"), a.get("dst_ip"), a.get("offender"), *(a.get("victims") or [])} - {None, ""}:
                    serious[ip].append({"id": a["id"], "title": a["title"], "severity": a["severity"]})
        for d in report["devices"]:
            d["alerts"] = sorted(serious.get(d["ip"], []), key=lambda x: (x["severity"] != "critical", x["id"]))[:6]
            d["malicious"] = bool(d["alerts"])
        report["devices"].sort(key=lambda d: (not d["malicious"], -d["notable"]))
        return {"current": current, "report": report}

    async def personalities(self, request: web.Request) -> web.Response:
        try:
            return json_response((await self._personalities())["report"])
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)

    async def personalities_remember(self, request: web.Request) -> web.Response:
        """Remember this capture's devices as normal (later captures are compared with them)."""
        try:
            found = await self._personalities()
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        personality.remember(found["current"], self._capture_meta()["name"] or "capture")
        return json_response((await self._personalities())["report"])

    async def personalities_forget(self, request: web.Request) -> web.Response:
        personality.forget()
        try:
            return json_response((await self._personalities())["report"])
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)

    # ------------------------------------------------------------- the time machine

    async def timeline_data(self, request: web.Request) -> web.Response:
        """The capture as a timeline to replay: traffic per slice, connections, alerts."""
        scope = self._scope(request.query.get("scope"))
        try:
            props = (await self.packets.stats(self._within(scope, ""), "", 0, []))["stats"]["properties"]
            interval = timeline.interval_for(float(props.get("duration") or 0))
            stats = (await self.packets.stats(self._within(scope, ""), "", interval, []))["stats"]
            sessions = await self._sessions_in(request)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        alerts = list(self.analyzer.alerts.values())
        if scope:
            conn = await self._connections(scope)
            alerts = [a for a in alerts
                      if scopes.alert_in(a, (self.analyzer.export_index.get(a["id"]) or {}).get("flows") or [], conn)]
        return json_response(await asyncio.get_running_loop().run_in_executor(None, timeline.build, stats, sessions, alerts))

    # ------------------------------------------------------------- network policy tests

    @staticmethod
    def _tz(value) -> int:
        """The viewer's time zone, as minutes behind UTC (the browser's getTimezoneOffset)."""
        try:
            tz = int(value)
        except (TypeError, ValueError):
            return 0
        return tz if -1440 <= tz <= 1440 else 0

    async def _policy_results(self, lines: list[str], tz: int = 0, placement: str | None = None) -> tuple:
        """The rules (tests and firewall lines, rules.py) against the open capture:
        (results per line, what enforcing them would do, why not) — (None, None, why) without a capture."""
        if not lines:
            return [], None, ""
        try:
            sessions = await self.packets.index()
        except PacketError as exc:
            return None, None, str(exc)
        need = policy.needs(lines)
        assets_rows = None
        if "assets" in need:
            with contextlib.suppress(PacketError):
                assets_rows = await self._asset_rows(None)
        ctx = policy.Context(sessions, assets_rows, self.geo if "geo" in need else None,
                             logins.report(sessions) if "logins" in need else None, tz,
                             personality.load() if "remembered" in need else None)
        results, enforce = await asyncio.get_running_loop().run_in_executor(
            None, rules.evaluate, lines, ctx, list(self.analyzer.alerts.values()), placement or policy.load_placement())
        return results, enforce, ""

    async def _policy_reply(self, lines: list[str], tz: int, placement: str | None, extra: dict | None = None) -> web.Response:
        placement = placement if placement in policy.PLACEMENTS else policy.load_placement()
        results, enforce, why = await self._policy_results(lines, tz, placement)
        return json_response({"rules": lines, "placement": placement, "results": results, "enforce": enforce, "error": why,
                              **(extra or {})})

    async def policy_get(self, request: web.Request) -> web.Response:
        """The saved rules checked against the open capture (?reference=1 adds the guide to what rules can say)."""
        extra = {"reference": rules.reference()} if request.query.get("reference") else None
        return await self._policy_reply(policy.load(), self._tz(request.query.get("tz")), None, extra)

    async def policy_put(self, request: web.Request) -> web.Response:
        """Save the rules (one per line) and where they are enforced, and check them."""
        body = await self._body(request)
        placement = body.get("placement")
        try:
            lines = policy.save(body.get("rules"), placement if placement in policy.PLACEMENTS else None)
        except policy.PolicyError as exc:
            return json_response({"error": str(exc)}, status=400)
        return await self._policy_reply(lines, self._tz(body.get("tz")), placement)

    async def policy_check(self, request: web.Request) -> web.Response:
        """Check rules without saving them (while they are being written)."""
        body = await self._body(request)
        try:
            lines = policy.clean(body.get("rules"))
        except policy.PolicyError as exc:
            return json_response({"error": str(exc)}, status=400)
        return await self._policy_reply(lines, self._tz(body.get("tz")), body.get("placement"))

    # ------------------------------------------------------------- ignored alert sources

    def _ignored_report(self) -> dict:
        counts = self.analyzer.ignored_counts()
        rules = self.analyzer.ignoring.rules
        return {"rules": [{**r, "count": counts[i] if i < len(counts) else 0} for i, r in enumerate(rules)],
                "ignored": len(self.analyzer.ignored),
                "kinds": [{"kind": k, "title": t} for k, t in sorted(TITLES.items(), key=lambda kv: kv[1])]}

    async def ignored_get(self, request: web.Request) -> web.Response:
        """The alert sources being ignored, with how many alerts each holds back."""
        return json_response(self._ignored_report())

    async def ignored_put(self, request: web.Request) -> web.Response:
        """Save the ignore rules and apply them at once: alerts from those sources leave every
        open window (they are kept aside), and alerts a removed rule held back come back."""
        body = await self._body(request)
        try:
            rules = ignore.save(body.get("rules"), TITLES)
        except ignore.IgnoreError as exc:
            return json_response({"error": str(exc)}, status=400)
        for alert in self.analyzer.set_ignored(rules):
            if alert.get("retracted"):
                self.pending.pop(alert["id"], None)
                self.retracted.add(alert["id"])
            else:
                self.retracted.discard(alert["id"])
                self.pending[alert["id"]] = alert
        return json_response(self._ignored_report())

    # ------------------------------------------------------------- the investigation

    def _capture_meta(self) -> dict:
        path = self.packets.files.path or ""
        size = None
        with contextlib.suppress(OSError):
            size = os.path.getsize(path) if path else None
        source = (self.sessions.state.get("source") if self.sessions else None) or path
        return {"name": os.path.basename(source or "") or "", "path": path if self.packets.files.inputs() else "",
                "size": size, "packets": self.analyzer.engine_stats.get("packets")}

    def _case_view(self) -> dict:
        verdicts = {}
        for a in self.analyzer.alerts.values():
            st = (a.get("triage") or {}).get("status")
            if st:
                verdicts[st] = verdicts.get(st, 0) + 1
        return {"notes": self.case["notes"], "pins": self.case["pins"], "verdicts": verdicts, "capture": self._capture_meta()}

    async def case_get(self, request: web.Request) -> web.Response:
        return json_response(self._case_view())

    async def case_notes(self, request: web.Request) -> web.Response:
        body = await self._body(request)
        if not isinstance(body.get("notes"), str) or len(body["notes"]) > casefile.MAX_NOTES:
            return json_response({"error": f"notes are text of up to {casefile.MAX_NOTES:,} characters"}, status=400)
        self.case["notes"] = casefile._text(body["notes"], casefile.MAX_NOTES, True)
        return json_response(self._case_view())

    async def case_pin(self, request: web.Request) -> web.Response:
        body = await self._body(request)
        try:
            p = casefile.pin(body.get("pin"))
        except casefile.CaseError as exc:
            return json_response({"error": str(exc)}, status=400)
        if len(self.case["pins"]) >= casefile.MAX_PINS:
            return json_response({"error": f"an investigation holds at most {casefile.MAX_PINS} pins"}, status=409)
        p["id"] = secrets.token_urlsafe(6)
        self.case["pins"].append(p)
        return json_response(self._case_view())

    async def case_unpin(self, request: web.Request) -> web.Response:
        pid = request.match_info["id"]
        self.case["pins"] = [p for p in self.case["pins"] if p["id"] != pid]
        return json_response(self._case_view())

    async def case_save(self, request: web.Request) -> web.Response:
        """The investigation as a file (notes, pins, verdicts, focus; no packets)."""
        body = await self._body(request)
        content = casefile.export(self._capture_meta(), self.case["notes"], self.case["pins"],
                                  list(self.analyzer.alerts.values()), body.get("focus"))
        fd, path = tempfile.mkstemp(prefix="anta_save_", suffix=".json", dir=runtime_dir())
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        stem = os.path.splitext(self._capture_meta()["name"] or "capture")[0]
        return json_response(self._offer(path, safe_name(f"{stem}.anta-investigation.json", "investigation.json"),
                                         "application/json"))

    async def case_open(self, request: web.Request) -> web.Response:
        """An investigation file the user chose: checked, then (on its capture, or when asked
        to anyway) its notes and pins replace these and its verdicts go back on the alerts."""
        body = await self._body(request)
        try:
            doc = casefile.load(body.get("content"))
        except casefile.CaseError as exc:
            return json_response({"error": str(exc)}, status=400)
        current = self._capture_meta()
        same = casefile.same_capture(doc["capture"], current)
        out = {"capture": {k: doc["capture"][k] for k in ("name", "size", "packets")}, "current": current["name"],
               "same": same, "can_open": casefile.openable(doc["capture"]["path"]) and not same,
               "path": doc["capture"]["path"] if casefile.openable(doc["capture"]["path"]) else "",
               "pins": len(doc["pins"]), "verdicts": len(doc["verdicts"]), "focus": doc["focus"], "saved": doc["saved"],
               "applied": False}
        if not (same or body.get("apply") is True):
            return json_response(out)
        self.case = {"notes": doc["notes"], "pins": doc["pins"]}
        by_sig: dict[tuple, list[str]] = {}
        for a in self.analyzer.alerts.values():
            by_sig.setdefault(casefile.signature(a), []).append(a["id"])
        matched = 0
        for v in doc["verdicts"]:
            ids = by_sig.get((v["kind"], v["src_ip"], v["dst_ip"], v["offender"])) or []
            for aid in ids:
                alert = self.analyzer.set_triage(aid, v["status"], v["note"])
                if alert is not None:
                    self.pending[aid] = alert  # (the feed shows the verdict)
            matched += bool(ids)
        out.update(applied=True, matched=matched, case=self._case_view())
        return json_response(out)

    async def ask_model(self, request: web.Request) -> web.Response:
        """The question to the configured AI model, on the user's click: the question only
        (internal addresses pseudonymized unless allowed), never the capture. Its filter is
        checked by the engine before it is offered."""
        q, _ = await self._question(request)
        if self.agent_settings.values["provider"] not in PROVIDERS or not self.reviewer.ready():
            return json_response({"error": "set up an AI model under Detection… (and agree to send it data) to ask it"},
                                 status=409)
        now = time.time()
        self.ask_times = [t for t in self.ask_times if now - t < 3600]
        if len(self.ask_times) >= 60:
            return json_response({"error": "that's 60 questions to the model this hour; ask again later"}, status=429)
        self.ask_times.append(now)
        try:
            fields = [f["name"] for f in await self.packets.filter_fields()]
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        try:
            out = await ask.translate_with_model(self.agent_settings, q, fields)
        except AgentError as exc:
            return json_response({"error": str(exc)}, status=502)
        plan = {"question": q, "understood": bool(out["filter"] or out["action"]), "parts": [], "intent": None,
                "source": "model", "model": self.reviewer.backend().name, **out}
        if out["filter"]:
            plan["check"] = await self._filter_check(out["filter"])
        return json_response(plan)

    async def host_names(self, request: web.Request) -> web.Response:
        """Names for addresses, from what the capture itself says (DNS answers, and the names
        hosts announced over NetBIOS, DHCP, NTLM, mDNS and the like once the statistics are
        read): the packet list's "Show host names", like Wireshark's network name resolution."""
        return json_response({"names": self._names()})

    async def find_packet(self, request: web.Request) -> web.Response:
        """Find Packet: {mode, text, where, from, dir} within the list's current view (dfilter,
        filter, alert) -> {frame, wrapped}."""
        q = request.query
        try:
            start = int(q.get("from", "0"))
        except ValueError:
            return json_response({"error": "from must be a frame number"}, status=400)
        flows: list[str] = []
        if q.get("alert"):
            info = self.analyzer.export_index.get(q["alert"])
            if not info:
                return json_response({"error": "unknown alert"}, status=404)
            flows = info["flows"] or ["6,0.0.0.0,0,0.0.0.0,0"]
        try:
            result = await self.packets.find(q.get("mode", "text"), q.get("text", ""), q.get("where", "list"), start,
                                             q.get("dir") == "prev", q.get("filter", "").strip(), flows,
                                             self._within(self._scope(q.get("scope")), q.get("dfilter", "")))
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        return json_response(result)

    async def check_filters(self, request: web.Request) -> web.Response:
        try:
            return json_response(await self.packets.check_filters(request.query.getall("f", [])))
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)

    async def filter_fields(self, request: web.Request) -> web.Response:
        try:
            return json_response(await self.packets.filter_fields())
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)

    async def stats(self, request: web.Request) -> web.Response:
        q = request.query
        try:
            interval = float(q.get("interval", "0") or 0)
        except ValueError:
            return json_response({"error": "interval must be a number"}, status=400)
        scope = self._scope(q.get("scope"))
        try:
            result = await self.packets.stats(self._within(scope, q.get("dfilter", "")), q.get("filter", ""), interval,
                                              q.getall("series", []))
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        devices = [entry["device"] for entry in self.analyzer.devices.values()]
        if devices and result.get("map"):
            result = {**result, "map": netmap.annotate_devices(result["map"], devices)}
        if result.get("map"):  # country and AS of the map's internet hosts
            result = {**result, "map": self._geo_map(result["map"])}
        result = {**result, "geo": await asyncio.get_running_loop().run_in_executor(
            None, assets.geo_summary, result["stats"], self.geo)}
        return json_response(result)

    async def lint_check(self, request: web.Request) -> web.Response:
        """The protocol spell-checker (lint.py): which rules of which standards the packets break,
        counted in one pass of the engine. ?dfilter= and ?scope= limit it like the statistics."""
        q = request.query
        scope = self._scope(q.get("scope"))
        try:
            result = await self.packets.stats(self._within(scope, q.get("dfilter", "")), "", 0, [], lint.filters())
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        return json_response(lint.report(result["stats"].get("counts") or []))

    def _geo_map(self, graph: dict) -> dict:
        nodes = []
        for n in graph.get("nodes") or []:
            if n.get("scope") == "public":
                g = self.geo.lookup(n["addr"])
                if g:
                    n = {**n, "geo": g}
            nodes.append(n)
        return {**graph, "nodes": nodes}

    async def follow(self, request: web.Request) -> web.Response:
        try:
            stream = int(request.query.get("stream", ""))
        except ValueError:
            return json_response({"error": "stream must be a number"}, status=400)
        h2 = request.query.get("h2")
        try:
            h2_stream = int(h2) if h2 else None
        except ValueError:
            return json_response({"error": "h2 must be a number"}, status=400)
        try:
            return json_response(await self.packets.follow(request.query.get("proto", "tcp"), stream, h2_stream))
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)

    async def get_color_rules(self, request: web.Request) -> web.Response:
        return json_response({"rules": self.color_rules.load(), "defaults": ColorRules.defaults()})

    async def put_color_rules(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except ValueError:
            return json_response({"error": "invalid JSON"}, status=400)
        try:
            rules = ColorRules.validate(body.get("rules") if isinstance(body, dict) else None)
            checks = await self.packets.check_filters([r["filter"] for r in rules])
            for i, c in enumerate(checks, 1):
                if not c.get("ok"):
                    raise PacketError(f"rule {i} ({rules[i - 1]['name']}): {c.get('error')}")
            self.color_rules.save(rules)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        except OSError:
            return json_response({"error": "could not save the coloring rules"}, status=500)
        return json_response({"rules": rules})

    async def packet_detail(self, request: web.Request) -> web.Response:
        try:
            frame = int(request.match_info["n"])
            detail = await self.packets.detail(frame)
            detail["explain"] = diagnose.explain_frame(detail)  # the packet in plain words
            stream = diagnose.stream_of(detail)
            detail["stream_ref"] = list(stream) if stream else None
            return json_response(detail)
        except ValueError:
            return json_response({"error": "bad frame number"}, status=400)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)

    async def stop_session(self, request: web.Request) -> web.Response:
        return json_response(await self._need_sessions().stop())

    async def quit(self, request: web.Request) -> web.Response:
        if not self.quit_callback:
            raise web.HTTPNotFound()
        asyncio.get_running_loop().call_later(0.2, self.quit_callback)
        return json_response({"ok": True})

    def _capture_inputs(self, capture: str | None) -> list[str]:
        """Resolve an alert's capture (plus its rotated predecessor) to safe input files."""
        if not capture:
            return []
        real = os.path.realpath(capture)
        if real not in self.trusted_captures:
            return []
        inputs = []
        for path in (real + ".1", real):  # oldest first
            try:
                if not os.path.isfile(path):
                    continue
                with open(path, "rb") as fh:
                    if fh.read(4) not in PCAP_MAGIC:
                        continue
            except OSError:
                continue
            inputs.append(path)
        return inputs

    async def export(self, request: web.Request) -> web.StreamResponse:
        """Slice only this alert's flows out of the capture into a standalone .pcap."""
        alert_id = request.match_info["id"]
        alert = self.analyzer.alerts.get(alert_id)
        info = self.analyzer.export_index.get(alert_id)
        if not alert or not info:
            raise web.HTTPNotFound(text="unknown alert")
        inputs = self._capture_inputs(info["capture"])
        if not inputs:
            raise web.HTTPConflict(text="no trusted capture file for this alert; run the engine with -w FILE")
        flows = [f for f in info["flows"] if re.fullmatch(r"(6|17),[0-9a-fA-F:.]+,\d{1,5},[0-9a-fA-F:.]+,\d{1,5}", f)]
        if not flows:
            raise web.HTTPConflict(text="alert has no exportable flows")

        async with self.export_slots:
            fd, out_path = tempfile.mkstemp(prefix=f"anta_{alert_id}_", suffix=".pcap", dir=runtime_dir())
            os.close(fd)
            self.temp_files.add(out_path)
            args = [self.engine_path, "-w", out_path]
            for path in inputs:
                args += ["-r", path]
            for spec in flows:
                args += ["--extract", spec]
            proc = await asyncio.create_subprocess_exec(*args, stdin=asyncio.subprocess.DEVNULL,
                                                        stdout=asyncio.subprocess.DEVNULL,
                                                        stderr=asyncio.subprocess.PIPE)
            try:
                _, err = await asyncio.wait_for(proc.communicate(), timeout=120)
            except TimeoutError:
                proc.kill()
                self._remove(out_path)
                raise web.HTTPGatewayTimeout(text="export timed out") from None
            if proc.returncode != 0:
                self._remove(out_path)
                print(f"anta: export failed: {err.decode(errors='replace')[:500]}", file=sys.stderr)
                raise web.HTTPInternalServerError(text="export failed")

        target = re.sub(r"[^A-Za-z0-9._-]+", "_", str(alert.get("target") or "stream"))[:80]
        name = f"anta_{alert_id}_{alert['kind']}_{target}.pcap"
        resp = web.FileResponse(out_path, headers={"Content-Disposition": f'attachment; filename="{name}"',
                                                   "Content-Type": "application/vnd.tcpdump.pcap"})
        asyncio.get_running_loop().call_later(120, self._remove, out_path)
        return resp

    # ----------------------------------------------------- saving files
    # Anything the page saves is prepared here as a private temp file and fetched
    # with GET /api/download/<token>: the native window's download handler shows a
    # Save dialog for it, and a browser saves it like any download.

    DOWNLOAD_TTL = 900
    TEXT_TYPES = {"csv": ("text/csv; charset=utf-8", ".csv"), "txt": ("text/plain; charset=utf-8", ".txt"),
                  "json": ("application/json", ".json")}

    def _offer(self, path: str, name: str, content_type: str) -> dict:
        token = secrets.token_urlsafe(18)
        self.temp_files.add(path)
        self.downloads[token] = {"path": path, "name": name, "type": content_type}

        def expire():
            self.downloads.pop(token, None)
            self._remove(path)
        asyncio.get_running_loop().call_later(self.DOWNLOAD_TTL, expire)
        return {"download": f"/api/download/{token}", "name": name, "size": os.path.getsize(path)}

    async def download(self, request: web.Request) -> web.StreamResponse:
        item = self.downloads.get(request.match_info["token"])
        if not item or not os.path.exists(item["path"]):
            raise web.HTTPNotFound(text="this download has expired; save it again")
        ascii_name = re.sub(r"[^A-Za-z0-9._-]+", "_", item["name"]) or "download"
        return web.FileResponse(item["path"], headers={
            "Content-Disposition": f'attachment; filename="{ascii_name}"',
            "Content-Type": item["type"], "X-Content-Type-Options": "nosniff"})

    async def _body(self, request: web.Request) -> dict:
        try:
            body = await request.json()
        except ValueError:
            raise web.HTTPBadRequest(text="invalid JSON") from None
        if not isinstance(body, dict):
            raise web.HTTPBadRequest(text="expected a JSON object")
        return body

    async def save_packets(self, request: web.Request) -> web.Response:
        """Save the capture: every packet, the ones a display filter shows, or marked ones."""
        body = await self._body(request)
        scope = body.get("scope")
        shown = scope == "displayed"
        dfilter = body.get("dfilter") if shown else ""
        bpf = body.get("bpf") if shown else ""
        frames = body.get("frames") if scope == "marked" else ""
        if scope not in ("all", "displayed", "marked") or not all(
                isinstance(v or "", str) for v in (dfilter, bpf, frames)):
            return json_response({"error": "scope must be all, displayed or marked"}, status=400)
        if scope == "marked" and not frames:
            return json_response({"error": "no packets are marked"}, status=400)
        flows: list[str] = []
        if shown and body.get("alert"):
            info = self.analyzer.export_index.get(str(body["alert"]))
            if not info:
                return json_response({"error": "unknown alert"}, status=404)
            flows = info["flows"] or ["6,0.0.0.0,0,0.0.0.0,0"]
        selection = self._scope(body.get("selection"))  # within a selection (the focus, or selected packets)
        if selection:
            dfilter = self._within(selection, dfilter or "")
        safe = body.get("safe")  # a share-safe copy: {keep_payload, shift_time}
        if safe is not None and not isinstance(safe, dict):
            return json_response({"error": "safe must be an object"}, status=400)
        if safe is not None:
            safe = {"keep_payload": safe.get("keep_payload") is True, "shift_time": safe.get("shift_time") is True}
        try:
            saved = await self.packets.save_packets(dfilter or "", frames or "", bpf or "", flows, safe)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        if not saved["packets"]:
            self._remove(saved["path"])
            if saved.get("key_path"):
                self._remove(saved["key_path"])
            return json_response({"error": "no packets matched, so there is nothing to save"}, status=409)
        part = "_selection" if selection and scope == "all" else "" if scope == "all" else "_" + scope
        stem = f"{self.packets.source_stem()}{part}{'_share-safe' if safe else ''}"
        offer = self._offer(saved["path"], f"{stem}.pcap", "application/vnd.tcpdump.pcap")
        out = {**offer, "packets": saved["packets"], "first": saved["first"], "last": saved["last"],
               "skipped_link_type": saved["skipped_link_type"]}
        if safe:
            key = self._offer(saved["key_path"], f"{stem}_address-key.csv", "text/csv")
            out.update(sanitized=saved["sanitized"], key=key)
        return json_response(out)

    async def lookup(self, request: web.Request) -> web.Response:
        """Quick look at an address, domain, MAC, hash, fingerprint, URL or file name: what the
        analysis already knows. `full=1` reads the capture's statistics and sessions if they
        haven't been read yet (the right-click menu asks without it, to answer at once)."""
        q = request.query.get("q", "").strip()
        if not q or len(q) > 512 or any(c in q for c in "\x00\r\n"):
            return json_response({"error": "nothing to look up"}, status=400)
        stats, sessions = self.packets.peek()
        if request.query.get("full") == "1":
            with contextlib.suppress(PacketError):
                stats = stats or await self.packets.stats("", "", 0, [])
            with contextlib.suppress(PacketError):
                sessions = sessions if sessions is not None else await self.packets.index()
        nodes = (stats or {}).get("map", {}).get("nodes") if stats else None
        objects = files_in(sessions) if sessions is not None else None
        result = await asyncio.get_running_loop().run_in_executor(
            None, quicklook.lookup, q, self.agent_context, self.analyzer, nodes, sessions, objects)
        return json_response(result)

    async def list_objects(self, request: web.Request) -> web.Response:
        scope = self._scope(request.query.get("scope"))
        try:
            if scope:  # the files carried by the selection's connections
                conn = await self._connections(scope)
                objects = list_objects([s for s in await self.packets.index() if scopes.session_in(s, conn)])
            else:
                objects = await self.packets.objects()
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        return json_response({"objects": objects})

    async def save_object(self, request: web.Request) -> web.Response:
        """Write one transferred file out of the capture, checked against its listed SHA-256."""
        body = await self._body(request)
        object_id = body.get("id")
        if not isinstance(object_id, str) or not OBJECT_ID.fullmatch(object_id):
            return json_response({"error": "bad object id"}, status=400)
        try:
            listed = next((o for o in await self.packets.objects() if o["id"] == object_id), None)
            if listed is None:
                return json_response({"error": "no such file in this capture"}, status=404)
            path = await self.packets.extract_object(object_id)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        import hashlib
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        verified = bool(listed["sha256"]) and digest.hexdigest() == listed["sha256"]
        offer = self._offer(path, safe_name(listed["name"], "file.bin"), "application/octet-stream")
        return json_response({**offer, "sha256": digest.hexdigest(), "verified": verified,
                              "complete": listed["complete"]})

    async def save_text(self, request: web.Request) -> web.Response:
        """A table (CSV) or report (text) the page built, saved as a file."""
        body = await self._body(request)
        kind, content = body.get("type"), body.get("content")
        if kind not in self.TEXT_TYPES or not isinstance(content, str):
            return json_response({"error": "type must be csv, txt or json, with string content"}, status=400)
        content_type, ext = self.TEXT_TYPES[kind]
        name = safe_name(str(body.get("name") or "anta"), "anta")
        if not name.lower().endswith(ext):
            name = os.path.splitext(name)[0] + ext
        fd, path = tempfile.mkstemp(prefix="anta_save_", suffix=ext, dir=runtime_dir())
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
        return json_response(self._offer(path, name, content_type))

    async def hunt(self, request: web.Request) -> web.Response:
        """Indicator sweep: where each pasted indicator turns up in the capture."""
        body = await self._body(request)
        text = body.get("text")
        if not isinstance(text, str) or len(text) > 512 * 1024:
            return json_response({"error": "paste up to 512 KB of indicators"}, status=400)
        try:
            sessions = await self.packets.index()
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        result = await asyncio.get_running_loop().run_in_executor(
            None, hunt.sweep, text, sessions, list(self.analyzer.alerts.values()))
        return json_response(result)

    async def set_triage(self, request: web.Request) -> web.Response:
        body = await self._body(request)
        status, note = body.get("status", "new"), body.get("note", "")
        if status not in TRIAGE_STATUSES or not isinstance(note, str):
            return json_response({"error": f"status must be one of {', '.join(TRIAGE_STATUSES)}"}, status=400)
        alert = self.analyzer.set_triage(request.match_info["id"], status, note)
        if alert is None:
            return json_response({"error": "unknown alert"}, status=404)
        self.pending[alert["id"]] = alert  # every open page updates its table
        return json_response(alert_summary(alert))

    async def explain(self, request: web.Request) -> web.Response:
        """Plain-English diagnosis of a conversation (a stream), an alert's flows, or
        whatever a display filter selects: what happened, why, and what to check."""
        q = request.query
        try:
            if q.get("stream"):
                m = re.fullmatch(r"(tcp|udp):(\d{1,12})", q["stream"])
                if not m:
                    return json_response({"error": "stream must look like tcp:5"}, status=400)
                proto, num = m.group(1), int(m.group(2))
                records = await self.packets.frames_with_fields(f"{proto}.stream eq {num}", diagnose.FIELDS,
                                                                diagnose.MAX_FRAMES)
                first = next((r for r in records if r.get("type") == "packet"), None)
                if first is None:
                    return json_response({"error": f"{proto.upper()} stream {num} not found"}, status=404)
                if proto == "tcp":  # the ICMP errors about it quote only its addresses and ports
                    f = first.get("f") or {}
                    a = (f.get("ip.src") or f.get("ipv6.src") or [None])[0]
                    b = (f.get("ip.dst") or f.get("ipv6.dst") or [None])[0]
                    pa, pb = (f.get("tcp.srcport") or [None])[0], (f.get("tcp.dstport") or [None])[0]
                    if a and b and pa and pb:
                        flt = hunt.flow_filter([f"6,{a},{pa},{b},{pb}"])
                        icmp = "icmpv6" if ":" in a else "icmp"
                        extra = await self.packets.frames_with_fields(f"{icmp} && ({flt})", diagnose.FIELDS, 200)
                        have = {r.get("n") for r in records}
                        records += [r for r in extra if r.get("type") == "packet" and r.get("n") not in have]
            elif q.get("alert"):
                info = self.analyzer.export_index.get(q["alert"])
                if not info or not info["flows"]:
                    return json_response({"error": "this alert has no flows to explain"}, status=404)
                records = await self.packets.frames_with_fields(hunt.flow_filter(info["flows"][:20]),
                                                                diagnose.FIELDS, diagnose.MAX_FRAMES)
            elif q.get("dfilter") or q.get("scope"):
                flt = self._within(self._scope(q.get("scope")), q.get("dfilter", ""))
                records = await self.packets.frames_with_fields(flt, diagnose.FIELDS, diagnose.MAX_FRAMES)
            else:
                return json_response({"error": "say what to explain: stream, alert, scope or dfilter"}, status=400)
            records.sort(key=lambda r: r.get("n", 0))
            result = await asyncio.get_running_loop().run_in_executor(None, diagnose.explain, records)
            # What the payload most likely is, for the first few conversations.
            for conv in result["conversations"][:3]:
                if conv["stream"] is None or conv["proto"] not in ("TCP", "UDP"):
                    continue
                try:
                    follow = await self.packets.follow(conv["proto"].lower(), conv["stream"])
                    conv["payload"] = diagnose.payload_summary(follow)
                except PacketError:
                    conv["payload"] = []
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        return json_response(result)

    async def explain_ai(self, request: web.Request) -> web.Response:
        """Explain with AI: {scope | stream | alert | dfilter, preview} -> with preview, exactly
        the text that would be sent (evidence about the packets, secrets and internal
        addresses removed); without, the AI model's explanation of it."""
        body = await self._body(request)
        provider = self.agent_settings.values["provider"]
        ready = provider in PROVIDERS and self.reviewer.ready()
        try:
            scope = self._scope(body.get("scope"))
            if isinstance(body.get("stream"), str) and re.fullmatch(r"(tcp|udp):\d{1,12}", body["stream"]):
                proto, num = body["stream"].split(":")
                flt, label = f"{proto}.stream eq {num}", f"{proto.upper()} stream {num}"
            elif body.get("alert"):
                flt, label = self._alert_flow_filter(str(body["alert"])), f"the connections of alert {body['alert']}"
            elif scope or isinstance(body.get("dfilter"), str):
                flt = self._within(scope, body.get("dfilter") if isinstance(body.get("dfilter"), str) else "")
                label = scope["label"] if scope else f"packets matching {body['dfilter']}"
            else:
                return json_response({"error": "say what to explain: a selection, stream, alert or filter"}, status=400)
            if not flt:
                return json_response({"error": "say what to explain"}, status=400)
            page = await self.packets.page(1, 1000, count=True, dfilter=flt)
            if not page.get("packets"):
                return json_response({"error": "No packets match."}, status=404)
            stats = (await self.packets.stats(flt, "", 0, []))["stats"]
            records = await self.packets.frames_with_fields(flt, diagnose.FIELDS, diagnose.MAX_FRAMES)
            records.sort(key=lambda r: r.get("n", 0))
            diagnosis = await asyncio.get_running_loop().run_in_executor(None, diagnose.explain, records)
        except (PacketError, scopes.ScopeError) as exc:
            return json_response({"error": str(exc)}, status=getattr(exc, "status", 400))
        conn = scopes.connections(stats)
        alerts = [a for a in self.analyzer.alerts.values()
                  if scopes.alert_in(a, (self.analyzer.export_index.get(a["id"]) or {}).get("flows") or [], conn)]
        text = explain_ai.evidence(label, page["packets"], page.get("matched_total"), page.get("first_ts"), stats,
                                   diagnosis, alerts)
        from .agent import Pseudonyms
        names = Pseudonyms(not self.agent_settings.values["share_internal"])
        text = names.scrub_text(text)
        model = self.reviewer.backend().name if ready else None
        if body.get("preview"):
            return json_response({"preview": text, "chars": len(text), "model": model, "ready": ready,
                                  "share_internal": bool(self.agent_settings.values["share_internal"]),
                                  "packets": page.get("matched_total")})
        if not ready:
            return json_response({"error": "Set up an AI model under Detection… (and agree to send it data) to "
                                           "explain with AI."}, status=409)
        now = time.time()
        self.ask_times = [t for t in self.ask_times if now - t < 3600]
        if len(self.ask_times) >= 60:
            return json_response({"error": "That's 60 requests to the model this hour; try again later."}, status=429)
        self.ask_times.append(now)
        from .agent_providers import ask_model_json
        try:
            data = await ask_model_json(self.agent_settings, explain_ai.SYSTEM, text, explain_ai.SCHEMA,
                                        effort="medium", max_tokens=16000)
            answer = explain_ai.clean(data, names)
        except AgentError as exc:
            return json_response({"error": str(exc)}, status=502)
        except ValueError as exc:
            return json_response({"error": f"the model's answer wasn't an explanation: {exc}"}, status=502)
        return json_response({**answer, "model": model, "sent_chars": len(text), "label": label})

    # ----------------------------------------------------- inventory and analytics

    async def _asset_rows(self, scope: dict | None) -> list[dict]:
        result = await self.packets.stats(scope["filter"] if scope else "", "", 0, [])
        graph = result["map"]
        devices = [entry["device"] for entry in self.analyzer.devices.values()]
        if devices:
            graph = netmap.annotate_devices(graph, devices)
        try:  # the whole capture's sessions; the analyzer's view while the index can't be read
            host_apps = assets.apps_by_host(await self.packets.index())
        except PacketError:
            host_apps = dict(self.analyzer.host_apps)
        return await asyncio.get_running_loop().run_in_executor(
            None, assets.build, result["stats"], graph, host_apps, self.geo, list(self.analyzer.alerts.values()))

    async def list_assets(self, request: web.Request) -> web.Response:
        """Passive asset inventory: every device, its likely OS and type, IoT, services, location."""
        scope = self._scope(request.query.get("scope"))
        try:  # (within a selection: the devices in it, as its packets show them)
            rows = await self._asset_rows(scope)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        return json_response({"assets": rows})

    async def list_eta(self, request: web.Request) -> web.Response:
        rows = list(self.analyzer.eta.values())
        scope = self._scope(request.query.get("scope"))
        if scope:
            try:
                conn = await self._connections(scope)
            except PacketError as exc:
                return json_response({"error": str(exc)}, status=exc.status)
            rows = [r for r in rows if scopes.session_in({"proto": r["proto"], "src_ip": r["src"], "src_port": r["sport"],
                                                          "dst_ip": r["dst"], "dst_port": r["dport"]}, conn)]
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["label"]] = counts.get(r["label"], 0) + 1
        return json_response({"sessions": rows[-5000:], "total": len(rows), "classes": counts})

    async def _sessions_in(self, request: web.Request) -> list[dict]:
        """The capture's sessions, or those of the selection the request names."""
        sessions = await self.packets.index()
        scope = self._scope(request.query.get("scope"))
        if scope:
            conn = await self._connections(scope)
            sessions = [s for s in sessions if scopes.session_in(s, conn)]
        return sessions

    async def _apps(self, sessions: list[dict]) -> dict:
        """apps.classify, kept for the session list it was made from (the capture's whole index)."""
        key = (id(sessions), len(sessions))
        cached = getattr(self, "_apps_cache", None)
        if cached and cached[0] == key:
            return cached[1]
        result = await asyncio.get_running_loop().run_in_executor(None, apps.classify, sessions, self._names())
        self._apps_cache = (key, result)
        return result

    async def app_usage(self, request: web.Request) -> web.Response:
        """The connections grouped into applications (Zoom, Slack, Windows Update…): what each
        moved, which devices used it, when."""
        try:
            sessions = await self._sessions_in(request)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        return json_response(await self._apps(sessions))

    def _recording(self) -> bool:
        return bool(self.packets.files.live and self.sessions
                    and self.sessions.state.get("state") in ("preparing", "starting", "authorizing", "running"))

    async def _seal_report(self, fresh: bool = False) -> dict:
        """The tamper seal (seal.py) for the open capture, kept until the file or its seal changes."""
        files = self.packets.files.inputs()
        if not files:
            raise PacketError("the tamper seal needs a capture file (or a recorded live capture)", 409)
        key = seal.seal_key([p for p, _ in files])
        sealed = seal.load_seals().get(key)
        state = (self.packets._file_state(), json.dumps(sealed, sort_keys=True), self._recording())
        cached = getattr(self, "_seal_cache", None)
        if cached and cached[0] == state and not fresh:
            return cached[1]
        bad = await self.packets.packet_times("ip.checksum_bad || tcp.checksum_bad || udp.checksum_bad", 5000, frames=True)
        missing = [(float(r["ts"]), str(r.get("src") or ""), str(r.get("dst") or ""), int(r.get("len") or 0), int(r.get("n") or 0),
                    ((r.get("f") or {}).get("tcp.stream") or [""])[0])
                   for r in await self.packets.frames_with_fields("tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment",
                                                                  "tcp.stream", 5000) if r.get("type") == "packet"]
        counts = {"bad_checksums": len(bad), "missing": len(missing), "bad_frames": [r[4] for r in bad[:20]]}
        # How many packets each sender of a wrong checksum sent in all: offloading spoils nearly every one.
        senders = []
        for ip, _ in Counter(r[1] for r in bad).most_common(10):
            with contextlib.suppress(ValueError):
                senders.append(str(ipaddress.ip_address(ip)))
        sent: dict[str, int] = {}
        if senders:
            st = await self.packets.stats("", "", 0, [], [f"{'ipv6' if ':' in ip else 'ip'}.src == {ip}" for ip in senders])
            for ip, c in zip(senders, st["stats"].get("counts") or [], strict=False):
                sent[ip] = int(c.get("count") or 0)
        result = await asyncio.get_running_loop().run_in_executor(None, seal.report, files, bad, missing, counts, sealed,
                                                                  self._recording(), sent)
        result["names"] = [os.path.basename(p) for p, _ in files]
        result["recording"] = self._recording()
        self._seal_cache = (state, result)
        return result

    async def seal_get(self, request: web.Request) -> web.Response:
        """Was the open capture edited, spliced or cut, and has it changed since it was sealed?"""
        try:
            return json_response(await self._seal_report())
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)

    async def seal_post(self, request: web.Request) -> web.Response:
        """Record the open capture's seal (its SHA-256) so later changes show."""
        try:
            files = self.packets.files.inputs()
            if not files:
                raise PacketError("there is no capture file to seal", 409)
            if self._recording():
                raise PacketError("stop the capture first: a file still being recorded changes with every packet", 409)
            names = [p for p, _ in files]
            fp = await asyncio.get_running_loop().run_in_executor(None, seal.fingerprint, names)
            await asyncio.get_running_loop().run_in_executor(None, seal.save_seal, seal.seal_key(names), {
                "sha256": fp["sha256"], "size": fp["size"], "sealed": time.time(), "names": [os.path.basename(n) for n in names]})
            return json_response(await self._seal_report(fresh=True))
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)

    async def moves_get(self, request: web.Request) -> web.Response:
        """Devices that changed address (moves.py): one device followed across its IP addresses and
        MACs, from what it says about itself (MAC, host name, DHCP request), and addresses that
        changed hands."""
        try:
            scope = self._scope(request.query.get("scope"))
            within = self._within(scope, "")
            st = await self.packets.stats(within, "", 0, [])
            dhcp = await self.packets.frames_with_fields(
                self._within(scope, "dhcp"), "dhcp.option.dhcp,dhcp.hw.mac_addr,dhcp.option.hostname,dhcp.option.vendor_class_id,"
                "dhcp.option.request_list_item,dhcp.ip.your,dhcp.ip.client", 20000)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        rows = [r for r in dhcp if r.get("type") == "packet"]
        result = await asyncio.get_running_loop().run_in_executor(None, moves.link, st["stats"], rows)
        props = st["stats"].get("properties") or {}
        result["start"], result["end"] = (props.get("first"), props.get("last")) if props.get("frames") else (None, None)
        result["names"] = [os.path.basename(p) for p, _ in self.packets.files.inputs()]
        result["scoped"] = bool(scope)
        return json_response(result)

    async def before_get(self, request: web.Request) -> web.Response:
        """Before the capture (before.py): what the recorded traffic shows happened before recording
        began (connections already open, addresses already known, the resolver's cache, DHCP leases
        held, TLS sessions resumed)."""
        try:
            sessions = await self.packets.index()
            dns_rows = await self.packets.frames_with_fields(
                "dns.flags.response == 1 && dns.resp.ttl", "dns.qry.name,dns.resp.type,dns.resp.ttl,dns.a,dns.aaaa", 20000)
            dhcp_rows = await self.packets.frames_with_fields(
                "dhcp", "dhcp.option.dhcp,dhcp.hw.mac_addr,dhcp.ip.client,dhcp.option.requested_ip_address,"
                "dhcp.option.dhcp_lease_time,dhcp.option.renewal_time_value", 5000)
            resumed = await self.packets.frames_with_fields("tls.handshake.type == 1 && tls.handshake.extension.type == 41",
                                                            "tls.handshake.extensions_server_name", 5000)
            st = await self.packets.stats()
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        props = st["stats"].get("properties") or {}
        pick = [r for r in dns_rows if r.get("type") == "packet"], [r for r in dhcp_rows if r.get("type") == "packet"], \
            [r for r in resumed if r.get("type") == "packet"]
        result = await asyncio.get_running_loop().run_in_executor(None, before.reconstruct, sessions, *pick,
                                                                  props.get("first") if props.get("frames") else None)
        result["names"] = [os.path.basename(p) for p, _ in self.packets.files.inputs()]
        return json_response(result)

    async def quiet_get(self, request: web.Request) -> web.Response:
        """The certificate of quiet (quiet.py): per device, what it sent to the internet openly,
        the most it could have hidden in headers and timing, and when it sent nothing at all."""
        try:
            sessions = await self._sessions_in(request)
            scope = self._scope(request.query.get("scope"))
            within = self._within(scope, "")
            icmp = await self.packets.packet_times(f"({within}) && (icmp || icmpv6)" if within else "icmp || icmpv6", 50000)
            other = "(ip || ipv6) && !tcp && !udp && !icmp && !icmpv6"
            other_rows = await self.packets.packet_times(f"({within}) && ({other})" if within else other, 50000)
            st = await self.packets.stats(within, "", 0, [], ["tcp.urgent_pointer != 0 && tcp.flags.urg == 0",
                                                              "tcp.flags.res != 0 || ip.flags.rb == 1"])
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        counts = st["stats"].get("counts") or [{}, {}]
        props = st["stats"].get("properties") or {}
        used = {"urgent": counts[0].get("count", 0), "reserved": counts[1].get("count", 0)}
        span = (props.get("first"), props.get("last")) if props.get("frames") else None
        result = await asyncio.get_running_loop().run_in_executor(None, quiet.certify, sessions, icmp, other_rows, used, span)
        result["names"] = [os.path.basename(p) for p, _ in self.packets.files.inputs()]
        result["recording"] = self._recording()
        result["scoped"] = bool(scope)
        return json_response(result)

    async def software_list(self, request: web.Request) -> web.Response:
        """Installed software read from the outside (software.py): each device's programs and
        versions as its own traffic reports them, judged against the end-of-support table."""
        try:
            sessions = await self._sessions_in(request)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        return json_response(await self._software(sessions))

    async def _software(self, sessions: list[dict]) -> dict:
        """software.inventory, kept for the session list it was made from."""
        key = (id(sessions), len(sessions))
        cached = getattr(self, "_software_cache", None)
        if cached and cached[0] == key:
            return cached[1]
        result = await asyncio.get_running_loop().run_in_executor(None, software.inventory, sessions)
        self._software_cache = (key, result)
        return result

    async def physics_check(self, request: web.Request) -> web.Response:
        """The speed-of-light check (physics.py): how far each internet server can be from the
        capture point, from its fastest handshake, and whether the country its network is
        registered in is possible. ?tz= is the browser's time zone (the default capture point)."""
        try:
            sessions = await self._sessions_in(request)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        setting = physics.load_point()
        point = physics.resolve_point(setting, request.query.get("tz", "")[:64])
        names: dict[str, str] = {}
        for sess in sessions:
            for d in sess.get("dns") or []:
                for a in d.get("answers") or []:
                    if isinstance(a, str) and d.get("qname"):
                        names.setdefault(a, str(d["qname"])[:120])
        result = await asyncio.get_running_loop().run_in_executor(None, physics.check, sessions, self.geo, point, names)
        result["setting"] = setting
        if request.query.get("places"):
            result["places"] = physics.places()
        return json_response(result)

    async def physics_point_put(self, request: web.Request) -> web.Response:
        """Where the capture was made: a place, coordinates, the time zone's place, or off."""
        body = await self._body(request)
        try:
            return json_response({"setting": physics.save_point(body.get("point"))})
        except physics.PhysicsError as exc:
            return json_response({"error": str(exc)}, status=400)

    async def physics_world(self, request: web.Request) -> web.Response:
        """Country outlines for the speed-of-light map (from the bundled borders)."""
        if getattr(self, "_world", None) is None:
            self._world = await asyncio.get_running_loop().run_in_executor(None, physics.outlines)
        return json_response({"countries": self._world})

    async def cleartext_logins(self, request: web.Request) -> web.Response:
        """Logins sent in clear text (account, service, accepted or not), never a password."""
        try:
            sessions = await self._sessions_in(request)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        return json_response(await asyncio.get_running_loop().run_in_executor(None, logins.report, sessions))

    async def fingerprints(self, request: web.Request) -> web.Response:
        """Every TLS client and server fingerprint in the capture, with who used it and any feed listing."""
        try:
            sessions = await self._sessions_in(request)
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)

        def build():
            clients: dict[tuple, dict] = {}
            servers: dict[tuple, dict] = {}
            for rec in sessions:
                t = rec.get("tls") or {}
                if t.get("ja3") or t.get("ja4"):
                    # By JA4 (stable); JA3 changes with every Chrome connection's shuffled extension order.
                    key = ("ja4", t["ja4"]) if t.get("ja4") else ("ja3", t.get("ja3", ""))
                    c = clients.setdefault(key, {"ja4": t.get("ja4", ""), "ja3s": {}, "sessions": 0, "clients": set(),
                                                 "sni": set()})
                    if t.get("ja3"):
                        c["ja3s"][t["ja3"]] = c["ja3s"].get(t["ja3"], 0) + 1
                    c["sessions"] += 1
                    c["clients"].add(rec["src_ip"])
                    if t.get("sni") and len(c["sni"]) < 50:
                        c["sni"].add(t["sni"])
                if t.get("ja3s") or t.get("ja4s"):
                    v = servers.setdefault((t.get("ja4s", ""), t.get("ja3s", "")), {
                        "ja4s": t.get("ja4s", ""), "ja3s": t.get("ja3s", ""), "sessions": 0, "servers": set(), "sni": set()})
                    v["sessions"] += 1
                    v["servers"].add(f"{rec['dst_ip']}:{rec['dst_port']}")
                    if t.get("sni") and len(v["sni"]) < 50:
                        v["sni"].add(t["sni"])
            idx = self.intel.index
            out_c = []
            for c in clients.values():
                hits = list(idx["ja4"].get(c["ja4"]) or [])
                for ja3 in c["ja3s"]:
                    hits += idx["ja3"].get(ja3) or []
                ja3s = sorted(c.pop("ja3s").items(), key=lambda kv: -kv[1])
                out_c.append({**c, "ja3": ja3s[0][0] if ja3s else "", "ja3_variants": [j for j, _ in ja3s[:20]],
                              "ja3_count": len(ja3s), "clients": sorted(c["clients"])[:50], "client_count": len(c["clients"]),
                              "sni": sorted(c["sni"]), "listed": sorted({f"{h['reason']} ({h['feed']})" for h in hits})})
            out_s = [{**v, "servers": sorted(v["servers"])[:50], "server_count": len(v["servers"]), "sni": sorted(v["sni"])}
                     for v in servers.values()]
            out_c.sort(key=lambda c: (not c["listed"], c["client_count"], -c["sessions"]))
            out_s.sort(key=lambda v: -v["sessions"])
            return {"clients": out_c, "servers": out_s}
        return json_response(await asyncio.get_running_loop().run_in_executor(None, build))

    # ----------------------------------------------------- threat intelligence

    async def intel_feeds(self, request: web.Request) -> web.Response:
        return json_response({"feeds": self.intel.feeds(), "indicators": self.intel.size(), "geo": self.geo.info()})

    async def intel_update(self, request: web.Request) -> web.Response:
        """Download the chosen built-in feeds (only ever on the user's request)."""
        body = await self._body(request)
        ids = list(INTEL_SOURCES) if body.get("id") == "all" else [body.get("id")]
        results = {}
        for fid in ids:
            if fid == "geoip":
                results[fid] = await self._update_geo()
                continue
            if fid not in INTEL_SOURCES:
                return json_response({"error": "unknown feed"}, status=400)
            try:
                meta = await asyncio.get_running_loop().run_in_executor(None, self.intel.update, fid)
                results[fid] = {"ok": True, "entries": meta["entries"]}
            except Exception as exc:  # network errors, bad files: reported per feed
                results[fid] = {"ok": False, "error": str(exc)[:200]}
        return json_response({"results": results, "feeds": self.intel.feeds(), "indicators": self.intel.size()})

    async def _update_geo(self) -> dict:
        def fetch():
            import urllib.request
            target = geoip.user_path()
            os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
            # Only geoip.SOURCE_URL, a fixed https:// address, is fetched.
            req = urllib.request.Request(geoip.SOURCE_URL, headers={"User-Agent": "ANTA GeoIP updater"})  # noqa: S310
            with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
                data = resp.read(geoip.MAX_DOWNLOAD + 1)
            if len(data) > geoip.MAX_DOWNLOAD or data[:2] != b"\x1f\x8b":
                raise ValueError("unexpected file")
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(target), suffix=".gz")
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, target)
        try:
            await asyncio.get_running_loop().run_in_executor(None, fetch)
            self.geo.reload()
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)[:200]}

    async def intel_import(self, request: web.Request) -> web.Response:
        body = await self._body(request)
        name, content = body.get("name"), body.get("content")
        if not isinstance(name, str) or not isinstance(content, str):
            return json_response({"error": "name and content are needed"}, status=400)
        try:
            meta = self.intel.import_text(name, content)
        except ValueError as exc:
            return json_response({"error": str(exc)}, status=400)
        return json_response({"imported": meta, "feeds": self.intel.feeds(), "indicators": self.intel.size()})

    # ----------------------------------------------------- TLS decryption keys

    _KEYLOG_LABELS = ("CLIENT_RANDOM", "PMS_CLIENT_RANDOM", "RSA", "CLIENT_EARLY_TRAFFIC_SECRET",
                      "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                      "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0",
                      "EXPORTER_SECRET", "EARLY_EXPORTER_SECRET")

    @classmethod
    def _keylog_count(cls, text: str) -> int:
        n = 0
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[0] in cls._KEYLOG_LABELS:
                n += 1
        return n

    def _keylog_status(self) -> dict:
        path = self.packets.keylog
        secrets = 0
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    secrets = self._keylog_count(fh.read(16 * 1024 * 1024))
            except OSError:
                secrets = 0
        return {"loaded": bool(path), "secrets": secrets, "scan": self._keylog_scan}

    async def get_keylog(self, request: web.Request) -> web.Response:
        return json_response(self._keylog_status())

    async def set_keylog(self, request: web.Request) -> web.Response:
        """Load a TLS key log (SSLKEYLOGFILE format) so the user's own TLS is decrypted: in
        the packet view, and for the checks that read HTTP (downloads, threat-feed URLs)
        and the Files list. It is kept owner-only in the private runtime folder, never
        logged, and used only to decrypt — exactly what Wireshark's tls.keylog_file does."""
        body = await self._body(request)
        content = body.get("content")
        if not isinstance(content, str):
            return json_response({"error": "the key log content is needed"}, status=400)
        if len(content) > 16 * 1024 * 1024:
            return json_response({"error": "that key log is larger than 16 MB"}, status=400)
        count = self._keylog_count(content)
        if not count:
            return json_response({"error": "no TLS secrets found: this does not look like an SSLKEYLOGFILE "
                                           "(lines like CLIENT_RANDOM … or CLIENT_TRAFFIC_SECRET_0 …)"}, status=400)
        # Named for this process, so a later start can tell a key log left by one that died.
        fd, path = tempfile.mkstemp(prefix=f"anta_keylog_{os.getpid()}_", suffix=".keys", dir=runtime_dir())
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
            if os.name != "nt":
                os.chmod(path, 0o600)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(path)
            return json_response({"error": "could not store the key log"}, status=500)
        self._clear_keylog_file()
        self.packets.keylog = path
        if self.packets.files.inputs():  # a capture is open: check the HTTPS sessions the keys open up
            self._keylog_scan = {"state": "running"}
            self._keylog_task = asyncio.get_running_loop().create_task(self._scan_decrypted())
        return json_response({**self._keylog_status(), "added": count})

    async def _scan_decrypted(self) -> None:
        """Index the capture with the key log and run the checks that need to see inside
        HTTPS (downloaded programs, threat-feed URLs and hashes) on the sessions it decrypts."""
        try:
            sessions = await self.packets.index()
            decrypted = [s for s in sessions if (s.get("tls") or {}).get("decrypted")]
            alerts = await asyncio.get_running_loop().run_in_executor(None, self.analyzer.check_decrypted, decrypted)
            for a in alerts:
                self.pending[a["id"]] = a
            files = sum(len(s.get("http_files") or []) for s in decrypted)
            self._keylog_scan = {"state": "done", "sessions": len(decrypted), "files": files, "alerts": len(alerts)}
        except PacketError as exc:
            self._keylog_scan = {"state": "error", "message": str(exc)}

    # --------------------------------------------------------- the desktop app's windows

    async def native_popout(self, request: web.Request) -> web.Response:
        """Open a view in a window of its own: {query: "popout=stats&tool=io", title}."""
        if self.native is None:
            return json_response({"error": "pop-out windows are opened by the browser here"}, status=404)
        body = await self._body(request)
        query, title = str(body.get("query") or "")[:512], str(body.get("title") or "ANTA")[:120]
        if not popout_query(dict(parse_qsl(query))):
            return json_response({"error": "unknown view"}, status=400)
        ok = await asyncio.get_running_loop().run_in_executor(None, self.native.pop_out, query, title)
        return json_response({"ok": bool(ok)})

    async def native_choose_capture(self, request: web.Request) -> web.Response:
        """The system's Open dialog for a capture file (the path is then opened as usual)."""
        if self.native is None:
            return json_response({"error": "not running in the desktop app"}, status=404)
        path = await asyncio.get_running_loop().run_in_executor(None, self.native.choose_capture)
        return json_response({"path": path or None})

    # --------------------------------------------------- detection models and the agent

    def _sdk_available(self) -> bool:
        import importlib.util
        return importlib.util.find_spec("anthropic") is not None

    async def get_models(self, request: web.Request) -> web.Response:
        return json_response({"models": self.models.list(), "active": self.models.active(),
                              "model_error": self.model_error, "agent": self.agent_settings.public(),
                              "features": FEATURE_NAMES, "calibration": self.models.calibration_sizes(),
                              "agent_status": self.reviewer.status(),
                              "agent_ready": self.reviewer.ready(),
                              "sdk_installed": self._sdk_available()})

    async def set_active_model(self, request: web.Request) -> web.Response:
        body = await self._body(request)
        try:
            self.models.set_active(str(body.get("id") or ""))
        except ModelError as exc:
            return json_response({"error": str(exc)}, status=400)
        self._apply_detector()
        return await self.get_models(request)

    async def upload_model(self, request: web.Request) -> web.Response:
        """Add an ONNX model: {name, filename, direction, fp_rate, content (base64)}. It is checked
        and calibrated before it can be chosen. (Read with its own cap: models outgrow the API's.)"""
        import base64
        chunks, size = [], 0
        async for chunk in request.content.iter_chunked(1 << 20):  # (one read() returns what has arrived so far)
            size += len(chunk)
            if size > 96 << 20:
                return json_response({"error": "that model is too large"}, status=413)
            chunks.append(chunk)
        raw = b"".join(chunks)
        try:
            body = json.loads(raw)
            data = base64.b64decode(str(body.get("content") or ""), validate=True)
            fp_rate = float(body.get("fp_rate", 0.005))
        except (ValueError, TypeError):
            return json_response({"error": "expected JSON with the model as base64"}, status=400)
        try:
            entry = await asyncio.get_running_loop().run_in_executor(
                None, lambda: self.models.add_onnx(str(body.get("name") or ""), data, str(body.get("direction") or "auto"),
                                                   fp_rate, str(body.get("filename") or "")))
        except ModelError as exc:
            return json_response({"error": str(exc)}, status=400)
        return json_response({"added": entry, **json.loads((await self.get_models(request)).text)})

    async def remove_model(self, request: web.Request) -> web.Response:
        body = await self._body(request)
        try:
            self.models.remove(str(body.get("id") or ""))
        except ModelError as exc:
            return json_response({"error": str(exc)}, status=400)
        self._apply_detector()
        return await self.get_models(request)

    async def set_agent_settings(self, request: web.Request) -> web.Response:
        """The agent's settings. API keys are write-only: send a string to save one, null to
        forget it; they are never sent back. The agent program can only be set in the config file."""
        body = await self._body(request)
        # A key is for `key_provider` (saving it doesn't switch providers), else `provider`, else the current one.
        key_for = next((body[k] for k in ("key_provider", "provider") if body.get(k) in PROVIDERS), None)
        if "api_key" in body:
            try:
                self.agent_settings.set_api_key(body["api_key"] if isinstance(body["api_key"], str) else None,
                                                key_for)
            except ValueError as exc:
                return json_response({"error": str(exc)}, status=400)
            self.reviewer.forget_backend()
        changes = {k: body[k] for k in ("provider", "model", "effort", "reviews_per_hour", "share_internal", "consent",
                                        "base_url") if k in body}
        try:
            self.agent_settings.update(changes)
        except ValueError as exc:
            return json_response({"error": str(exc)}, status=400)
        return await self.get_models(request)

    async def list_agent_models(self, request: web.Request) -> web.Response:
        """The models an AI provider offers to the saved key (or, for an OpenAI-compatible
        server, at the saved address): {provider} -> {models: [{id, name}]}."""
        body = await self._body(request)
        provider = body.get("provider") if body.get("provider") in PROVIDERS else self.agent_settings.values["provider"]
        if provider not in PROVIDERS:
            return json_response({"error": "choose an AI provider first"}, status=400)
        from .agent_providers import list_models
        try:
            models = await list_models(self.agent_settings, provider)
        except AgentError as exc:
            return json_response({"error": str(exc)}, status=502)
        return json_response({"provider": provider, "models": models[:500]})

    SAMPLE_SESSION = {  # what "Test the agent" sends: a made-up session to a documentation address
        "type": "session", "final": True, "flow_id": 0, "proto": "tcp", "src_ip": "10.0.0.50", "src_port": 51515,
        "dst_ip": "203.0.113.77", "dst_port": 8443, "start": 1_790_000_000.0, "end": 1_790_000_030.0,
        "c2s": {"packets": 12, "bytes": 2400, "payload_bytes": 1800}, "s2c": {"packets": 10, "bytes": 1600,
        "payload_bytes": 900}, "app": "tls", "tls": {"sni": "updates.example-cdn.test", "ja3": "", "ja4": ""}}

    async def test_agent(self, request: web.Request) -> web.Response:
        """One review of a made-up session, to check the agent works (a paid request with most providers)."""
        if not self.reviewer.ready():
            return json_response({"error": "set the agent up first: choose a model and agree to send it session details"},
                                 status=409)
        try:
            verdict = await self.reviewer.review(dict(self.SAMPLE_SESSION))
        except AgentError as exc:
            return json_response({"error": str(exc)}, status=502)
        return json_response({"verdict": verdict})

    async def review_alert(self, request: web.Request) -> web.Response:
        """Ask the agent about an alert's session; its verdict is attached to the alert."""
        alert = self.analyzer.alerts.get(request.match_info["id"])
        if alert is None:
            return json_response({"error": "no such alert"}, status=404)
        if not self.reviewer.ready():
            return json_response({"error": "set up the detection agent first (Detection… in the toolbar)"}, status=409)
        s = alert.get("stream") or {}
        mt = alert.get("metrics") or {}
        start = float(alert.get("first_seen") or 0)
        rec = {"type": "session", "final": True, "flow_id": 0, "proto": s.get("proto") or "tcp",
               "src_ip": alert.get("src_ip") or "", "src_port": 0, "dst_ip": alert.get("dst_ip") or "",
               "dst_port": int(alert.get("dst_port") or 0), "start": start,
               "end": start + float(s.get("duration") or mt.get("duration") or 0),
               "c2s": {"packets": int(s.get("packets") or 0), "bytes": 0, "payload_bytes": int(s.get("bytes_out") or 0)},
               "s2c": {"packets": 0, "bytes": 0, "payload_bytes": int(s.get("bytes_in") or 0)},
               "tls": {"sni": mt.get("sni") or "", "ja3": s.get("ja3") or ""} if (mt.get("sni") or s.get("ja3")) else None}
        rec = {k: v for k, v in rec.items() if v is not None}
        try:
            verdict = await self.reviewer.review(rec)
        except AgentError as exc:
            return json_response({"error": str(exc)}, status=502)
        alert["agent_review"] = verdict
        self.pending[alert["id"]] = alert
        return json_response({"verdict": verdict})

    def _clear_keylog_file(self) -> None:
        old = self.packets.keylog
        self.packets.keylog = None
        if self._keylog_task and not self._keylog_task.done():
            self._keylog_task.cancel()
        self._keylog_task = None
        self._keylog_scan = None
        if old:
            with contextlib.suppress(OSError):
                os.unlink(old)

    async def clear_keylog(self, request: web.Request) -> web.Response:
        self._clear_keylog_file()
        return json_response(self._keylog_status())

    async def intel_change(self, request: web.Request) -> web.Response:
        body = await self._body(request)
        fid = body.get("id")
        if not isinstance(fid, str) or fid not in self.intel.meta:
            return json_response({"error": "unknown feed"}, status=404)
        if body.get("remove"):
            self.intel.remove(fid)
        elif "enabled" in body:
            self.intel.set_enabled(fid, bool(body["enabled"]))
        return json_response({"feeds": self.intel.feeds(), "indicators": self.intel.size()})

    async def intel_recheck(self, request: web.Request) -> web.Response:
        """Match every session of this capture against the feeds as they are now."""
        try:
            sessions = await self.packets.index()
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        alerts = await asyncio.get_running_loop().run_in_executor(None, self.analyzer.recheck_intel, sessions)
        for a in alerts:
            self.pending[a["id"]] = a
        return json_response({"sessions": len(sessions), "matches": len(alerts)})

    # ----------------------------------------------------- settings, logs, recordings

    async def get_settings(self, request: web.Request) -> web.Response:
        return json_response({"settings": self.settings, "defaults": settings.DEFAULTS, "limits": settings.LIMITS,
                              "flowlog_dir": self.flowlog.dir, "flowlogs": self.flowlog.files(),
                              "captures_dir": paths.captures_dir(), "geo": self.geo.info()})

    async def put_settings(self, request: web.Request) -> web.Response:
        body = await self._body(request)
        try:
            self.settings = settings.save({**self.settings, **(body.get("settings") or {})})
        except OSError:
            return json_response({"error": "could not save the settings"}, status=500)
        self.flowlog.configure(self.settings["flowlog_days"], self.settings["flowlog_max_mb"])
        return await self.get_settings(request)

    @staticmethod
    def _recordings() -> list[dict]:
        """Live recordings in the captures folder: each capture with its rolling-buffer segments."""
        folder = paths.captures_dir()
        groups: dict[str, dict] = {}
        for name in os.listdir(folder):
            m = re.fullmatch(r"(live-\d{8}-\d{6}\.pcap)(?:\.(\d{1,4}))?", name)
            if not m:
                continue
            full = os.path.join(folder, name)
            try:
                st = os.stat(full)
            except OSError:
                continue
            g = groups.setdefault(m.group(1), {"name": m.group(1), "segments": [], "size": 0, "modified": 0})
            g["segments"].append({"file": name, "size": st.st_size, "modified": st.st_mtime,
                                  "generation": int(m.group(2) or 0), "path": full})
            g["size"] += st.st_size
            g["modified"] = max(g["modified"], st.st_mtime)
        for g in groups.values():
            g["segments"].sort(key=lambda x: -x["generation"])  # oldest first
        return sorted(groups.values(), key=lambda g: -g["modified"])

    async def list_recordings(self, request: web.Request) -> web.Response:
        return json_response({"recordings": self._recordings(), "folder": paths.captures_dir()})

    async def delete_recording(self, request: web.Request) -> web.Response:
        body = await self._body(request)
        name = body.get("name")
        rec = next((g for g in self._recordings() if g["name"] == name), None)
        if rec is None:
            return json_response({"error": "no such recording"}, status=404)
        current = self.packets.files.path
        live = self.sessions and self.sessions.state.get("state") in ("running", "starting", "authorizing", "stopping")
        if current and (current in {seg["path"] for seg in rec["segments"]} or
                        (live and os.path.basename(current) == name)):
            return json_response({"error": "this recording is open in ANTA; open another capture first"}, status=409)
        removed = 0
        for seg in rec["segments"]:
            try:
                os.unlink(seg["path"])
                removed += 1
            except OSError:
                pass
        return json_response({"removed": removed, "recordings": self._recordings()})

    async def save_flows(self, request: web.Request) -> web.Response:
        """This capture's flow log (one JSON line per session) as a file."""
        try:
            sessions = await self.packets.index()
        except PacketError as exc:
            return json_response({"error": str(exc)}, status=exc.status)
        fd, path = tempfile.mkstemp(prefix="anta_save_", suffix=".jsonl", dir=runtime_dir())
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for rec in sessions:
                fh.write(json.dumps(flowlog.record(rec, self.geo), separators=(",", ":"), default=str) + "\n")
        offer = self._offer(path, f"{self.packets.source_stem()}_flows.jsonl", "application/x-ndjson")
        return json_response({**offer, "flows": len(sessions)})

    def _remove(self, path: str) -> None:
        self.temp_files.discard(path)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)

    def cleanup(self) -> None:
        for path in list(self.temp_files):
            self._remove(path)
        self._clear_keylog_file()  # the key log holds TLS secrets; don't leave it on disk

    def app(self) -> web.Application:
        app = web.Application(middlewares=[self.guard], client_max_size=16 * 1024 * 1024)
        app.router.add_get("/", self.index)
        app.router.add_get("/ws", self.websocket)
        app.router.add_get("/api/alerts", self.list_alerts)
        app.router.add_get("/api/alerts/{id}", self.get_alert)
        app.router.add_get("/api/summary", self.summary)
        app.router.add_get("/api/export/{id}", self.export)
        app.router.add_put("/api/alerts/{id}/triage", self.set_triage)
        app.router.add_post("/api/save/packets", self.save_packets)
        app.router.add_post("/api/save/object", self.save_object)
        app.router.add_post("/api/save/text", self.save_text)
        app.router.add_get("/api/host", self.host_info)
        app.router.add_get("/api/triage", self.triage_list)
        app.router.add_get("/api/policy", self.policy_get)
        app.router.add_get("/api/timeline", self.timeline_data)
        app.router.add_get("/api/timeline/packets", self.timeline_packets)
        app.router.add_get("/api/personalities", self.personalities)
        app.router.add_post("/api/personalities/remember", self.personalities_remember)
        app.router.add_delete("/api/personalities", self.personalities_forget)
        app.router.add_put("/api/policy", self.policy_put)
        app.router.add_get("/api/ignored", self.ignored_get)
        app.router.add_put("/api/ignored", self.ignored_put)
        app.router.add_post("/api/policy/check", self.policy_check)
        app.router.add_get("/api/case", self.case_get)
        app.router.add_put("/api/case/notes", self.case_notes)
        app.router.add_post("/api/case/pins", self.case_pin)
        app.router.add_delete("/api/case/pins/{id}", self.case_unpin)
        app.router.add_post("/api/case/save", self.case_save)
        app.router.add_post("/api/case/open", self.case_open)
        app.router.add_get("/api/download/{token}", self.download)
        app.router.add_get("/api/objects", self.list_objects)
        app.router.add_get("/api/lookup", self.lookup)
        app.router.add_post("/api/hunt", self.hunt)
        app.router.add_get("/api/explain", self.explain)
        app.router.add_get("/api/assets", self.list_assets)
        app.router.add_get("/api/eta", self.list_eta)
        app.router.add_get("/api/fingerprints", self.fingerprints)
        app.router.add_get("/api/logins", self.cleartext_logins)
        app.router.add_get("/api/apps", self.app_usage)
        app.router.add_get("/api/physics", self.physics_check)
        app.router.add_get("/api/software", self.software_list)
        app.router.add_get("/api/seal", self.seal_get)
        app.router.add_get("/api/quiet", self.quiet_get)
        app.router.add_get("/api/before", self.before_get)
        app.router.add_get("/api/moves", self.moves_get)
        app.router.add_post("/api/seal", self.seal_post)
        app.router.add_put("/api/physics/point", self.physics_point_put)
        app.router.add_get("/api/physics/world", self.physics_world)
        app.router.add_get("/api/intel", self.intel_feeds)
        app.router.add_post("/api/intel/update", self.intel_update)
        app.router.add_post("/api/intel/import", self.intel_import)
        app.router.add_get("/api/keylog", self.get_keylog)
        app.router.add_post("/api/keylog", self.set_keylog)
        app.router.add_post("/api/keylog/clear", self.clear_keylog)
        app.router.add_post("/api/native/popout", self.native_popout)
        app.router.add_post("/api/native/choose-capture", self.native_choose_capture)
        app.router.add_get("/api/models", self.get_models)
        app.router.add_post("/api/models/active", self.set_active_model)
        app.router.add_post("/api/models/upload", self.upload_model)
        app.router.add_post("/api/models/remove", self.remove_model)
        app.router.add_post("/api/agent/settings", self.set_agent_settings)
        app.router.add_post("/api/agent/test", self.test_agent)
        app.router.add_post("/api/agent/models", self.list_agent_models)
        app.router.add_post("/api/alerts/{id}/review", self.review_alert)
        app.router.add_post("/api/intel/change", self.intel_change)
        app.router.add_post("/api/intel/recheck", self.intel_recheck)
        app.router.add_get("/api/settings", self.get_settings)
        app.router.add_put("/api/settings", self.put_settings)
        app.router.add_get("/api/recordings", self.list_recordings)
        app.router.add_post("/api/recordings/delete", self.delete_recording)
        app.router.add_post("/api/save/flows", self.save_flows)
        app.router.add_get("/api/interfaces", self.interfaces)
        app.router.add_get("/api/packets", self.list_packets)
        app.router.add_get(r"/api/packets/{n:\d+}", self.packet_detail)
        app.router.add_get("/api/packets/find", self.find_packet)
        app.router.add_get("/api/names", self.host_names)
        app.router.add_get("/api/tcpgraph", self.tcp_graph)
        app.router.add_get("/api/storyline", self.storyline)
        app.router.add_get("/api/rhythm", self.rhythm_view)
        app.router.add_post("/api/scope", self.create_scope)
        app.router.add_get("/api/scope/{id}", self.get_scope)
        app.router.add_get("/api/scope/{id}/alerts", self.scope_alerts)
        app.router.add_post("/api/explain/ai", self.explain_ai)
        app.router.add_post("/api/ask", self.ask_question)
        app.router.add_post("/api/ask/model", self.ask_model)
        app.router.add_get("/api/filters/check", self.check_filters)
        app.router.add_get("/api/filters/fields", self.filter_fields)
        app.router.add_get("/api/stats", self.stats)
        app.router.add_get("/api/lint", self.lint_check)
        app.router.add_get("/api/follow", self.follow)
        app.router.add_get("/api/color-rules", self.get_color_rules)
        app.router.add_put("/api/color-rules", self.put_color_rules)
        app.router.add_get("/api/session", self.get_session)
        app.router.add_post("/api/session", self.start_session)
        app.router.add_delete("/api/session", self.stop_session)
        app.router.add_post("/api/quit", self.quit)
        app.router.add_static("/static/", WEB_DIR, follow_symlinks=False)
        return app


def allowed_hosts_for(bind_host: str, extra: list[str]) -> set[str]:
    hosts = {"localhost", "127.0.0.1", "::1", "[::1]"}
    if bind_host not in ("0.0.0.0", "::", ""):
        hosts.add(bind_host.strip("[]").lower())
    hosts.update(h.lower() for h in extra)
    return hosts


def _process_alive(pid: int) -> bool:
    if pid == os.getpid():
        return True
    if os.name == "nt":
        return False  # can't probe cheaply; a key log is only kept while its app runs
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def purge_stale_exports() -> None:
    """Remove temp files a previous run (e.g. one that crashed or was killed) left behind:
    export captures, and TLS key logs whose app is no longer running (they hold secrets)."""
    rdir = runtime_dir()
    for name in os.listdir(rdir):
        stale = name.startswith("anta_") and name.endswith(".pcap")
        if name.startswith("anta_keylog_") and name.endswith(".keys"):
            owner = name[len("anta_keylog_"):].split("_", 1)[0]
            stale = not (owner.isdigit() and _process_alive(int(owner)))
        if stale:
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(rdir, name))


async def start_dashboard(dash: Dashboard, host: str, port: int) -> tuple[web.AppRunner, int]:
    """Serve the dashboard; port 0 picks a free one. Returns the runner and the real port."""
    runner = web.AppRunner(dash.app(), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    sockets = site._server.sockets if site._server else []
    return runner, (sockets[0].getsockname()[1] if sockets else port)


async def run(args, analyzer: Analyzer) -> None:
    """`anta serve`: dashboard plus one of: a session it starts (--pcap/--interface),
    stdin, or a listener for an engine you run yourself."""
    purge_stale_exports()
    token = args.token or os.environ.get("ANTA_TOKEN") or secrets.token_urlsafe(32)
    dash = Dashboard(analyzer, os.path.abspath(args.engine), token,
                     allowed_hosts_for(args.host, args.allow_host or []), set())
    loop = asyncio.get_running_loop()
    raw: asyncio.Queue = asyncio.Queue(maxsize=50_000)
    sessions = dash.attach_sessions(raw)
    tasks = [asyncio.create_task(dash.consume(raw)), asyncio.create_task(dash.flusher())]
    zmq_source = None

    if args.stdin:
        ingest.start_stdin_thread(loop, raw)
    elif not (args.pcap or args.interface) and not args.no_listen:
        # Listener for an engine started separately (e.g. under sudo on a sensor).
        if args.transport == "zmq":
            endpoint = args.endpoint or f"ipc://{socket_path('engine.ipc')}"
            if endpoint.startswith("tcp://"):
                host = urlsplit(endpoint.replace("tcp://", "//", 1)).hostname or ""
                try:
                    loopback = ipaddress.ip_address(host).is_loopback
                except ValueError:
                    loopback = host == "localhost"
                if not loopback:
                    print("anta: WARNING: ZeroMQ NULL mechanism is unauthenticated and unencrypted; any host that "
                          "can reach this port can inject records. Prefer ipc:// or a loopback address behind an "
                          "SSH tunnel.", file=sys.stderr)
            zmq_source = ingest.ZmqSource(endpoint, raw)
            print(f"anta: engine endpoint zmq+{endpoint}", file=sys.stderr)
        else:
            path = args.endpoint or socket_path("engine.sock")
            await ingest.serve_unix_socket(path, raw)
            print(f"anta: engine endpoint unix:{path}", file=sys.stderr)

    runner, port = await start_dashboard(dash, args.host, args.port)
    shown_host = f"[{args.host}]" if ":" in args.host else args.host
    if args.host in ("0.0.0.0", "::"):
        shown_host = "127.0.0.1"
        print("anta: WARNING: dashboard bound to all interfaces over plain HTTP; the token protects access but "
              "not confidentiality. Prefer an SSH tunnel to a loopback-bound dashboard.", file=sys.stderr)
    print(f"anta: dashboard at http://{shown_host}:{port}/?token={token}", file=sys.stderr)
    print("anta: (the token is exchanged for a cookie on first visit; keep this URL private)", file=sys.stderr)

    try:
        if args.pcap:
            await sessions.start_file(args.pcap, args.replay_speed)
        elif args.interface:
            await sessions.start_live(args.interface, args.filter or "", record=True)
    except SessionError as exc:
        print(f"anta: {exc}", file=sys.stderr)
    stop = asyncio.Event()
    if os.name != "nt":  # a plain kill (SIGTERM) stops cleanly too, so temp files and key logs go
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stop.set)
    try:
        await stop.wait()
    finally:
        await sessions.stop()
        for task in tasks:
            task.cancel()
        if zmq_source:
            zmq_source.close()
        dash.cleanup()
        await runner.cleanup()
