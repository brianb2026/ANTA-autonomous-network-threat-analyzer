"""Dashboard server security: auth, DNS rebinding, cross-site WebSockets, headers, export trust."""
import asyncio
import os

import pytest
from aiohttp import WSServerHandshakeError
from aiohttp.test_utils import TestClient, TestServer

from anta.analyzer import Analyzer
from anta.server import Dashboard, allowed_hosts_for
from conftest import ENGINE

TOKEN = "test-token-0123456789"


def run(coro):
    return asyncio.run(coro)


class Client(TestClient):
    async def close(self):
        self.dash.cleanup()
        await super().close()


async def make_client(analyzer=None, trusted=()):
    dash = Dashboard(analyzer or Analyzer(), ENGINE, TOKEN, allowed_hosts_for("127.0.0.1", []), set(trusted))
    client = Client(TestServer(dash.app(), host="127.0.0.1"))
    client.dash = dash
    await client.start_server()
    return dash, client


AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_api_requires_token():
    async def go():
        _, c = await make_client()
        try:
            assert (await c.get("/api/alerts")).status == 401
            assert (await c.get("/api/alerts", headers={"Authorization": "Bearer wrong"})).status == 401
            assert (await c.get("/api/alerts", headers=AUTH)).status == 200
            assert (await c.get("/")).status == 401          # locked page, no data
            assert (await c.get("/?token=wrong")).status == 403
        finally:
            await c.close()
    run(go())


def test_token_is_exchanged_for_strict_httponly_cookie():
    async def go():
        _, c = await make_client()
        try:
            r = await c.get(f"/?token={TOKEN}", allow_redirects=False)
            assert r.status == 303 and r.headers["Location"] == "/"
            cookie = r.headers["Set-Cookie"]
            assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
            assert (await c.get("/api/summary")).status == 200  # cookie jar now authenticates
        finally:
            await c.close()
    run(go())


def test_dns_rebinding_host_header_rejected():
    async def go():
        _, c = await make_client()
        try:
            r = await c.get("/api/alerts", headers={**AUTH, "Host": "attacker.example"})
            assert r.status == 421
        finally:
            await c.close()
    run(go())


def test_cross_origin_websocket_rejected():
    async def go():
        _, c = await make_client()
        try:
            with pytest.raises(WSServerHandshakeError):
                await c.ws_connect("/ws", headers={**AUTH, "Origin": "http://attacker.example"})
            ws = await c.ws_connect("/ws", headers={**AUTH, "Origin": f"http://127.0.0.1:{c.port}"})
            msg = await ws.receive_json(timeout=5)
            assert msg["type"] == "snapshot"
            await ws.close()
        finally:
            await c.close()
    run(go())


def test_security_headers():
    async def go():
        _, c = await make_client()
        try:
            r = await c.get("/api/summary", headers=AUTH)
            assert "default-src 'none'" in r.headers["Content-Security-Policy"]
            assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
            assert r.headers["X-Frame-Options"] == "DENY"
            assert r.headers["X-Content-Type-Options"] == "nosniff"
            assert r.headers["Referrer-Policy"] == "no-referrer"
            assert r.headers["Cache-Control"] == "no-store"
        finally:
            await c.close()
    run(go())


def test_static_path_traversal_blocked():
    async def go():
        _, c = await make_client()
        try:
            for path in ("/static/../server.py", "/static/%2e%2e/server.py", "/static/..%2fserver.py"):
                r = await c.get(path, headers=AUTH)
                assert r.status in (403, 404), path
        finally:
            await c.close()
    run(go())


def test_export_only_from_trusted_capture(demo_records, data_dir, tmp_path):
    """A session record naming an arbitrary file must not turn the export into a file reader."""
    async def go():
        analyzer = Analyzer()
        bogus = tmp_path / "not-a-capture.pcap"
        bogus.write_text("secret")
        analyzer.ingest({"type": "hello", "capture": str(bogus)})
        for rec in demo_records:
            analyzer.ingest(dict(rec, capture=str(bogus)) if rec["type"] == "session" else rec)
        _, c = await make_client(analyzer)
        try:
            alert_id = next(iter(analyzer.alerts))
            r = await c.get(f"/api/export/{alert_id}", headers=AUTH)
            assert r.status == 409  # announced, but not a pcap: refused
        finally:
            await c.close()
    run(go())


def test_export_slices_only_the_alert_flows(demo_records, data_dir):
    async def go():
        demo = os.path.realpath(os.path.join(data_dir, "mixed_demo.pcap"))
        analyzer = Analyzer()
        for rec in demo_records:
            analyzer.ingest(rec)
        _, c = await make_client(analyzer, trusted={demo})
        try:
            alert = next(a for a in analyzer.alerts.values() if a["kind"] == "beacon" and a["dst_ip"] == "192.168.1.105")
            r = await c.get(f"/api/export/{alert['id']}", headers=AUTH)
            assert r.status == 200 and "attachment" in r.headers["Content-Disposition"]
            body = await r.read()
            assert body[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4") and len(body) < 2_000_000
            leftovers = [n for n in os.listdir(os.environ["ANTA_RUNTIME_DIR"]) if n.endswith(".pcap")]
            assert all(os.stat(os.path.join(os.environ["ANTA_RUNTIME_DIR"], n)).st_mode & 0o077 == 0
                       for n in leftovers)
        finally:
            await c.close()
    run(go())


def test_dashboard_scripts_do_not_redefine_each_others_globals():
    # The dashboard's scripts share one global scope: a second top-level `function select`
    # silently replaced the alert feed's, so alerts could no longer be opened.
    import re
    web = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "anta", "web")
    with open(os.path.join(web, "index.html"), encoding="utf-8") as fh:
        scripts = re.findall(r'<script src="/static/([^"]+\.js)"', fh.read())
    assert len(scripts) >= 4
    owner: dict[str, str] = {}
    for name in scripts:
        with open(os.path.join(web, name), encoding="utf-8") as fh:
            for m in re.finditer(r"^(?:async\s+)?function\s+(\w+)|^(?:const|let|var|class)\s+(\w+)", fh.read(), re.M):
                ident = m.group(1) or m.group(2)
                assert ident not in owner, f"{ident} is defined in both {owner[ident]} and {name}"
                owner[ident] = name
