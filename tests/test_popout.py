"""Pop-out windows: a view of the dashboard in a window of its own. The desktop app signs
each one in with a single-use ticket; the view it shows comes from checked parameters."""
import os
import re
import sys
import types

import pytest

import anta.server as server
from anta import paths
from conftest import ROOT
from test_server import make_client, run


def test_popout_parameters_are_checked():
    q = server.popout_query
    assert q({"popout": "stats", "tool": "io"}) == "popout=stats&tool=io"
    assert q({"popout": "alert", "id": "A00002", "card": "chart"}) == "popout=alert&id=A00002&card=chart"
    assert q({"popout": "stats", "other": "x"}) == "popout=stats"            # unknown keys are dropped
    for bad in ({"popout": "settings"}, {}, {"popout": "alert", "id": "A1<script>"}, {"popout": "stats", "tool": "a b"},
                {"popout": "stats", "tool": "x" * 41}):
        assert q(bad) is None, bad


def test_a_ticket_opens_one_window_once(monkeypatch):
    async def go():
        dash, c = await make_client()
        try:
            ticket = dash.issue_ticket()
            r = await c.get(f"/?ticket={ticket}&popout=stats&tool=io", allow_redirects=False)
            assert r.status == 303 and r.headers["Location"] == "/?popout=stats&tool=io"
            assert server.COOKIE in r.cookies and r.cookies[server.COOKIE]["httponly"]
            again = await c.get(f"/?ticket={ticket}&popout=stats", allow_redirects=False)
            assert again.status == 403                                     # single use
            r = await c.get(f"/?ticket={dash.issue_ticket()}&popout=alert&id=bad%3Cid", allow_redirects=False)
            assert r.status == 303 and r.headers["Location"] == "/"         # a bad view: just the app
            assert (await c.get("/?ticket=guessed", allow_redirects=False)).status == 403
            monkeypatch.setattr(server, "TICKET_TTL", -1.0)                 # expired
            assert (await c.get(f"/?ticket={dash.issue_ticket()}", allow_redirects=False)).status == 403
            # The API still wants the cookie: a ticket isn't a credential for it.
            c.session.cookie_jar.clear()
            assert (await c.get(f"/api/summary?ticket={dash.issue_ticket()}")).status == 401
        finally:
            await c.close()
    run(go())


def test_the_app_opens_a_popout_window(monkeypatch):
    made, state = [], {"private_mode": True}

    class Window:
        def __init__(self, title, url, **kw):
            self.title, self.url, self.kw, self.closed = title, url, kw, False
            made.append(self)

        def destroy(self):
            self.closed = True

    fake = types.SimpleNamespace(create_window=lambda title, url, **kw: Window(title, url, **kw), _state=state)
    monkeypatch.setitem(sys.modules, "webview", fake)
    from anta.app import Bridge

    class Dash:
        def issue_ticket(self):
            return "TICKET123"

    bridge = Bridge(types.SimpleNamespace(dash=Dash()), "http://127.0.0.1:5555")
    assert bridge.pop_out("popout=stats&tool=io", "Statistics: I/O graph\x07") is True
    w = made[0]
    assert w.url == "http://127.0.0.1:5555/?ticket=TICKET123&popout=stats&tool=io"
    assert w.title == "Statistics: I/O graph — ANTA" and "js_api" not in w.kw  # (no script bridge: see app.py)
    assert state["private_mode"] is (not paths.IS_MAC)  # (macOS: join the main window's store, see app.py)
    assert bridge.pop_out("popout=../../etc") is False and bridge.pop_out("") is False and len(made) == 1
    bridge._close_popouts()
    assert w.closed and not bridge._popouts
    # pywebview hands the page only public methods: the closing and the server stay private.
    assert not [n for n in vars(bridge) if not n.startswith("_")]


def test_every_pane_button_has_a_target_and_an_explanation():
    html = open(os.path.join(ROOT, "anta", "web", "index.html")).read()
    shell = open(os.path.join(ROOT, "anta", "web", "shell.js")).read()
    helps = set(re.findall(r'data-help="([^"]+)"', html))
    known = set(re.findall(r'^\s+"?([a-z-]+)"?: \["', shell, re.M))
    assert helps and helps <= known, helps - known
    assert set(re.findall(r'data-popout="([^"]+)"', html)) <= set(server.POPOUT_VIEWS)


@pytest.mark.parametrize("view", server.POPOUT_VIEWS)
def test_each_view_has_a_window_title(view):
    shell = open(os.path.join(ROOT, "anta", "web", "shell.js")).read()
    titles = re.search(r"const POP_TITLES = \{(.*?)\};", shell, re.S).group(1)
    assert re.search(rf"\b{view}:", titles), view


def test_the_page_asks_the_app_for_windows_through_the_api():
    from test_server import AUTH

    class Native:
        def __init__(self):
            self.calls = []

        def pop_out(self, query, title):
            self.calls.append((query, title))
            return True

        def choose_capture(self):
            return "/tmp/picked.pcap"

    async def go():
        dash, c = await make_client()
        try:
            # In a browser there is no app to ask: the page opens its own window.
            r = await c.post("/api/native/popout", headers=AUTH, json={"query": "popout=map"})
            assert r.status == 404
            dash.native = Native()
            r = await (await c.post("/api/native/popout", headers=AUTH,
                                    json={"query": "popout=stats&tool=io", "title": "Statistics: I/O graph"})).json()
            assert r == {"ok": True} and dash.native.calls == [("popout=stats&tool=io", "Statistics: I/O graph")]
            bad = await c.post("/api/native/popout", headers=AUTH, json={"query": "popout=nope"})
            assert bad.status == 400 and len(dash.native.calls) == 1
            r = await (await c.post("/api/native/choose-capture", headers=AUTH, json={})).json()
            assert r == {"path": "/tmp/picked.pcap"}
            assert (await c.post("/api/native/popout", json={"query": "popout=map"})).status == 401  # signed in only
        finally:
            await c.close()
    run(go())
