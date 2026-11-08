"""Ask the capture: questions in plain words read by rules into a display filter and/or the
view that answers them; a model asked only on request, with the question alone."""
import asyncio
import datetime as dt

import pytest

from anta import ask
from anta.agent import AgentError
from test_server import AUTH, make_client


@pytest.mark.parametrize("question, expected", [
    ("DNS from 10.0.0.5", "dns && ip.src == 10.0.0.5"),
    ("retransmissions to 203.0.113.50 in the first 5 minutes",
     "tcp.analysis.retransmission && ip.dst == 203.0.113.50 && frame.time_relative <= 300"),
    ("traffic between 10.0.0.5 and 10.0.0.9 on port 445",
     "(ip.addr == 10.0.0.5 && ip.addr == 10.0.0.9) && (tcp.port == 445 || udp.port == 445)"),
    ("dns but not mdns", "dns && !mdns"),
    ("pings from fe80::1", "(icmp || icmpv6) && ipv6.src == fe80::1"),
    ("arp from 02-00-00-00-00-01", "arp && eth.src == 02:00:00:00:00:01"),
    ("ports 80 and 443 to 10.0.0.1", "(tcp.port in {80, 443} || udp.port in {80, 443}) && ip.dst == 10.0.0.1"),
    ("failed dns lookups", "dns.flags.rcode != 0"),
    ("http errors from 10.0.0.0/24", "http.response.code >= 400 && ip.src == 10.0.0.0/24"),
    ("packets larger than 1400 bytes", "frame.len > 1400"),
    ("who downloaded payload.exe", 'frame contains "payload.exe"'),
    ("file sharing traffic", "smb || smb2"),
])
def test_questions_become_filters(question, expected):
    plan = ask.parse(question)
    assert plan["understood"] and plan["filter"] == expected and plan["action"] == {"kind": "packets"}
    assert all(p["words"].lower() in question.lower() for p in plan["parts"])


@pytest.mark.parametrize("question, action", [
    ("who talked the most?", {"kind": "stats", "tool": "endpoints"}),
    ("any passwords sent in clear text?", {"kind": "stats", "tool": "logins"}),
    ("which devices call home on a timer?", {"kind": "stats", "tool": "rhythm"}),
    ("what happened?", {"kind": "view", "view": "story"}),
    ("what devices are on the network", {"kind": "view", "view": "assets"}),
])
def test_questions_a_view_answers(question, action):
    plan = ask.parse(question)
    assert plan["understood"] and plan["filter"] == "" and plan["action"] == action


def test_a_subject_narrows_and_the_view_comes_too():
    plan = ask.parse("what happened to 10.0.0.23?")
    assert plan["filter"] == "ip.addr == 10.0.0.23" and plan["also"] == {"kind": "view", "view": "story"}


def test_clock_times_need_the_capture_and_use_the_viewers_time_zone():
    plan = ask.parse("after 10:05")
    assert plan["needs_times"] and not plan["understood"]
    first = dt.datetime(2026, 10, 6, 10, 0, 0, tzinfo=dt.timezone(dt.timedelta(hours=-7))).timestamp()
    plan = ask.parse("after 10:05", {"first": first, "last": first + 900, "duration": 900}, tz_min=420)
    assert plan["filter"] == f"frame.time_epoch >= {first + 300:.0f}"
    plan = ask.parse("in the last 2 minutes", {"first": first, "last": first + 900, "duration": 900})
    assert plan["filter"] == "frame.time_relative >= 780"


def test_nonsense_gets_examples():
    plan = ask.parse("hello there")
    assert not plan["understood"] and plan["examples"]


# ---------------------------------------------------------------- the shape of a question

S, P = "10.0.0.5", "203.0.113.50"


def about(question, **kw):
    plan = ask.parse(question, **kw)
    return plan, plan.get("about") or {}


# (question, kind, what else the reading must say)
PHRASINGS = [
    # Who an address talked to: the question that started this.
    ("who did 10.0.0.5 talk to the most", "peers", {"subject": S, "dir": "any", "order": "most"}),
    ("who did 10.0.0.5 talk to the most?", "peers", {"subject": S}),
    ("Who did 10.0.0.5 talk to?", "peers", {"subject": S}),
    ("who is 10.0.0.5 talking to", "peers", {"subject": S}),
    ("who's 10.0.0.5 talking to?", "peers", {"subject": S}),
    ("who has 10.0.0.5 been talking to", "peers", {"subject": S}),
    ("whom did 10.0.0.5 communicate with", "peers", {"subject": S}),
    ("who does 10.0.0.5 communicate with", "peers", {"subject": S}),
    ("who was 10.0.0.5 chatting with", "peers", {"subject": S}),
    ("10.0.0.5 talked to who?", "peers", {"subject": S}),
    ("what ip did 10.0.0.5 talk to the most", "peers", {"subject": S}),
    ("which host did 10.0.0.5 talk to most", "peers", {"subject": S}),
    ("what did 10.0.0.5 connect to", "peers", {"dir": "servers"}),
    ("which servers did 10.0.0.5 reach", "peers", {"dir": "servers"}),
    ("which hosts did 10.0.0.5 contact", "peers", {"dir": "servers"}),
    ("10.0.0.5's top destinations", "peers", {"dir": "servers"}),
    ("top 3 destinations of 10.0.0.5", "peers", {"dir": "servers", "n": 3}),
    ("what servers does 10.0.0.5 use", "peers", {"dir": "servers"}),
    ("where did 10.0.0.5 send data", "peers", {"dir": "out"}),
    ("where does 10.0.0.5 send the most data", "peers", {"dir": "out"}),
    ("who sent the most data to 203.0.113.50", "peers", {"subject": P, "dir": "in"}),
    ("who did 10.0.0.5 download the most from", "peers", {"dir": "in"}),
    ("who talked to 10.0.0.5", "peers", {"dir": "any"}),
    ("who connected to 10.0.0.5", "peers", {"dir": "clients"}),
    ("which hosts contacted 10.0.0.5", "peers", {"dir": "clients"}),
    ("who are the clients of 10.0.0.5", "peers", {"dir": "clients"}),
    ("top talkers for 10.0.0.5", "peers", {}),
    ("top peers of 10.0.0.5", "peers", {}),
    ("10.0.0.5's biggest peers", "peers", {}),
    ("conversations with 10.0.0.5", "peers", {}),
    ("show me 10.0.0.5's connections", "peers", {"dir": "any"}),
    ("list everything 10.0.0.5 talked to", "peers", {}),
    ("how many hosts did 10.0.0.5 talk to", "peers", {}),
    ("did 10.0.0.5 talk to anyone outside", "peers", {"scope": "public"}),
    ("what external hosts did 10.0.0.5 talk to", "peers", {"scope": "public"}),
    ("which internal machines did 10.0.0.5 talk to", "peers", {"scope": "private"}),
    ("who did 10.0.0.5 talk to the least", "peers", {"order": "least"}),
    ("which servers did 10.0.0.5 contact most often", "peers", {"dir": "servers", "rank": "connections"}),
    ("who did 10.0.0.5 send the most packets to", "peers", {"dir": "out", "rank": "packets"}),
    ("who did 10.0.0.5 talk to the longest", "peers", {"rank": "duration"}),
    ("who did 10.0.0.5 talk to over https", "peers", {"filter": "ip.addr == 10.0.0.5 && tls"}),
    ("who did 10.0.0.5 talk to besides 8.8.8.8", "peers", {"filter": "ip.addr == 10.0.0.5 && !ip.addr == 8.8.8.8"}),
    ("who did 10.0.0.5 talk to in the first 5 minutes", "peers",
     {"filter": "ip.addr == 10.0.0.5 && frame.time_relative <= 300"}),
    ("who did the 10.0.0.0/24 network talk to", "peers", {"subject": "10.0.0.0/24"}),
    ("who did 02:00:00:00:00:01 talk to", "peers", {"subject": "02:00:00:00:00:01", "filter": "eth.addr == 02:00:00:00:00:01"}),
    ("who did fe80::1 talk to", "peers", {"filter": "ipv6.addr == fe80::1"}),
    ("can you tell me who 10.0.0.5 talked to the most please", "peers", {}),
    ("hey, so who did 10.0.0.5 talk to in this capture?", "peers", {}),
    # The busiest hosts and conversations.
    ("who talked the most?", "talkers", {"dir": "any"}),
    ("top talkers", "talkers", {}),
    ("top 10 talkers", "talkers", {"n": 10}),
    ("who are the top five talkers", "talkers", {"n": 5}),
    ("which ip sent the most packets", "talkers", {"dir": "out", "rank": "packets"}),
    ("who is hogging the bandwidth", "talkers", {}),
    ("which device uses the most bandwidth", "talkers", {}),
    ("what's the busiest host", "talkers", {}),
    ("noisiest devices", "talkers", {}),
    ("who received the most data", "talkers", {"dir": "in"}),
    ("which host downloaded the most", "talkers", {"dir": "in"}),
    ("which host uploaded the most", "talkers", {"dir": "out"}),
    ("which host has the most connections", "talkers", {"rank": "connections"}),
    ("who talked the least", "talkers", {"order": "least"}),
    ("which internal host sent the most data", "talkers", {"dir": "out", "scope": "private"}),
    ("who used the most dns", "talkers", {"filter": "dns"}),
    ("which hosts had the most retransmissions", "talkers", {"rank": "packets", "filter": "tcp.analysis.retransmission"}),
    ("biggest conversations", "conversations", {"rank": "bytes"}),
    ("largest flows", "conversations", {}),
    ("longest connection", "conversations", {"rank": "duration"}),
    ("which conversation lasted the longest", "conversations", {"rank": "duration"}),
    ("which two hosts talked to each other the most", "conversations", {}),
    # Two addresses: did they talk?
    ("did 10.0.0.5 talk to 203.0.113.50", "pair", {"subject": S, "other": P,
                                                  "filter": "ip.addr == 10.0.0.5 && ip.addr == 203.0.113.50"}),
    ("did 10.0.0.5 ever connect to 203.0.113.50?", "pair", {"other": P}),
    ("has 10.0.0.5 contacted 203.0.113.50", "pair", {}),
    ("is there any traffic between 10.0.0.5 and 10.0.0.9", "pair", {"other": "10.0.0.9"}),
    ("how much data went between 10.0.0.5 and 10.0.0.9", "pair", {}),
    ("how much data did 10.0.0.5 send to 203.0.113.50", "pair", {}),
    ("when did 10.0.0.5 talk to 203.0.113.50", "pair", {}),
    ("did 10.0.0.5 talk to example.com", "pair", {"name": "example.com"}),
    # What a host is.
    ("what is 10.0.0.5", "identity", {"subject": S}),
    ("who is 10.0.0.5", "identity", {}),
    ("what's 10.0.0.5?", "identity", {}),
    ("10.0.0.5", "identity", {}),
    ("tell me about 10.0.0.5", "identity", {}),
    ("tell me everything about 10.0.0.5", "identity", {}),
    ("what kind of device is 10.0.0.5", "identity", {}),
    ("what is the hostname of 10.0.0.5", "identity", {}),
    ("what's the mac address of 10.0.0.5", "identity", {}),
    ("what os is 10.0.0.5 running", "identity", {}),
    ("is 10.0.0.5 a printer", "identity", {}),
    ("10.0.0.5's hostname", "identity", {}),
    ("which ip has mac 02:00:00:00:00:01", "identity", {"subject": "02:00:00:00:00:01"}),
    ("who is 02:00:00:00:00:01", "identity", {}),
    ("what is 10.0.0.5 doing", "identity", {}),
    ("what has 10.0.0.5 been up to", "identity", {}),
    ("what's going on with 10.0.0.5", "identity", {}),
    ("investigate 10.0.0.5", "identity", {}),
    # Where it is.
    ("where is 203.0.113.50", "geo", {"subject": P}),
    ("what country is 203.0.113.50 in", "geo", {}),
    ("who owns 203.0.113.50", "geo", {}),
    ("what countries did 10.0.0.5 talk to", "geo", {"peers": True}),
    # Ports and services.
    ("what ports did 10.0.0.5 use", "ports", {"dir": "both"}),
    ("which ports is 10.0.0.5 listening on", "ports", {"dir": "serves"}),
    ("what services does 10.0.0.5 run", "ports", {"dir": "serves"}),
    ("open ports on 10.0.0.5", "ports", {"dir": "serves"}),
    ("what ports did 10.0.0.5 connect to", "ports", {"dir": "uses"}),
    ("most used ports", "ports", {}),
    ("top ports", "ports", {}),
    ("what services are running on the network", "ports", {"dir": "serves"}),
    ("which port had the most traffic", "ports", {}),
    # Protocols.
    ("what protocols did 10.0.0.5 use", "protocols", {"subject": S}),
    ("which protocols does 10.0.0.5 speak", "protocols", {}),
    ("protocol breakdown for 10.0.0.5", "protocols", {}),
    ("what kind of traffic is 10.0.0.5 sending", "protocols", {}),
    ("what are the most common protocols", "protocols", {}),
    ("which protocol uses the most bandwidth", "protocols", {}),
    ("what protocols are in this capture", "protocols", {}),
    # Names looked up and sites visited.
    ("what domains did 10.0.0.5 look up", "names", {"subject": S}),
    ("what sites did 10.0.0.5 visit", "names", {}),
    ("which websites did 10.0.0.5 go to", "names", {}),
    ("what did 10.0.0.5 look up", "names", {}),
    ("what did 10.0.0.5 browse", "names", {}),
    ("top domains", "names", {}),
    ("most visited websites", "names", {}),
    ("what sites were visited", "names", {}),
    ("which domains were looked up the most", "names", {}),
    ("what ip is example.com", "resolve", {"name": "example.com"}),
    ("what does example.com resolve to", "resolve", {}),
    ("what is the ip address of www.example.com", "resolve", {"name": "www.example.com"}),
    ("example.com", "resolve", {}),
    # How much, and when.
    ("how much data did 10.0.0.5 send", "volume", {"dir": "out"}),
    ("how many bytes did 10.0.0.5 receive", "volume", {"dir": "in"}),
    ("how much traffic is from 10.0.0.5", "volume", {"dir": "out", "filter": "ip.src == 10.0.0.5"}),
    ("how many packets came from 10.0.0.5", "volume", {"dir": "out", "rank": "packets"}),
    ("how much bandwidth did 10.0.0.5 use", "volume", {}),
    ("how much dns traffic is there", "volume", {"filter": "dns"}),
    ("when did 10.0.0.5 first appear", "when", {"subject": S}),
    ("when was 10.0.0.5 last seen", "when", {}),
    ("when did 10.0.0.5 start talking", "when", {}),
    ("how long was 10.0.0.5 active", "when", {}),
    ("when did the dns failures happen", "when", {"filter": "dns.flags.rcode != 0"}),
    # Hosts in some traffic.
    ("who used ssh", "hosts", {"filter": "ssh"}),
    ("which hosts use port 22", "hosts", {}),
    ("who visited example.com", "hosts", {}),
    ("who looked up example.com", "hosts", {}),
    ("did anyone visit example.com", "hosts", {}),
    ("is anyone using telnet", "hosts", {"filter": "telnet"}),
    ("which devices sent dns queries", "hosts", {}),
    ("which hosts had retransmissions", "hosts", {}),
    # The whole capture.
    ("summarize this capture", "capture", {}),
    ("give me an overview", "capture", {}),
    ("what's in this capture", "capture", {}),
    ("how long is the capture", "capture", {}),
    ("when did the capture start", "capture", {}),
    ("how much data is in the capture", "capture", {}),
    ("how many hosts are there", "count", {"what": "hosts"}),
    ("how many ips are in this capture", "count", {"what": "hosts"}),
    ("how many conversations are there", "count", {"what": "conversations"}),
    ("how many connections were made", "count", {"what": "conversations"}),
    ("how many packets are there", "count", {"what": "packets"}),
    ("how many dns queries", "count", {"what": "packets", "filter": "dns"}),
    ("how many domains were looked up", "count", {"what": "names"}),
    # Slips.
    ("who did 10.0.0.5 tlak to the msot", "peers", {}),
    ("waht protocols did 10.0.0.5 use", "protocols", {}),
    ("whcih hosts recieved the most data", "talkers", {"dir": "in"}),
    ("top doamins", "names", {}),
]


@pytest.mark.parametrize("question, kind, expect", PHRASINGS)
def test_how_a_question_is_read(question, kind, expect):
    plan, a = about(question)
    assert plan["understood"] and plan["intent"] == kind, (question, plan["intent"], a)
    for k, v in expect.items():
        got = plan["filter"] if k == "filter" else a.get(k)
        assert got == v, (question, k, got)
    if a.get("subject") and kind not in ("volume", "hosts", "talkers", "conversations", "count"):
        assert plan["filter"].startswith(ask._ip_field(a["subject"], "addr"))  # (all its traffic, both ways)


# Questions a tool or view answers, read the same with a subject or not.
VIEWS = [
    ("any passwords sent in clear text?", "logins", ""),
    ("did 10.0.0.5 send a password", "logins", "ip.addr == 10.0.0.5"),
    ("which hosts sent passwords", "logins", ""),
    ("is anything beaconing", "rhythm", ""),
    ("which devices call home on a timer?", "rhythm", ""),
    ("what happened?", "story", ""),
    ("was 10.0.0.5 compromised", "story", "ip.addr == 10.0.0.5"),
    ("is 10.0.0.5 infected", "story", "ip.addr == 10.0.0.5"),
    ("is 10.0.0.5 malicious", "alerts", "ip.addr == 10.0.0.5"),
    ("is 10.0.0.5 safe", "alerts", "ip.addr == 10.0.0.5"),
    ("any alerts about 10.0.0.5", "alerts", "ip.addr == 10.0.0.5"),
    ("who has the most alerts", "alerts", ""),
    ("is anyone scanning the network", "alerts", ""),
    ("was there a port scan", "alerts", ""),
    ("what files did 10.0.0.5 download", "files", "ip.addr == 10.0.0.5"),
    ("what did 10.0.0.5 download", "files", "ip.addr == 10.0.0.5"),
    ("were any executables downloaded", "files", ""),
    ("traffic over time", "io", ""),
    ("when was the traffic busiest", "io", ""),
    ("what devices are on the network", "devices", ""),
    ("list all devices", "devices", ""),
    ("what countries did we talk to", "countries", ""),
    ("ja3 fingerprints", "fingerprints", ""),
]


@pytest.mark.parametrize("question, intent, flt", VIEWS)
def test_questions_a_view_answers_with_or_without_a_host(question, intent, flt):
    plan = ask.parse(question)
    assert plan["understood"] and plan["intent"] == intent and plan["filter"] == flt and "about" not in plan


@pytest.mark.parametrize("question, flt", [
    ("pings from fe80::1", "(icmp || icmpv6) && ipv6.src == fe80::1"),
    ("dns from 10.0.0.5 or 10.0.0.6", "dns && (ip.src == 10.0.0.5 || ip.src == 10.0.0.6)"),
    ("traffic from 10.0.0.5 and 10.0.0.6", "ip.src == 10.0.0.5 || ip.src == 10.0.0.6"),
    ("http involving 10.0.0.5 or 10.0.0.6", "http && (ip.addr == 10.0.0.5 || ip.addr == 10.0.0.6)"),
    ("dns except 10.0.0.1", "dns && !ip.addr == 10.0.0.1"),
])
def test_a_filter_request_stays_a_filter(question, flt):
    plan = ask.parse(question)
    assert plan["filter"] == flt and plan["action"] == {"kind": "packets"}


@pytest.mark.parametrize("word, fixed", [
    ("tlak", "talk"), ("msot", "most"), ("pakcets", "packets"), ("packest", "packets"), ("retransmisions", "retransmissions"),
    ("protocls", "protocols"), ("conectoins", "connections"), ("hsots", "hosts"), ("whcih", "which"), ("recieved", "received"),
    ("doamins", "domains"), ("devics", "devices"),
    # Ordinary words are left alone, even one letter from a word the rules know.
    ("going", "going"), ("tasks", "tasks"), ("there", "there"), ("form", "form"), ("cost", "cost"), ("mist", "mist"),
    ("doing", "doing"), ("thing", "thing"),
])
def test_slips_are_read_as_meant_and_words_left_alone(word, fixed):
    assert ask._fix_word(word) == fixed


def test_what_was_read_is_shown_when_a_word_was_fixed():
    plan = ask.parse("who did 10.0.0.5 tlak to the msot")
    assert plan["read_as"] == "who did 10.0.0.5 talk to the most"
    assert ask.parse("who did 10.0.0.5 talk to the most")["read_as"] == ""
    assert ask.parse("what's going on with 10.0.0.5")["read_as"] == ""  # (a short form spelled out isn't a fix)


def test_hosts_by_the_names_they_announced():
    plan = ask.parse("who did desktop-7h2 talk to", hosts={"desktop-7h2": "10.0.0.21"})
    assert plan["intent"] == "peers" and plan["about"]["subject"] == "10.0.0.21" and plan["filter"] == "ip.addr == 10.0.0.21"
    plan = ask.parse("what is nas.local", hosts={"nas.local": "10.0.0.40"})
    assert plan["intent"] == "identity" and plan["about"]["subject"] == "10.0.0.40"
    assert ask.parse("who did desktop-7h2 talk to")["intent"] != "peers"  # (a name nobody announced)


def test_the_answer_opens_its_tool_with_the_same_packets():
    plan = ask.parse("who did 10.0.0.5 talk to the most")
    assert plan["action"] == {"kind": "packets"}
    assert plan["also"] == {"kind": "stats", "tool": "conversations", "filter": "ip.addr == 10.0.0.5"}
    assert ask.parse("top talkers")["action"] == {"kind": "stats", "tool": "endpoints"}
    assert ask.parse("what is 10.0.0.5")["also"] == {"kind": "view", "view": "host", "addr": "10.0.0.5"}


class FakeSettings:
    def __init__(self, share=False):
        self.values = {"provider": "openai", "share_internal": share}

    def consented(self, p):
        return True

    def model(self, p=None):
        return "gpt-test"


def test_the_model_sees_pseudonyms_and_its_filter_comes_back_real(monkeypatch):
    sent = {}

    async def fake(settings, provider, system, question, schema):
        sent["question"], sent["system"] = question, system
        return {"filter": "ip.src == internal-host-1 && tls", "view": "packets", "explanation": "TLS from internal-host-1"}

    import anta.agent_providers as ap
    monkeypatch.setattr(ap, "ask_json", fake)
    out = asyncio.run(ask.translate_with_model(FakeSettings(), "what did 10.0.0.5 say to 8.8.8.8 over tls", ["ip.src"]))
    assert "10.0.0.5" not in sent["question"] and "internal-host-1" in sent["question"] and "8.8.8.8" in sent["question"]
    assert out["filter"] == "ip.src == 10.0.0.5 && tls" and out["summary"] == "TLS from 10.0.0.5"
    assert "ip.src" in sent["system"]


def test_a_models_answer_is_checked():
    assert ask.model_answer({"filter": "x", "view": "nonsense", "explanation": "e"})["action"] == {"kind": "packets"}
    assert ask.model_answer({"filter": "", "view": "rhythm", "explanation": ""})["action"] == {"kind": "stats", "tool": "rhythm"}
    with pytest.raises(ValueError):
        ask.model_answer({"filter": "a\nb", "view": "packets", "explanation": ""})


def test_command_agents_are_not_asked():
    s = FakeSettings()
    s.values["provider"] = "command"
    with pytest.raises(AgentError):
        asyncio.run(ask.translate_with_model(s, "dns", []))


def test_the_ask_endpoints(engine, data_dir):
    import os

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(os.path.join(data_dir, "http_download.pcap"))
            post = lambda path, body: c.post(path, json=body, headers=AUTH)  # noqa: E731
            plan = await (await post("/api/ask", {"q": "http from 10.0.0.5", "tz": 0})).json()
            assert plan["filter"] == "http && ip.src == 10.0.0.5" and plan["check"]["ok"] and plan["model"] is None
            raw = await (await post("/api/ask", {"q": "tcp.port == 80"})).json()
            assert raw["source"] == "filter" and raw["filter"] == "tcp.port == 80"
            assert (await post("/api/ask", {"q": ""})).status == 400
            assert (await post("/api/ask", {"q": "x" * 600})).status == 400
            assert (await post("/api/ask/model", {"q": "dns"})).status == 409  # no model set up
            assert (await c.post("/api/ask", json={"q": "dns"})).status == 401
        finally:
            await c.close()
    asyncio.run(go())


def test_claude_through_the_real_sdk(tmp_path, monkeypatch):
    """Asking Claude through the Anthropic SDK itself, talking to a stand-in for the API (no
    key, nothing leaves the machine): the request it sends and the answer it reads back."""
    import json

    anthropic = pytest.importorskip("anthropic")
    httpx2 = pytest.importorskip("httpx2")
    from anta.agent import AgentSettings, ClaudeBackend
    sent = []

    def api(request):
        body = json.loads(request.content)
        sent.append(body)
        answer = {"filter": "ip.src == internal-host-1 && dns", "view": "packets", "explanation": "DNS from internal-host-1"}
        return httpx2.Response(200, json={"id": "msg_1", "type": "message", "role": "assistant", "model": body["model"],
                                          "content": [{"type": "text", "text": json.dumps(answer)}],
                                          "stop_reason": "end_turn", "stop_sequence": None,
                                          "usage": {"input_tokens": 900, "output_tokens": 40}})

    client = anthropic.AsyncAnthropic(api_key="sk-ant-test",
                                      http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(api)))
    monkeypatch.setattr(ClaudeBackend, "client", lambda self: client)
    settings = AgentSettings(directory=str(tmp_path))
    settings.update({"provider": "claude", "consent": True})
    out = asyncio.run(ask.translate_with_model(settings, "dns from 10.0.0.5", ["ip.src", "dns"]))
    [body] = sent
    assert body["model"] == "claude-opus-5-5" and body["messages"] == [{"role": "user", "content": "dns from internal-host-1"}]
    assert body["output_config"]["format"]["schema"] == ask.ASK_SCHEMA and "ip.src dns" in body["system"]
    assert out["filter"] == "ip.src == 10.0.0.5 && dns" and out["action"] == {"kind": "packets"}


# ---------------------------------------------------------------- answers from the capture

def test_questions_answered_from_the_demo_capture(engine, data_dir):
    """The answers are the capture's own numbers, and every filter they offer (the plan's,
    the tool's and each row's) is one the engine accepts."""
    import json
    import os
    import subprocess

    questions = ["who did 10.0.0.21 talk to the most?", "what did 10.0.0.44 connect to", "who connected to 52.96.36.226",
                 "top talkers", "biggest conversations", "did 10.0.0.44 talk to 203.0.113.50", "did 10.0.0.21 talk to 8.8.8.8",
                 "did 10.0.0.21 talk to www.google.com", "what is 10.0.0.21", "what ports did 10.0.0.21 use",
                 "which ports is 52.96.36.226 listening on", "most used ports", "what protocols did 10.0.0.21 use",
                 "what sites did 10.0.0.21 visit", "top domains", "how much data did 10.0.0.44 send", "when was 10.0.0.21 last seen",
                 "summarize this capture", "how many hosts are there", "who used dns", "what ip is zoom.us",
                 "what countries did 10.0.0.21 talk to", "who did 10.0.0.21 tlak to the msot"]

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(os.path.join(data_dir, "mixed_demo.pcap"))
            out = {}
            for q in questions:
                r = await c.post("/api/ask", json={"q": q, "tz": 0}, headers=AUTH)
                assert r.status == 200, q
                out[q] = await r.json()
            return out
        finally:
            await c.close()
    plans = asyncio.run(go())
    for q, plan in plans.items():
        assert plan["understood"] and plan["answer"], q

    peers = plans["who did 10.0.0.21 talk to the most?"]
    assert peers["answer"][0].startswith("10.0.0.21 talked to 22 hosts")
    assert peers["answer"][1].startswith("Most data: 142.250.72.14 (dl.google.com): 11.4 MB")
    first = peers["table"]["rows"][0]
    assert first["cells"][0] == "142.250.72.14 (dl.google.com)" and first["filter"] == "ip.addr == 10.0.0.21 && ip.addr == 142.250.72.14"
    assert plans["who did 10.0.0.21 tlak to the msot"]["answer"] == peers["answer"]
    assert plans["who did 10.0.0.21 tlak to the msot"]["read_as"] == "who did 10.0.0.21 talk to the most"
    assert plans["what did 10.0.0.44 connect to"]["table"]["rows"][0]["cells"][0] == "203.0.113.50 (backup-sync.io)"
    assert plans["who connected to 52.96.36.226"]["answer"][0].startswith("14 hosts connected to 52.96.36.226")
    assert plans["top talkers"]["answer"][0].startswith("Busiest: 142.250.72.14")
    assert plans["did 10.0.0.44 talk to 203.0.113.50"]["answer"][0].startswith("Yes: 10.0.0.44 and 203.0.113.50")
    assert plans["did 10.0.0.44 talk to 203.0.113.50"]["table"]["rows"][0]["filter"].startswith("tcp.stream == ")
    assert plans["did 10.0.0.21 talk to 8.8.8.8"]["answer"][0].startswith("No: ")
    assert plans["did 10.0.0.21 talk to www.google.com"]["answer"][0].startswith("Yes: 10.0.0.21 named www.google.com")
    who = plans["what is 10.0.0.21"]
    assert who["answer"][0].startswith("10.0.0.21: Computer") and who["table"]["facts"]
    assert {r["cells"][0] for r in who["table"]["rows"]} >= {"Address", "Device", "Traffic", "Alerts"}
    assert "TCP 443 (HTTPS)" in plans["what ports did 10.0.0.21 use"]["answer"][1]
    assert plans["which ports is 52.96.36.226 listening on"]["answer"][0].endswith("accepted connections on TCP 443 (HTTPS).")
    assert plans["what protocols did 10.0.0.21 use"]["answer"][0].startswith("10.0.0.21: TLS (")
    assert plans["top domains"]["table"]["rows"][0]["cells"][0] == "telemetry.edr-vendor.com"
    assert plans["how much data did 10.0.0.44 send"]["answer"][0].startswith("10.0.0.44 sent 6.1 MB")
    assert "last seen 14:10:16" in plans["when was 10.0.0.21 last seen"]["answer"][0]
    assert plans["summarize this capture"]["answer"][0].startswith("157,181 packets")
    assert plans["how many hosts are there"]["answer"][0].startswith("62 hosts")
    assert plans["what ip is zoom.us"]["answer"][0].startswith("zoom.us → 170.114.52.2")

    filters = set()
    for plan in plans.values():
        filters.add(plan["filter"])
        for a in (plan["action"], plan["also"]):
            if a and a.get("filter"):
                filters.add(a["filter"])
        for row in (plan.get("table") or {}).get("rows") or []:
            filters.add(row["filter"])
    filters.discard("")
    args = [engine]
    for f in sorted(filters):
        args += ["--check-filter", f]
    res = [json.loads(x) for x in subprocess.run(args, capture_output=True, text=True, check=True).stdout.splitlines()]
    assert len(res) == len(filters) and not [(r["filter"], r.get("error")) for r in res if not r["ok"]]


def test_answers_read_direction_scope_and_order():
    from anta import ask_answers as aa
    # Conversations of 10.0.0.5: it connects to two servers; one host connects to it.
    stats = {
        "conversations": {
            "ipv4": {"rows": [["10.0.0.5", None, "203.0.113.9", None, 10, 1000, 20, 9000, 0.0, 5.0, None, {"tls": 30}],
                              ["10.0.0.5", None, "10.0.0.1", None, 2, 100, 2, 200, 1.0, 0.1, None, {"dns": 4}],
                              ["10.0.0.7", None, "10.0.0.5", None, 40, 50000, 30, 3000, 2.0, 9.0, None, {"smb2": 70}]]},
            "tcp": {"rows": [["10.0.0.5", 50000, "203.0.113.9", 443, 10, 1000, 20, 9000, 0.0, 5.0, 1, {}],
                             ["10.0.0.7", 51000, "10.0.0.5", 445, 40, 50000, 30, 3000, 2.0, 9.0, 2, {}]]},
            "udp": {"rows": [["10.0.0.5", 53000, "10.0.0.1", 53, 2, 100, 2, 200, 1.0, 0.1, None, {}]]},
        },
        "hosts": [{"addr": "10.0.0.5", "tcp_serves": {"445": 1}}, {"addr": "203.0.113.9", "tcp_serves": {"443": 1}},
                  {"addr": "10.0.0.1", "udp_serves": {"53": 1}}],
    }
    ctx = aa.Ctx()

    def ask_(question):
        plan = ask.parse(question)
        return aa.answer(plan["about"], stats, ctx)

    first = lambda out: out["table"]["rows"][0]["cells"][0]  # noqa: E731
    assert first(ask_("who did 10.0.0.5 talk to the most")) == "10.0.0.7"           # (53 KB both ways)
    assert first(ask_("where did 10.0.0.5 send the most data")) == "10.0.0.7"       # (3 KB out of 10.0.0.5)
    assert first(ask_("who sent the most data to 10.0.0.5")) == "10.0.0.7"
    assert [r["cells"][0] for r in ask_("what did 10.0.0.5 connect to")["table"]["rows"]] == ["203.0.113.9", "10.0.0.1"]
    assert [r["cells"][0] for r in ask_("who connected to 10.0.0.5")["table"]["rows"]] == ["10.0.0.7"]
    assert [r["cells"][0] for r in ask_("what external hosts did 10.0.0.5 talk to")["table"]["rows"]] == ["203.0.113.9"]
    assert first(ask_("who did 10.0.0.5 talk to the least")) == "10.0.0.1"
    assert first(ask_("who did 10.0.0.5 talk to the longest")) == "10.0.0.7"
    out = ask_("what ports did 10.0.0.5 use")
    assert out["lines"] == ["10.0.0.5 accepted connections on TCP 445 (SMB).",
                            "It connected to TCP 443 (HTTPS), UDP 53 (DNS) on other hosts."]
    assert ask_("who did 10.0.0.9 talk to")["lines"] == ["10.0.0.9 has no conversations in these packets."]
