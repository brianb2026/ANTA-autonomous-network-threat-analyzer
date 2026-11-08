"""Apps on your network: connections named after the application they belong to, from the
TLS server name, the HTTP Host or a DNS answer for the server's address, else the protocol."""
import asyncio
import os

from anta import apps, ask
from test_server import AUTH, make_client


def S(src, dst, dport, app="tls", proto="tcp", up=100, down=1000, sni=None, host=None, dns=None):
    return {"proto": proto, "src_ip": src, "dst_ip": dst, "dst_port": dport, "app": app, "start": 1.0, "end": 2.0,
            "c2s": {"payload_bytes": up}, "s2c": {"payload_bytes": down}, "tls": {"sni": sni} if sni else {},
            "http": [{"host": host}] if host else [], "dns": dns or []}


def test_connections_named_after_their_applications():
    assert apps.by_name("us04web.zoom.us") == ("Zoom", "Video calls")
    assert apps.by_name("rr3.googlevideo.com") == ("YouTube", "Video streaming")  # (before plain google)
    assert apps.by_name("www.google.com") == ("Google search and services", "Search")
    assert apps.by_name("notzoom.us") is None and apps.by_name("") is None
    sessions = [
        S("10.0.0.5", "10.0.0.1", 53, "dns", "udp", 40, 80, dns=[{"qname": "zoom.us", "answers": ["170.114.52.2"]}]),
        S("10.0.0.5", "170.114.52.2", 443, down=5_000_000),            # named by the DNS answer
        S("10.0.0.6", "52.96.36.226", 443, sni="outlook.office365.com"),
        S("10.0.0.6", "23.48.200.11", 80, "http", host="tlu.dl.delivery.mp.microsoft.com", down=9_000_000),
        S("10.0.0.7", "10.0.5.50", 9100, "", up=200_000, down=0),        # by port: printing
        S("10.0.0.7", "10.0.5.10", 22, "ssh"),                           # by protocol
        S("10.0.0.8", "198.51.100.9", 443),                              # an unnamed HTTPS server
    ]
    out = apps.classify(sessions)
    by = {r["app"]: r for r in out["apps"]}
    assert by["Zoom"]["bytes"] == 5_000_100 and by["Zoom"]["devices"] == 1 and by["Zoom"]["filter"] == "ip.addr in {170.114.52.2}"
    assert by["Windows Update"]["category"] == "Software updates" and by["Microsoft 365"]["names"] == ["outlook.office365.com"]
    assert {"Printing", "SSH", "DNS", "Other web (HTTPS)"} <= set(by)
    assert out["apps"][0]["app"] == "Windows Update"  # (the most data first)
    assert [x["app"] for x in out["devices"]["10.0.0.7"]] == ["Printing", "SSH"]
    assert out["categories"][0]["category"] == "Software updates" and out["total"] == sum(r["bytes"] for r in out["apps"])


def test_questions_about_applications():
    assert ask.parse("what apps did 10.0.0.12 use")["about"]["kind"] == "apps"
    assert ask.parse("what is using the bandwidth")["about"]["kind"] == "apps"
    assert ask.parse("who uses zoom")["about"]["named"] == "zoom"
    assert ask.parse("which protocols does 10.0.0.5 speak")["about"]["kind"] == "protocols"


def test_the_apps_endpoint_and_answers(engine, data_dir):
    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(os.path.join(data_dir, "mixed_demo.pcap"))
            d = await (await c.get("/api/apps", headers=AUTH)).json()
            by = {r["app"]: r for r in d["apps"]}
            assert by["Zoom"]["devices"] == 16 and by["Slack"]["category"] == "Messaging"
            assert d["apps"][0]["app"] == "Google software updates"
            p = await (await c.post("/api/ask", json={"q": "who uses zoom"}, headers=AUTH)).json()
            assert p["answer"][0].startswith("Zoom: 16 devices") and p["table"]["rows"][0]["host"]
            h = await (await c.get("/api/host?addr=10.0.0.12", headers=AUTH)).json()
            assert h["apps"][0]["app"] == "Google software updates"
        finally:
            await c.close()
    asyncio.run(go())
