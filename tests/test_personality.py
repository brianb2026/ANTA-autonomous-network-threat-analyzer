"""Device personalities and drift: each device in one sentence, and what it does differently
from what was remembered as normal (kept in the data folder, owner-only)."""
import asyncio
import json
import os

from anta import personality
from test_server import AUTH, make_client


def P(**kw):
    base = {"ip": "10.0.0.5", "name": "", "device": "Computer", "os": "macOS", "up": 1_000_000, "down": 9_000_000,
            "peers": 12, "internet": 11, "local_peers": ["10.0.0.1"], "served": [], "clients": 0,
            "apps": {"Zoom": 5_000_000, "Slack": 1_000_000}, "app_kind": {"Zoom": "Video calls", "Slack": "Messaging"},
            "categories": {"Video calls": 5_000_000, "Messaging": 1_000_000, "News": 10}, "first": 0, "last": 1}
    base.update(kw)
    return base


def test_a_device_in_one_sentence():
    assert personality.sentence(P()) == ("A computer (macOS) that joins video calls, chats and browses the web; it mostly "
                                         "downloads; it talks to 12 hosts, 11 on the internet.")
    server = P(device="Server", os="", categories={}, up=50, down=50, peers=0, internet=0, served=["tcp/445"], clients=4)
    assert personality.sentence(server) == ("A server with little traffic of its own; it sends and receives about equally; it "
                                            "answers on SMB (TCP 445) for 4 clients.")


def test_what_changed_from_the_remembered_normal():
    old = P()
    new = P(up=40_000_000, served=["tcp/22"], local_peers=["10.0.0.1", "10.0.0.7", "10.0.0.8", "10.0.0.9", "10.0.0.10", "10.0.0.11"],
            apps={**P()["apps"], "SSH": 900}, app_kind={**P()["app_kind"], "SSH": "Remote access"},
            categories={"Video calls": 5_000_000, "Remote access": 900})
    changes = personality.drift(old, new, {"SSH": "ip.addr in {10.0.0.7}"})
    what = [c["what"] for c in changes]
    assert "New kind of traffic: remote access (SSH)." in what
    assert "Started answering on SSH (TCP 22)." in what
    assert any(w.startswith("Talks to 5 local hosts it never talked to before") for w in what)
    assert "Sends much more data: 38.1 MB, against 976.6 KB before." in what
    assert "No longer seen: messaging, news." in what
    assert all(c["notable"] for c in changes if not c["what"].startswith("No longer"))
    ssh = next(c for c in changes if c["what"].startswith("New kind"))
    assert ssh["filter"] == "ip.addr == 10.0.0.5 && ((ip.addr in {10.0.0.7}))"
    assert personality.drift(old, P(), {}) == []
    assert personality.drift(None, P(), {})[0]["what"].startswith("A device that wasn't on the network")


def test_remembered_normal_is_kept_privately(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTA_DATA_DIR", str(tmp_path))
    assert personality.load() is None
    personality.remember({"mac:aa": P()}, "first.pcap")
    personality.remember({"ip:10.0.0.9": P(ip="10.0.0.9")}, "second.pcap")  # (added to what was remembered)
    data = personality.load()
    assert set(data["devices"]) == {"mac:aa", "ip:10.0.0.9"} and data["capture"] == "second.pcap"
    if os.name != "nt":
        assert os.stat(personality.path()).st_mode & 0o777 == 0o600
    report = personality.report({"mac:aa": P(up=30_000_000)}, data, {})
    assert report["devices"][0]["notable"] == 1 and report["missing"][0]["ip"] == "10.0.0.9"
    personality.forget()
    assert personality.load() is None


def test_the_personality_endpoints(engine, data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTA_DATA_DIR", str(tmp_path))

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(os.path.join(data_dir, "mixed_demo.pcap"))
            d = await (await c.get("/api/personalities", headers=AUTH)).json()
            assert d["remembered"] is None and len(d["devices"]) >= 20
            first = next(x for x in d["devices"] if x["ip"] == "10.0.0.21")
            assert first["sentence"].startswith("A computer (macOS) that") and not first["changes"]
            r = await (await c.post("/api/personalities/remember", json={}, headers=AUTH)).json()
            assert r["remembered"]["capture"] == "mixed_demo.pcap" and not any(x["changes"] for x in r["devices"])
            saved = json.load(open(personality.path()))
            key = next(k for k, v in saved["devices"].items() if v["ip"] == "10.0.0.44")
            saved["devices"][key].update(up=40_000)
            json.dump(saved, open(personality.path(), "w"))
            d = await (await c.get("/api/personalities", headers=AUTH)).json()
            x = next(x for x in d["devices"] if x["ip"] == "10.0.0.44")
            assert x["notable"] and x["changes"][0]["what"].startswith("Sends much more data")
            items = (await (await c.get("/api/triage", headers=AUTH)).json())["items"]
            assert any(i["title"] == "10.0.0.44 changed its behavior" for i in items)
            h = await (await c.get("/api/host?addr=10.0.0.44", headers=AUTH)).json()
            assert h["personality"]["changes"]
            # A device in a serious alert comes first, marked (the page shows it in red).
            dash.analyzer.alerts["A1"] = {"id": "A1", "kind": "exfil", "severity": "high", "title": "Data Exfiltration",
                                          "src_ip": "10.0.0.44", "dst_ip": "203.0.113.50", "triage": None}
            d = await (await c.get("/api/personalities", headers=AUTH)).json()
            assert d["devices"][0]["ip"] == "10.0.0.44" and d["devices"][0]["malicious"]
            assert d["devices"][0]["alerts"] == [{"id": "A1", "title": "Data Exfiltration", "severity": "high"}]
            dash.analyzer.alerts["A1"]["triage"] = {"status": "false_positive", "note": ""}
            d = await (await c.get("/api/personalities", headers=AUTH)).json()
            assert not any(x["malicious"] for x in d["devices"])  # (dismissed: not malicious)
            r = await (await c.delete("/api/personalities", json={}, headers=AUTH)).json()
            assert r["remembered"] is None
        finally:
            await c.close()
    asyncio.run(go())
