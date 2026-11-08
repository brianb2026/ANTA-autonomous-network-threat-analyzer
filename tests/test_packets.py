"""Packet viewer: engine paging/decoding, live feed, rotation mapping, API."""
import asyncio
import json
import os
import subprocess

from aiohttp.test_utils import TestClient, TestServer

from anta.analyzer import Analyzer
from anta.packets import CaptureFiles, PacketService
from anta.server import Dashboard, allowed_hosts_for
from conftest import ENGINE, run_engine

TOKEN = "packets-test-token-0123456789"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
JSON = {**AUTH, "Content-Type": "application/json"}


def lines(engine, *args):
    out = subprocess.run([engine, *args], capture_output=True, text=True)
    return out.returncode, [json.loads(x) for x in out.stdout.splitlines() if x.strip()], out.stderr


def test_packets_mode_lists_every_frame_with_protocols(engine, data_dir):
    edge = os.path.join(data_dir, "edge_cases.pcap")
    code, recs, _ = lines(engine, "--packets", "-r", edge, "--limit", "1000", "--count")
    assert code == 0
    packets = [r for r in recs if r["type"] == "packet"]
    page = recs[-1]
    stats = next(r for r in run_engine(engine, "-r", edge) if r["type"] == "stats")
    assert len(packets) == stats["packets"] == page["matched_total"] == page["last_frame"]
    assert [p["n"] for p in packets] == list(range(1, len(packets) + 1))
    protos = {p["proto"] for p in packets}
    assert {"TCP", "HTTP", "DNS", "ARP", "IPv4"} <= protos and any(x.startswith("TLSv1") for x in protos)
    arp = next(p for p in packets if p["proto"] == "ARP")
    assert arp["info"] == "ARP Announcement for 0.0.0.0"  # sender and target 0.0.0.0, as Wireshark names it
    # IP fragments are reassembled like Wireshark does: the first points at the
    # frame that completes the datagram, which shows the UDP inside.
    (frag,) = [p for p in packets if p["info"].startswith("Fragmented IP protocol")]
    done = int(frag["info"].rsplit("#", 1)[1].rstrip("]"))
    assert next(p for p in packets if p["n"] == done)["proto"] == "UDP"
    assert any(p["info"] == "40001 → 80 [SYN] Seq=0 Win=65535 Len=0" for p in packets)  # UTF-8 arrow intact
    assert any("[FIN, ACK]" in p["info"] for p in packets)


def test_paging_filters_and_flow_scope(engine, data_dir):
    demo = os.path.join(data_dir, "mixed_demo.pcap")
    _, recs, _ = lines(engine, "--packets", "-r", demo, "--limit", "50", "--count", "-f", "udp port 53")
    page = recs[-1]
    assert page["returned"] == 50 and page["next"] and page["matched_total"] > 50
    assert all(r["proto"] in ("DNS",) for r in recs if r["type"] == "packet")
    # Page 2 starts exactly at `next` and continues the numbering.
    _, recs2, _ = lines(engine, "--packets", "-r", demo, "--limit", "5", "--from", str(page["next"]), "-f", "udp port 53")
    assert recs2[0]["n"] == page["next"]
    # Flow scope: only the 5-tuple asked for, both directions.
    _, sessions, _ = lines(engine, "-r", demo)
    beacon = next(s for s in sessions if s.get("type") == "session" and s["dst_ip"] == "192.168.1.105")
    spec = f"6,{beacon['src_ip']},{beacon['src_port']},{beacon['dst_ip']},{beacon['dst_port']}"
    _, flow_recs, _ = lines(engine, "--packets", "-r", demo, "--flow", spec, "--count", "--limit", "100")
    pkts = [r for r in flow_recs if r["type"] == "packet"]
    assert pkts and len(pkts) == flow_recs[-1]["matched_total"]
    assert all({p["src"], p["dst"]} == {beacon["src_ip"], "192.168.1.105"} for p in pkts)


def test_packet_detail_layers_and_bytes(engine, data_dir):
    edge = os.path.join(data_dir, "edge_cases.pcap")
    code, recs, _ = lines(engine, "--packet-detail", "4", "-r", edge)
    d = recs[0]
    assert code == 0 and d["proto"] == "HTTP" and d["info"] == "GET /vlan HTTP/1.1 "  # Wireshark's trailing space
    names = [layer["name"] for layer in d["layers"]]
    assert names == ["Ethernet II", "802.1Q Virtual LAN", "Internet Protocol Version 4",
                     "Transmission Control Protocol", "Hypertext Transfer Protocol"]
    raw = bytes.fromhex(d["hex"])
    assert len(raw) == d["cap"]
    for layer in d["layers"]:  # every highlight range lies inside the captured bytes
        assert layer["offset"] + layer["length"] <= len(raw)
        for _, _, off, length in layer["fields"]:
            assert off + length <= len(raw)
    vlan = d["layers"][1]
    assert vlan["fields"][2][:2] == ["ID", "100"]
    http = d["layers"][-1]
    start = http["fields"][0]
    assert raw[start[2]:start[2] + start[3]] == b"GET /vlan HTTP/1.1\r"[: start[3]]
    code, _, err = lines(engine, "--packet-detail", "99999", "-r", edge)
    assert code == 1 and "not found" in err


def test_live_feed_is_rate_limited(engine, data_dir):
    demo = os.path.join(data_dir, "mixed_demo.pcap")
    recs = run_engine(engine, "-r", demo, "--packet-feed", "50")
    feed = [r for r in recs if r["type"] == "packet"]
    stats = next(r for r in recs if r["type"] == "stats" and r["final"])
    span = feed[-1]["ts"] - feed[0]["ts"]  # token bucket runs on capture time
    assert 0 < len(feed) <= 50 * span + 50 and stats["feed_dropped"] > 0
    assert stats["feed_dropped"] + len(feed) == stats["packets"]
    assert all(b["n"] > a["n"] for a, b in zip(feed, feed[1:], strict=False))


def test_rotation_maps_frames_to_files(engine, data_dir, tmp_path):
    rec = str(tmp_path / "rec.pcap")
    recs = run_engine(engine, "-r", os.path.join(data_dir, "mixed_demo.pcap"), "-w", rec, "--write-max-mb", "20")
    rotations = [r for r in recs if r["type"] == "capture_rotated"]
    assert rotations
    files = CaptureFiles(rec, live=True)
    last = rotations[-1]
    files.rotated(last["base"], last["previous_base"])
    args = []
    for path, base in files.inputs():
        args += ["-r", path, "--frame-base", str(base)]
    # The first frame still on disk is previous_base + 1, and numbering matches the analysis run.
    _, page, _ = lines(engine, "--packets", *args, "--limit", "3")
    assert page[0]["n"] == last["previous_base"] + 1
    full = {p["n"]: p for p in (r for r in lines(engine, "--packets", "-r", os.path.join(data_dir, "mixed_demo.pcap"),
                                                 "--from", str(page[0]["n"]), "--limit", "3")[1])
            if p["type"] == "packet"}
    for p in page[:3]:  # the same frames (Info may differ: the rotated file lacks the earlier context)
        assert all(full[p["n"]][k] == p[k] for k in ("ts", "src", "dst", "len"))


def test_packet_api_and_follow_feed(engine, data_dir):
    async def go():
        dash = Dashboard(Analyzer(), ENGINE, TOKEN, allowed_hosts_for("127.0.0.1", []), set())
        queue = asyncio.Queue()
        dash.attach_sessions(queue)
        tasks = [asyncio.create_task(dash.consume(queue)), asyncio.create_task(dash.flusher())]
        client = TestClient(TestServer(dash.app(), host="127.0.0.1"))
        await client.start_server()
        try:
            r = await client.get("/api/packets", headers=AUTH)
            assert r.status == 409  # nothing loaded yet
            demo = os.path.join(data_dir, "mixed_demo.pcap")
            ws = await client.ws_connect("/ws", headers={**AUTH, "Origin": f"http://127.0.0.1:{client.port}"})
            await ws.receive_json()  # snapshot
            await ws.send_json({"type": "follow", "on": True})
            r = await client.post("/api/session", headers=JSON, json={"mode": "file", "path": demo, "speed": 1000})
            assert r.status == 200
            got = None
            for _ in range(80):
                msg = await ws.receive_json(timeout=10)
                if msg["type"] == "packets":
                    got = msg
                    break
            assert got and got["packets"] and all("n" in p and "info" in p for p in got["packets"])
            await ws.close()

            r = await client.get("/api/packets?from=1&limit=25&count=1", headers=AUTH)
            page = await r.json()
            assert r.status == 200 and len(page["packets"]) == 25 and page["matched_total"] > 100_000
            assert page["first_ts"] == page["packets"][0]["ts"]
            r = await client.get("/api/packets?filter=" + "udp port 53", headers=AUTH)
            assert all(p["proto"] == "DNS" for p in (await r.json())["packets"])
            bad = await client.get("/api/packets?filter=" + "not a ( valid filter", headers=AUTH)
            assert bad.status == 400 and "filter" in (await bad.json())["error"]
            r = await client.get("/api/packets/5", headers=AUTH)
            detail = await r.json()
            assert r.status == 200 and detail["n"] == 5 and detail["layers"] and detail["hex"]
            assert (await client.get("/api/packets/999999999", headers=AUTH)).status == 404
            assert (await client.get("/api/packets/5")).status == 401
            # Alert scope: only that alert's flows.
            await asyncio.sleep(0.5)
            for _ in range(100):
                if dash.analyzer.alerts:
                    break
                await asyncio.sleep(0.2)
            alert_id = next(iter(dash.analyzer.alerts))
            r = await client.get(f"/api/packets?alert={alert_id}&count=1", headers=AUTH)
            assert r.status == 200 and (await r.json())["matched_total"] > 0
            assert (await client.get("/api/packets?alert=nope", headers=AUTH)).status == 404
        finally:
            await dash.sessions.stop()
            for t in tasks:
                t.cancel()
            await client.close()
    asyncio.run(go())


def test_feed_without_recording_serves_ring_buffer():
    async def go():
        svc = PacketService(ENGINE)
        svc.reset(None, live=True)
        for n in range(1, 11):
            svc.on_packet({"type": "packet", "n": n, "ts": 100.0 + n, "len": 60, "cap": 60, "src": "a", "dst": "b",
                           "proto": "TCP", "info": "x" * 1000})
        page = await svc.page(5, 3)
        assert [p["n"] for p in page["packets"]] == [5, 6, 7] and page["source"] == "feed"
        assert len(page["packets"][0]["info"]) == 300  # attacker-sized strings are capped
        try:
            await svc.page(1, 10, bpf="tcp")
            raise AssertionError("filters need a recording")
        except Exception as exc:  # PacketError
            assert "recording" in str(exc)
    asyncio.run(go())


def test_http_line_cut_short_by_snaplen_does_not_hang(engine, tmp_path):
    # Found by the fuzzer: a request line with no line end in a segment the capture
    # cut short (so it can't be reassembled) used to make no progress forever.
    import struct

    from anta.tools.pcapgen import ACK, PSH, tcp_frame
    frame = tcp_frame("10.9.0.1", 40000, "10.9.0.2", 80, 1, 1, PSH | ACK, b"GET /no-line-end" + b"A" * 200)
    cut = frame[:len(frame) - 150]
    path = tmp_path / "cut.pcap"
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 1))
        fh.write(struct.pack("<IIII", 1, 0, len(cut), len(frame)))
        fh.write(cut)
    out = subprocess.run([engine, "--packets", "-r", str(path)], capture_output=True, text=True, timeout=30)
    rec = json.loads(out.stdout.splitlines()[0])
    assert out.returncode == 0 and rec["proto"] == "HTTP" and rec["info"].startswith("GET /no-line-end")
