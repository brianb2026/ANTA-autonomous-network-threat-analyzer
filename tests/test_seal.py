"""The tamper seal: a capture's fingerprint recorded and compared later, and the contradictions
editing leaves inside a file that was never sealed (record lengths, time running backwards,
wrong checksums from other computers, a stretch cut out, pcapng blocks that disagree)."""
import asyncio
import os
import struct

import pytest

from anta import seal
from anta.tools import samples
from conftest import run_engine
from test_server import AUTH, make_client

PSH_ACK = 0x18
ACK = 0x10


def rows(engine, path, flt):
    out = run_engine(engine, "--packets", "-r", str(path), "--from", "1", "--limit", "5000", "-Y", flt)
    return [(float(r["ts"]), r.get("src", ""), r.get("dst", ""), r.get("len", 0), r["n"]) for r in out if r.get("type") == "packet"]


def judge(engine, path, sealed=None, sent=None):
    bad = rows(engine, path, "ip.checksum_bad || tcp.checksum_bad || udp.checksum_bad")
    out = run_engine(engine, "--packets", "-r", str(path), "--from", "1", "--limit", "5000", "-Y",
                     "tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment", "--fields", "tcp.stream")
    miss = [(float(r["ts"]), r.get("src", ""), r.get("dst", ""), r.get("len", 0), r["n"], r["f"]["tcp.stream"][0])
            for r in out if r.get("type") == "packet"]
    counts = {"bad_checksums": len(bad), "missing": len(miss), "bad_frames": [r[4] for r in bad[:20]]}
    if sent is None:  # (each bad sender's whole count, as the server reads it)
        sent = {ip: len(rows(engine, path, f"ip.src == {ip}")) for ip in {r[1] for r in bad}}
    return seal.report([(str(path), 0)], bad, miss, counts, sealed, False, sent)


def ids(r, status=None):
    return {c["id"] for c in r["checks"] if status is None or c["status"] == status}


def frames_of(path):
    data = open(path, "rb").read()
    out, off = [], 24
    while off + 16 <= len(data):
        incl = struct.unpack_from("<I", data, off + 8)[0]
        out.append(off)
        off += 16 + incl
    return bytearray(data), out


@pytest.fixture
def office(tmp_path):
    path = tmp_path / "office.pcap"
    samples.write_pcap(str(path), samples.software_lab())
    return path


def test_a_clean_capture(engine, office):
    r = judge(engine, office)
    assert r["verdict"] == "consistent" and not ids(r, "fail")
    assert {"time", "checksums", "missing"} <= ids(r, "pass") and r["packets"] == 72 and r["format"] == "pcap"
    assert len(r["fingerprint"]["sha256"]) == 64


def test_changed_bytes_break_checksums(engine, office):
    data, at = frames_of(office)
    data[at[35] + 16 + 70] ^= 0x20       # a byte of the Apache response
    data[at[4] + 16 + 14 + 8] -= 1        # one packet's TTL
    office.write_bytes(bytes(data))
    r = judge(engine, office)
    c = next(c for c in r["checks"] if c["id"] == "checksums")
    assert r["verdict"] == "edited" and c["status"] == "fail" and set(c["frames"]) == {5, 36}


def test_offloading_is_not_editing(engine, tmp_path):
    # The capturing computer's own sent packets carry wrong TCP checksums (filled in by the card later).
    frames = samples.tcp_session("10.1.1.5", 40000, "10.1.1.9", 80, [(True, b"x" * 200)] * 12)
    out = []
    for t, f in frames:
        b = bytearray(f)
        if b[14 + 12:14 + 16] == bytes([10, 1, 1, 5]):
            b[14 + 20 + 16] ^= 0xFF  # (its TCP checksum)
        out.append((t, bytes(b)))
    path = tmp_path / "offload.pcap"
    samples.write_pcap(str(path), out)
    r = judge(engine, path)
    c = next(c for c in r["checks"] if c["id"] == "checksums")
    assert c["status"] == "note" and "offloading" in c["why"] and r["verdict"] == "consistent"


def test_time_running_backwards_and_impossible_records(engine, office):
    data, at = frames_of(office)
    s20 = struct.unpack_from("<I", data, at[20])[0]
    struct.pack_into("<I", data, at[21], s20 - 5)      # frame 22: five seconds before frame 21
    struct.pack_into("<I", data, at[30] + 4, 1_500_000)  # frame 31: 1.5 million microseconds
    office.write_bytes(bytes(data))
    r = judge(engine, office)
    assert {"backwards", "fraction"} <= ids(r, "fail")
    assert 22 in next(c for c in r["checks"] if c["id"] == "backwards")["frames"]
    # A snap length smaller than what's stored; and a file cut off mid-packet.
    struct.pack_into("<I", data, 16, 60)
    office.write_bytes(bytes(data[:-10]))
    r = judge(engine, office)
    assert "snaplen" in ids(r, "fail") and "ends" in ids(r, "note")


def test_packets_dated_after_the_file_was_saved(engine, office):
    os.utime(office, (1_600_000_000, 1_600_000_000))  # (saved in 2020; packets are from 2023)
    assert "mtime" in ids(judge(engine, office), "fail")


def test_a_stretch_cut_out(engine, tmp_path):
    """Four connections stream data; ten seconds go missing from all of them at once."""
    frames = []
    conns = [("10.2.0.5", 41000 + i, "10.2.0.9", 8080) for i in range(4)]
    seq = {c: 1000 for c in conns}
    t = 0.0
    for step in range(40):
        if 20 <= step < 30:   # (the cut: these steps' packets are left out)
            for c in conns:
                seq[c] += 100
            t += 1
            continue
        for c in conns:
            cl, cp, sv, sp = c
            frames.append((t, samples.tcp(cl, sv, cp, sp, seq[c], 5000, PSH_ACK, b"d" * 100)))
            seq[c] += 100
            frames.append((t + 0.01, samples.tcp(sv, cl, sp, cp, 5000, seq[c], ACK)))
        t += 1
    path = tmp_path / "cut.pcap"
    samples.write_pcap(str(path), sorted(frames, key=lambda f: f[0]))
    r = judge(engine, path)
    c = next(c for c in r["checks"] if c["id"] == "cut")
    assert c["status"] == "fail" and "4 connections" in c["what"] and r["verdict"] == "edited"
    assert "backwards" not in ids(r)


def _block(btype, body):
    body += b"\0" * (-len(body) % 4)
    n = len(body) + 12
    return struct.pack("<II", btype, n) + body + struct.pack("<I", n)


def _opt(code, value):
    return struct.pack("<HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def pcapng(frames, writer="Dumpcap (Wireshark) 4.2.0", sections=1):
    out = b""
    for _ in range(sections):
        out += _block(seal.PCAPNG_SHB, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _opt(4, writer.encode()) + _opt(0, b""))
        out += _block(1, struct.pack("<HHI", 1, 0, 65535) + _opt(0, b""))
        for t, data in frames:
            us = int((1_700_000_000 + t) * 1e6)
            out += _block(6, struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(data), len(data)) + data)
    return out


def test_pcapng_writer_sections_and_broken_blocks(engine, tmp_path):
    frames = samples.software_lab()[:20]
    path = tmp_path / "a.pcapng"
    path.write_bytes(pcapng(frames))
    r = judge(engine, path)
    assert r["format"] == "pcapng" and r["packets"] == 20 and r["writer"].startswith("Dumpcap") and "writer" in ids(r, "pass")
    assert r["verdict"] == "consistent"
    path.write_bytes(pcapng(frames, writer="Editcap (Wireshark) 4.2.0", sections=2))
    r = judge(engine, path)
    assert {"writer", "sections"} <= ids(r, "note")
    data = bytearray(pcapng(frames))
    struct.pack_into("<I", data, len(data) - 4, 99)  # (the last block's closing length)
    path.write_bytes(bytes(data))
    assert "blocks" in ids(judge(engine, path), "fail")


def test_sealing_and_finding_a_change(office, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTA_DATA_DIR", str(tmp_path / "data"))

    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(str(office))
            d = await (await c.get("/api/seal", headers=AUTH)).json()
            assert d["verdict"] == "consistent" and d["sealed"] is None and d["names"] == ["office.pcap"]
            d = await (await c.post("/api/seal", json={}, headers=AUTH)).json()
            assert d["verdict"] == "sealed" and d["matches"] is True
            assert os.stat(seal.seals_path()).st_mode & 0o077 == 0  # (only the user can read the seals)
            data = bytearray(office.read_bytes())
            data[-5] ^= 1  # (one byte of the last packet)
            office.write_bytes(bytes(data))
            d = await (await c.get("/api/seal", headers=AUTH)).json()
            assert d["verdict"] == "changed" and d["matches"] is False
            assert next(x for x in d["checks"] if x["id"] == "seal")["status"] == "fail"
        finally:
            await c.close()
    asyncio.run(go())
