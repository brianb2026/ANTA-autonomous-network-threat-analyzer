"""Share-safe copies: every address replaced by a consistent stand-in that keeps the
network's shape, what the packets carried cut away (or kept, on request, with checksums
made right for the stand-ins), and the address key written for the user alone."""
import csv
import ipaddress
import os
import shutil
import socket
import stat
import struct
import subprocess

import pytest

from anta.tools import samples
from conftest import run_engine

SECRET = "Sup3rS3cret!"  # noqa: S105 - the login lab's made-up password
TSHARK = shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark"


def read_pcap(path):
    with open(path, "rb") as fh:
        data = fh.read()
    magic, = struct.unpack("<I", data[:4])
    assert magic == 0xA1B2C3D4
    link, = struct.unpack("<I", data[20:24])
    out, off = [], 24
    while off + 16 <= len(data):
        sec, usec, caplen, wire = struct.unpack("<IIII", data[off:off + 16])
        out.append((sec + usec / 1e6, wire, data[off + 16:off + 16 + caplen]))
        off += 16 + caplen
    return link, out


def save(engine, src, dst, *extra):
    key = dst + ".key.csv"
    rec = run_engine(engine, "--packets", "-r", src, "--save", dst, "--sanitize", "--sanitize-key", key, *extra)[-1]
    with open(key, newline="") as fh:
        rows = list(csv.DictReader(fh))
    return rec, {r["real"]: r["stand_in"] for r in rows}, key


def eth_ipv6(src, dst, nh, payload, smac="02:00:00:00:00:0a", dmac="33:33:00:00:00:01"):
    hdr = struct.pack("!IHBB", 6 << 28, len(payload), nh, 64) + socket.inet_pton(socket.AF_INET6, src) \
        + socket.inet_pton(socket.AF_INET6, dst)
    return bytes.fromhex(dmac.replace(":", "")) + bytes.fromhex(smac.replace(":", "")) + b"\x86\xdd" + hdr + payload


def shape_lab():
    frames = [
        samples.udp("10.0.0.5", "10.0.0.6", 5000, 53, b"one"),
        samples.udp("10.0.0.6", "10.0.1.5", 5000, 53, b"two"),
        samples.udp("192.168.1.20", "8.8.8.8", 5001, 53, b"three"),
        samples.udp("10.0.0.5", "10.0.0.255", 138, 138, b"bcast"),
        samples.udp("10.0.0.5", "224.0.0.251", 5353, 5353, b"mdns"),
        samples.udp("10.0.0.5", "255.255.255.255", 68, 67, b"dhcp"),
        samples.arp("02:00:00:00:00:05", "10.0.0.5", tpa="10.0.0.6", oper=1),
        samples.icmp("10.0.0.1", "10.0.0.5", 5, 1, socket.inet_aton("10.0.0.254") + b"\0" * 28),  # redirect
        eth_ipv6("2001:db8:1::5", "2001:db8:1::6", 17, struct.pack("!HHHH", 1, 2, 12, 0) + b"six!"),
        eth_ipv6("fe80::1:2:3:4", "ff02::1:ff03:4", 58, b"\x87\x00\x00\x00" + b"\0" * 4
                 + socket.inet_pton(socket.AF_INET6, "2001:db8:1::5") + b"\x01\x01\x02\x00\x00\x00\x00\x0a"),
    ]
    return [(i * 0.1, f) for i, f in enumerate(frames)]


@pytest.fixture()
def shape(engine, tmp_path):
    src = str(tmp_path / "shape.pcap")
    samples.write_pcap(src, shape_lab())
    return src


def test_stand_ins_keep_the_network_shape(engine, shape, tmp_path):
    rec, key, key_path = save(engine, shape, str(tmp_path / "safe.pcap"))
    assert rec["packets"] == 10 and rec["sanitized"]["keep_payload"] is False
    a, b, c = (ipaddress.ip_address(key[x]) for x in ("10.0.0.5", "10.0.0.6", "10.0.1.5"))
    # The same /24 stays one /24, a neighbouring one becomes another; private stays private; public stays public.
    assert a in ipaddress.ip_network("10.0.0.0/8") and a.packed[:3] == b.packed[:3] != c.packed[:3]
    assert ipaddress.ip_address(key["192.168.1.20"]) in ipaddress.ip_network("192.168.0.0/16")
    assert not ipaddress.ip_address(key["8.8.8.8"]).is_private and key["8.8.8.8"] != "8.8.8.8"
    assert key["10.0.0.255"].startswith(".".join(key["10.0.0.5"].split(".")[:3])) and key["10.0.0.255"].endswith(".255")
    for kept in ("224.0.0.251", "255.255.255.255", "ff02::1"):
        assert kept not in key
    assert all(real != stand for real, stand in key.items())
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600

    _, frames = read_pcap(str(tmp_path / "safe.pcap"))
    blob = b"".join(f for _, _, f in frames)
    for real in key:  # (each packet on its own: bytes across two records could spell anything)
        packed = (bytes.fromhex(real.replace(":", "")) if real.count(":") == 5
                  else ipaddress.ip_address(real).packed)
        assert not any(packed in f for _, _, f in frames), real
    assert b"three" not in blob and b"six!" not in blob  # contents cut …
    assert [w for _, w, _ in frames] == [len(f) for _, f in shape_lab()]  # … sizes kept
    # ARP names the same stand-ins as IP; the redirect's gateway is replaced too.
    arp = frames[6][2]
    assert arp[28:32] == ipaddress.ip_address(key["10.0.0.5"]).packed
    assert frames[7][2][38:42] == ipaddress.ip_address(key["10.0.0.254"]).packed
    # IPv6: one stand-in /64 for one /64; a solicited-node address keeps matching its host.
    v6a, v6b = (ipaddress.ip_address(key[x]) for x in ("2001:db8:1::5", "2001:db8:1::6"))
    assert v6a.packed[:8] == v6b.packed[:8] and v6a in ipaddress.ip_network("2000::/3")
    ll = ipaddress.ip_address(key["fe80::1:2:3:4"])
    assert ll.packed[:8] == bytes.fromhex("fe80000000000000")
    sn = frames[9][2][14 + 24:14 + 40]
    assert sn[:13] == bytes.fromhex("ff0200000000000000000001ff") and sn[13:] == ll.packed[13:]


def test_every_copy_has_its_own_key(engine, shape, tmp_path):
    _, k1, _ = save(engine, shape, str(tmp_path / "a.pcap"))
    _, k2, _ = save(engine, shape, str(tmp_path / "b.pcap"))
    assert k1.keys() == k2.keys() and k1["10.0.0.5"] != k2["10.0.0.5"]


def test_contents_cut_unless_asked(engine, tmp_path):
    src = str(tmp_path / "logins.pcap")
    samples.write_pcap(src, samples.login_lab(SECRET))
    _, key, _ = save(engine, src, str(tmp_path / "safe.pcap"))
    _, frames = read_pcap(str(tmp_path / "safe.pcap"))
    assert not any(SECRET.encode() in f for _, _, f in frames)
    # The copy still reads as the same conversations.
    orig = [r for r in run_engine(engine, "--index", "-r", src) if r.get("type") == "session"]
    copy = [r for r in run_engine(engine, "--index", "-r", str(tmp_path / "safe.pcap")) if r.get("type") == "session"]
    assert sorted((key[r["src_ip"]], key[r["dst_ip"]], r["dst_port"], r["c2s"]["bytes"]) for r in orig) == \
        sorted((r["src_ip"], r["dst_ip"], r["dst_port"], r["c2s"]["bytes"]) for r in copy)
    assert not any(r.get("logins") for r in copy)

    rec, key, _ = save(engine, src, str(tmp_path / "keep.pcap"), "--sanitize-keep-payload", "--sanitize-shift-time")
    assert rec["sanitized"]["bytes_cut"] == 0
    _, frames = read_pcap(str(tmp_path / "keep.pcap"))
    assert frames[0][0] == 946684800.0 and any(SECRET.encode() in f for _, _, f in frames)
    users = {l["user"] for r in run_engine(engine, "--index", "-r", str(tmp_path / "keep.pcap"))
             for l in r.get("logins") or []}
    assert "alice" in users  # (contents kept: the copy reads as the original did)


@pytest.mark.skipif(not os.path.exists(TSHARK), reason="tshark not installed")
def test_wireshark_reads_the_copy_cleanly(engine, data_dir, tmp_path):
    src = os.path.join(data_dir, "http_download.pcap")
    for extra in ((), ("--sanitize-keep-payload",)):
        dst = str(tmp_path / f"copy{len(extra)}.pcap")
        save(engine, src, dst, *extra)
        bad = subprocess.run([TSHARK, "-r", dst, "-o", "tcp.check_checksum:TRUE", "-o", "ip.check_checksum:TRUE",
                              "-o", "udp.check_checksum:TRUE", "-Y",
                              "_ws.malformed || _ws.expert.severity == error || tcp.checksum.status == 0 || "
                              "ip.checksum.status == 0 || udp.checksum.status == 0"],
                             capture_output=True, text=True, check=True).stdout
        assert bad == "", bad[:500]


def test_link_types_it_cannot_clean_are_left_out(engine, tmp_path):
    src = str(tmp_path / "wifi.pcap")
    with open(src, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105))  # 802.11
        frame = b"\x08\x00\x00\x00" + b"\x02" * 18 + b"\0\0" + b"payload"
        fh.write(struct.pack("<IIII", 1_700_000_000, 0, len(frame), len(frame)) + frame)
    rec, key, _ = save(engine, src, str(tmp_path / "out.pcap"))
    assert rec["packets"] == 0 and rec["sanitized"]["unsupported"] == 1 and rec["skipped_link_type"] == 1


def test_sanitize_needs_a_save(engine, shape):
    r = subprocess.run([engine, "--packets", "-r", shape, "--sanitize"], capture_output=True, text=True)
    assert r.returncode == 2 and "--save" in r.stderr


def test_no_address_is_ever_its_own_stand_in(engine, tmp_path):
    """Over many copies (each with a fresh key): every address changes, documentation /24s
    (which keep their network) included; outside those, no real address is anywhere in a packet."""
    src = str(tmp_path / "all.pcap")
    samples.write_pcap(src, samples.all_samples())
    doc = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for i in range(25):
        out = str(tmp_path / f"copy{i}.pcap")
        _, key, _ = save(engine, src, out)
        assert key and all(real != stand for real, stand in key.items())
        _, frames = read_pcap(out)
        private = [ipaddress.ip_address(r).packed for r in key if r.count(".") == 3 and
                   not any(ipaddress.ip_address(r) in d for d in doc)]
        assert not any(b in f for b in private for _, _, f in frames)
