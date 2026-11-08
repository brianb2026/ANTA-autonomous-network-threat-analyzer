"""DTLS over UDP, dissected as Wireshark's DTLS heuristic does: the Protocol column follows
the session's version (a Client Hello doesn't settle it; the second pass starts from the
version the first ended on), handshake messages split across records are reassembled
("(Fragment)" until the piece ending a complete message, "(Reassembled)"), and DTLS 1.3's
unified-header records are "Encrypted Data". Records are not decrypted.

The captures in tests/fixtures/dtls are real OpenSSL 3 DTLS 1.0 and 1.2 sessions on
loopback, recorded by `python -m anta.tools.tls_record tests/fixtures/dtls dtls...` (no key
logs). The tests also lose, repeat and reorder their datagrams, put sessions back to back
on the same ports, and build a DTLS 1.3 exchange (OpenSSL 3 has no DTLS 1.3).
"""
import glob
import os
import struct

import pytest

from anta.tools import samples
from anta.tools.compare_wireshark import compare
from conftest import ROOT, run_engine
from test_protocols import _find_tshark

FIX = os.path.join(ROOT, "tests", "fixtures", "dtls")
CAPTURES = sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(FIX, "*.pcap")))


def packets(engine, pcap, *extra):
    return [r for r in run_engine(engine, "--packets", "-r", pcap, "--limit", "100000", *extra) if r.get("type") == "packet"]


def rows(engine, pcap, two_pass=True):
    return [(r["proto"], r["info"]) for r in packets(engine, pcap, *([] if two_pass else ["--single-pass"]))]


def read_pcap(path):
    data = open(path, "rb").read()
    pos, frames = 24, []
    while pos + 16 <= len(data):
        n = struct.unpack("<I", data[pos + 8:pos + 12])[0]
        frames.append(data[pos + 16:pos + 16 + n])
        pos += 16 + n
    return frames


def write(path, frames):
    samples.write_pcap(str(path), [(i * 0.01, f) for i, f in enumerate(frames)])
    return str(path)


def variants(tmp_path):
    """The recorded sessions with datagrams lost, repeated and reordered, and back to back."""
    r = read_pcap(os.path.join(FIX, "dtls12_ecdhe_gcm.pcap"))  # 4-8: the server's fragmented flight
    r10 = read_pcap(os.path.join(FIX, "dtls10_aes256_sha.pcap"))
    rm = read_pcap(os.path.join(FIX, "dtls12_aes128_sha_mtu.pcap"))
    pick = lambda *idx: [r[i - 1] for i in idx]
    rest = range(11, 19)
    made = {
        "reorder": pick(1, 2, 3, 4, 7, 6, 5, 8, 9, 10, *rest),
        "last_first": pick(1, 2, 3, 8, 4, 5, 6, 7, 9, 10, *rest),
        "dup_flight": pick(*range(1, 11), *range(4, 11), *rest),
        "drop_piece": pick(1, 2, 3, 4, 5, 7, 8, 9, 10, *rest),
        "dup_piece": pick(1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, *rest),
        "no_hvr": pick(3, 4, 5, 6, 7, 8, 9, 10, *rest),
        "server_only": pick(2, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15, 18),
        "starts_late": pick(*range(9, 19)),
        "two_sessions": r + r,
        "mixed_versions": r10 + r,
        "three": rm + r10 + r,
    }
    return {name: write(tmp_path / f"{name}.pcap", frames) for name, frames in made.items()}


def dtls13(tmp_path):
    """A DTLS 1.3 exchange: hellos naming DTLS 1.3 in supported_versions, then unified-header
    records (with and without a length, 8- and 16-bit sequence numbers), a plaintext alert,
    and a unified header in a conversation with no DTLS session (not DTLS)."""
    def rec(ct, seq, body, ver=0xfefd):
        return struct.pack(">BHH", ct, ver, 0) + seq.to_bytes(6, "big") + struct.pack(">H", len(body)) + body

    def hs(t, body):
        n = len(body).to_bytes(3, "big")
        return bytes([t]) + n + b"\x00\x00" + b"\x00\x00\x00" + n + body

    def ext(t, b):
        return struct.pack(">HH", t, len(b)) + b

    sni = b"dtls13.example"
    ch_ext = ext(0, struct.pack(">HBH", len(sni) + 3, 0, len(sni)) + sni) + ext(43, bytes([4, 0xfe, 0xfc, 0xfe, 0xfd]))
    ch = b"\xfe\xfd" + bytes(range(32)) + b"\x00\x00" + struct.pack(">HH", 2, 0x1301) + b"\x01\x00" + \
        struct.pack(">H", len(ch_ext)) + ch_ext
    sh_ext = ext(43, b"\xfe\xfc")
    sh = b"\xfe\xfd" + bytes(range(31, -1, -1)) + b"\x00" + struct.pack(">HB", 0x1301, 0) + struct.pack(">H", len(sh_ext)) + sh_ext
    blob = bytes((i * 37 + 11) & 0xFF for i in range(48))

    def uni(first, seq, data, length=True):
        return bytes([first]) + struct.pack(">H", seq) + (struct.pack(">H", len(data)) if length else b"") + data

    c, s = ("10.97.0.5", 50400), ("10.97.0.80", 4434)
    udp = lambda a, b, data: samples.udp(a[0], b[0], a[1], b[1], data)
    return write(tmp_path / "dtls13.pcap", [
        udp(c, s, rec(22, 0, hs(1, ch), ver=0xfeff)),
        udp(s, c, rec(22, 0, hs(2, sh))),
        udp(s, c, uni(0x2e, 1, blob)),
        udp(c, s, uni(0x2e, 1, blob[:40])),
        udp(s, c, uni(0x2e, 2, blob[:20]) + uni(0x2a, 3, blob[:30], length=False)),
        udp(c, s, uni(0x2f, 7, blob[:24])),
        udp(s, c, rec(21, 9, b"\x02\x28")),
        udp(("10.97.0.6", 50401), s, uni(0x2e, 1, blob)),
    ])


def test_the_fixtures_are_all_there():
    assert CAPTURES == ["dtls10_aes256_sha", "dtls12_aes128_sha_mtu", "dtls12_chacha20", "dtls12_ecdhe_gcm"]
    assert not glob.glob(os.path.join(FIX, "*.keys"))


def test_a_dtls_12_session_as_wireshark_lists_it(engine):
    pcap = os.path.join(FIX, "dtls12_ecdhe_gcm.pcap")
    two, one = rows(engine, pcap), rows(engine, pcap, two_pass=False)
    assert [i for _, i in two] == [
        "Client Hello (SNI=tls.example)", "Hello Verify Request", "Client Hello (SNI=tls.example)",
        "Server Hello, Certificate (Fragment)", "Certificate (Fragment)", "Certificate (Fragment)",
        "Certificate (Fragment)", "Certificate (Reassembled), Server Key Exchange (Fragment)",
        "Server Key Exchange (Reassembled)", "Server Hello Done",
        "Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message", "New Session Ticket",
        "Change Cipher Spec, Encrypted Handshake Message", "Application Data", "Application Data",
        "Application Data", "Encrypted Alert", "Encrypted Alert"]
    assert [i for _, i in one] == [i for _, i in two]
    # The first pass: the Client Hello settles nothing, the Hello Verify Request says DTLS
    # 1.0 (its record version), the Server Hello DTLS 1.2. The second starts at DTLS 1.2.
    assert [p for p, _ in one[:4]] == ["DTLS", "DTLSv1.0", "DTLSv1.0", "DTLSv1.2"]
    assert {p for p, _ in two} == {"DTLSv1.2"}


def test_dtls_10(engine):
    pcap = os.path.join(FIX, "dtls10_aes256_sha.pcap")
    info = [i for _, i in rows(engine, pcap)]
    assert "Certificate (Reassembled), Server Hello Done" in info
    assert info[8:10] == ["Client Key Exchange (Fragment)",
                          "Client Key Exchange (Reassembled), Change Cipher Spec, Encrypted Handshake Message"]
    assert {p for p, _ in rows(engine, pcap)} == {"DTLSv1.0"}


def test_dtls_13_unified_headers(engine, tmp_path):
    got = rows(engine, dtls13(tmp_path), two_pass=False)
    assert got == [("DTLSv1.2", "Client Hello (SNI=dtls13.example)"), ("DTLSv1.3", "Server Hello"),
                   ("DTLSv1.3", "Encrypted Data"), ("DTLSv1.3", "Encrypted Data"),
                   ("DTLSv1.3", "Encrypted Data, Encrypted Data"), ("DTLSv1.3", "Encrypted Data"),
                   ("DTLSv1.3", "Alert (Level: Fatal, Description: Handshake Failure)"),
                   ("UDP", "50401 → 4434 Len=53")]


def test_lost_repeated_and_reordered_datagrams(engine, tmp_path):
    made = variants(tmp_path)
    info = lambda name: [i for _, i in rows(engine, made[name])]
    # Out of order: whatever piece arrives last completes nothing unless it ends the message.
    assert info("reorder")[4:8] == ["Certificate (Fragment)"] * 3 + ["Certificate (Reassembled), Server Key Exchange (Fragment)"]
    assert "Certificate (Reassembled)" not in " ".join(info("drop_piece"))
    # A repeated flight: the reassembled message is complete again where its last piece is.
    assert info("dup_flight").count("Certificate (Reassembled), Server Key Exchange (Fragment)") == 2


@pytest.mark.parametrize("two_pass", [True, False])
def test_like_wireshark(engine, tmp_path, two_pass):
    tshark = _find_tshark()
    if not tshark:
        pytest.skip("no tshark to compare with")
    pcaps = [os.path.join(FIX, n + ".pcap") for n in CAPTURES] + list(variants(tmp_path).values()) + [dtls13(tmp_path)]
    for pcap in pcaps:
        result = compare(pcap, engine, tshark, show=0, two_pass=two_pass)
        assert result["identical"] == result["frames"], (os.path.basename(pcap), two_pass)


FILTERS = ["dtls", "dtls.record.content_type == 22", "dtls.record.epoch == 1", "dtls.record.version == 0xfeff",
           "dtls.handshake.type == 3", "dtls.handshake.fragment_offset > 0", "dtls.handshake.message_seq == 2",
           'dtls.handshake.extensions_server_name == "tls.example"', "dtls.handshake.ja3s", "udp && !dtls"]


def test_display_filters(engine, tmp_path):
    pcap = os.path.join(FIX, "dtls12_aes128_sha_mtu.pcap")
    hit = lambda f: [p["n"] for p in packets(engine, pcap, "-Y", f)]
    assert hit("dtls.handshake.type == 1") == [1, 3]
    assert hit("dtls.record.epoch == 1") == [7, 8, 9, 10, 11, 12, 13]
    tshark = _find_tshark()
    if not tshark:
        return
    import subprocess
    for name in CAPTURES:
        path = os.path.join(FIX, name + ".pcap")
        for f in FILTERS:
            ws = subprocess.run([tshark, "-2", "-r", path, "-Y", f, "-T", "fields", "-e", "frame.number"],
                                capture_output=True, text=True, check=True).stdout.split()
            assert [p["n"] for p in packets(engine, path, "-Y", f)] == [int(n) for n in ws], (name, f)


def test_sessions_carry_the_hellos(engine):
    for name, ja4 in [("dtls12_ecdhe_gcm", "dd2d"), ("dtls10_aes256_sha", "dd1d")]:
        [s] = [r for r in run_engine(engine, "--index", "-r", os.path.join(FIX, name + ".pcap")) if r.get("type") == "session"]
        assert s["app"] == "dtls" and s["tls"]["sni"] == "tls.example"
        assert s["tls"]["ja4"].startswith(ja4) and s["tls"]["ja4s"].startswith(ja4[:3])
        assert s["tls"]["server_version"] == (0xfefd if ja4 == "dd2d" else 0xfeff)
        assert not s["tls"].get("decrypted")
