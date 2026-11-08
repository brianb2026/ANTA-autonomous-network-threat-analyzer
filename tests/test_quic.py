"""QUIC: Initial packets are decrypted (their keys follow from the connection ID,
RFC 9001 5.2) to list their frames and read the Client Hello, as Wireshark does.

The capture is built by anta.tools.samples with a pure-Python AES-GCM; the
expected rows are what Wireshark 4.6 shows for it."""
import pytest

from anta import netmap
from anta.tools import samples
from conftest import run_engine, sessions

CLIENT, SERVER = "10.0.0.5", "203.0.113.80"


@pytest.fixture(scope="module")
def quic_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("quic") / "quic.pcap"
    samples.write_pcap(path, samples.quic_session(CLIENT, 50300, SERVER))
    return str(path)


def rows(engine, path, *args):
    return [r for r in run_engine(engine, "--packets", "-r", path, *args) if r["type"] == "packet"]


def test_packet_list_reads_like_wireshark(engine, quic_pcap):
    assert [(r["proto"], r["info"]) for r in rows(engine, quic_pcap)] == [
        ("QUIC", "Initial, DCID=c864bc90495127fe, PKN: 0, CRYPTO, PING, CRYPTO, PADDING"),
        ("QUIC", "Initial, DCID=c864bc90495127fe, PKN: 1, PING, CRYPTO, PADDING"),
        ("QUIC", "Handshake, SCID=02bc57870a00cc31"),  # coalesced after the server's Initial: the last one shows
        ("QUIC", "Protected Payload (KP0), DCID=02bc57870a00cc31"),  # the DCID length comes from the handshake
        ("QUIC", "Protected Payload (KP0)"),  # the client chose an empty connection ID
    ]


def test_client_hello_fields_and_filters(engine, quic_pcap):
    sni = rows(engine, quic_pcap, "-Y", 'quic && tls.handshake.extensions_server_name == "quic.example.com"')
    assert [r["n"] for r in sni] == [2]  # the frame that completes the Client Hello
    ja4 = rows(engine, quic_pcap, "-Y", 'tls.handshake.ja4 == "q13d1516h3_8daaf6152771_3a5cf5875c80"')
    assert [r["n"] for r in ja4] == [2]


def test_sessions_and_map_get_the_server_name(engine, quic_pcap):
    s = next(s for s in sessions(run_engine(engine, "-r", quic_pcap)) if s["proto"] == "udp")
    assert s["tls"]["sni"] == "quic.example.com" and s["tls"]["ja4"].startswith("q13")
    stats = next(r for r in run_engine(engine, "--stats", "-r", quic_pcap) if r["type"] == "stats")
    node = {n["addr"]: n for n in netmap.build(stats)["nodes"]}[SERVER]
    assert any(name == "quic.example.com" for name, _ in node["names"])


def test_tampered_initial_is_not_decrypted(engine, tmp_path):
    frames = samples.quic_session(CLIENT, 50301, SERVER)[:1]
    t, frame = frames[0]
    bad = bytearray(frame)
    bad[200] ^= 0x01  # inside the ciphertext: the AEAD tag no longer matches
    path = tmp_path / "bad.pcap"
    samples.write_pcap(path, [(t, bytes(bad))])
    assert rows(engine, str(path))[0]["info"] == "Initial, DCID=c864bc90495127fe"  # Wireshark: no PKN either
