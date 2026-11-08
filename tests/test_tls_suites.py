"""TLS decryption beyond TLS 1.3's GCM/ChaCha suites and TLS 1.2 AEAD: the CBC suites in
SSL 3.0 and TLS 1.0-1.2 (AES, Camellia, SEED, Triple DES; SHA-1, SHA-256 and SHA-384 MACs,
with and without encrypt-then-MAC), AES-CCM and CCM_8 in TLS 1.2 and 1.3, ARIA-GCM, RC4,
the NULL suites, TLS 1.3 key updates from either side, TLS 1.2 renegotiation started by
either side, TLS 1.3 early data on a resumed session, and key logs that give only the
premaster secret (RSA and PMS_CLIENT_RANDOM lines), with and without the extended master
secret.

The captures in tests/fixtures/tls_suites are real OpenSSL sessions recorded on loopback
by anta.tools.tls_record, each with the key log its client wrote; the Triple DES, RC4 and
SSL 3.0 ones (which OpenSSL 3 no longer makes) are built by that tool byte for byte and
are checked by Wireshark decrypting them. The packet view must match Wireshark's with the
keys (both views), except for ARIA, which Wireshark 4.6 can't decrypt; the session
analysis must read the HTTP inside them, across every re-key.
"""
import glob
import hashlib
import os
import random

import pytest

from anta.tools import samples
from anta.tools.compare_wireshark import compare
from anta.tools.tls_record import SYNTHETIC
from conftest import ROOT, run_engine
from test_protocols import _find_tshark

FIX = os.path.join(ROOT, "tests", "fixtures", "tls_suites")
CAPTURES = sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(FIX, "*.pcap")))
WWW = [n for n in CAPTURES if n not in SYNTHETIC and
       not n.endswith(("key_update", "renegotiation", "renegotiation_cbc", "early_data"))]
WIRESHARK_CANNOT = {"tls12_aria128_gcm", "tls12_dhe_aria256_gcm"}  # (no ARIA in Wireshark 4.6)
PREMASTER_ONLY = sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(FIX, "*.rsa-only.keys")) +
                        glob.glob(os.path.join(FIX, "*.premaster.keys")))


def paths(name):
    return os.path.join(FIX, name + ".pcap"), os.path.join(FIX, name + ".keys")


def sessions(engine, pcap, *extra):
    return [r for r in run_engine(engine, "--index", "-r", pcap, *extra) if r.get("type") == "session"]


def packets(engine, pcap, *extra):
    return [r for r in run_engine(engine, "--packets", "-r", pcap, "--limit", "100000", *extra)
            if r.get("type") == "packet"]


def body_sha(status):  # what tls_record's responses carry
    return hashlib.sha256(f"status {status}\r\n".encode()).hexdigest()


def test_the_fixtures_are_all_there():
    assert len(CAPTURES) == 29 and len(WWW) == 19 and len(PREMASTER_ONLY) == 6


@pytest.mark.parametrize("name", CAPTURES)
def test_decrypted_like_wireshark(engine, name):
    pcap, keys = paths(name)
    # Without the keys nothing inside is read; with them, HTTP shows up in the packet list.
    assert not any(r["proto"] == "HTTP" for r in packets(engine, pcap))
    assert any(r["proto"] == "HTTP" for r in packets(engine, pcap, "--keylog", keys))
    tshark = _find_tshark()
    if not tshark:
        pytest.skip("no tshark to compare with")
    for two_pass in (True, False):
        result = compare(pcap, engine, tshark, show=0, two_pass=two_pass, keylog=None if name in WIRESHARK_CANNOT else keys)
        assert result["identical"] == result["frames"], (name, two_pass)


@pytest.mark.parametrize("name", WWW)
def test_every_suite_is_read_by_the_session_analysis(engine, name):
    pcap, keys = paths(name)
    assert not any((s.get("tls") or {}).get("decrypted") for s in sessions(engine, pcap))
    [s] = sessions(engine, pcap, "--keylog", keys)
    assert s["tls"]["decrypted"] is True
    assert [(h["method"], h["uri"]) for h in s["http"]] == [("GET", "/")]
    # s_server's status page, read until the connection closed, names the suite it used.
    assert len(s["http_files"]) == 1 and s["http_files"][0]["size"] > 1000


@pytest.mark.parametrize("name", sorted(SYNTHETIC))
def test_ciphers_openssl_no_longer_makes(engine, name):
    pcap, keys = paths(name)
    [s] = sessions(engine, pcap, "--keylog", keys)
    assert s["tls"]["decrypted"] is True and [h["uri"] for h in s["http"]] == ["/legacy"]
    assert [f["sha256"] for f in s["http_files"]] == [hashlib.sha256(f"synthetic {name}\n".encode()).hexdigest()]


@pytest.mark.parametrize("keylog", PREMASTER_ONLY)
def test_key_logs_with_only_the_premaster_secret(engine, keylog):
    """RSA lines (keyed by the encrypted premaster) and PMS_CLIENT_RANDOM lines: the master
    secret is computed, over the handshake when the extended master secret is in use."""
    name = keylog.split(".", 1)[0]
    pcap, keys = paths(name)
    only = os.path.join(FIX, keylog + ".keys")
    assert all(x.split()[0] in ("RSA", "PMS_CLIENT_RANDOM") for x in open(only))
    [s] = sessions(engine, pcap, "--keylog", only)
    assert s["tls"]["decrypted"] is True and [h["uri"] for h in s["http"]] == ["/"]
    full = sessions(engine, pcap, "--keylog", keys)[0]
    assert [f["sha256"] for f in s["http_files"]] == [f["sha256"] for f in full["http_files"]]
    tshark = _find_tshark()
    if tshark:
        result = compare(pcap, engine, tshark, show=0, keylog=only)
        assert result["identical"] == result["frames"]


def test_key_updates_from_both_sides(engine):
    pcap, keys = paths("tls13_key_update")
    [s] = sessions(engine, pcap, "--keylog", keys)
    assert [h["uri"] for h in s["http"]] == ["/1-before-any-update", "/2-after-the-client-update",
                                            "/3-after-an-update-requested", "/4-at-the-end"]
    # 201 answers the client's request for an update; 202 follows the server's own.
    assert [f["sha256"] for f in s["http_files"]] == [body_sha(200), body_sha(201), body_sha(202)]
    info = [r["info"] for r in packets(engine, pcap, "--keylog", keys)]
    assert info.count("Key Update") == 4


@pytest.mark.parametrize("name,uris", [
    ("tls12_renegotiation", ["/1-before-renegotiating", "/2-after-the-client-one", "/3-after-the-server-one"]),
    ("tls12_renegotiation_cbc", ["/1-before-renegotiating", "/2-after-renegotiating"])])
def test_renegotiation_moves_each_side_to_new_keys(engine, name, uris):
    pcap, keys = paths(name)
    assert sum(1 for x in open(keys) if x.startswith("CLIENT_RANDOM")) == len(uris)  # one session per handshake
    [s] = sessions(engine, pcap, "--keylog", keys)
    assert [h["uri"] for h in s["http"]] == uris
    assert [f["sha256"] for f in s["http_files"]] == [body_sha(200)]
    info = [r["info"] for r in packets(engine, pcap, "--keylog", keys)]
    # The renegotiating hellos, read under the old keys, are listed like plaintext ones.
    assert sum("Client Hello (SNI=tls.example)" in i for i in info) == len(uris)


def test_early_data(engine, tmp_path):
    pcap, keys = paths("tls13_early_data")
    first, resumed = sorted(sessions(engine, pcap, "--keylog", keys), key=lambda s: s["src_port"])
    assert not first.get("http") and first["tls"]["decrypted"]
    assert [(h["method"], h["uri"]) for h in resumed["http"]] == [("GET", "/early")]
    rows = {r["n"]: r for r in packets(engine, pcap, "--keylog", keys)}
    assert any(r["info"].startswith("Client Hello (SNI=tls.example)GET /early") for r in rows.values())
    assert any(r["info"] == "End of Early Data, Finished" for r in rows.values())
    # Without CLIENT_EARLY_TRAFFIC_SECRET the request stays unread; the rest still decrypts.
    no_early = tmp_path / "no_early.keys"
    no_early.write_text("".join(x for x in open(keys) if not x.startswith("CLIENT_EARLY_TRAFFIC_SECRET")))
    first, resumed = sorted(sessions(engine, pcap, "--keylog", str(no_early)), key=lambda s: s["src_port"])
    assert not resumed.get("http") and resumed["tls"]["decrypted"]


# ---------------------------------------------- a response read until the connection closes

def close_layouts(tmp_path):
    """An HTTPS response with no length (it ends when the server's stream does), laid out
    the ways that decide where Wireshark completes it: with the close_notify in the same
    segment, in a later one, behind a record that spans segments, after more data, or not
    at all (only the FIN)."""
    app, alert = 0x17, 0x15
    get = b"GET /s HTTP/1.1\r\nHost: x\r\n\r\n"
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
    small, big = head + b"until close", head + b"y" * 3000
    layouts = {
        "same_segment": [[(small, app), (b"\x01\x00", alert)]],
        "next_segment": [[(small, app)], [(b"\x01\x00", alert)]],
        "spanning_record": [[(big, app), (b"\x01\x00", alert)]],
        "more_data_first": [[(small, app)], [(b"more body", app)], [(b"\x01\x00", alert)]],
        "fin_only": [[(small, app)]],
    }
    from anta.tools.pcapgen import BROWSER_CIPHERS, BROWSER_EXTS, tls_client_hello, tls_server_hello
    out = {}
    for i, (name, flights) in enumerate(layouts.items()):
        ch = tls_client_hello("x", BROWSER_CIPHERS, BROWSER_EXTS, rng=random.Random(100 + i))
        sh = tls_server_hello(random.Random(200 + i), cipher=0x1301)
        cs, ss = hashlib.sha256(b"c%d" % i).digest(), hashlib.sha256(b"s%d" % i).digest()
        ex, seq = [(True, ch), (False, sh), (True, samples.tls13_record(cs, 0, get, app))], 0
        for recs in flights:
            data = b""
            for plain, inner in recs:
                data += samples.tls13_record(ss, seq, plain, inner)
                seq += 1
            ex.append((False, data))
        pcap, keys = str(tmp_path / f"{name}.pcap"), str(tmp_path / f"{name}.keys")
        samples.write_pcap(pcap, samples.tcp_session("10.9.0.5", 50000, "10.9.0.80", 443, ex))
        r = ch[11:43].hex()
        with open(keys, "w") as fh:
            fh.write(f"CLIENT_TRAFFIC_SECRET_0 {r} {cs.hex()}\nSERVER_TRAFFIC_SECRET_0 {r} {ss.hex()}\n")
        out[name] = (pcap, keys)
    return out


def test_a_response_read_until_close_completes_where_wireshark_completes_it(engine, tmp_path):
    layouts = close_layouts(tmp_path)

    def response_frame(name):  # where it completes, and whether that is the server's FIN
        pcap, keys = layouts[name]
        rows = packets(engine, pcap, "--keylog", keys)
        done = [r["n"] for r in rows if r["info"].startswith("HTTP/1.1 200 OK")]
        return (done[0], done[0] == len(rows) - 1) if done else None  # (the FIN is next to last)

    # With the close_notify in the same segment, there; otherwise TCP holds the rest of
    # the stream until the FIN and the response completes on it.
    assert response_frame("same_segment") == (10, False)
    for name in ("spanning_record", "fin_only"):
        n, at_fin = response_frame(name)
        assert at_fin, name
    tshark = _find_tshark()
    if tshark:
        for name, (pcap, keys) in layouts.items():
            for two_pass in (True, False):
                result = compare(pcap, engine, tshark, show=0, two_pass=two_pass, keylog=keys)
                assert result["identical"] == result["frames"], (name, two_pass)
