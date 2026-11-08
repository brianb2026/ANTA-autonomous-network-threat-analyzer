"""HTTPS the user holds the keys for (an SSLKEYLOGFILE, as Wireshark's tls.keylog_file
takes): the HTTP inside it is dissected in the packet view, and indexed, extracted
and checked by the detectors the way plain HTTP is. Driven by samples.https_lab, built
from the shapes that make decrypted HTTP hard to follow: a chunked response cut across
records, pipelined messages sharing a record, a gzip body, a body with no length that
ends at close_notify, a 100 KB program in full-size records spanning many TCP
segments, and a key log holding only the server's secret.
"""
import hashlib
import subprocess

import pytest

from anta.analyzer import Analyzer
from anta.intel import IntelStore
from anta.objects import list_objects
from anta.security import validate_session
from anta.tools import samples
from anta.tools.compare_wireshark import compare
from conftest import run_engine
from test_protocols import _find_tshark

EXE = samples.windows_exe(100_000, seed=11)
PAGE = b"<html><body>" + b"compressed inside TLS " * 40 + b"</body></html>"
BODIES = {"/chunked.txt": b"split across records " * 8, "/a": b"first", "/b": b"second", "/page.html": PAGE,
          "/stream": b"until the connection closes", "/update.exe": EXE, None: b"half-open"}


@pytest.fixture
def lab(tmp_path):
    frames, keylog = samples.https_lab()
    pcap, keys = str(tmp_path / "https.pcap"), str(tmp_path / "https.keys")
    samples.write_pcap(pcap, frames)
    with open(keys, "w") as fh:
        fh.write(keylog)
    return pcap, keys


def sessions(engine, pcap, *extra):
    return [r for r in run_engine(engine, "--index", "-r", pcap, *extra) if r.get("type") == "session"]


def packets(engine, pcap, *extra):
    return {r["n"]: r for r in run_engine(engine, "--packets", "-r", pcap, "--limit", "100000", *extra)
            if r.get("type") == "packet"}


def test_files_inside_https_are_hashed_like_http(engine, lab):
    pcap, keys = lab
    plain = sessions(engine, pcap)
    assert not any(s.get("http") or s.get("http_files") or (s.get("tls") or {}).get("decrypted") for s in plain)
    found = {}
    for s in sessions(engine, pcap, "--keylog", keys):
        assert s["tls"]["decrypted"] is True
        for f in s.get("http_files", []):
            found[f.get("uri")] = f
    assert set(found) == set(BODIES)
    for uri, f in found.items():
        assert f["sha256"] == hashlib.sha256(BODIES[uri]).hexdigest(), uri
        assert f["complete"], uri
    assert found["/page.html"]["encoded_size"] < found["/page.html"]["size"]  # the gzip body, decoded
    assert found["/b"]["status"] == 404                                       # the second pipelined response
    assert "uri" not in found[None]  # only the server's secret: its response, but not the request
    # The Files list: every one marked HTTPS; the request-less one named by its TLS server name.
    objects = list_objects([validate_session(s) for s in sessions(engine, pcap, "--keylog", keys)])
    assert {o["proto"] for o in objects} == {"HTTPS"} and len(objects) == 7
    assert "https://half.example/" in {o["location"] for o in objects}
    assert next(o for o in objects if o["name"] == "update.exe")["program"]


def test_a_program_downloaded_over_https_is_extracted_whole(engine, lab, tmp_path):
    pcap, keys = lab
    flow = next(s["flow_id"] for s in sessions(engine, pcap, "--keylog", keys)
                if any(f.get("uri") == "/update.exe" for f in s.get("http_files", [])))
    out = tmp_path / "update.exe"
    run_engine(engine, "--object", f"{flow}:h:0", "--object-out", str(out), "-r", pcap, "--keylog", keys)
    assert out.read_bytes() == EXE
    # Without the keys the file isn't there to extract.
    rc = subprocess.run([engine, "--object", f"{flow}:h:0", "--object-out", str(out), "-r", pcap],
                        capture_output=True).returncode
    assert rc == 1


def analyze(engine, pcap, *extra, intel=None):
    a = Analyzer(intel=intel)
    for rec in run_engine(engine, "-r", pcap, *extra):
        a.ingest(rec)
    return list(a.alerts.values())


def test_the_download_detector_sees_inside_https(engine, lab):
    pcap, keys = lab
    assert not [a for a in analyze(engine, pcap) if a["kind"] == "download"]
    dl = [a for a in analyze(engine, pcap, "--keylog", keys) if a["kind"] == "download"]
    assert len(dl) == 1
    alert = dl[0]
    assert alert["metrics"]["url"] == "https://files.example/update.exe"
    assert alert["metrics"]["sha256"] == hashlib.sha256(EXE).hexdigest()
    assert alert["severity"] == "high"  # a program fetched by curl; 443 is the usual port for HTTPS
    assert "over HTTPS (decrypted with your TLS key log)" in alert["headline"]
    assert "unusual TCP port" not in alert["headline"]


def test_a_listed_url_is_matched_inside_https(engine, lab, tmp_path):
    pcap, keys = lab
    store = IntelStore(str(tmp_path / "intel"))
    store.import_text("urlhaus", "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
                                 '"9","2026-10-01 10:00:00","https://files.example:443/update.exe","online",'
                                 '"2026-10-01","malware_download","exe","https://urlhaus.abuse.ch/url/9/","x"\n')
    hits = lambda alerts: [a for a in alerts if a["kind"] == "intel_match" and a["intel"]["kind"] == "url"]  # noqa: E731
    assert not hits(analyze(engine, pcap, intel=store))
    found = hits(analyze(engine, pcap, "--keylog", keys, intel=store))
    assert [a["intel"]["indicator"] for a in found] == ["files.example/update.exe"]


def test_a_key_log_loaded_later_checks_the_decrypted_sessions(engine, lab):
    pcap, keys = lab
    a = Analyzer()
    for rec in run_engine(engine, "-r", pcap):
        a.ingest(rec)
    assert not [x for x in a.alerts.values() if x["kind"] == "download"]
    decrypted = sessions(engine, pcap, "--keylog", keys)
    alerts = a.check_decrypted([validate_session(s) for s in decrypted])
    assert [x["metrics"]["url"] for x in alerts if x["kind"] == "download"] == ["https://files.example/update.exe"]


@pytest.mark.parametrize("one_pass", [False, True])
def test_decrypted_http_is_dissected_like_wireshark(engine, lab, one_pass):
    pcap, keys = lab
    mode = ["--single-pass"] if one_pass else []
    rows = packets(engine, pcap, "--keylog", keys, "--fields", "tls.reassembled_in,http.request.full_uri", *mode)
    info = [r["info"] for r in rows.values()]
    assert "GET /update.exe HTTP/1.1 " in info
    # Pipelined messages sharing a frame run together in Info, exactly as Wireshark writes them.
    assert "GET /a HTTP/1.1 GET /b HTTP/1.1 " in info
    assert "HTTP/1.1 200 OK  (text/plain)HTTP/1.1 404 Not Found  (text/plain)" in info
    pieces = [r for r in rows.values() if r["info"] == "[TLS segment of a reassembled PDU]"]
    assert pieces and all(r["proto"] == "TLSv1.3" for r in pieces)
    if not one_pass:  # the look-ahead names the frame each piece was reassembled in
        assert all((r.get("f") or {}).get("tls.reassembled_in") for r in pieces)
    full = {u for r in rows.values() for u in (r.get("f") or {}).get("http.request.full_uri", [])}
    assert "https://files.example/update.exe" in full
    # Without keys it is all encrypted application data.
    assert not any(r["proto"] == "HTTP" for r in packets(engine, pcap, *mode).values())
    tshark = _find_tshark()
    if tshark:
        result = compare(pcap, engine, tshark, show=0, two_pass=not one_pass, keylog=keys)
        assert result["identical"] == result["frames"] > 200


def test_files_after_a_capture_gap_are_still_read(engine, tmp_path):
    """A TCP segment the capture missed, inside the second of three downloads on one
    connection: that file is marked incomplete, and decryption picks up again at the next
    TLS record, so the third file is still read whole."""
    import random
    from anta.tools.pcapgen import BROWSER_CIPHERS, BROWSER_EXTS, tls_client_hello, tls_server_hello
    ch = tls_client_hello("gap.example", BROWSER_CIPHERS, BROWSER_EXTS, rng=random.Random(77))
    sh = tls_server_hello(random.Random(78), cipher=0x1301)
    cs, ss = hashlib.sha256(b"gap c").digest(), hashlib.sha256(b"gap s").digest()
    seq = [0, 0]

    def rec(side, plain):
        r = samples.tls13_record(cs if side == 0 else ss, seq[side], plain)
        seq[side] += 1
        return r

    bodies = [samples.windows_exe(30_000, seed=n) for n in (1, 2, 3)]
    flights = [(True, ch), (False, sh)]
    for i, body in enumerate(bodies):
        flights.append((True, rec(0, f"GET /file{i}.exe HTTP/1.1\r\nHost: gap.example\r\n\r\n".encode())))
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body)
        flights.append((False, b"".join(rec(1, resp[j:j + 8000]) for j in range(0, len(resp), 8000))))
    frames = samples.tcp_session("10.98.0.5", 53333, "10.98.0.80", 443, flights)
    server_data = [i for i, (_, f) in enumerate(frames) if len(f) > 1000 and f[26:30] == bytes([10, 98, 0, 80])]
    drop = server_data[len(server_data) // 2]  # inside the second response
    pcap, keys = str(tmp_path / "gap.pcap"), str(tmp_path / "gap.keys")
    samples.write_pcap(pcap, frames[:drop] + frames[drop + 1:])
    with open(keys, "w") as fh:
        fh.write(f"CLIENT_TRAFFIC_SECRET_0 {ch[11:43].hex()} {cs.hex()}\nSERVER_TRAFFIC_SECRET_0 {ch[11:43].hex()} {ss.hex()}\n")
    files = {f["uri"]: f for s in sessions(engine, pcap, "--keylog", keys) for f in s.get("http_files", [])}
    assert files["/file0.exe"]["complete"] and files["/file0.exe"]["sha256"] == hashlib.sha256(bodies[0]).hexdigest()
    assert not files["/file1.exe"]["complete"]                       # the one the gap cut
    assert files["/file2.exe"]["complete"] and files["/file2.exe"]["sha256"] == hashlib.sha256(bodies[2]).hexdigest()
