"""HTTP/2: HPACK against RFC 7541's own examples, the packet view against Wireshark,
and the analysis reading HTTP/2 like HTTP/1.x — downloads hashed and extracted, the
detectors seeing inside — on three kinds of traffic:

  * tests/fixtures/h2_curl.pcap: real curl (nghttp2) over TLS 1.3, recorded on loopback
    with anta.tools.h2_record (parallel streams, interleaved and padded DATA, gzip);
  * samples.h2_lab(): CONTINUATION, server push, 103, trailers, PING, RST_STREAM,
    priority, frames cut across TLS records, every common status, and cleartext h2c;
  * the RFC's header blocks, Huffman-coded with a dynamic table that evicts.
"""
import hashlib
import json
import os
import subprocess

import pytest

from anta.analyzer import Analyzer
from anta.objects import list_objects
from anta.security import validate_session
from anta.tools import samples
from anta.tools.compare_wireshark import compare
from conftest import ROOT, run_engine
from test_protocols import _find_tshark

FIX = os.path.join(ROOT, "tests", "fixtures")
CURL, CURL_KEYS = os.path.join(FIX, "h2_curl.pcap"), os.path.join(FIX, "h2_curl.keys")


@pytest.fixture
def lab(tmp_path):
    frames, keylog = samples.h2_lab()
    pcap, keys = str(tmp_path / "h2.pcap"), str(tmp_path / "h2.keys")
    samples.write_pcap(pcap, frames)
    with open(keys, "w") as fh:
        fh.write(keylog)
    return pcap, keys


def sessions(engine, pcap, *extra):
    return [r for r in run_engine(engine, "--index", "-r", pcap, *extra) if r.get("type") == "session"]


def packets(engine, pcap, *extra):
    return {r["n"]: r for r in run_engine(engine, "--packets", "-r", pcap, "--limit", "100000", *extra)
            if r.get("type") == "packet"}


# --------------------------------------------------------------- HPACK (RFC 7541 Appendix C)

RFC_REQUESTS = ["828684418cf1e3c2e5f23a6ba0ab90f4ff", "828684be5886a8eb10649cbf",
                "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"]
RFC_RESPONSES = [  # C.6, behind a size update to the example's 256-byte table
    "3fe1014882640258" "85aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
    "4883640effc1c0bf",
    "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af"
    "27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007"]


def test_hpack_decodes_the_rfc_examples(engine, tmp_path):
    flights = [(True, samples.H2_PREFACE + samples.h2_frame(4, 0, 0))]
    for i, (q, r) in enumerate(zip(RFC_REQUESTS, RFC_RESPONSES, strict=True)):
        flights += [(True, samples.h2_frame(1, 5, 1 + 2 * i, bytes.fromhex(q))),
                    (False, samples.h2_frame(1, 5, 1 + 2 * i, bytes.fromhex(r)))]
    pcap = str(tmp_path / "rfc7541.pcap")
    samples.write_pcap(pcap, samples.tcp_session("10.1.1.1", 40000, "10.1.1.2", 80, flights))
    rows = [r for r in packets(engine, pcap, "--fields", "http2.header.name,http2.header.value").values()
            if r["proto"] == "HTTP2" and "HEADERS" in r["info"]]
    got = [list(zip(r["f"]["http2.header.name"], r["f"]["http2.header.value"], strict=True)) for r in rows]
    assert len(got) == 6  # request, response, three times over
    assert got[0] == [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")]
    assert got[1] == [(":status", "302"), ("cache-control", "private"), ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                      ("location", "https://www.example.com")]
    assert got[2][-1] == ("cache-control", "no-cache")
    assert got[3][0] == (":status", "307")
    assert got[4] == [(":method", "GET"), (":scheme", "https"), (":path", "/index.html"),
                      (":authority", "www.example.com"), ("custom-key", "custom-value")]
    # C.6.3 evicts from the 256-byte table; its entries must still be the right ones.
    assert got[5] == [(":status", "200"), ("cache-control", "private"), ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                      ("location", "https://www.example.com"), ("content-encoding", "gzip"),
                      ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")]


# --------------------------------------------------------------- analysis: files and detectors

def test_real_curl_http2_downloads_are_extracted(engine, tmp_path):
    expect = json.load(open(os.path.join(FIX, "h2_curl.json")))
    assert not any(s.get("http_files") for s in sessions(engine, CURL))  # nothing without the keys
    (s,) = [s for s in sessions(engine, CURL, "--keylog", CURL_KEYS) if s.get("http_files")]
    assert s["http2"] is True and s["tls"]["decrypted"] is True
    assert [h["uri"] for h in s["http"]] == list(expect)  # curl's HPACK: Huffman and its dynamic table
    assert all(h["user_agent"] == "curl/8.7.1" for h in s["http"])
    files = {f["uri"]: f for f in s["http_files"]}
    for uri, e in expect.items():
        assert files[uri]["sha256"] == e["sha256"] and files[uri]["status"] == e["status"], uri
        assert files[uri]["complete"], uri
    assert files["/page.html"]["encoded_size"] < files["/page.html"]["size"]  # gzip, decoded before hashing
    assert files["/update.exe"]["filename"] == "setup.exe"                    # Content-Disposition
    out = tmp_path / "setup.exe"
    run_engine(engine, "--object", f"{s['flow_id']}:h:{files['/update.exe']['n']}", "--object-out", str(out),
               "-r", CURL, "--keylog", CURL_KEYS)
    assert hashlib.sha256(out.read_bytes()).hexdigest() == expect["/update.exe"]["sha256"]


def test_the_download_detector_sees_inside_http2(engine):
    a = Analyzer()
    for rec in run_engine(engine, "-r", CURL, "--keylog", CURL_KEYS):
        a.ingest(rec)
    (alert,) = [x for x in a.alerts.values() if x["kind"] == "download"]
    assert alert["metrics"]["url"].startswith("https://h2.example:") and alert["metrics"]["url"].endswith("/update.exe")
    assert "curl/8.7.1" in alert["headline"] and "over HTTPS (decrypted" in alert["headline"]


def test_http2_lab_files_push_trailers_and_h2c(engine, lab):
    pcap, keys = lab
    by_uri = {}
    for s in sessions(engine, pcap, "--keylog", keys):
        assert s.get("http2")
        for f in s.get("http_files", []):
            by_uri[f["uri"]] = (s, f)
    exe = samples.windows_exe(60_000, seed=31)
    assert by_uri["/download/update.exe"][1]["sha256"] == hashlib.sha256(exe).hexdigest()  # CONTINUATION request
    assert by_uri["/s.css"][1]["size"] == 20                     # server push: its request came in a PUSH_PROMISE
    assert by_uri["/form"][1]["complete"] and by_uri["/form"][1]["status"] == 201  # ended by trailers
    assert by_uri["/index.html"][1]["size"] == 80                # after a 103, padded DATA
    assert "/cancel-me" not in by_uri and "/status/204" not in by_uri  # reset, and no body
    s, f = by_uri["/clear.txt"]                                   # cleartext h2c on port 80
    assert s["dst_port"] == 80 and "tls" not in s and f["size"] == len(b"plain HTTP/2 without TLS")
    objects = list_objects([validate_session(x) for x in sessions(engine, pcap, "--keylog", keys)])
    assert {o["proto"] for o in objects if o["location"].startswith("https://")} == {"HTTPS"}
    assert any(o["location"] == "http://h2c.example/clear.txt" for o in objects)


def test_a_broken_hpack_block_stops_that_side_only(engine, tmp_path):
    """A header block that can't be decoded leaves the sender's table unknown: nothing later
    from that side is trusted, but the engine carries on and the other side is unaffected."""
    c, s = samples.HpackEncoder(), samples.HpackEncoder()
    good = c.block([(":method", "GET"), (":scheme", "http"), (":authority", "x"), (":path", "/ok")])
    flights = [(True, samples.H2_PREFACE + samples.h2_frame(4, 0, 0) + samples.h2_frame(1, 5, 1, good)),
               (False, samples.h2_frame(1, 4, 1, s.block([(":status", "200"), ("content-length", "2")]))
                + samples.h2_frame(0, 1, 1, b"ok")),
               (True, samples.h2_frame(1, 5, 3, b"\xff\xff\xff\xff\x0f")),  # an index past any table
               (True, samples.h2_frame(1, 5, 5, c.block([(":method", "GET"), (":path", "/later")])))]
    pcap = str(tmp_path / "broken.pcap")
    samples.write_pcap(pcap, samples.tcp_session("10.1.1.1", 40000, "10.1.1.2", 80, flights))
    (sess,) = sessions(engine, pcap)
    assert [h["uri"] for h in sess["http"]] == ["/ok"]
    assert [f["status"] for f in sess["http_files"]] == [200]


# --------------------------------------------------------------- packet view

@pytest.mark.parametrize("one_pass", [False, True])
def test_http2_packet_view_matches_wireshark(engine, lab, one_pass):
    pcap, keys = lab
    mode = ["--single-pass"] if one_pass else []
    rows = packets(engine, pcap, "--keylog", keys, *mode)
    info = [r["info"] for r in rows.values()]
    assert "Magic, SETTINGS[0], WINDOW_UPDATE[0]" in info
    assert "CONTINUATION[5]" in info and "PUSH_PROMISE[1]: GET /s.css" not in info  # (cleared by the next record)
    assert "HEADERS[3]: 201 Created, DATA[3], HEADERS[3], JSON (application/json), HEADERS[7]: 200 OK" in info
    assert "DATA[5][TLS segment of a reassembled PDU]" in info                     # a frame cut across records
    assert "Magic, SETTINGS[0], HEADERS[1]: GET /clear.txt" in info                # h2c
    assert {r["proto"] for r in rows.values() if "HEADERS" in r["info"]} >= {"HTTP2"}
    # Display filters on HTTP/2 fields.
    hits = packets(engine, pcap, "--keylog", keys, "-Y", 'http2.headers.path == "/download/update.exe"', *mode)
    assert len(hits) == 1
    statuses = packets(engine, pcap, "--keylog", keys, "-Y", "http2.headers.status == 404", *mode)
    assert [r["info"].split(", ")[0] for r in statuses.values()] == ["HEADERS[31]: 404 Not Found"]
    tshark = _find_tshark()
    if tshark:
        for path, k in ((pcap, keys), (CURL, CURL_KEYS)):
            result = compare(path, engine, tshark, show=0, two_pass=not one_pass, keylog=k)
            assert result["identical"] == result["frames"]


FIELDS = ["http2.type", "http2.streamid", "http2.length", "http2.flags.end_stream", "http2.flags.eh",
          "http2.header.name", "http2.header.value", "http2.header.repr", "http2.header.index",
          "http2.header.count", "http2.headers.method", "http2.headers.path", "http2.headers.status",
          "http2.request.full_uri", "http2.request_in", "http2.response_in", "tls.reassembled_in",
          "http2.push_promise.promised_stream_id", "http2.data.data"]


@pytest.mark.parametrize("one_pass", [False, True])
def test_http2_fields_match_wireshark(engine, lab, one_pass):
    tshark = _find_tshark()
    if not tshark:
        pytest.skip("tshark not installed")
    from anta.tools.compare_wireshark import unescape
    pcap, keys = lab
    for path, k in ((pcap, keys), (CURL, CURL_KEYS)):
        cmd = [tshark, *([] if one_pass else ["-2"]), "-r", path, "-o", f"tls.keylog_file:{k}", "-T", "fields",
               "-E", "separator=\x1f", "-E", "occurrence=a", "-E", "aggregator=\x1e", "-e", "frame.number"]
        for f in FIELDS:
            cmd += ["-e", f]
        want = {}
        for line in subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.split("\n"):
            if line:
                parts = line.split("\x1f")
                want[int(parts[0])] = {f: [unescape(v).replace(":", "") if f == "http2.data.data" else
                                           ("1" if v == "True" else "0" if v == "False" else unescape(v))
                                           for v in p.split("\x1e") if v] for f, p in zip(FIELDS, parts[1:], strict=True)}
        rows = packets(engine, path, "--keylog", k, "--fields", ",".join(FIELDS), *(["--single-pass"] if one_pass else []))
        for n, w in want.items():
            got = {f: [v.replace(":", "") if f == "http2.data.data" else v for v in (rows[n].get("f") or {}).get(f, [])]
                   for f in FIELDS}
            assert got == w, f"{os.path.basename(path)} frame {n}"


def test_tls13_handshake_records_decrypt_with_handshake_secrets(engine, tmp_path):
    """curl's (and browsers') key logs carry the handshake secrets too: the encrypted
    handshake shows as Wireshark shows it, and its ALPN picks HTTP/2."""
    rows = packets(engine, CURL, "--keylog", CURL_KEYS)
    assert rows[6]["info"] == ("Server Hello, Change Cipher Spec, Encrypted Extensions, Certificate, "
                               "Certificate Verify, Finished")
    assert rows[8]["info"] == "Change Cipher Spec, Finished"
    assert packets(engine, CURL)[6]["info"].endswith("Application Data, Application Data")
    # Without the handshake secrets the handshake stays encrypted, but the application
    # data still decrypts, and HTTP/2 is still found (from the client's preface).
    with open(CURL_KEYS) as fh:
        app_only = "".join(x for x in fh if "TRAFFIC_SECRET_0" in x)
    keys = tmp_path / "app_only.keys"
    keys.write_text(app_only)
    rows = packets(engine, CURL, "--keylog", str(keys))
    assert rows[6]["info"].endswith("Application Data, Application Data")
    assert rows[10]["info"] == "Magic, SETTINGS[0], WINDOW_UPDATE[0]" and rows[12]["proto"] == "HTTP2"


# --------------------------------------------------------------- Follow TLS / HTTP/2 Stream

def _follow(engine, spec, path, keys=None):
    (res,) = run_engine(engine, "--follow", spec, "-r", path, *(["--keylog", keys] if keys else []))
    by_dir = {0: b"", 1: b""}
    for c in res["chunks"]:
        by_dir[c["dir"]] += bytes.fromhex(c["hex"])
    return res, by_dir


def test_follow_tls_and_http2_streams(engine):
    expect = json.load(open(os.path.join(FIX, "h2_curl.json")))
    tcp, raw = _follow(engine, "tcp,0", CURL)
    assert tcp["tls"] is True and not raw[0].startswith(samples.H2_PREFACE)  # the bytes are encrypted
    tls, plain = _follow(engine, "tls,0", CURL, CURL_KEYS)
    assert plain[0].startswith(samples.H2_PREFACE) and tls["h2_streams"] == [1, 3, 5, 7]
    assert (len(plain[0]), len(plain[1])) == (190, 100969)  # Wireshark's Follow TLS Stream, byte for byte
    for sid, uri in zip([1, 3, 5, 7], expect, strict=True):
        res, data = _follow(engine, f"http2,0,{sid}", CURL, CURL_KEYS)
        assert data[0].startswith(b":method: GET\n:scheme: https\n") and f":path: {uri}\n".encode() in data[0]
        body = data[1].split(b"\n\n", 1)[1]  # after the response's header block: the body, decoded
        assert hashlib.sha256(body).hexdigest() == expect[uri]["sha256"], uri
    tshark = _find_tshark()
    if tshark:  # and exactly what Wireshark's Follow shows
        for spec in ("tls,raw,0", "http2,raw,0,3", "http2,raw,0,7"):
            out = subprocess.run([tshark, "-r", CURL, "-o", f"tls.keylog_file:{CURL_KEYS}", "-q", "-z", f"follow,{spec}"],
                                 capture_output=True, text=True, check=True).stdout
            ws = {0: b"", 1: b""}
            for line in out.splitlines():
                if line and not line.startswith(("=", "Follow", "Filter", "Node")):
                    ws[0 if line.startswith("\t") else 1] += bytes.fromhex(line.strip())
            kind, _, rest = spec.partition(",raw,")
            _, ours = _follow(engine, f"{kind},{rest}", CURL, CURL_KEYS)
            assert {0: ours[0], 1: ours[1]} in ({0: ws[0], 1: ws[1]}, {0: ws[1], 1: ws[0]}), spec
