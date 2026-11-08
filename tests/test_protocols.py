"""Engine decoding added for inventory and hunting: database protocols (MySQL,
PostgreSQL, SQL Server) and their errors, HTTP request/response matching, the
duplicate-ACK rule with SACK, Wireshark 4.6 set syntax, application identification
by payload (DPI), server TLS fingerprints (JA3S, JA4S), the fields passive OS
fingerprinting reads, the one-click filter templates and the rolling capture buffer.

Expected values are what Wireshark 4.6 shows for the same packets."""
import hashlib
import hmac
import json
import os
import random
import struct
import subprocess

import pytest

from anta.tools import samples
from anta.tools.pcapgen import BROWSER_CIPHERS, BROWSER_EXTS, tls_client_hello, tls_server_hello
from anta.tools.samples import ACK, PSH, SACK_PERM, SYN, mss_option, tcp, tcp_session, udp
from conftest import ROOT, run_engine

TEMPLATES = os.path.join(ROOT, "anta", "web", "filter-templates.json")


def write(tmp_path, name, frames):
    path = tmp_path / name
    samples.write_pcap(path, frames)
    return str(path)


def packets(engine, path, *args):
    return [r for r in run_engine(engine, "--packets", "-r", path, "--limit", "5000", *args) if r["type"] == "packet"]


def matching(engine, path, dfilter):
    return [p["n"] for p in packets(engine, path, "-Y", dfilter)]


def index(engine, path):
    return [r for r in run_engine(engine, "--index", "-r", path) if r["type"] == "session"]


def check(engine, *filters):
    args = []
    for f in filters:
        args += ["--check-filter", f]
    return run_engine(engine, *args)


@pytest.fixture(scope="module")
def db_pcap(tmp_path_factory):
    return write(tmp_path_factory.mktemp("db"), "db.pcap", samples.database_lab())


# ------------------------------------------------------------------ databases

def test_database_packets_read_as_wireshark_shows_them(engine, db_pcap):
    rows = {(p["proto"], p["info"]) for p in packets(engine, db_pcap) if p["proto"] != "TCP"}
    for row in [("MySQL", "Server Greeting  proto=10 version=8.0.36 "), ("MySQL", "Login Request user=shop_app db=shop "),
                ("MySQL", "Response  OK "), ("MySQL", "Request Query"), ("MySQL", "Response TABULAR Response "),
                ("MySQL", "Response  Error 1146 "), ("MySQL", "Request Quit"),
                ("PGSQL", ">?"), ("PGSQL", "<R/S/K/Z"), ("PGSQL", ">Q"), ("PGSQL", "<T/D/C/Z"), ("PGSQL", "<E/Z"), ("PGSQL", ">X"),
                ("TDS", "TDS7 pre-login message"), ("TDS", "SQL batch"), ("TDS", "Response")]:
        assert row in rows, row


def test_database_errors_are_filterable(engine, db_pcap):
    assert len(matching(engine, db_pcap, 'mysql.error_code == 1146 && mysql.sqlstate == "42S02"')) == 1
    assert len(matching(engine, db_pcap, 'pgsql.type == "Error" && pgsql.code == "42P01"')) == 1
    assert len(matching(engine, db_pcap, 'tds.error.number == 208 && tds.error.msgtext contains "Payroll"')) == 1
    assert len(matching(engine, db_pcap, 'mysql.error_code || pgsql.type == "Error" || tds.error')) == 3
    assert matching(engine, db_pcap, 'mysql.query contains "orderz"')
    assert matching(engine, db_pcap, 'pgsql.query == "SELECT * FROM invoices"')
    assert matching(engine, db_pcap, 'tds.query contains "dbo.Payroll"')
    assert matching(engine, db_pcap, 'mysql.user == "shop_app" && mysql.schema == "shop"')


def test_database_detail_shows_the_error(engine, db_pcap):
    n = matching(engine, db_pcap, "mysql.error_code")[0]
    detail = run_engine(engine, "--packet-detail", str(n), "-r", db_pcap)[0]
    fields = {f[0]: f[1] for layer in detail["layers"] for f in layer["fields"]}
    assert fields["Error Code"] == "1146" and "orderz" in fields["Error message"]


def test_mysql_tls_and_pgsql_ssl_hand_over_to_tls(engine, tmp_path):
    greeting = (b"\x0a8.0.36\x00" + struct.pack("<I", 41) + b"abcdefgh\x00" + struct.pack("<H", 0xFFFF) + b"\xff" +
                struct.pack("<HH", 2, 0xDEFF) + b"\x15" + bytes(10) + b"ijklmnopqrst\x00caching_sha2_password\x00")
    ssl_login = struct.pack("<II", 0x00AFAE85, 16 << 20) + b"\xff" + bytes(23)
    hello = tls_client_hello("db.example", BROWSER_CIPHERS, BROWSER_EXTS, rng=random.Random(1))
    frames = tcp_session("10.9.0.1", 55000, "10.9.0.2", 3306, [(False, samples._mysql(0, greeting)),
                                                               (True, samples._mysql(1, ssl_login)), (True, hello)])
    frames += tcp_session("10.9.0.1", 55001, "10.9.0.3", 5432, [(True, struct.pack("!II", 8, 80877103)), (False, b"S"),
                                                               (True, hello)], t0=5)
    path = write(tmp_path, "starttls.pcap", frames)
    infos = [(p["proto"], p["info"]) for p in packets(engine, path) if p["proto"] != "TCP"]
    assert ("MySQL", "Login Request user= ") in infos and ("PGSQL", "<") in infos
    assert sum(1 for proto, info in infos if info == "Client Hello (SNI=db.example)") == 2


# ------------------------------------------------------- HTTP request matching

def test_http_responses_carry_their_request(engine, tmp_path):
    path = write(tmp_path, "http.pcap", samples.http_download("10.0.0.5", "203.0.113.80", 80, "/files/a.exe", b"MZ" + bytes(500)))
    resp = packets(engine, path, "-Y", "http.response", "--fields", "http.request_in,http.time,http.request.uri,http.request.full_uri")
    req = matching(engine, path, "http.request")
    assert len(resp) == 1 and len(req) == 1
    f = resp[0]["f"]
    assert f["http.request_in"] == [str(req[0])]
    assert f["http.request.uri"] == ["/files/a.exe"] and f["http.request.full_uri"] == ["http://203.0.113.80/files/a.exe"]
    assert float(f["http.time"][0]) > 0
    assert matching(engine, path, "http.time > 0 && http.response.code == 200") == [resp[0]["n"]]


# ------------------------------------------------------------- TCP analysis

def test_an_ack_with_sack_blocks_is_a_duplicate_even_if_the_window_changed(engine, tmp_path):
    def sack(le, re):
        return b"\x01\x01\x05\x0a" + struct.pack("!II", le, re)

    def conn(port, first_sack, second_sack):
        c, s, cs, ss = "10.1.0.1", "10.1.0.2", 101, 5001
        return [tcp(c, s, port, 80, cs - 1, 0, SYN, opts=mss_option(1460) + SACK_PERM),
                tcp(s, c, 80, port, ss - 1, cs, SYN | ACK, opts=mss_option(1460) + SACK_PERM),
                tcp(c, s, port, 80, cs, ss, ACK),
                tcp(s, c, 80, port, ss, cs, PSH | ACK, b"a" * 100),
                tcp(s, c, 80, port, ss + 200, cs, PSH | ACK, b"c" * 100),
                tcp(c, s, port, 80, cs, ss + 100, ACK, opts=sack(ss + 200, ss + 300) if first_sack else b"", window=60000),
                tcp(c, s, port, 80, cs, ss + 100, ACK, opts=sack(ss + 200, ss + 300) if second_sack else b"", window=64000)]
    frames = [(i * 0.01, f) for i, f in enumerate(conn(40001, True, True) + conn(40002, False, True) + conn(40003, True, False))]
    path = write(tmp_path, "sack.pcap", frames)
    info = {p["n"]: p["info"] for p in packets(engine, path)}
    assert info[7].startswith("[TCP Dup ACK 6#1]") and info[14].startswith("[TCP Dup ACK 13#1]")
    assert info[21].startswith("[TCP Window Update]")


# ------------------------------------------------------------ filter syntax

def test_set_elements_need_commas_as_in_wireshark_4_6(engine):
    good, *bad = check(engine, "tcp.port in {80, 443, 8000..8100}", "tcp.port in {80 443}", "tcp.port in {80,}",
                       "tcp.port in {,80}", "tcp.port in {}", 'ftp.request.command in {"USER" "PASS"}', "tcp.port in {80")
    assert good["ok"]
    assert [b["error"] for b in bad] == ['"443" was unexpected in this context.', '"}" was unexpected in this context.',
                                         '"," was unexpected in this context.', '"}" was unexpected in this context.',
                                         '""PASS"" was unexpected in this context.', "Unexpected end of filter expression."]


def test_every_filter_template_is_valid(engine):
    groups = json.load(open(TEMPLATES))["groups"]
    templates = [t for g in groups for t in g["templates"]]
    assert len(templates) >= 25 and len({t["name"] for t in templates}) == len(templates)
    for t, result in zip(templates, check(engine, *[t["filter"] for t in templates]), strict=True):
        assert result["ok"], (t["name"], result)
        assert t["about"]


def test_filter_templates_find_what_they_promise(engine, db_pcap, tmp_path):
    groups = json.load(open(TEMPLATES))["groups"]
    by_name = {t["name"]: t["filter"] for g in groups for t in g["templates"]}
    assert len(matching(engine, db_pcap, by_name["Database errors"])) == 3
    assert matching(engine, db_pcap, by_name["Database traffic"])
    lab = write(tmp_path, "lab.pcap", samples.troubleshooting_lab())
    assert matching(engine, lab, by_name["Connection resets"])
    assert matching(engine, lab, by_name["ICMP errors"])
    assert matching(engine, lab, by_name["HTTP errors"])
    assert matching(engine, lab, by_name["Login failures"])
    assert matching(engine, lab, by_name["Receiver full (zero window)"])
    every = set(matching(engine, lab, "frame"))
    hidden = set(matching(engine, lab, by_name["Hide the noise"]))
    assert hidden <= every and not (hidden & set(matching(engine, lab, by_name["Discovery chatter"])))


# --------------------------------------------------------------------- DPI

def test_applications_are_identified_by_payload_not_port(engine, tmp_path):
    frames = tcp_session("10.0.0.5", 50001, "198.51.100.9", 80, [(True, b"SSH-2.0-OpenSSH_9.6\r\n"),
                                                                 (False, b"SSH-2.0-OpenSSH_8.9p1\r\n")])
    frames += tcp_session("10.0.0.5", 50002, "198.51.100.9", 8080, [(True, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
                                                                    (False, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")], t0=2)
    frames += tcp_session("10.0.0.5", 50003, "198.51.100.9", 22, [(True, b"SSH-2.0-PuTTY_0.80\r\n"),
                                                                  (False, b"SSH-2.0-OpenSSH_9.6\r\n")], t0=4)
    path = write(tmp_path, "dpi.pcap", frames)
    by_port = {r["dst_port"]: r for r in index(engine, path)}
    assert (by_port[80]["app"], by_port[80]["app_source"], by_port[80]["app_expected"]) == ("ssh", "payload", "http")
    assert by_port[8080]["app"] == "http" and by_port[8080].get("app_expected") is None  # HTTP on an HTTP port
    assert by_port[22]["app"] == "ssh" and by_port[22].get("app_expected") is None


def test_ftp_and_smtp_greetings_are_told_apart(engine, tmp_path):
    # Both greet with 220: the client's first command decides, else the greeting's first line
    # (FTP's later "331 Send email" is not mail).
    frames = tcp_session("10.0.0.5", 50001, "198.51.100.9", 21, [(False, b"220 Service ready\r\n"),
                                                                 (True, b"USER anonymous\r\n"),
                                                                 (False, b"331 Send email as password\r\n")])
    frames += tcp_session("10.0.0.5", 50002, "198.51.100.9", 2121, [(False, b"220 mail.example.com FTP server\r\n")], t0=2)
    frames += tcp_session("10.0.0.5", 50003, "198.51.100.9", 25, [(False, b"220 relay ready\r\n"), (True, b"EHLO me\r\n")], t0=4)
    by_port = {r["dst_port"]: r for r in index(engine, write(tmp_path, "greet.pcap", frames))}
    assert by_port[21]["app"] == "ftp" and by_port[21].get("app_expected") is None
    assert by_port[2121]["app"] == "ftp" and by_port[25]["app"] == "smtp"


# ---------------------------------------------------------- JA3S and JA4S

def ja3s_ja4s(server_hello: bytes):
    """Independent implementation of both, from the published definitions."""
    hs = server_hello[5:]
    body = hs[4:]
    legacy, = struct.unpack("!H", body[:2])
    sid_len = body[34]
    at = 35 + sid_len
    cipher, = struct.unpack("!H", body[at:at + 2])
    at += 3
    ext_total, = struct.unpack("!H", body[at:at + 2])
    at += 2
    exts, version = [], legacy
    end = at + ext_total
    while at < end:
        etype, elen = struct.unpack("!HH", body[at:at + 4])
        data = body[at + 4:at + 4 + elen]
        if (etype & 0x0F0F) != 0x0A0A:
            exts.append(etype)
        if etype == 0x002B:
            version, = struct.unpack("!H", data[:2])
        at += 4 + elen
    ja3s_text = f"{legacy},{cipher},{'-'.join(str(e) for e in exts)}"
    vers = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}[version]
    ja4s = f"t{vers}{len(exts):02d}00_{cipher:04x}_" + hashlib.sha256(",".join(f"{e:04x}" for e in exts).encode()).hexdigest()[:12]
    return hashlib.md5(ja3s_text.encode(), usedforsecurity=False).hexdigest(), ja3s_text, ja4s  # JA3S is defined as MD5


def test_server_fingerprints_match_the_reference(engine, tmp_path):
    rng = random.Random(7)
    sh = tls_server_hello(rng, cipher=0x1302)
    frames = tcp_session("10.0.0.5", 50010, "203.0.113.9", 443, [
        (True, tls_client_hello("fp.example", BROWSER_CIPHERS, BROWSER_EXTS, rng=rng)), (False, sh)])
    path = write(tmp_path, "sh.pcap", frames)
    tls = index(engine, path)[0]["tls"]
    want_ja3s, want_text, want_ja4s = ja3s_ja4s(sh)
    assert (tls["ja3s"], tls["ja3s_string"], tls["ja4s"]) == (want_ja3s, want_text, want_ja4s)
    p = packets(engine, path, "-Y", "tls.handshake.type == 2", "--fields", "tls.handshake.ja3s,tls.handshake.ja3s_full")[0]
    assert p["f"]["tls.handshake.ja3s"] == [want_ja3s] and p["f"]["tls.handshake.ja3s_full"] == [want_text]


# ------------------------------------------------- passive OS fingerprinting

def with_macs(frame: bytes, dst: str, src: str) -> bytes:
    return bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", "")) + frame[12:]


def dhcp_discover(mac: str, prl: list[int], vendor: bytes) -> bytes:
    hw = bytes.fromhex(mac.replace(":", ""))
    bootp = struct.pack("!BBBBIHH", 1, 1, 6, 0, 0x1234, 0, 0x8000) + bytes(16) + hw + bytes(10) + bytes(192)
    opts = b"\x63\x82\x53\x63" + b"\x35\x01\x01" + bytes([55, len(prl)]) + bytes(prl) + bytes([60, len(vendor)]) + vendor + b"\xff"
    return with_macs(udp("0.0.0.0", "255.255.255.255", 68, 67, bootp + opts), "ff:ff:ff:ff:ff:ff", mac)  # noqa: S104


def mdns_announcement(service: str, instance: str) -> bytes:
    def name(n):
        return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0"
    rdata = name(instance)
    msg = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + name(service) + struct.pack("!HHIH", 12, 1, 120, len(rdata)) + rdata
    return msg


WINDOWS_PRL = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
WINDOWS_SYN_OPTS = mss_option(1460) + b"\x01\x03\x03\x08\x01\x01\x04\x02"


def fingerprint_lab():
    win_mac, gw_mac, cast_mac = "02:aa:00:00:00:0a", "02:aa:00:00:00:01", "02:aa:00:00:00:20"
    syn = tcp("10.40.0.10", "10.40.0.1", 50000, 445, 1000, 0, SYN, opts=WINDOWS_SYN_OPTS, window=64240)
    syn = syn[:22] + bytes([128]) + syn[23:]  # Windows starts at TTL 128 (the IP checksum isn't checked)
    synack = tcp("10.40.0.1", "10.40.0.10", 445, 50000, 7000, 1001, SYN | ACK, opts=mss_option(1460))
    cast = udp("10.40.0.20", "224.0.0.251", 5353, 5353, mdns_announcement("_googlecast._tcp.local", "Living-Room._googlecast._tcp.local"))
    return [(0.0, dhcp_discover(win_mac, WINDOWS_PRL, b"MSFT 5.0")),
            (0.5, with_macs(syn, gw_mac, win_mac)), (0.51, with_macs(synack, win_mac, gw_mac)),
            (1.0, with_macs(cast, "01:00:5e:00:00:fb", cast_mac))]


def test_fingerprint_fields(engine, tmp_path):
    path = write(tmp_path, "fp.pcap", fingerprint_lab())
    syn = packets(engine, path, "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "--fields", "tcp.option_kind")[0]
    assert syn["f"]["tcp.option_kind"] == ["2", "1", "3", "1", "1", "4"]
    dhcp = packets(engine, path, "-Y", "dhcp", "--fields", "dhcp.option.request_list_item")[0]
    assert dhcp["f"]["dhcp.option.request_list_item"] == [str(x) for x in WINDOWS_PRL]
    assert matching(engine, path, "dhcp.option.request_list_item == 252") == [dhcp["n"]]


# ------------------------------------------------------- rolling capture buffer

def test_recording_keeps_only_the_newest_segments(engine, data_dir, tmp_path):
    rec = tmp_path / "ring.pcap"
    run_engine(engine, "-r", os.path.join(data_dir, "mixed_demo.pcap"), "-w", str(rec), "--write-max-mb", "1",
               "--write-keep", "3")
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == ["ring.pcap", "ring.pcap.1", "ring.pcap.2", "ring.pcap.3"]
    for p in tmp_path.iterdir():
        assert p.stat().st_size <= (1 << 20) + 70000 and (p.stat().st_mode & 0o077) == 0


# ---------------------------------------------- TLS decryption from a key log

# TLS 1.3 suites: (cipher, secret length, HKDF hash, seal function name).
TLS13_SUITES = {0x1301: (32, False, "aes128_gcm_seal"), 0x1302: (48, True, "aes256_gcm_seal"),
                0x1303: (32, False, "chacha20_poly1305_seal")}


def _tls13_record(cipher, secret, seq, plaintext, inner=0x17):
    """One TLS 1.3 record sealed with keys derived from a traffic secret, for any suite."""
    from anta.tools import samples as s
    _, sha384, seal = TLS13_SUITES[cipher]
    key_len = 16 if cipher == 0x1301 else 32
    key = s.hkdf_expand_label(secret, "key", key_len, sha384)
    iv = s.hkdf_expand_label(secret, "iv", 12, sha384)
    nonce = bytes(a ^ b for a, b in zip(iv, (0).to_bytes(4, "big") + seq.to_bytes(8, "big"), strict=True))
    inner_plain = plaintext + bytes([inner])
    hdr = b"\x17\x03\x03" + struct.pack("!H", len(inner_plain) + 16)
    return hdr + getattr(s, seal)(key, nonce, hdr, inner_plain)


def _tls13_capture(tmp_path, cipher=0x1301):
    """A TLS 1.3 session over TCP and the matching key log, with the client random
    taken from a real ClientHello so Wireshark keys it too."""
    slen = TLS13_SUITES[cipher][0]
    ch = tls_client_hello("decrypt.example", BROWSER_CIPHERS, BROWSER_EXTS, rng=random.Random(1))
    client_random = ch[11:43]
    sh = tls_server_hello(random.Random(2), cipher=cipher)
    cas = bytes((i * 7 + 1) & 0xFF for i in range(slen))
    sas = bytes((i * 5 + 3) & 0xFF for i in range(slen))
    req = b"GET /secret.html HTTP/1.1\r\nHost: decrypt.example\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 11\r\n\r\nhello world"
    frames = tcp_session("10.90.0.5", 51000, "10.90.0.80", 443, [
        (True, ch), (False, sh),
        (True, _tls13_record(cipher, cas, 0, req)), (False, _tls13_record(cipher, sas, 0, resp)),
        (True, _tls13_record(cipher, cas, 1, b"GET /again HTTP/1.1\r\nHost: decrypt.example\r\n\r\n"))])
    pcap = str(tmp_path / f"tls13_{cipher:04x}.pcap")
    keys = str(tmp_path / f"tls13_{cipher:04x}.keys")
    samples.write_pcap(pcap, frames)
    with open(keys, "w") as fh:
        fh.write(f"CLIENT_TRAFFIC_SECRET_0 {client_random.hex()} {cas.hex()}\n")
        fh.write(f"SERVER_TRAFFIC_SECRET_0 {client_random.hex()} {sas.hex()}\n")
    return pcap, keys


@pytest.mark.parametrize("cipher", [0x1301, 0x1302, 0x1303])
def test_tls13_records_decrypt_with_a_key_log(engine, tmp_path, cipher):
    pcap, keys = _tls13_capture(tmp_path, cipher)
    # Without keys, the application-data records stay encrypted.
    plain = {p["n"]: p["info"] for p in packets(engine, pcap)}
    assert plain[8] == "Application Data" and plain[10] == "Application Data"
    # With the key log, each record is decrypted and dissected as HTTP (Info exactly as
    # Wireshark writes it), and the counter self-synchronises (client seq 0 then 1, server seq 0).
    rows = {p["n"]: p for p in packets(engine, pcap, "--keylog", keys)}
    dec = {n: p["info"] for n, p in rows.items()}
    assert dec[8] == "GET /secret.html HTTP/1.1 "
    assert dec[10] == "HTTP/1.1 200 OK  (text/html)"
    assert dec[12] == "GET /again HTTP/1.1 "
    assert rows[8]["proto"] == rows[10]["proto"] == "HTTP"
    detail = run_engine(engine, "--packet-detail", "10", "-r", pcap, "--keylog", keys)[0]
    fields = {f[0]: f[1] for ly in detail["layers"] for f in ly["fields"]}
    assert fields["Inner Content Type"] == "Application Data (23)"
    assert fields["Decrypted"].endswith("hello world")


@pytest.mark.parametrize("cipher", [0x1301, 0x1302, 0x1303])
def test_tls13_decryption_matches_wireshark(engine, tmp_path, cipher):
    """ANTA's decrypted plaintext equals what tshark decrypts with the same key log."""
    tshark = _find_tshark()
    if not tshark:
        pytest.skip("tshark not installed")
    pcap, keys = _tls13_capture(tmp_path, cipher)
    out = subprocess.run([tshark, "-r", pcap, "-o", f"tls.keylog_file:{keys}", "-2", "-T", "fields",
                          "-e", "frame.number", "-e", "http.request.uri", "-e", "http.file_data"],
                         capture_output=True, text=True).stdout
    rows = dict(line.split("\t", 1) for line in out.splitlines() if "\t" in line)
    assert rows.get("8", "").startswith("/secret.html")          # tshark decrypts the request
    assert "68656c6c6f20776f726c64" in rows.get("10", "")         # "hello world" in the decrypted body
    dec = {p["n"]: p["info"] for p in packets(engine, pcap, "--keylog", keys)}
    assert dec[8] == "GET /secret.html HTTP/1.1 " and dec[10] == "HTTP/1.1 200 OK  (text/html)"


def _find_tshark():
    import shutil
    for c in (shutil.which("tshark"), "/Applications/Wireshark.app/Contents/MacOS/tshark"):
        if c and os.path.exists(c):
            return c
    return None


def _tls12_capture(tmp_path, cipher=0xC02F):
    """A minimal TLS 1.2 AEAD session over TCP and a CLIENT_RANDOM master-secret key log."""
    import hashlib
    from anta.tools import samples as s
    sha384 = cipher in (0xC030, 0xC02C, 0x009D, 0x009F)
    chacha = cipher in (0xCCA8, 0xCCA9, 0xCCAA)
    key_len = 16 if cipher in (0xC02F, 0xC02B, 0x009C, 0x009E) else 32
    fixed = 12 if chacha else 4

    def prf(secret, label, seed, n):
        algo = hashlib.sha384 if sha384 else hashlib.sha256
        ls, out, a = label + seed, b"", hmac.new(secret, label + seed, algo).digest()
        while len(out) < n:
            out += hmac.new(secret, a + ls, algo).digest()
            a = hmac.new(secret, a, algo).digest()
        return out[:n]

    cr, srv_r, master = bytes(range(32)), bytes(range(100, 132)), bytes(range(48))
    kb = prf(master, b"key expansion", srv_r + cr, 2 * key_len + 2 * fixed)
    ck, sk = kb[:key_len], kb[key_len:2 * key_len]
    civ, siv = kb[2 * key_len:2 * key_len + fixed], kb[2 * key_len + fixed:2 * key_len + 2 * fixed]
    seal = s.chacha20_poly1305_seal if chacha else (s.aes256_gcm_seal if key_len == 32 else s.aes128_gcm_seal)

    def rec(key, fiv, seq, ctype, plain):
        aad = seq.to_bytes(8, "big") + bytes([ctype]) + b"\x03\x03" + struct.pack("!H", len(plain))
        if chacha:
            nonce = bytes(a ^ b for a, b in zip(fiv, (0).to_bytes(4, "big") + seq.to_bytes(8, "big"), strict=True))
            body = seal(key, nonce, aad, plain)
        else:
            body = seq.to_bytes(8, "big") + seal(key, fiv + seq.to_bytes(8, "big"), aad, plain)
        return bytes([ctype]) + b"\x03\x03" + struct.pack("!H", len(body)) + body

    def hs(t, b):
        return bytes([t]) + struct.pack("!I", len(b))[1:] + b

    def hrec(p):
        return b"\x16\x03\x03" + struct.pack("!H", len(p)) + p
    ch = b"\x16\x03\x01" + struct.pack("!H", len(hs(1, b"\x03\x03" + cr + b"\x00" + struct.pack("!H", 2)
         + struct.pack("!H", cipher) + b"\x01\x00" + struct.pack("!H", 0)))) \
         + hs(1, b"\x03\x03" + cr + b"\x00" + struct.pack("!H", 2) + struct.pack("!H", cipher) + b"\x01\x00" + struct.pack("!H", 0))
    sh = hrec(hs(2, b"\x03\x03" + srv_r + b"\x00" + struct.pack("!H", cipher) + b"\x00" + struct.pack("!H", 0))) \
        + hrec(hs(11, b"\x00\x00\x00")) + hrec(hs(14, b""))
    ccs = b"\x14\x03\x03\x00\x01\x01"
    req = b"GET /secret.html HTTP/1.1\r\nHost: tls12.example\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world"
    frames = tcp_session("10.91.0.5", 52000, "10.91.0.80", 443, [
        (True, ch), (False, sh), (True, hrec(hs(16, b"\x00")) + ccs + rec(ck, civ, 0, 22, hs(20, bytes(12)))),
        (False, ccs + rec(sk, siv, 0, 22, hs(20, bytes(12)))),
        (True, rec(ck, civ, 1, 23, req)), (False, rec(sk, siv, 1, 23, resp))])
    pcap, keys = str(tmp_path / f"tls12_{cipher:04x}.pcap"), str(tmp_path / f"tls12_{cipher:04x}.keys")
    samples.write_pcap(pcap, frames)
    open(keys, "w").write(f"CLIENT_RANDOM {cr.hex()} {master.hex()}\n")
    return pcap, keys


@pytest.mark.parametrize("cipher", [0xC02F, 0xC030, 0xCCA8])
def test_tls12_decrypts_and_matches_wireshark(engine, tmp_path, cipher):
    pcap, keys = _tls12_capture(tmp_path, cipher)
    enc = {p["n"]: p["info"] for p in packets(engine, pcap)}
    assert enc[12] == "Application Data"                           # encrypted without keys
    dec = {p["n"]: p["info"] for p in packets(engine, pcap, "--keylog", keys)}
    assert dec[12] == "GET /secret.html HTTP/1.1 " and dec[14] == "HTTP/1.1 200 OK "
    tshark = _find_tshark()
    if tshark:
        out = subprocess.run([tshark, "-r", pcap, "-o", f"tls.keylog_file:{keys}", "-2", "-T", "fields",
                              "-e", "frame.number", "-e", "http.file_data"], capture_output=True, text=True).stdout
        assert "68656c6c6f20776f726c64" in out                    # tshark decrypts the same "hello world"


# ------------------------------------------------- HTTP pipelining, as Wireshark pairs it

def _http_fields(engine, path, *mode):
    out = {}
    for r in run_engine(engine, "--packets", "-r", path, "--fields",
                        "http.request.full_uri,http.request_in,http.response_in", *mode):
        if r.get("type") == "packet" and r["proto"] == "HTTP":
            f = r.get("f") or {}
            out[r["n"]] = (f.get("http.request.full_uri", []), f.get("http.request_in", []), f.get("http.response_in", []))
    return out


def test_pipelined_http_pairs_like_wireshark(engine, tmp_path):
    """Wireshark pairs a response with the newest request still unanswered (not the oldest),
    and its file view shows every message in a frame with the pair of the frame's last one."""
    get = lambda u: f"GET {u} HTTP/1.1\r\nHost: pipe.example\r\n\r\n".encode()  # noqa: E731
    ok = lambda b: b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(b)).encode() + b"\r\n\r\n" + b  # noqa: E731
    sep, mix = str(tmp_path / "sep.pcap"), str(tmp_path / "mix.pcap")
    samples.write_pcap(sep, tcp_session("10.1.1.1", 40000, "10.1.1.2", 80, [
        (True, get("/a")), (True, get("/b")), (True, get("/c")), (False, ok(b"A")), (False, ok(b"B")), (False, ok(b"C"))]))
    samples.write_pcap(mix, tcp_session("10.1.1.1", 40001, "10.1.1.2", 80, [
        (True, get("/a") + get("/b")), (False, ok(b"A")), (True, get("/c")), (False, ok(b"B") + ok(b"C"))]))
    u = "http://pipe.example/"
    s = _http_fields(engine, sep)
    assert s[8] == ([u + "c"], [], ["10"]) and s[10] == ([u + "c"], ["8"], [])  # the first response takes /c
    assert s[12] == ([], [], []) and s[14] == ([], [], [])                       # the rest stand alone
    m = _http_fields(engine, mix)
    assert m[4] == ([u + "b", u + "b"], [], ["6", "6"])  # both requests shown with the frame's last pair
    assert m[10] == ([], [], [])                         # two responses: the frame's last stands alone
    live = _http_fields(engine, mix, "--single-pass")
    assert live[4][0] == [u + "a", u + "b"] and live[10] == ([u + "c"], ["8"], [])
    tshark = _find_tshark()
    if tshark:  # and the same, field by field, in Wireshark
        for path in (sep, mix):
            for two_pass in (True, False):
                out = subprocess.run([tshark, *(["-2"] if two_pass else []), "-r", path, "-Y", "http", "-T", "fields",
                                      "-E", "occurrence=a", "-E", "aggregator=,", "-e", "frame.number",
                                      "-e", "http.request.full_uri", "-e", "http.request_in", "-e", "http.response_in"],
                                     capture_output=True, text=True).stdout
                ours = _http_fields(engine, path, *([] if two_pass else ["--single-pass"]))
                for line in out.splitlines():
                    n, *cols = line.split("\t")
                    assert tuple(c.split(",") if c else [] for c in cols) == ours[int(n)], (path, two_pass, n)


# ------------------------------------------------- media types, as Wireshark's dissectors take them

MEDIA_CASES = [
    ("application/xml", b"x"), ("application/xml", b"xx"), ("application/xhtml+xml", b"<html/>"),
    ("application/x-wms-logplaystats", b"x"), ("application/x-wms-logplaystats", b"<a/>"),
    ("image/webp", b"RIFF"), ("image/webp", b"RIFF\x04\x00\x00\x00WEBP"),
    ("image/webp", b"RIFF\x0e\x00\x00\x00WEBPVP8 \x01\x00\x00\x00A\x00"), ("image/webp", b"not riff"),
    ("image/gif", b"GIF89a\x01\x00\x01\x00\x00\x00\x00;"),
    ("image/gif", b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00"),
    ("image/png", b"not a png"), ("application/javascript", b"x"), ("text/javascript", b"x"),
    ("application/dns-message", bytes(12)), ("application/grpc", bytes(5)), ("application/sdp", b"v=0\r\n"),
]


def test_media_bodies_are_labelled_like_wireshark(engine, tmp_path):
    h1, h2 = str(tmp_path / "media1.pcap"), str(tmp_path / "media2.pcap")
    flights = []
    for ct, body in MEDIA_CASES:
        flights += [(True, b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"), (False, b"HTTP/1.1 200 OK\r\nContent-Type: " + ct.encode()
                    + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)]
    samples.write_pcap(h1, tcp_session("10.1.1.1", 40000, "10.1.1.2", 80, flights))
    enc = samples.HpackEncoder()
    flights = [(True, samples.H2_PREFACE)]
    for i, (ct, body) in enumerate(MEDIA_CASES):
        flights.append((False, samples.h2_frame(1, 4, 1 + 2 * i, enc.block([(":status", "200"), ("content-type", ct)]))
                        + samples.h2_frame(0, 1, 1 + 2 * i, body)))
    samples.write_pcap(h2, tcp_session("10.1.1.1", 40001, "10.1.1.2", 80, flights))
    one = [(p["proto"], p["info"]) for p in packets(engine, h1) if p["proto"] != "TCP" and not p["info"].startswith("GET")]
    two = [(p["proto"], p["info"].split(", ", 1)[1]) for p in packets(engine, h2) if p["info"].startswith("HEADERS")]
    assert one[0] == ("HTTP", "HTTP/1.1 200 OK [Malformed Packet]") and one[1][0] == "HTTP/XML"    # XML, 1 byte
    assert one[2][0] == "HTTP/XML" and two[2] == ("HTTP2", "DATA[5]")                            # XHTML: not under h2
    assert one[3][1].endswith("[Malformed Packet]") and two[5] == ("HTTP2", "DATA[11][Malformed Packet]")  # RIFF
    assert one[8][1] == "HTTP/1.1 200 OK  (image/webp)" and two[8] == ("HTTP2", "DATA[17]")      # not RIFF
    assert one[9][1] == "HTTP/1.1 200 OK  (image/gif)" and one[10][1].endswith("(GIF89a)[Malformed Packet]")
    assert one[12][1].endswith("(application/javascript)") and two[12] == ("HTTP2", "DATA[25]")  # no dissector
    assert one[14][0] == "DoH" and one[14][1] == "Standard query 0x0000"
    tshark = _find_tshark()
    if tshark:
        from anta.tools.compare_wireshark import compare
        for path in (h1, h2):
            result = compare(path, engine, tshark, show=0)
            assert result["identical"] == result["frames"]
