"""Record real TLS sessions in the versions and suites the decryption tests need, on loopback.

  python -m anta.tools.tls_record OUTDIR [NAME ...]  ->  OUTDIR/NAME.pcap and OUTDIR/NAME.keys

OpenSSL's own s_server and s_client (OpenSSL 3, from PATH or OPENSSL) make each session
through a relay here that records the exact bytes each way; the client writes the key
log for it. The sessions: CBC suites with and without encrypt-then-MAC in TLS 1.0, 1.1
and 1.2 (SHA-1, SHA-256 and SHA-384 MACs), AES-CCM and CCM_8 in TLS 1.2 and 1.3, TLS 1.3
key updates from either side, TLS 1.2 renegotiation started by either side, and TLS 1.3
early data on a resumed session. The DTLS 1.0 and 1.2 sessions (dtls*) are for the DTLS
dissector: their captures only, with no key log. Nothing leaves the machine.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from anta.tools import samples

GET = "GET / HTTP/1.0\n"
LEGACY = "@SECLEVEL=0"  # TLS 1.0 and 1.1 are off at OpenSSL 3's default security level
REN = ["-client_renegotiation"]  # (OpenSSL 3 servers refuse a client's renegotiation otherwise)
PROV = ["-provider", "legacy", "-provider", "default"]  # SEED lives in OpenSSL 3's legacy provider


# Lines each side of a DTLS session sends (s_server and s_client relay their input).
DTLS_TALK = [("c", 0.5, "1 a datagram from the client"), ("s", 0.3, "2 the server answers"),
             ("c", 0.3, "3 the client again"), ("c", 0.4, "Q")]


def req(path: str) -> str:  # a request, its blank line included (-crlf makes the line ends CRLF)
    return f"GET {path} HTTP/1.1\nHost: tls.example\n"


def resp(status: int) -> str:  # its body, "status NNN" and the CRLF -crlf ends it with
    return f"HTTP/1.1 {status} OK\nContent-Type: text/plain\nContent-Length: 12\n\nstatus {status}"

# name -> server args, client args, then the script: (who, seconds to wait, line). A
# line that is a single letter is an s_client/s_server command (k/K key update, R/r
# renegotiate, Q quit). "www" sessions answer one GET with s_server's status page; "server"
# holds options only the server takes.
SCENARIOS = {
    "tls12_aes128_sha_etm": dict(www=True, both=["-tls1_2", "-cipher", "AES128-SHA"]),
    "tls12_aes256_sha256": dict(www=True, both=["-tls1_2", "-cipher", "AES256-SHA256", "-no_etm"]),
    "tls12_ecdhe_aes256_sha384_etm": dict(www=True, both=["-tls1_2", "-cipher", "ECDHE-RSA-AES256-SHA384"]),
    "tls11_aes128_sha": dict(www=True, both=["-tls1_1", "-cipher", "AES128-SHA" + LEGACY, "-no_etm"]),
    "tls10_aes256_sha_etm": dict(www=True, both=["-tls1", "-cipher", "AES256-SHA" + LEGACY]),
    "tls10_aes128_sha": dict(www=True, both=["-tls1", "-cipher", "AES128-SHA" + LEGACY, "-no_etm"]),
    "tls12_aes128_ccm": dict(www=True, both=["-tls1_2", "-cipher", "AES128-CCM"]),
    "tls12_aes128_ccm8": dict(www=True, both=["-tls1_2", "-cipher", "AES128-CCM8" + LEGACY]),  # (a 64-bit tag)
    "tls12_camellia128_sha": dict(www=True, both=["-tls1_2", "-cipher", "CAMELLIA128-SHA" + LEGACY]),
    "tls12_ecdhe_camellia256_sha384": dict(www=True, both=["-tls1_2", "-cipher", "ECDHE-RSA-CAMELLIA256-SHA384" + LEGACY,
                                                           "-no_etm"]),
    "tls12_aria128_gcm": dict(www=True, both=["-tls1_2", "-cipher", "ARIA128-GCM-SHA256" + LEGACY]),
    "tls12_dhe_aria256_gcm": dict(www=True, both=["-tls1_2", "-cipher", "DHE-RSA-ARIA256-GCM-SHA384" + LEGACY]),
    "tls12_seed_sha": dict(www=True, both=["-tls1_2", "-cipher", "SEED-SHA" + LEGACY, *PROV]),
    "tls10_seed_sha": dict(www=True, both=["-tls1", "-cipher", "SEED-SHA" + LEGACY, "-no_etm", *PROV]),
    "tls12_null_sha256": dict(www=True, both=["-tls1_2", "-cipher", "NULL-SHA256" + LEGACY]),
    "tls12_null_sha": dict(www=True, both=["-tls1_2", "-cipher", "NULL-SHA" + LEGACY]),
    "tls12_rsa_no_ems": dict(www=True, both=["-tls1_2", "-cipher", "AES128-GCM-SHA256", "-no_ems"]),
    "tls13_aes128_ccm": dict(www=True, both=["-tls1_3", "-ciphersuites", "TLS_AES_128_CCM_SHA256"]),
    "tls13_aes128_ccm8": dict(www=True, both=["-tls1_3", "-ciphersuites", "TLS_AES_128_CCM_8_SHA256",
                                               "-cipher", "DEFAULT" + LEGACY]),
    # (HTTP inside, so the session analysis shows each message it read after each re-key)
    "tls13_key_update": dict(both=["-tls1_3", "-crlf"], script=[
        ("c", 0.4, req("/1-before-any-update")), ("s", 0.3, resp(200)),
        ("c", 0.3, "k"), ("c", 0.3, req("/2-after-the-client-update")),
        ("c", 0.3, "K"), ("c", 0.3, req("/3-after-an-update-requested")), ("s", 0.3, resp(201)),
        ("s", 0.3, "k"), ("s", 0.3, resp(202)), ("c", 0.3, req("/4-at-the-end")),
        ("c", 0.4, "Q")]),
    "tls12_renegotiation": dict(both=["-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256", "-crlf"], server=REN,
                                script=[
        ("c", 0.4, req("/1-before-renegotiating")), ("c", 0.3, "R"), ("c", 0.6, req("/2-after-the-client-one")),
        ("s", 0.3, "r"), ("s", 0.6, resp(200)), ("c", 0.3, req("/3-after-the-server-one")),
        ("c", 0.4, "Q")]),
    "tls12_renegotiation_cbc": dict(both=["-tls1_2", "-cipher", "AES128-SHA256", "-crlf"], server=REN, script=[
        ("c", 0.4, req("/1-before-renegotiating")), ("c", 0.3, "R"), ("c", 0.6, req("/2-after-renegotiating")),
        ("s", 0.3, resp(200)), ("c", 0.4, "Q")]),
    "tls13_early_data": dict(early=True, both=["-tls1_3"]),
    # DTLS (over UDP): the cookie exchange, handshake messages split across datagrams by a
    # small MTU, and DTLS 1.0's CBC.
    "dtls12_ecdhe_gcm": dict(dtls=True, both=["-dtls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256"],
                             server=["-listen"], script=DTLS_TALK),
    "dtls12_aes128_sha_mtu": dict(dtls=True, both=["-dtls1_2", "-cipher", "AES128-SHA", "-mtu", "500"],
                                  script=DTLS_TALK),
    "dtls10_aes256_sha": dict(dtls=True, both=["-dtls1", "-cipher", "AES256-SHA" + LEGACY, "-no_etm"],
                              script=DTLS_TALK),
    "dtls12_chacha20": dict(dtls=True, both=["-dtls1_2", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305"],
                            script=DTLS_TALK),
}


def _openssl() -> str:
    exe = os.environ.get("OPENSSL") or shutil.which("openssl") or "openssl"
    out = subprocess.run([exe, "version"], capture_output=True, text=True).stdout
    if not out.startswith("OpenSSL 3"):
        sys.exit(f"needs OpenSSL 3's openssl command (set OPENSSL=/path/to/openssl); {exe} is {out.strip()!r}")
    return exe


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Relay:
    """Accepts connections on its own port, forwards each to the server, and keeps the
    bytes of each connection in order."""

    def __init__(self, server_port: int):
        self.server_port = server_port
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.connections: list[list] = []
        self.threads: list[threading.Thread] = []

    def accept(self) -> None:
        c, _ = self.sock.accept()
        s = socket.create_connection(("127.0.0.1", self.server_port))
        chunks: list = []
        self.connections.append(chunks)
        lock = threading.Lock()

        def pump(src, dst, from_client):
            while True:
                try:
                    data = src.recv(65536)
                except OSError:
                    data = b""
                if not data:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                with lock:
                    chunks.append((from_client, data))
                dst.sendall(data)

        for args in ((c, s, True), (s, c, False)):
            t = threading.Thread(target=pump, args=args, daemon=True)
            t.start()
            self.threads.append(t)

    def join(self, timeout: float = 10) -> None:
        for t in self.threads:
            t.join(timeout)


class UdpRelay:
    """DTLS through a relay on its own UDP port: each datagram forwarded and kept, in order."""

    def __init__(self, server_port: int):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.up.connect(("127.0.0.1", server_port))
        self.datagrams: list = []
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        import select
        client = None
        while not self.done.is_set():
            ready, _, _ = select.select([self.sock, self.up], [], [], 0.2)
            for s in ready:
                try:
                    if s is self.sock:
                        data, client = self.sock.recvfrom(65535)
                        self.datagrams.append((True, data))
                        self.up.send(data)
                    else:
                        data = self.up.recv(65535)
                        self.datagrams.append((False, data))
                        if client:
                            self.sock.sendto(data, client)
                except OSError:
                    pass

    def close(self) -> None:
        self.done.set()
        self.thread.join(2)


def record_dtls(name: str, outdir: str, exe: str, cert: str, key: str, work: str) -> None:
    """A DTLS session, for the dissector (no key log: DTLS records aren't decrypted)."""
    cfg = SCENARIOS[name]
    port = _free_port()
    server, slog = _server(exe, port, cert, key, cfg, work, 1)
    relay = UdpRelay(port)
    try:
        client = _client(exe, relay.port, cfg, None, interactive=True)
        for who, wait, line in cfg["script"]:
            time.sleep(wait)
            proc = client if who == "c" else server
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
        client.wait(10)
        time.sleep(0.3)
    finally:
        relay.close()
        if server.poll() is None:
            server.kill()
    frames = []
    for i, (from_client, data) in enumerate(relay.datagrams):
        a, b = ("10.98.0.5", 50300), ("10.98.0.80", 4433)
        src, dst = (a, b) if from_client else (b, a)
        frames.append((i * 0.01, samples.udp(src[0], dst[0], src[1], dst[1], data)))
    # The talk went both ways: application data records (content type 23) from each side.
    if {c for c, data in relay.datagrams if data[:1] == b"\x17"} != {True, False}:
        sys.exit(f"{name}: no DTLS session was made:\n" + "".join(slog))
    samples.write_pcap(os.path.join(outdir, name + ".pcap"), frames)
    print(f"{name}: {len(frames)} datagrams")


def _server(exe, port, cert, key, cfg, work, naccept):
    args = [exe, "s_server", "-accept", str(port), "-cert", cert, "-key", key, "-naccept", str(naccept),
            *cfg.get("both", []), *cfg.get("server", [])]
    if cfg.get("www"):
        args.append("-www")
    if cfg.get("early"):
        args.append("-early_data")
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=work, text=True)
    ready = threading.Event()
    log: list[str] = []

    def read():
        for line in proc.stdout:
            log.append(line)
            if line.startswith("ACCEPT"):
                ready.set()

    threading.Thread(target=read, daemon=True).start()
    if not ready.wait(10):
        proc.kill()
        sys.exit("s_server didn't start:\n" + "".join(log))
    return proc, log


def _client(exe, port, cfg, keylog, extra=(), interactive=False):
    args = [exe, "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "tls.example",
            *(["-keylogfile", keylog] if keylog else []), *cfg.get("both", []), *extra]
    if not interactive:
        args += ["-ign_eof", "-crlf"]
    return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def record(name: str, outdir: str, exe: str, cert: str, key: str, work: str) -> None:
    cfg = SCENARIOS[name]
    keylog = os.path.join(outdir, name + ".keys")
    if os.path.exists(keylog):
        os.unlink(keylog)
    port = _free_port()
    naccept = 2 if cfg.get("early") else 1
    server, slog = _server(exe, port, cert, key, cfg, work, naccept)
    relay = Relay(port)
    try:
        if cfg.get("early"):  # a session to resume, then early data on the resumption
            sess = os.path.join(work, name + ".sess")
            early = os.path.join(work, "early.txt")
            with open(early, "w") as fh:
                fh.write("GET /early HTTP/1.0\r\n\r\n")
            for extra, line in ((["-sess_out", sess], "1 first connection"),
                                (["-sess_in", sess, "-early_data", early], "2 after early data")):
                client = _client(exe, relay.port, cfg, keylog, extra, interactive=True)
                relay.accept()
                time.sleep(0.5)
                client.stdin.write(line + "\n")
                client.stdin.flush()
                time.sleep(0.5)
                client.stdin.write("Q\n")
                client.stdin.flush()
                client.wait(10)
        elif cfg.get("www"):
            client = _client(exe, relay.port, cfg, keylog)
            relay.accept()
            client.communicate(GET + "\n", timeout=15)
        else:
            client = _client(exe, relay.port, cfg, keylog, interactive=True)
            relay.accept()
            for who, wait, line in cfg["script"]:
                time.sleep(wait)
                proc = client if who == "c" else server
                proc.stdin.write(line + "\n")
                proc.stdin.flush()
            client.wait(10)
        relay.join()
    finally:
        for p in (server,):
            if p.poll() is None:
                p.kill()
    frames, t0 = [], 0.0
    for i, chunks in enumerate(relay.connections):
        frames += samples.tcp_session("10.98.0.5", 50100 + i, "10.98.0.80", 443, chunks, t0=t0)
        t0 = frames[-1][0] + 1.0
    samples.write_pcap(os.path.join(outdir, name + ".pcap"), frames)
    with open(keylog) as fh:  # the key log, without OpenSSL's comment line
        lines = [x for x in fh if not x.startswith("#")]
    with open(keylog, "w") as fh:
        fh.writelines(lines)
    if cfg.get("early") and not any(x.startswith("CLIENT_EARLY_TRAFFIC_SECRET") for x in lines):
        sys.exit(f"{name}: the resumed session sent no early data:\n" + "".join(slog))
    print(f"{name}: {len(relay.connections)} connection(s), {len(frames)} frames, {len(lines)} secrets")


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit("usage: python -m anta.tools.tls_record OUTDIR [NAME ...]\n  names: " + " ".join([*SCENARIOS, *SYNTHETIC]))
    outdir, names = argv[0], argv[1:] or [*SCENARIOS, *SYNTHETIC]
    os.makedirs(outdir, exist_ok=True)
    exe = _openssl()
    work = tempfile.mkdtemp(prefix="tlsrec-")
    cert, key = os.path.join(work, "cert.pem"), os.path.join(work, "key.pem")
    subprocess.run([exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                    "-days", "2", "-subj", "/CN=tls.example"], check=True, capture_output=True)
    for name in names:
        if name in SYNTHETIC:
            synthesize(name, outdir, exe)
        elif SCENARIOS[name].get("dtls"):
            record_dtls(name, outdir, exe, cert, key, work)
        else:
            record(name, outdir, exe, cert, key, work)



# --------------------------------------------------- sessions OpenSSL 3 no longer makes
# Triple DES, RC4 and SSL 3.0 are gone from OpenSSL 3's TLS (SSL 3.0 isn't even built),
# so these sessions are built here byte for byte, by RFC 6101 / 2246 / 5246: hellos, key
# exchange, Change Cipher Spec, Finished, an HTTP exchange and close_notify, every record
# MACed and encrypted as the version and suite say. The cipher itself is `openssl enc`'s.
# Wireshark decrypting them with the key log is what shows they are right.


SYNTHETIC = {  # name -> (version, cipher suite, cipher, MAC hash)
    "tls12_3des_sha": (0x0303, 0x000A, "des-ede3", "sha1"),
    "tls10_3des_sha": (0x0301, 0x000A, "des-ede3", "sha1"),
    "tls12_rc4_sha": (0x0303, 0x0005, "rc4", "sha1"),
    "tls11_rc4_md5": (0x0302, 0x0004, "rc4", "md5"),
    "ssl3_3des_sha": (0x0300, 0x000A, "des-ede3", "sha1"),
    "ssl3_rc4_md5": (0x0300, 0x0004, "rc4", "md5"),
}


def _p_hash(name, secret, seed, n):
    out, a = b"", _hmac.new(secret, seed, name).digest()
    while len(out) < n:
        out += _hmac.new(secret, a + seed, name).digest()
        a = _hmac.new(secret, a, name).digest()
    return out[:n]


def _prf(version, secret, label, seed, n):
    if version == 0x0303:
        return _p_hash("sha256", secret, label + seed, n)
    half = (len(secret) + 1) // 2
    return bytes(x ^ y for x, y in zip(_p_hash("md5", secret[:half], label + seed, n),
                                       _p_hash("sha1", secret[-half:], label + seed, n), strict=True))


def _ssl3_block(secret, a, b, n):
    out, i = b"", 0
    while len(out) < n:
        inner = hashlib.sha1(bytes([65 + i]) * (i + 1) + secret + a + b).digest()
        out += hashlib.md5(secret + inner).digest()
        i += 1
    return out[:n]


def _enc(exe, cipher, key, iv, data):
    args = [exe, "enc", "-provider", "legacy", "-provider", "default", f"-{cipher}", "-K", key.hex(), "-nopad"]
    if iv is not None:
        args += ["-iv", iv.hex()]
    return subprocess.run(args, input=data, capture_output=True, check=True).stdout


class _Writer:
    """One direction's protected records: MAC, padding, encryption and its sequence number."""

    def __init__(self, exe, version, cipher, mac_name, mac_key, key, iv, rng):
        self.exe, self.version, self.cipher, self.mac_name = exe, version, cipher, mac_name
        self.mac_key, self.key, self.iv, self.rng, self.seq = mac_key, key, iv, rng, 0
        self.stream = _enc(exe, "rc4", key, None, bytes(65536)) if cipher == "rc4" else None
        self.pos = 0

    def mac(self, ct, data):
        head = struct.pack(">QB", self.seq, ct)
        if self.version != 0x0300:
            return _hmac.new(self.mac_key, head + struct.pack(">HH", self.version, len(data)) + data,
                             self.mac_name).digest()
        h, pad = getattr(hashlib, self.mac_name), 48 if self.mac_name == "md5" else 40
        inner = h(self.mac_key + b"\x36" * pad + head + struct.pack(">H", len(data)) + data).digest()
        return h(self.mac_key + b"\x5c" * pad + inner).digest()

    def record(self, ct, data):
        body = data + self.mac(ct, data)
        if self.stream is not None:
            out = bytes(a ^ b for a, b in zip(body, self.stream[self.pos:self.pos + len(body)], strict=True))
            self.pos += len(body)
        else:
            padlen = 7 - len(body) % 8
            # SSL 3.0 padding bytes are arbitrary; TLS fills them with the length.
            pad = (bytes(self.rng.getrandbits(8) for _ in range(padlen)) if self.version == 0x0300
                   else bytes([padlen]) * padlen) + bytes([padlen])
            iv = self.iv if self.version <= 0x0301 else bytes(self.rng.getrandbits(8) for _ in range(8))
            enc = _enc(self.exe, "des-ede3-cbc", self.key, iv, body + pad)
            out = enc if self.version <= 0x0301 else iv + enc
            self.iv = enc[-8:]  # (SSL 3.0 and TLS 1.0 chain the IV)
        self.seq += 1
        return _rec(ct, self.version, out)


def _rec(ct, version, data):
    return struct.pack(">BHH", ct, version, len(data)) + data


def _hs(t, body):
    return struct.pack(">I", (t << 24) | len(body)) + body


def synthesize(name: str, outdir: str, exe: str) -> None:
    import random
    version, suite, cipher, mac_name = SYNTHETIC[name]
    rng = random.Random(name)
    rb = lambda n: bytes(rng.getrandbits(8) for _ in range(n))  # noqa: E731
    cr, sr, master = rb(32), rb(32), rb(48)
    ch = _hs(1, struct.pack(">H", version) + cr + b"\x00" + struct.pack(">HH", 2, suite) + b"\x01\x00")
    sh = _hs(2, struct.pack(">H", version) + sr + b"\x20" + rb(32) + struct.pack(">H", suite) + b"\x00")
    pms = rb(128)
    cke = _hs(16, pms if version == 0x0300 else struct.pack(">H", 128) + pms)
    mac_len, key_len, iv_len = (16 if mac_name == "md5" else 20), (16 if cipher == "rc4" else 24), 0
    if cipher != "rc4" and version <= 0x0301:
        iv_len = 8
    need = 2 * (mac_len + key_len + iv_len)
    kb = _ssl3_block(master, sr, cr, need) if version == 0x0300 else _prf(version, master, b"key expansion", sr + cr, need)
    cmac, smac = kb[:mac_len], kb[mac_len:2 * mac_len]
    ckey, skey = kb[2 * mac_len:2 * mac_len + key_len], kb[2 * mac_len + key_len:2 * (mac_len + key_len)]
    civ = kb[2 * (mac_len + key_len):2 * (mac_len + key_len) + iv_len]
    siv = kb[2 * (mac_len + key_len) + iv_len:]
    client = _Writer(exe, version, cipher, mac_name, cmac, ckey, civ, rng)
    server = _Writer(exe, version, cipher, mac_name, smac, skey, siv, rng)
    fin = 36 if version == 0x0300 else 12
    body = b"synthetic " + name.encode() + b"\n"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode() +
            b"\r\n\r\n" + body)
    ccs = _rec(20, version, b"\x01")
    exchanges = [(True, _rec(22, version, ch)), (False, _rec(22, version, sh + _hs(14, b""))),
                 (True, _rec(22, version, cke) + ccs + client.record(22, _hs(20, rb(fin)))),
                 (False, ccs + server.record(22, _hs(20, rb(fin)))),
                 (True, client.record(23, b"GET /legacy HTTP/1.1\r\nHost: tls.example\r\n\r\n")),
                 (False, server.record(23, resp)),
                 (True, client.record(21, b"\x01\x00")), (False, server.record(21, b"\x01\x00"))]
    samples.write_pcap(os.path.join(outdir, name + ".pcap"),
                       samples.tcp_session("10.98.0.5", 50100, "10.98.0.80", 443, exchanges))
    with open(os.path.join(outdir, name + ".keys"), "w") as fh:
        fh.write(f"CLIENT_RANDOM {cr.hex()} {master.hex()}\n")
    print(f"{name}: synthetic, {len(exchanges)} flights")


if __name__ == "__main__":
    main(sys.argv[1:])
