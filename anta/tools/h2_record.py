"""Record real HTTP/2-over-TLS traffic for tests, entirely on loopback.

  python -m anta.tools.h2_record OUTPREFIX   ->  OUTPREFIX.pcap, OUTPREFIX.keys, OUTPREFIX.json

curl (nghttp2: a real HPACK encoder, Huffman strings and its dynamic table) fetches four
files in parallel through a relay that records the exact bytes, from a minimal HTTP/2
server here whose responses use the dynamic table, padding, and DATA frames interleaved
across the streams. The server's OpenSSL writes the TLS key log for that one session;
the .json holds the SHA-256 of each body. Nothing leaves the machine.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

from anta.tools import samples

EXE = samples.windows_exe(60_000, seed=21)
PAGE = b"<html><body>" + b"compressed inside HTTP/2 " * 60 + b"</body></html>"
ALL_BYTES = bytes(range(0x20, 0x7F)) + bytes(range(0x80, 0x100))
RESPONSES = {  # path -> (status, headers, body as sent, body as decoded)
    "/update.exe": (200, [("content-type", b"application/octet-stream"),
                          ("content-disposition", b'attachment; filename="setup.exe"')], EXE, EXE),
    "/page.html": (200, [("content-type", b"text/html"), ("content-encoding", b"gzip")],
                   gzip.compress(PAGE, mtime=0), PAGE),
    "/missing": (404, [("content-type", b"text/html")], b"<h1>not found</h1>", b"<h1>not found</h1>"),
    "/bytes": (200, [("content-type", b"text/plain"), ("x-all-bytes", ALL_BYTES)], b"x" * 40_000, b"x" * 40_000),
}
ORDER = list(RESPONSES)


def _serve(lsock: socket.socket, cert: str, key: str, keylog: str) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2"])
    ctx.keylog_filename = keylog
    raw, _ = lsock.accept()
    conn = ctx.wrap_socket(raw, server_side=True)
    buf = b""

    def need(n):
        nonlocal buf
        while len(buf) < n:
            chunk = conn.recv(65536)
            if not chunk:
                raise EOFError
            buf += chunk
        out, buf = buf[:n], buf[n:]
        return out

    try:
        assert need(24) == samples.H2_PREFACE
        enc = samples.HpackEncoder()
        conn.sendall(samples.h2_frame(4, 0, 0, struct.pack("!HIHI", 3, 100, 4, 1 << 20)))
        pending = {}
        while len(pending) < len(ORDER):
            hdr = need(9)
            ftype, flags, sid = hdr[3], hdr[4], struct.unpack("!I", hdr[5:9])[0] & 0x7FFFFFFF
            payload = need(int.from_bytes(hdr[:3], "big"))
            if ftype == 4 and not flags & 1:
                conn.sendall(samples.h2_frame(4, 1, 0))
            elif ftype == 6 and not flags & 1:
                conn.sendall(samples.h2_frame(6, 1, 0, payload))
            elif ftype == 1:
                pending[sid] = ORDER[len(pending)]  # curl asks in order
            elif ftype == 7:
                break
        out = b""
        for sid, path in pending.items():  # every response's headers, then the bodies interleaved
            status, hdrs, body, _ = RESPONSES[path]
            block = enc.block([(":status", str(status)), ("server", "anta-h2lab/1.0"), *hdrs,
                               ("content-length", str(len(body)))])
            out += samples.h2_frame(1, 4, sid, block)
        offsets, k = {sid: 0 for sid in pending}, 0
        while offsets:
            for sid in list(offsets):
                body = RESPONSES[pending[sid]][2]
                chunk = body[offsets[sid]:offsets[sid] + 7000]
                offsets[sid] += len(chunk)
                last = offsets[sid] >= len(body)
                k += 1
                if k % 3 == 0:  # PADDED
                    pad = 5 + k % 7
                    out += samples.h2_frame(0, 0x8 | last, sid, bytes([pad]) + chunk + bytes(pad))
                else:
                    out += samples.h2_frame(0, int(last), sid, chunk)
                if last:
                    del offsets[sid]
        conn.sendall(out + samples.h2_frame(7, 0, 0, struct.pack("!II", max(pending), 0)))
        time.sleep(0.3)
    except (EOFError, ConnectionError, ssl.SSLError):
        pass
    finally:
        conn.close()


def record(prefix: str) -> None:
    work = tempfile.mkdtemp(prefix="h2rec-")
    cert, key = os.path.join(work, "cert.pem"), os.path.join(work, "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                    "-days", "2", "-subj", "/CN=h2.example"], check=True, capture_output=True)
    keylog = prefix + ".keys"
    if os.path.exists(keylog):
        os.unlink(keylog)
    server, relay = socket.socket(), socket.socket()
    for s in (server, relay):
        s.bind(("127.0.0.1", 0))
        s.listen(1)
    threading.Thread(target=_serve, args=(server, cert, key, keylog), daemon=True).start()
    chunks, lock = [], threading.Lock()

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

    def proxy():
        c, _ = relay.accept()
        s = socket.create_connection(server.getsockname())
        threads = [threading.Thread(target=pump, args=(c, s, True)), threading.Thread(target=pump, args=(s, c, False))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        c.close()
        s.close()

    pt = threading.Thread(target=proxy, daemon=True)
    pt.start()
    port = relay.getsockname()[1]
    urls = [f"https://h2.example:{port}{p}" for p in ORDER]
    subprocess.run(["curl", "--http2", "-k", "-s", "-Z", "--parallel-max", "4", "--resolve", f"h2.example:{port}:127.0.0.1",
                    *sum(([u, "-o", os.devnull] for u in urls), [])], check=True, timeout=30)
    pt.join(5)
    samples.write_pcap(prefix + ".pcap", samples.tcp_session("10.97.0.5", 51515, "10.97.0.80", 443, chunks))
    with open(keylog) as fh:  # the key log, without OpenSSL's comment line
        lines = [x for x in fh if not x.startswith("#")]
    with open(keylog, "w") as fh:
        fh.writelines(lines)
    expect = {p: {"status": RESPONSES[p][0], "sha256": hashlib.sha256(RESPONSES[p][3]).hexdigest(),
                  "size": len(RESPONSES[p][3])} for p in ORDER}
    with open(prefix + ".json", "w") as fh:
        json.dump(expect, fh, indent=1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m anta.tools.h2_record OUTPREFIX")
    record(sys.argv[1])
