"""Hand-built packets for tests and fuzzing seeds.

Frames are byte-accurate (valid checksums, real TCP sequencing) so the engine and
Wireshark decode them the same way: TCP sessions with options, HTTP downloads
(plain, chunked, gzip), Kerberos (UDP and TCP), Windows browser announcements, a
non-TLS session on port 443, a QUIC handshake with real Initial encryption, the
Windows domain protocols: LDAP and CLDAP, SMB2 file copies with an NTLM logon, and
DCE/RPC (the endpoint mapper, SAMR), and a routed lab: router configurations backed
up over FTP (passive behind NAT, and active), resolvers that disagree, and TCP
segments with no flags.

    python -m anta.tools.samples out.pcap     # every sample in one capture (fuzz seeds)
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import socket
import struct
import sys

SYN, ACK, FIN, PSH, RST = 0x02, 0x10, 0x01, 0x08, 0x04
SACK_PERM = b"\x04\x02"


# ------------------------------------------------------------------ frames

def checksum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ipv4(src, dst, proto, payload, ttl=64):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0x4000, ttl, proto, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return b"\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00" + ip + payload


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b"", opts=b"", window=65535):
    while len(opts) % 4:
        opts += b"\x01"
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, (20 + len(opts)) // 4 << 4,
                      flags, window, 0, 0) + opts
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    c = checksum(pseudo + hdr + payload)
    return ipv4(src, dst, 6, hdr[:16] + struct.pack("!H", c) + hdr[18:] + payload)


def udp(src, dst, sport, dport, payload, ttl=64):
    return ipv4(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload, ttl)


def icmp(src, dst, typ, code, body):
    h = struct.pack("!BBH", typ, code, 0) + body
    return ipv4(src, dst, 1, h[:2] + struct.pack("!H", checksum(h)) + h[4:])


def mss_option(v):
    return struct.pack("!BBH", 2, 4, v)


def _mac(s):
    return bytes.fromhex(s.replace(":", ""))


def arp(sha, spa, tha="00:00:00:00:00:00", tpa="0.0.0.0", oper=2, dst="ff:ff:ff:ff:ff:ff"):  # noqa: S104
    """One ARP packet: sender hardware/protocol address sha/spa, target tha/tpa.
    oper 1 = request, 2 = reply. A reply (or request) whose spa is another host's IP
    is a gratuitous announcement, and the way ARP cache poisoning is done."""
    body = (bytes.fromhex("0001080006040000")[:7] + bytes([oper]) + _mac(sha) + socket.inet_aton(spa)
            + _mac(tha) + socket.inet_aton(tpa))
    return _mac(dst) + _mac(sha) + b"\x08\x06" + body


def write_pcap(path, frames):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in frames:
            fh.write(struct.pack("<IIII", 1_700_000_000 + int(ts), int(round(ts % 1 * 1e6)), len(data), len(data)))
            fh.write(data)


# --------------------------------------------------------------- sessions

def tcp_session(client, cport, server, sport, exchanges, t0=0.0, step=0.01, seg=1400, close=True):
    """A whole connection: handshake, then each (from_client, payload) sent in
    segments of `seg` bytes, each acknowledged, then FIN/ACK both ways."""
    frames, t = [], t0
    cseq, sseq = 1000, 5000

    def add(frame):
        nonlocal t
        frames.append((t, frame))
        t += step

    add(tcp(client, server, cport, sport, cseq, 0, SYN, opts=mss_option(1460) + SACK_PERM))
    add(tcp(server, client, sport, cport, sseq, cseq + 1, SYN | ACK, opts=mss_option(1460) + SACK_PERM))
    cseq += 1
    sseq += 1
    add(tcp(client, server, cport, sport, cseq, sseq, ACK))
    for from_client, payload in exchanges:
        for i in range(0, len(payload), seg):
            chunk = payload[i:i + seg]
            if from_client:
                add(tcp(client, server, cport, sport, cseq, sseq, PSH | ACK, chunk))
                cseq += len(chunk)
                add(tcp(server, client, sport, cport, sseq, cseq, ACK))
            else:
                add(tcp(server, client, sport, cport, sseq, cseq, PSH | ACK, chunk))
                sseq += len(chunk)
                add(tcp(client, server, cport, sport, cseq, sseq, ACK))
    if close:
        add(tcp(client, server, cport, sport, cseq, sseq, FIN | ACK))
        add(tcp(server, client, sport, cport, sseq, cseq + 1, FIN | ACK))
        add(tcp(client, server, cport, sport, cseq + 1, sseq + 1, ACK))
    return frames


def chunked(body: bytes, size=1000) -> bytes:
    out = b"".join(b"%x\r\n" % len(body[i:i + size]) + body[i:i + size] + b"\r\n" for i in range(0, len(body), size))
    return out + b"0\r\n\r\n"


def http_download(client, server, port, uri, body, host=None, agent="curl/8.21.0", content_type="binary/octet-stream",
                  chunk=False, compress=False, t0=0.0, cport=50100):
    """One GET and its response; the body optionally gzip-compressed and/or chunked."""
    host = host or (server if port == 80 else f"{server}:{port}")
    request = (f"GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {agent}\r\nAccept: */*\r\n\r\n").encode()
    data = gzip.compress(body, mtime=0) if compress else body
    headers = ["HTTP/1.1 200 OK", f"Content-Type: {content_type}"]
    if compress:
        headers.append("Content-Encoding: gzip")
    headers.append("Transfer-Encoding: chunked" if chunk else f"Content-Length: {len(data)}")
    response = ("\r\n".join(headers) + "\r\n\r\n").encode() + (chunked(data) if chunk else data)
    return tcp_session(client, cport, server, port, [(True, request), (False, response)], t0=t0)


def windows_exe(size=20_000, seed=7) -> bytes:
    """Bytes that start like a PE file (MZ ... PE\\0\\0), then pseudo-random content."""
    import random
    rng = random.Random(seed)
    head = bytearray(b"MZ" + bytes(58) + struct.pack("<I", 0x80) + bytes(0x80 - 64) + b"PE\0\0")
    return bytes(head) + bytes(rng.randrange(256) for _ in range(size - len(head)))


# ---------------------------------------------------------------- Kerberos

def _der(tag, content):
    n = len(content)
    length = bytes([n]) if n < 128 else b"\x81" + bytes([n]) if n < 256 else b"\x82" + struct.pack("!H", n)
    return bytes([tag]) + length + content


def _ctx(n, content):
    return _der(0xA0 + n, content)


def _int(v):
    return _der(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def _gstr(s):
    return _der(0x1B, s.encode())


def _seq(*items):
    return _der(0x30, b"".join(items))


def _principal(name_type, *names):
    return _seq(_ctx(0, _int(name_type)), _ctx(1, _seq(*[_gstr(n) for n in names])))


def _ktime(s="20261001120000Z"):
    return _der(0x18, s.encode())


def krb_error(code, realm="EXAMPLE.COM", cname=None):
    items = [_ctx(0, _int(5)), _ctx(1, _int(30)), _ctx(4, _ktime()), _ctx(5, _int(0)), _ctx(6, _int(code))]
    if cname:
        items += [_ctx(7, _gstr(realm)), _ctx(8, _principal(1, cname))]
    items += [_ctx(9, _gstr(realm)), _ctx(10, _principal(2, "krbtgt", realm))]
    return _der(0x7E, _seq(*items))


def krb_request(user, realm, netbios=None, msg_type=10):
    """AS-REQ (10) or TGS-REQ (12) with a client name and, optionally, a NetBIOS address."""
    body = [_ctx(0, _der(0x03, b"\x00\x40\x81\x00\x10")), _ctx(1, _principal(1, user)), _ctx(2, _gstr(realm)),
            _ctx(3, _principal(2, "krbtgt", realm)), _ctx(5, _ktime("20370913024805Z")), _ctx(7, _int(12345)),
            _ctx(8, _seq(_int(18), _int(17), _int(23)))]
    if netbios:
        address = _seq(_ctx(0, _int(20)), _ctx(1, _der(0x04, netbios.ljust(16).encode())))
        body.append(_ctx(9, _seq(address)))
    return _der(0x60 + msg_type, _seq(_ctx(1, _int(5)), _ctx(2, _int(msg_type)), _ctx(4, _seq(*body))))


def krb_reply(user, realm, msg_type=11):
    """AS-REP (11) or TGS-REP (13)."""
    enc = _seq(_ctx(0, _int(18)), _ctx(1, _int(2)), _ctx(2, _der(0x04, bytes(40))))
    ticket = _der(0x61, _seq(_ctx(0, _int(5)), _ctx(1, _gstr(realm)), _ctx(2, _principal(2, "krbtgt", realm)),
                             _ctx(3, enc)))
    return _der(0x60 + msg_type, _seq(_ctx(0, _int(5)), _ctx(1, _int(msg_type)), _ctx(3, _gstr(realm)),
                                      _ctx(4, _principal(1, user)), _ctx(5, ticket), _ctx(6, enc)))


# ------------------------------------------------- Windows browser protocol

def _nb_name(name, suffix):
    raw = name.upper().ljust(15)[:15].encode() + bytes([suffix])
    return bytes([32]) + bytes(c for b in raw for c in (0x41 + (b >> 4), 0x41 + (b & 15))) + b"\0"


def browser_datagram(src_ip, src_name, dst_name, payload, mailslot=b"\\MAILSLOT\\BROWSE"):
    """NetBIOS datagram (UDP 138) → SMB Trans → mailslot write carrying a browser message."""
    name = mailslot + b"\0"
    setup = struct.pack("<HHH", 1, 1, 2)
    header = b"\xffSMB" + bytes([0x25]) + bytes(27)
    data_offset = 32 + 1 + 2 * 17 + 2 + len(name)
    words = struct.pack("<HHHHBBHIHHHHHBB", 0, len(payload), 0, 0, 0, 0, 0, 1000, 0, 0, 0, len(payload), data_offset,
                        3, 0)
    smb = header + bytes([17]) + words + setup + struct.pack("<H", len(name) + len(payload)) + name + payload
    body = _nb_name(*src_name) + _nb_name(*dst_name) + smb
    dgram = struct.pack("!BBH4sHHH", 0x11, 0x0A, 0x1234, socket.inet_aton(src_ip), 138, len(body), 0) + body
    return udp(src_ip, "10.0.0.255", 138, 138, dgram)


def host_announcement(server, server_type=0x00001003, cmd=0x01, os=(10, 0), comment=b""):
    return (bytes([cmd, 0]) + struct.pack("<I", 240000) + server.encode().ljust(16, b"\0")[:16] + bytes(os) +
            struct.pack("<I", server_type) + bytes([15, 1]) + struct.pack("<H", 0xAA55) + comment + b"\0")


# ------------------------------------------------------------------ QUIC
# QUIC Initial packets are encrypted with keys derived from the connection ID
# (RFC 9001 5.2); the standard library has no AES, so a small one is here.

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16")

def _xtime(x):
    return ((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else x << 1


def _aes128_encrypt(key: bytes, block: bytes) -> bytes:
    rk = list(key)
    rcon = 1
    for i in range(16, 176, 4):
        t = rk[i - 4:i]
        if i % 16 == 0:
            t = [_SBOX[t[1]] ^ rcon, _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            rcon = _xtime(rcon)
        rk += [rk[i - 16 + j] ^ t[j] for j in range(4)]
    s = [b ^ k for b, k in zip(block, rk[:16])]
    for rnd in range(1, 11):
        t = [_SBOX[b] for b in s]
        s = [t[((c + r) % 4) * 4 + r] for c in range(4) for r in range(4)]
        if rnd != 10:
            for c in range(4):
                a = s[c * 4:c * 4 + 4]
                al = a[0] ^ a[1] ^ a[2] ^ a[3]
                s[c * 4:c * 4 + 4] = [a[i] ^ al ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
        s = [b ^ k for b, k in zip(s, rk[rnd * 16:rnd * 16 + 16])]
    return bytes(s)


def _gf_mul(x: int, y: int) -> int:
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z


def _ghash(h: int, data: bytes) -> int:
    acc = 0
    for i in range(0, len(data), 16):
        acc = _gf_mul(acc ^ int.from_bytes(data[i:i + 16].ljust(16, b"\0"), "big"), h)
    return acc


def aes128_gcm_seal(key: bytes, nonce: bytes, aad: bytes, plain: bytes) -> bytes:
    """Ciphertext followed by the 16-byte tag."""
    h = int.from_bytes(_aes128_encrypt(key, bytes(16)), "big")
    out = bytearray()
    for i in range(0, len(plain), 16):
        ks = _aes128_encrypt(key, nonce + struct.pack("!I", 2 + i // 16))
        out += bytes(a ^ b for a, b in zip(plain[i:i + 16], ks))

    def pad(b):
        return b + bytes(-len(b) % 16)

    acc = _ghash(h, pad(aad) + pad(bytes(out)) + struct.pack("!QQ", len(aad) * 8, len(out) * 8))
    tag = acc ^ int.from_bytes(_aes128_encrypt(key, nonce + struct.pack("!I", 1)), "big")
    return bytes(out) + tag.to_bytes(16, "big")


def _aes256_encrypt(key: bytes, block: bytes) -> bytes:
    rk = list(key)
    rcon = 1
    for i in range(32, 240, 4):
        t = rk[i - 4:i]
        if i % 32 == 0:
            t = [_SBOX[t[1]] ^ rcon, _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            rcon = _xtime(rcon)
        elif i % 32 == 16:
            t = [_SBOX[x] for x in t]
        rk += [rk[i - 32 + j] ^ t[j] for j in range(4)]
    s = [b ^ k for b, k in zip(block, rk[:16], strict=True)]
    for rnd in range(1, 15):
        t = [_SBOX[b] for b in s]
        s = [t[((c + r) % 4) * 4 + r] for c in range(4) for r in range(4)]
        if rnd != 14:
            for c in range(4):
                a = s[c * 4:c * 4 + 4]
                al = a[0] ^ a[1] ^ a[2] ^ a[3]
                s[c * 4:c * 4 + 4] = [a[i] ^ al ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
        s = [b ^ k for b, k in zip(s, rk[rnd * 16:rnd * 16 + 16], strict=True)]
    return bytes(s)


def _gcm_seal(enc, nonce: bytes, aad: bytes, plain: bytes) -> bytes:
    """AES-GCM with a given block-encrypt function (AES-128 or AES-256)."""
    h = int.from_bytes(enc(bytes(16)), "big")
    out = bytearray()
    for i in range(0, len(plain), 16):
        ks = enc(nonce + struct.pack("!I", 2 + i // 16))
        out += bytes(a ^ b for a, b in zip(plain[i:i + 16], ks, strict=False))

    def pad(b):
        return b + bytes(-len(b) % 16)

    acc = _ghash(h, pad(aad) + pad(bytes(out)) + struct.pack("!QQ", len(aad) * 8, len(out) * 8))
    tag = acc ^ int.from_bytes(enc(nonce + struct.pack("!I", 1)), "big")
    return bytes(out) + tag.to_bytes(16, "big")


def aes256_gcm_seal(key: bytes, nonce: bytes, aad: bytes, plain: bytes) -> bytes:
    return _gcm_seal(lambda b: _aes256_encrypt(key, b), nonce, aad, plain)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    st += list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    x = list(st)

    def rot(v, n):
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    def qr(a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = rot(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = rot(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = rot(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = rot(x[b] ^ x[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return struct.pack("<16I", *[(x[i] + st[i]) & 0xFFFFFFFF for i in range(16)])


def _poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    sk = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        acc = (acc + (int.from_bytes(block, "little") + (1 << (8 * len(block))))) % p
        acc = (acc * r) % p
    return ((acc + sk) & ((1 << 128) - 1)).to_bytes(16, "little")


def chacha20_poly1305_seal(key: bytes, nonce: bytes, aad: bytes, plain: bytes) -> bytes:
    poly_key = _chacha20_block(key, 0, nonce)[:32]
    out = bytearray()
    for i in range(0, len(plain), 64):
        ks = _chacha20_block(key, 1 + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(plain[i:i + 64], ks, strict=False))

    def pad16(b):
        return b + bytes(-len(b) % 16)

    mac_data = pad16(aad) + pad16(bytes(out)) + struct.pack("<QQ", len(aad), len(out))
    return bytes(out) + _poly1305(poly_key, mac_data)


def hkdf_expand_label(secret: bytes, label: str, n: int, sha384: bool = False) -> bytes:
    import hashlib
    full = b"tls13 " + label.encode()
    info = struct.pack("!HB", n, len(full)) + full + b"\0"
    algo = hashlib.sha384 if sha384 else hashlib.sha256
    out, t, i = b"", b"", 0
    while len(out) < n:
        i += 1
        t = hmac.new(secret, t + info + bytes([i]), algo).digest()
        out += t
    return out[:n]


def tls13_record(secret: bytes, seq: int, plaintext: bytes, inner: int = 0x17, cipher: int = 0x1301) -> bytes:
    """One TLS 1.3 record sealed with the keys of a traffic secret (any of the three suites)."""
    sha384 = cipher == 0x1302
    key = hkdf_expand_label(secret, "key", 16 if cipher == 0x1301 else 32, sha384)
    iv = hkdf_expand_label(secret, "iv", 12, sha384)
    nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big"), strict=True))
    inner_plain = plaintext + bytes([inner])
    hdr = b"\x17\x03\x03" + struct.pack("!H", len(inner_plain) + 16)
    seal = {0x1301: aes128_gcm_seal, 0x1302: aes256_gcm_seal, 0x1303: chacha20_poly1305_seal}[cipher]
    return hdr + seal(key, nonce, hdr, inner_plain)


def https_lab(t0=0.0):
    """HTTPS the capture's owner holds the keys for (TLS 1.3 and an SSLKEYLOGFILE), in
    the shapes that make decrypted HTTP hard to follow: a chunked response cut across
    records, pipelined requests and responses sharing a record, a gzip body, a response
    with no length that runs until close_notify, a 100 KB program download in full-size
    records spanning many TCP segments (fetched by curl: the download detector's case),
    and a session whose key log holds only the server's secret. Returns (frames, keylog)."""
    import random
    from anta.tools.pcapgen import BROWSER_CIPHERS, BROWSER_EXTS, tls_client_hello, tls_server_hello
    client, server = "10.95.0.5", "10.95.0.80"
    frames, keylog = [], []

    def session(n, sni, flights, server_only=False):
        ch = tls_client_hello(sni, BROWSER_CIPHERS, BROWSER_EXTS, rng=random.Random(100 + n))
        sh = tls_server_hello(random.Random(200 + n), cipher=0x1301)
        cs = hashlib.sha256(b"client secret %d" % n).digest()
        ss = hashlib.sha256(b"server secret %d" % n).digest()
        seq = [0, 0]
        exchanges = [(True, ch), (False, sh)]
        for from_client, records in flights:
            side = 0 if from_client else 1
            data = b""
            for plain, inner in records:
                data += tls13_record(cs if from_client else ss, seq[side], plain, inner)
                seq[side] += 1
            exchanges.append((from_client, data))
        random_hex = ch[11:43].hex()
        if not server_only:
            keylog.append(f"CLIENT_TRAFFIC_SECRET_0 {random_hex} {cs.hex()}")
        keylog.append(f"SERVER_TRAFFIC_SECRET_0 {random_hex} {ss.hex()}")
        frames.extend(tcp_session(client, 50000 + n, server, 443, exchanges, t0=t0 + n))

    def get(uri, host, agent="Mozilla/5.0"):
        return f"GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {agent}\r\n\r\n".encode()

    app = 0x17
    # 1: a chunked response whose chunk framing is cut across three records
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" + \
        chunked(b"split across records " * 8, 37)
    session(1, "chunked.example", [(True, [(get("/chunked.txt", "chunked.example"), app)]),
                                   (False, [(resp[:60], app)]), (False, [(resp[60:75], app)]),
                                   (False, [(resp[75:], app)])])
    # 2: two pipelined requests in one record, both responses in one record
    r1 = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nfirst"
    r2 = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nsecond"
    session(2, "pipe.example", [(True, [(get("/a", "pipe.example") + get("/b", "pipe.example"), app)]),
                                (False, [(r1 + r2, app)])])
    # 3: a gzip-compressed page
    page = b"<html><body>" + b"compressed inside TLS " * 40 + b"</body></html>"
    gz = gzip.compress(page, mtime=0)
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: " + \
        str(len(gz)).encode() + b"\r\n\r\n" + gz
    session(3, "gzip.example", [(True, [(get("/page.html", "gzip.example"), app)]), (False, [(resp, app)])])
    # 4: no Content-Length: the body runs until the server's close_notify alert
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil the connection closes"
    session(4, "close.example", [(True, [(get("/stream", "close.example"), app)]),
                                 (False, [(resp, app), (b"\x01\x00", 0x15)])])
    # 5: a 100 KB program, in full 16 KB records, fetched by a command-line tool
    exe = windows_exe(100_000, seed=11)
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " + \
        str(len(exe)).encode() + b"\r\n\r\n" + exe
    session(5, "files.example", [(True, [(get("/update.exe", "files.example", "curl/8.4.0"), app)]),
                                 (False, [(resp[i:i + 16384], app) for i in range(0, len(resp), 16384)])])
    # 6: the key log has only the server's secret: responses decrypt, requests don't
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nhalf-open"
    session(6, "half.example", [(True, [(get("/half", "half.example"), app)]), (False, [(resp, app)])],
            server_only=True)
    return frames, "\n".join(keylog) + "\n"


# --------------------------------------------------------------- HTTP/2

# HPACK Huffman code lengths (RFC 7541 Appendix B); the codes are canonical in (length, symbol).
_HUFF_LEN = [13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28,
             28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6,
             6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8,
             13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15,
             11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23,
             23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
             21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26,
             26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21,
             22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27,
             27, 26, 30]


def _huff_codes():
    code, codes, prev = 0, [0] * 257, 0
    for sym in sorted(range(257), key=lambda x: (_HUFF_LEN[x], x)):
        code <<= _HUFF_LEN[sym] - prev
        codes[sym], prev, code = code, _HUFF_LEN[sym], code + 1
    return codes


_HUFF_CODES = _huff_codes()
_HPACK_STATIC = [(":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"), (":path", "/index.html"),
                 (":scheme", "http"), (":scheme", "https"), (":status", "200"), (":status", "204"),
                 (":status", "206"), (":status", "304"), (":status", "400"), (":status", "404"), (":status", "500"),
                 ("accept-charset", ""), ("accept-encoding", "gzip, deflate"), ("accept-language", ""),
                 ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
                 ("authorization", ""), ("cache-control", ""), ("content-disposition", ""), ("content-encoding", ""),
                 ("content-language", ""), ("content-length", ""), ("content-location", ""), ("content-range", ""),
                 ("content-type", ""), ("cookie", ""), ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""),
                 ("from", ""), ("host", ""), ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""),
                 ("if-range", ""), ("if-unmodified-since", ""), ("last-modified", ""), ("link", ""), ("location", ""),
                 ("max-forwards", ""), ("proxy-authenticate", ""), ("proxy-authorization", ""), ("range", ""),
                 ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""), ("set-cookie", ""),
                 ("strict-transport-security", ""), ("transfer-encoding", ""), ("user-agent", ""), ("vary", ""),
                 ("via", ""), ("www-authenticate", "")]


def hpack_huffman(data: bytes) -> bytes:
    acc, n = 0, 0
    for b in data:
        acc, n = (acc << _HUFF_LEN[b]) | _HUFF_CODES[b], n + _HUFF_LEN[b]
    pad = (8 - n % 8) % 8
    return ((acc << pad) | ((1 << pad) - 1)).to_bytes((n + pad) // 8, "big")


def _hpack_int(v: int, prefix: int, first: int) -> bytes:
    lim = (1 << prefix) - 1
    if v < lim:
        return bytes([first | v])
    out, v = [first | lim], v - lim
    while v >= 128:
        out.append((v & 127) | 128)
        v >>= 7
    return bytes(out + [v])


class HpackEncoder:
    """Enough HPACK to write test traffic: static and dynamic table references,
    literals with or without indexing, Huffman or raw strings."""

    def __init__(self):
        self.dyn = []  # newest first

    def _str(self, s: bytes, huff: bool) -> bytes:
        if huff:
            h = hpack_huffman(s)
            return _hpack_int(len(h), 7, 0x80) + h
        return _hpack_int(len(s), 7, 0) + s

    def block(self, headers, huff=True, index=True) -> bytes:
        out = b""
        for name, value in headers:
            value = value.encode() if isinstance(value, str) else value
            table = [(n, v.encode()) for n, v in _HPACK_STATIC] + list(self.dyn)
            hit = next((i + 1 for i, (n, v) in enumerate(table) if n == name and v == value), 0)
            if hit:
                out += _hpack_int(hit, 7, 0x80)
                continue
            name_idx = next((i + 1 for i, (n, _) in enumerate(table) if n == name), 0)
            if index:
                self.dyn.insert(0, (name, value))
            out += _hpack_int(name_idx, 6, 0x40) if index else _hpack_int(name_idx, 4, 0)
            if not name_idx:
                out += self._str(name.encode(), huff)
            out += self._str(value, huff)
        return out


def h2_frame(ftype: int, flags: int, sid: int, payload: bytes = b"") -> bytes:
    return struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack("!I", sid) + payload


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_STATUSES = [200, 201, 204, 206, 301, 302, 304, 400, 401, 403, 404, 405, 500, 502, 503]


def h2_lab(t0=0.0):
    """HTTP/2 the capture's owner holds the keys for (TLS 1.3 + key log), in the shapes that
    make it hard to follow: header blocks continued in CONTINUATION frames and records,
    server push, a 103 interim response, trailers, padding and priority, PING, RST_STREAM,
    frames cut across TLS records and records across TCP segments, every common status
    code, a POST body, a HEAD — plus a cleartext h2c connection (prior knowledge, port 80)
    and a 60 KB program download. Returns (frames, keylog)."""
    import random
    from anta.tools.pcapgen import BROWSER_CIPHERS, BROWSER_EXTS, tls_client_hello, tls_server_hello
    client, server = "10.96.0.5", "10.96.0.80"
    ch = tls_client_hello("h2lab.example", BROWSER_CIPHERS, BROWSER_EXTS, rng=random.Random(300))
    sh = tls_server_hello(random.Random(301), cipher=0x1301)
    cs, ss = hashlib.sha256(b"h2 client").digest(), hashlib.sha256(b"h2 server").digest()
    seq = [0, 0]
    flights = [(True, ch), (False, sh)]

    def send(from_client, *records):  # one TCP send of one or more records
        side, data = (0, cs) if from_client else (1, ss)
        out = b""
        for r in records:
            out += tls13_record(data, seq[side], r)
            seq[side] += 1
        flights.append((from_client, out))

    cenc, senc = HpackEncoder(), HpackEncoder()
    auth = "h2lab.example"

    def req(sid, method, path, flags=0x5, extra=(), **kw):
        hdrs = [(":method", method), (":scheme", "https"), (":authority", auth), (":path", path),
                ("user-agent", "Mozilla/5.0 (h2lab)"), ("accept", "*/*"), *extra]
        return h2_frame(1, flags, sid, cenc.block(hdrs, **kw))

    def resp(sid, status, extra=(), flags=0x4):
        return h2_frame(1, flags, sid, senc.block([(":status", str(status)), ("server", "h2lab"), *extra]))

    settings = h2_frame(4, 0, 0, struct.pack("!HIHI", 3, 100, 4, 6291456))
    send(True, H2_PREFACE + settings + h2_frame(8, 0, 0, struct.pack("!I", 15663105)))
    send(False, h2_frame(4, 0, 0, struct.pack("!HIHIHI", 1, 4096, 3, 128, 5, 16384)), h2_frame(4, 1, 0))
    send(True, h2_frame(4, 1, 0) + req(1, "GET", "/index.html"))
    # 3: a POST with a body, HEADERS carrying priority, the body in its own record
    post = b"name=value&upload=" + b"A" * 300
    hp = cenc.block([(":method", "POST"), (":scheme", "https"), (":authority", auth), (":path", "/form"),
                     ("content-type", "application/x-www-form-urlencoded"), ("content-length", str(len(post)))])
    send(True, h2_frame(1, 0x24, 3, struct.pack("!IB", 0x80000000 | 1, 41) + hp), h2_frame(0, 1, 3, post))
    # 5: a header block continued by CONTINUATION, each piece in its own record
    big = req(5, "GET", "/download/update.exe", flags=0x1, extra=[("x-trace", "t" * 120)])[9:]
    send(True, h2_frame(1, 0x1, 5, big[:40]), h2_frame(9, 0, 5, big[40:90]), h2_frame(9, 0x4, 5, big[90:]))
    send(True, req(7, "HEAD", "/index.html"))
    send(True, req(9, "GET", "/cancel-me"))
    for i, st in enumerate(H2_STATUSES):  # streams 11, 13, …: one status code each
        send(True, req(11 + 2 * i, "GET", f"/status/{st}"))
    send(True, h2_frame(6, 0, 0, b"pingpong"), h2_frame(3, 0, 9, struct.pack("!I", 8)))  # PING, RST_STREAM CANCEL
    # Responses. 1: 103 Early Hints, then 200 with a padded body; a pushed stylesheet.
    page = b"<html><head><link rel=stylesheet href=/s.css></head><body>hello h2</body></html>"
    send(False, resp(1, 103, [("link", "</s.css>; rel=preload")]),
         resp(1, 200, [("content-type", "text/html"), ("content-length", str(len(page)))]) +
         h2_frame(0, 0x9, 1, bytes([6]) + page + bytes(6)))
    css = b"body { color: #333 }"
    promise = senc.block([(":method", "GET"), (":scheme", "https"), (":authority", auth), (":path", "/s.css")])
    send(False, h2_frame(5, 0x4, 1, struct.pack("!I", 2) + promise),
         resp(2, 200, [("content-type", "text/css")]) + h2_frame(0, 1, 2, css))
    send(False, h2_frame(6, 1, 0, b"pingpong"))
    # 3: 201 with a body and trailers; 7: HEAD answered with headers only
    send(False, resp(3, 201, [("content-type", "application/json")]) + h2_frame(0, 0, 3, b'{"ok":true}') +
         h2_frame(1, 0x5, 3, senc.block([("x-checksum", "abc123")])) + resp(7, 200, flags=0x5))
    # 5: a 60 KB program, DATA frames of 10000 bytes, cut across 16 KB records and TCP segments
    exe = windows_exe(60_000, seed=31)
    stream5 = resp(5, 200, [("content-type", "application/octet-stream"), ("content-length", str(len(exe)))])
    for i in range(0, len(exe), 10_000):
        stream5 += h2_frame(0, 1 if i + 10_000 >= len(exe) else 0, 5, exe[i:i + 10_000])
    send(False, *[stream5[i:i + 16384] for i in range(0, len(stream5), 16384)])
    for i, st in enumerate(H2_STATUSES):
        sid = 11 + 2 * i
        body = b"" if st in (204, 304) else f"status {st}".encode()
        flags = 0x5 if not body else 0x4
        out = resp(sid, st, [("content-type", "text/plain")], flags=flags)
        if body:
            out += h2_frame(0, 1, sid, body)
        send(False, out)
    send(False, h2_frame(7, 0, 0, struct.pack("!II", 41, 0)))
    frames = tcp_session(client, 52000, server, 443, flights, t0=t0)
    keylog = (f"CLIENT_TRAFFIC_SECRET_0 {ch[11:43].hex()} {cs.hex()}\n"
              f"SERVER_TRAFFIC_SECRET_0 {ch[11:43].hex()} {ss.hex()}\n")
    # Cleartext h2c with prior knowledge on port 80.
    c2, s2 = HpackEncoder(), HpackEncoder()
    text = b"plain HTTP/2 without TLS"
    frames += tcp_session(client, 52001, server, 80, [
        (True, H2_PREFACE + h2_frame(4, 0, 0) + h2_frame(1, 0x5, 1, c2.block(
            [(":method", "GET"), (":scheme", "http"), (":authority", "h2c.example"), (":path", "/clear.txt"),
             ("user-agent", "curl/8.4.0")]))),
        (False, h2_frame(4, 0, 0) + h2_frame(4, 1, 0) + h2_frame(1, 0x4, 1, s2.block(
            [(":status", "200"), ("content-type", "text/plain"), ("content-length", str(len(text)))])) +
         h2_frame(0, 1, 1, text)),
        (True, h2_frame(4, 1, 0) + h2_frame(7, 0, 0, struct.pack("!II", 0, 0)))], t0=t0 + 30)
    return frames, keylog


def _hkdf_label(secret: bytes, label: str, n: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack("!HB", n, len(full)) + full + b"\0"
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:n]


QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def quic_initial_keys(odcid: bytes, server: bool):
    initial = hmac.new(QUIC_V1_SALT, odcid, hashlib.sha256).digest()
    secret = _hkdf_label(initial, "server in" if server else "client in", 32)
    return _hkdf_label(secret, "quic key", 16), _hkdf_label(secret, "quic iv", 12), _hkdf_label(secret, "quic hp", 16)


def _varint(v: int) -> bytes:
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return struct.pack("!H", 0x4000 | v)
    return struct.pack("!I", 0x80000000 | v)


def quic_crypto(offset: int, data: bytes) -> bytes:
    return b"\x06" + _varint(offset) + _varint(len(data)) + data


def quic_initial(odcid: bytes, dcid: bytes, scid: bytes, pn: int, frames: bytes, server=False, pad_to=0) -> bytes:
    """One protected QUIC v1 Initial packet (2-byte packet number)."""
    key, iv, hp = quic_initial_keys(odcid, server)
    head_len = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1 + 2 + 2
    if pad_to and head_len + len(frames) + 16 < pad_to:
        frames += bytes(pad_to - head_len - len(frames) - 16)  # PADDING frames
    header = (bytes([0xC1]) + struct.pack("!I", 1) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
              + b"\0" + struct.pack("!H", 0x4000 | (2 + len(frames) + 16)) + struct.pack("!H", pn))
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    packet = bytearray(header + aes128_gcm_seal(key, nonce, header, frames))
    pn_off = len(header) - 2
    mask = _aes128_encrypt(hp, bytes(packet[pn_off + 4:pn_off + 20]))
    packet[0] ^= mask[0] & 0x0F
    packet[pn_off] ^= mask[1]
    packet[pn_off + 1] ^= mask[2]
    return bytes(packet)


def quic_session(client, cport, server, sni="quic.example.com", t0=0.0):
    """A QUIC connection's start: the client's Client Hello split over two Initial
    packets (pieces out of order, as Chrome sends them), the server's Initial and
    Handshake replies in one datagram, then 1-RTT packets each way."""
    import random

    from anta.tools.pcapgen import BROWSER_CIPHERS, BROWSER_EXTS, tls_client_hello, tls_server_hello
    rng = random.Random(9)
    hello = tls_client_hello(sni, BROWSER_CIPHERS, BROWSER_EXTS + [0x0039], alpn=("h3",), rng=rng)[5:]
    odcid, server_cid = bytes.fromhex("c864bc90495127fe"), bytes.fromhex("02bc57870a00cc31")
    half = len(hello) // 2
    first = quic_crypto(half, hello[half:half + 100]) + b"\x01" + quic_crypto(0, hello[:half])
    second = b"\x01" + quic_crypto(half + 100, hello[half + 100:])
    shello = tls_server_hello(rng)[5:]
    ack = b"\x02\x01\x00\x00\x01"  # ACK: largest 1, no delay, no more ranges, first range 1
    handshake = (bytes([0xE1]) + struct.pack("!I", 1) + b"\0" + bytes([8]) + server_cid
                 + struct.pack("!H", 0x4000 | 60) + rng.randbytes(60))
    return [
        (t0, udp(client, server, cport, 443, quic_initial(odcid, odcid, b"", 0, first, pad_to=1200))),
        (t0 + 0.001, udp(client, server, cport, 443, quic_initial(odcid, odcid, b"", 1, second, pad_to=1200))),
        (t0 + 0.02, udp(server, client, 443, cport,
                        quic_initial(odcid, b"", server_cid, 0, ack + quic_crypto(0, shello), server=True)
                        + handshake)),
        (t0 + 0.03, udp(client, server, cport, 443, bytes([0x40]) + server_cid + rng.randbytes(40))),
        (t0 + 0.04, udp(server, client, 443, cport, bytes([0x44]) + rng.randbytes(60))),
    ]


# ------------------------------------------------- Windows domain protocols
# LDAP / CLDAP (BER), SMB2 over NetBIOS with an NTLM logon, DCE/RPC.

def _ber(tag, content):
    return _der(tag, content)


def _bint(v):
    return _ber(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def _boct(s):
    return _ber(0x04, s.encode() if isinstance(s, str) else s)


def ldap_message(msg_id, op, controls=b""):
    return _ber(0x30, _bint(msg_id) + op + controls)


def ldap_search(msg_id, base, scope=2, attrs=("cn",)):
    return ldap_message(msg_id, _ber(0x63, _boct(base) + _ber(0x0A, bytes([scope])) + _ber(0x0A, b"\0") + _bint(0)
                                     + _bint(0) + _ber(0x01, b"\0") + _ber(0x87, b"objectClass")
                                     + _ber(0x30, b"".join(_boct(a) for a in attrs))))


def ldap_entry(msg_id, dn, attrs=(("cn", b"x"),)):
    items = b"".join(_ber(0x30, _boct(t) + _ber(0x31, _boct(v))) for t, v in attrs)
    return ldap_message(msg_id, _ber(0x64, _boct(dn) + _ber(0x30, items)))


def ldap_result(msg_id, app, code, error=""):
    return ldap_message(msg_id, _ber(app, _ber(0x0A, bytes([code])) + _boct("") + _boct(error)))


def ldap_bind(msg_id, name, password=None, mechanism=None, credentials=b""):
    auth = _ber(0x80, password.encode()) if password is not None else \
        _ber(0xA3, _boct(mechanism) + (_boct(credentials) if credentials else b""))
    return ldap_message(msg_id, _ber(0x60, _bint(3) + _boct(name) + auth))


def netlogon_response(forest, domain, host, nb_domain, nb_host, site="Default-First-Site-Name"):
    """MS-ADTS NETLOGON_SAM_LOGON_RESPONSE_EX, as a domain controller answers a CLDAP ping."""
    def name(n):
        return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".") if p) + b"\0"
    return (struct.pack("<HHI", 23, 0, 0x0003F3FD) + bytes(16) + name(forest) + name(domain) + name(host)
            + name(nb_domain) + name(nb_host) + b"\0" + name(site) + name(site) + struct.pack("<IHH", 5, 0xFFFF, 0xFFFF))


def ldap_session(client, cport, server, t0=0.0):
    ex = [(True, ldap_bind(1, "cn=admin,dc=example,dc=com", "pw")), (False, ldap_result(1, 0x61, 0)),
          (True, ldap_search(2, "dc=example,dc=com")),
          (False, ldap_entry(2, "cn=a,dc=example,dc=com") + ldap_entry(2, "cn=b,dc=example,dc=com")
           + ldap_result(2, 0x65, 0)),
          (True, ldap_search(3, "dc=example,dc=com", 1)), (False, ldap_result(3, 0x65, 32, "no such object")),
          (True, ldap_message(4, b"\x42\x00"))]
    frames = tcp_session(client, cport, server, 389, ex, t0=t0)
    t = frames[-1][0] + 0.1
    ping = ldap_search(5, "", 0, ("Netlogon",))
    reply = ldap_entry(5, "", (("Netlogon", netlogon_response("example.com", "example.com", "dc-1.example.com",
                                                                 "EXAMPLE", "DC-1")),)) + ldap_result(5, 0x65, 0)
    return frames + [(t, udp(client, server, cport + 1, 389, ping)), (t + 0.01, udp(server, client, 389, cport + 1, reply))]


def _utf16(s):
    return s.encode("utf-16-le")


def smb2_header(cmd, msg_id, response=False, status=0, tree=0, session=0x11):
    return (b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 1, status, cmd, 1, 1 if response else 0, 0, msg_id, 0xFEFF,
                                     tree, session) + bytes(16))


def _nb(msg):
    return struct.pack("!I", len(msg)) + msg


def _fid(n):
    return struct.pack("<QQ", n, n + 0x100)


def ntlm_negotiate():
    return b"NTLMSSP\0" + struct.pack("<II", 1, 0xE2088297) + bytes(16)


def ntlm_challenge():
    return (b"NTLMSSP\0" + struct.pack("<IHHII", 2, 0, 0, 56, 0xE2898215) + bytes(8) + bytes(8)
            + struct.pack("<HHI", 0, 0, 56) + bytes(8))


def ntlm_auth(domain, user, host):
    fields = [bytes(24), bytes(24), _utf16(domain), _utf16(user), _utf16(host)]
    body, off = b"NTLMSSP\0" + struct.pack("<I", 3), 88
    for data in fields:
        body += struct.pack("<HHI", len(data), len(data), off)
        off += len(data)
    body += struct.pack("<HHII", 0, 0, 0, 0xE2888215) + bytes(24)
    return body.ljust(88, b"\0") + b"".join(fields)


def spnego(token, response=False):
    if response:
        return _der(0xA1, _der(0x30, _der(0xA2, _der(0x04, token))))
    mech = _der(0x30, _der(0x06, bytes.fromhex("2b06010401823702020a")))
    return _der(0x60, _der(0x06, bytes.fromhex("2b0601050502")) + _der(0xA0, _der(0x30, _der(0xA0, mech)
                                                                                + _der(0xA2, _der(0x04, token)))))


def smb2_file_session(client, cport, server, transfers, user=("CORP", "alice", "WS-1"), t0=0.0):
    """An NTLM logon, then for each (share, path, data, write) a tree connect,
    create, the data in 4 KB writes or reads, and close."""
    msgs, mid = [], [0]

    def nxt():
        mid[0] += 1
        return mid[0]

    def pair(req, resp):
        msgs.append((True, _nb(req)))
        msgs.append((False, _nb(resp)))

    m = nxt()
    hello = spnego(ntlm_negotiate())
    pair(smb2_header(1, m, session=0) + struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(hello), 0) + hello,
         smb2_header(1, m, True, 0xC0000016) + struct.pack("<HHHH", 9, 0, 72, len(spnego(ntlm_challenge(), True)))
         + spnego(ntlm_challenge(), True))
    auth = spnego(ntlm_auth(*user), True)
    m = nxt()
    pair(smb2_header(1, m) + struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(auth), 0) + auth,
         smb2_header(1, m, True) + struct.pack("<HHHH", 9, 0, 72, 0))
    for i, (share, path, data, write) in enumerate(transfers):
        tree, fid = 5 + i, 0x41 + i
        m = nxt()
        p = _utf16(share)
        stype = 2 if share.upper().endswith("IPC$") else 1
        pair(smb2_header(3, m) + struct.pack("<HHHH", 9, 0, 72, len(p)) + p,
             smb2_header(3, m, True, tree=tree) + struct.pack("<HBBIII", 16, stype, 0, 0, 0, 0x1F01FF))
        m = nxt()
        n = _utf16(path)
        pair(smb2_header(5, m, tree=tree) + struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, 0x12019F, 0x80, 7,
                                                        5 if write else 1, 0x40, 120, len(n), 0, 0) + n,
             smb2_header(5, m, True, tree=tree) + struct.pack("<HBBI", 89, 0, 0, 2 if write else 1) + bytes(32)
             + struct.pack("<QQII", 0, 0 if write else len(data), 0x80, 0) + _fid(fid) + struct.pack("<II", 0, 0))
        for off in range(0, len(data), 4096):
            chunk, m = data[off:off + 4096], nxt()
            if write:
                pair(smb2_header(9, m, tree=tree) + struct.pack("<HHIQ", 49, 112, len(chunk), off) + _fid(fid)
                     + struct.pack("<IIHHI", 0, 0, 0, 0, 0) + chunk,
                     smb2_header(9, m, True, tree=tree) + struct.pack("<HHIIHH", 17, 0, len(chunk), 0, 0, 0))
            else:
                pair(smb2_header(8, m, tree=tree) + struct.pack("<HBBIQ", 49, 0, 0, len(chunk), off) + _fid(fid)
                     + struct.pack("<IIIHHB", 0, 0, 0, 0, 0, 0),
                     smb2_header(8, m, True, tree=tree) + struct.pack("<HBBIII", 17, 80, 0, len(chunk), 0, 0) + chunk)
        m = nxt()
        pair(smb2_header(6, m, tree=tree) + struct.pack("<HHI", 24, 0, 0) + _fid(fid),
             smb2_header(6, m, True, tree=tree) + struct.pack("<HHI", 60, 0, 0) + bytes(32) + struct.pack("<QQI", 0, 0, 0))
    return tcp_session(client, cport, server, 445, msgs, t0=t0, seg=1400)


_NDR32 = ("8a885d04-1ceb-11c9-9fe8-08002b104860", 2)
_NDR64 = ("71710533-beba-4937-8319-b5dbef9ccc36", 1)


def _uuid(s):
    import uuid
    return uuid.UUID(s).bytes_le


def dcerpc_pdu(ptype, call_id, body, flags=3):
    return struct.pack("<BBBB4sHHI", 5, 0, ptype, flags, b"\x10\0\0\0", 16 + len(body), 0, call_id) + body


def dcerpc_bind(call_id, iface, version, syntaxes=(_NDR32, _NDR64), alter=False):
    items = b"".join(struct.pack("<HBB", i, 1, 0) + _uuid(iface) + struct.pack("<HH", *version) + _uuid(s)
                     + struct.pack("<I", v) for i, (s, v) in enumerate(syntaxes))
    return dcerpc_pdu(14 if alter else 11, call_id, struct.pack("<HHIB3x", 5840, 5840, 0, len(syntaxes)) + items)


def dcerpc_bind_ack(call_id, results):
    port = b"\\PIPE\\x\0"
    body = struct.pack("<HHIH", 5840, 5840, 0x1234, len(port)) + port
    body += bytes(-(len(body) + 16) % 4) + struct.pack("<B3x", len(results))
    body += b"".join(struct.pack("<HH", r, 0) + (_uuid(_NDR32[0]) + struct.pack("<I", 2) if r == 0 else bytes(20))
                     for r in results)
    return dcerpc_pdu(12, call_id, body)


def dcerpc_request(call_id, ctx, opnum, stub=b"\0" * 20):
    return dcerpc_pdu(0, call_id, struct.pack("<IHH", len(stub), ctx, opnum) + stub)


def dcerpc_response(call_id, ctx, stub=b"\0" * 8):
    return dcerpc_pdu(2, call_id, struct.pack("<IHBB", len(stub), ctx, 0, 0) + stub)


def dcerpc_fault(call_id, ctx, status):
    return dcerpc_pdu(3, call_id, struct.pack("<IHBBI4x", 0, ctx, 0, 0, status))


def epm_map_request(call_id, ctx, iface, version):
    floors = [b"\x0d" + _uuid(iface) + struct.pack("<H", version[0]), struct.pack("<H", version[1]),
              b"\x0d" + _uuid(_NDR32[0]) + struct.pack("<H", 2), b"\0\0", b"\x0b", b"\0\0", b"\x07", b"\0\x87",
              b"\x09", bytes(4)]
    tower = struct.pack("<H", 5) + b"".join(struct.pack("<H", len(floors[i])) + floors[i] + struct.pack("<H", len(
        floors[i + 1])) + floors[i + 1] for i in range(0, 10, 2))
    stub = struct.pack("<I", 1) + bytes(16) + struct.pack("<I", 2) + struct.pack("<II", len(tower), len(tower))
    stub += tower + bytes(-len(tower) % 4) + bytes(20) + struct.pack("<I", 4)
    return dcerpc_request(call_id, ctx, 3, stub)


def dcerpc_session(client, cport, server, t0=0.0):
    """The endpoint mapper locating DRSUAPI, then SAMR calls (two in one segment) and a fault."""
    epm, samr, drs = ("e1af8308-5d1f-11c9-91a4-08002b14a0fa", (3, 0)), \
        ("12345778-1234-abcd-ef00-0123456789ac", (1, 0)), ("e3514235-4b06-11d1-ab04-00c04fc2dcd2", (4, 0))
    no_towers = bytes(20) + struct.pack("<IIII", 0, 4, 0, 0) + struct.pack("<I", 0)  # handle, none found, status
    handle = bytes(4) + bytes(range(1, 17))
    close_req, close_resp = handle, bytes(20) + bytes(4)  # samr_Close: the handle in, a zeroed handle and status out
    frames = tcp_session(client, cport, server, 135, [
        (True, dcerpc_bind(2, *epm)), (False, dcerpc_bind_ack(2, (0, 2))),
        (True, epm_map_request(3, 0, *drs)), (False, dcerpc_response(3, 0, no_towers))], t0=t0)
    frames += tcp_session(client, cport + 1, server, 49667, [
        (True, dcerpc_bind(2, *samr)), (False, dcerpc_bind_ack(2, (0, 2))),
        (True, dcerpc_request(3, 0, 1, close_req)), (False, dcerpc_response(3, 0, close_resp)),
        (True, dcerpc_request(4, 0, 1, close_req) + dcerpc_request(5, 0, 1, close_req)),
        (False, dcerpc_response(4, 0, close_resp) + dcerpc_response(5, 0, close_resp)),
        (True, dcerpc_request(6, 0, 999)), (False, dcerpc_fault(6, 0, 0x1C010002))], t0=frames[-1][0] + 0.1)
    return frames


# ------------------------------------- FTP, DNS from several resolvers, hand-built TCP

class _Tcp:
    """One TCP connection built a step at a time, so several can interleave."""

    def __init__(self, client, cport, server, sport):
        self.ends = (client, cport, server, sport)
        self.cseq, self.sseq = 1000, 5000

    def open(self):
        c, cp, s, sp = self.ends
        out = [tcp(c, s, cp, sp, self.cseq, 0, SYN, opts=mss_option(1460) + SACK_PERM),
               tcp(s, c, sp, cp, self.sseq, self.cseq + 1, SYN | ACK, opts=mss_option(1460) + SACK_PERM)]
        self.cseq += 1
        self.sseq += 1
        out.append(tcp(c, s, cp, sp, self.cseq, self.sseq, ACK))
        return out

    def send(self, from_client, payload, seg=1400):
        c, cp, s, sp = self.ends
        out = []
        for i in range(0, len(payload), seg):
            chunk = payload[i:i + seg]
            if from_client:
                out.append(tcp(c, s, cp, sp, self.cseq, self.sseq, PSH | ACK, chunk))
                self.cseq += len(chunk)
                out.append(tcp(s, c, sp, cp, self.sseq, self.cseq, ACK))
            else:
                out.append(tcp(s, c, sp, cp, self.sseq, self.cseq, PSH | ACK, chunk))
                self.sseq += len(chunk)
                out.append(tcp(c, s, cp, sp, self.cseq, self.sseq, ACK))
        return out

    def close(self):
        c, cp, s, sp = self.ends
        return [tcp(c, s, cp, sp, self.cseq, self.sseq, FIN | ACK),
                tcp(s, c, sp, cp, self.sseq, self.cseq + 1, FIN | ACK),
                tcp(c, s, cp, sp, self.cseq + 1, self.sseq + 1, ACK)]


def _timeline(frames, t0=0.0, step=0.01):
    return [(t0 + i * step, f) for i, f in enumerate(frames)]


def ftp_session(client, cport, server, transfers, announce=None, user="anonymous", t0=0.0):
    """A login and its transfers as vsftpd answers them; AUTH TLS is refused before
    login, so everything goes in the clear. Each transfer is (mode, command, data):
    mode "pasv" (the 227 names `announce` instead of `server` when given, as a server
    behind NAT does) or "port" (the server connects back from port 20); command
    "STOR name", "RETR name" or "LIST"."""
    ctl = _Tcp(client, cport, server, 21)
    out = ctl.open()

    def say(from_client, text):
        out.extend(ctl.send(from_client, text.encode() + b"\r\n"))

    say(False, "220 (vsFTPd 3.0.5)")
    say(True, "AUTH TLS")
    say(False, "530 Please login with USER and PASS.")
    say(True, f"USER {user}")
    say(False, "331 Please specify the password.")
    say(True, "PASS ")
    say(False, "230 Login successful.")
    say(True, "TYPE I")
    say(False, "200 Switching to Binary mode.")
    for n, (mode, command, data) in enumerate(transfers):
        dport = 45100 + n  # (40000 is SAP NI to Wireshark)
        upload = command.split()[0] in ("STOR", "APPE", "STOU")
        if mode == "pasv":
            say(True, "PASV")
            say(False, f"227 Entering Passive Mode ({(announce or server).replace('.', ',')},{dport >> 8},{dport & 255}).")
            conn = _Tcp(client, cport + 1 + n, server, dport)
            out.extend(conn.open())  # clients connect as soon as they know the port
            say(True, command)
            say(False, "150 Ok to send data.")
            sender_is_client = upload
        else:
            say(True, f"PORT {client.replace('.', ',')},{dport >> 8},{dport & 255}")
            say(False, "200 PORT command successful. Consider using PASV.")
            say(True, command)
            say(False, "150 Ok to send data.")
            conn = _Tcp(server, 20, client, dport)
            out.extend(conn.open())
            sender_is_client = not upload
        out.extend(conn.send(sender_is_client, data))
        out.extend(conn.close())
        say(False, "226 Transfer complete.")
    say(True, "QUIT")
    say(False, "221 Goodbye.")
    out.extend(ctl.close())
    return _timeline(out, t0)


def dns_lookups(lookups, t0=0.0):
    """Each (client, resolver, name, answers) as a query and its answer: A records,
    or AAAA when the answers are IPv6."""
    from anta.tools.pcapgen import dns_query, dns_response
    frames = []
    for n, (client, resolver, name, answers) in enumerate(lookups):
        qtype = 28 if answers and ":" in answers[0] else 1
        frames.append((t0 + n * 0.1, udp(client, resolver, 41000 + n, 53, dns_query(0x1000 + n, name, qtype))))
        frames.append((t0 + n * 0.1 + 0.005,
                       udp(resolver, client, 53, 41000 + n, dns_response(0x1000 + n, name, qtype, answers))))
    return frames


def flagless_tcp(client, cport, server, sport, payloads, t0=0.0):
    """Data in TCP segments with no flags at all, not even ACK: only a program writing
    raw packets sends these."""
    frames, seq = [], {True: 7000, False: 9000}
    for i, (from_client, data) in enumerate(payloads):
        if from_client:
            frames.append((t0 + i * 0.2, tcp(client, server, cport, sport, seq[True], 0, 0, data)))
        else:
            frames.append((t0 + i * 0.2, tcp(server, client, sport, cport, seq[False], 0, 0, data)))
        seq[from_client] += len(data)
    return frames


# A small routed lab: three OpenWrt routers back their configurations up to an FTP
# server, and gw3 lies about a package mirror's address.
FTP_SERVER, FTP_NAT = "172.16.9.5", "172.16.90.5"
GW1, GW2, GW3 = "192.168.10.254", "192.168.20.254", "192.168.30.254"
GW3_ADDRESSES = ["127.9.9.3", "192.168.30.254", "10.9.5.1"]
MIRROR, MIRROR_ADDRS, FALSE_ADDR = "deb.debian.org", ["151.101.2.132", "151.101.66.132"], "203.0.113.77"
GW1_CONFIG = """config system
\toption hostname 'gw1'

config interface 'lan'
\toption proto 'static'
\toption ipaddr '192.168.10.254'
\toption netmask '255.255.255.0'

config interface 'uplink'
\toption proto 'static'
\toption ipaddr '10.9.4.1'
\toption netmask '255.255.255.240'
"""
GW3_CONFIG = """config interface 'loopback'
\toption device 'lo'
\toption proto 'static'
\toption ipaddr '127.9.9.3'
\toption netmask '255.0.0.0'

config interface 'lan'
\toption device 'br-lan'
\toption proto 'static'
\toption ipaddr '192.168.30.254'
\toption netmask '255.255.255.0'

config interface 'uplink'
\toption device 'eth1'
\toption proto 'static'
\tlist ipaddr '10.9.5.1/28'

config interface 'wan'
\toption device 'eth2'
\toption proto 'dhcp'

config route
\toption target '0.0.0.0/0'
\toption gateway '10.9.5.2'
\toption interface 'uplink'
"""
LISTING = ("-rw------- 1 122 124  258 Aug 29 13:59 gw1_backup.config\r\n"
           "-rw------- 1 122 124  522 Aug 29 14:06 gw3_backup.config\r\n"
           "-rw-r--r-- 1 122 124    0 Aug 29 13:51 test.txt\r\n")


def router_lab(t0=0.0):
    """gw1 backs up over passive FTP; gw3 from its uplink address through a server
    behind NAT (the 227 names an address that isn't on the wire); a workstation lists
    the directory in active mode. Two resolvers answer the mirror truthfully, gw3
    with a documentation address, and its client then talks to that address in
    hand-built TCP segments."""
    frames = ftp_session("10.9.4.1", 51000, FTP_SERVER, [("pasv", "STOR backups/gw1_backup.config", GW1_CONFIG.encode())],
                         t0=t0)
    frames += ftp_session("10.9.5.1", 51100, FTP_SERVER, [
        ("pasv", "STOR backups/gw3_backup.config", GW3_CONFIG.encode()),
        ("pasv", "STOR backups/test.txt", b"")], announce=FTP_NAT, t0=frames[-1][0] + 1)
    frames += ftp_session("192.168.10.20", 51200, FTP_SERVER, [("port", "LIST", LISTING.encode())],
                          t0=frames[-1][0] + 1)
    frames += dns_lookups([("192.168.10.20", GW1, MIRROR, MIRROR_ADDRS),
                           ("192.168.20.31", GW2, MIRROR, MIRROR_ADDRS[::-1]),
                           ("192.168.30.40", GW3, MIRROR, [FALSE_ADDR])], t0=frames[-1][0] + 1)
    frames += flagless_tcp("192.168.30.40", 52000, FALSE_ADDR, 14159,
                           [(True, b"\x13\x37" + bytes(range(120))), (False, b"\x13\x38" + bytes(40)),
                            (True, bytes(range(200)))], t0=frames[-1][0] + 1)
    return frames


# ------------------------------------------------- what failing connections look like

def _quoted(frame: bytes) -> bytes:
    """What an ICMP error carries: the offending packet's IP header and first 8 bytes."""
    return b"\0\0\0\0" + frame[14:14 + 28]


def _dns_reply(txid, name, rcode, answers=()):
    from anta.tools.pcapgen import dns_response
    msg = dns_response(txid, name, 1, list(answers))
    return msg[:2] + struct.pack("!H", 0x8180 | rcode) + msg[4:]


def _tls_server_hello_12(seed=9):
    """A TLS 1.2 ServerHello (no supported_versions): what follows it stays readable."""
    import random
    rng = random.Random(seed)
    body = struct.pack("!H", 0x0303) + rng.randbytes(32) + b"\x20" + rng.randbytes(32) + struct.pack("!HB", 0xC02F, 0)
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def _tls_alert(desc, fatal=True):
    return b"\x15\x03\x03\x00\x02" + bytes([2 if fatal else 1, desc])


TROUBLE_CLIENT = "10.20.0.5"


def troubleshooting_lab(t0=0.0):
    """Connections that fail in the ways analysts have to explain, one of each:
    refused, unanswered, blocked by a firewall (ICMP), a closed UDP port, a TLS
    handshake the server rejects, a certificate the client rejects, HTTP errors,
    a server that resets mid-transfer, a receiver that stops reading (zero window),
    packet loss, DNS failures, a wrong Kerberos password, an FTP login failure and
    hand-built TCP. Each is on its own server so it is its own conversation."""
    import random
    from anta.tools.pcapgen import BROWSER_CIPHERS, BROWSER_EXTS, tls_client_hello
    c = TROUBLE_CLIENT
    frames = []

    def at(t, f):
        frames.append((t0 + t, f))

    # Refused: the SYN is answered with RST, ACK.
    at(0.0, tcp(c, "10.20.0.10", 50001, 3389, 1000, 0, SYN, opts=mss_option(1460)))
    at(0.0004, tcp("10.20.0.10", c, 3389, 50001, 0, 1001, RST | ACK))
    # No answer: the SYN is sent three times and nothing comes back.
    for t in (1.0, 2.0, 4.0):
        at(t, tcp(c, "10.20.0.11", 50002, 22, 2000, 0, SYN, opts=mss_option(1460)))
    # A firewall rejects it: ICMP "administratively prohibited" from the gateway.
    syn = tcp(c, "198.51.100.20", 50003, 8443, 3000, 0, SYN, opts=mss_option(1460))
    at(5.0, syn)
    at(5.002, icmp("10.20.0.1", c, 3, 13, _quoted(syn)))
    # UDP to a closed port: the host answers ICMP port unreachable.
    q = udp(c, "10.20.0.12", 50004, 161, b"\x30\x1a\x02\x01\x01\x04\x06public\xa0\x0d\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x00")
    at(6.0, q)
    at(6.001, icmp("10.20.0.12", c, 3, 3, _quoted(q)))

    def session(t, server, cport, sport, exchanges, close=True):
        for dt, f in tcp_session(c, cport, server, sport, exchanges, step=0.01, close=close):
            at(t + dt, f)

    rng = random.Random(4)
    hello = tls_client_hello("legacy.example.net", BROWSER_CIPHERS, BROWSER_EXTS, rng=rng)
    # The server refuses the TLS handshake (no cipher or version in common).
    session(7.0, "203.0.113.30", 50005, 443, [(True, hello), (False, _tls_alert(40))])
    # The client refuses the server's certificate (an untrusted CA: interception, or self-signed).
    hello2 = tls_client_hello("intranet.example.net", BROWSER_CIPHERS, BROWSER_EXTS, rng=rng)
    session(8.0, "10.20.0.13", 50006, 443, [(True, hello2), (False, _tls_server_hello_12()), (True, _tls_alert(48))])
    # HTTP errors: a missing page, then an overloaded back end.
    session(9.0, "10.20.0.14", 50007, 80, [
        (True, b"GET /old/report.pdf HTTP/1.1\r\nHost: files.example.net\r\n\r\n"),
        (False, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"),
        (True, b"GET /api/status HTTP/1.1\r\nHost: files.example.net\r\n\r\n"),
        (False, b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")])
    # The server resets the connection in the middle of a download.
    conn = _Tcp(c, 50008, "10.20.0.15", 8080)
    steps = conn.open() + conn.send(True, b"GET /big.iso HTTP/1.1\r\nHost: mirror\r\n\r\n")
    steps += conn.send(False, b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n" + bytes(2800))
    steps.append(tcp("10.20.0.15", c, 8080, 50008, conn.sseq, conn.cseq, RST | ACK))
    for i, f in enumerate(steps):
        at(10.0 + i * 0.01, f)
    # The receiver stops reading: it advertises a zero window, the sender probes, then it reads again.
    s0, c0 = 7000, 9000
    z = [tcp(c, "10.20.0.16", 50009, 7070, c0, 0, SYN, opts=mss_option(1460)),
         tcp("10.20.0.16", c, 7070, 50009, s0, c0 + 1, SYN | ACK, opts=mss_option(1460)),
         tcp(c, "10.20.0.16", 50009, 7070, c0 + 1, s0 + 1, ACK),
         tcp("10.20.0.16", c, 7070, 50009, s0 + 1, c0 + 1, PSH | ACK, bytes(1400)),
         tcp(c, "10.20.0.16", 50009, 7070, c0 + 1, s0 + 1401, ACK, window=0),
         tcp("10.20.0.16", c, 7070, 50009, s0 + 1400, c0 + 1, ACK, bytes(1)),
         tcp(c, "10.20.0.16", 50009, 7070, c0 + 1, s0 + 1401, ACK, window=0),
         tcp(c, "10.20.0.16", 50009, 7070, c0 + 1, s0 + 1401, ACK, window=65535),
         tcp("10.20.0.16", c, 7070, 50009, s0 + 1401, c0 + 1, PSH | ACK, bytes(600)),
         tcp(c, "10.20.0.16", 50009, 7070, c0 + 1, s0 + 2001, ACK)]
    for t, f in zip((12.0, 12.01, 12.02, 12.03, 12.04, 12.5, 12.51, 14.0, 14.01, 14.02), z):
        at(t, f)
    # Packet loss: two data segments are sent again after a timeout.
    conn = _Tcp(c, 50010, "10.20.0.17", 5001)
    steps = conn.open()
    for i, f in enumerate(steps):
        at(15.0 + i * 0.01, f)
    seq = conn.cseq
    for k in range(4):
        seg = tcp(c, "10.20.0.17", 50010, 5001, seq + k * 1000, conn.sseq, PSH | ACK, bytes(1000))
        at(15.1 + k * 0.001, seg)
        if k in (1, 2):
            at(15.5 + k * 0.001, seg)  # retransmitted
    at(15.6, tcp("10.20.0.17", c, 5001, 50010, conn.sseq, seq + 4000, ACK))
    # DNS: a name that doesn't exist, a resolver that fails, and a query nobody answers.
    from anta.tools.pcapgen import dns_query
    at(16.0, udp(c, "10.20.0.53", 51001, 53, dns_query(0x2001, "printer-old.corp.example")))
    at(16.01, udp("10.20.0.53", c, 53, 51001, _dns_reply(0x2001, "printer-old.corp.example", 3)))
    at(16.1, udp(c, "10.20.0.53", 51002, 53, dns_query(0x2002, "partner.example.org")))
    at(16.2, udp("10.20.0.53", c, 53, 51002, _dns_reply(0x2002, "partner.example.org", 2)))
    for t in (17.0, 18.0, 20.0):
        at(t, udp(c, "10.20.0.54", 51003, 53, dns_query(0x2003, "updates.example.com")))
    # Kerberos: the password was wrong (pre-authentication failed).
    at(21.0, udp(c, "10.20.0.88", 51004, 88, krb_request("jdoe", "CORP.EXAMPLE", "WS-7")))
    at(21.01, udp("10.20.0.88", c, 88, 51004, krb_error(24, "CORP.EXAMPLE", "jdoe")))
    # FTP: the login is refused.
    session(22.0, "10.20.0.21", 50011, 21, [
        (False, b"220 FTP server ready\r\n"), (True, b"USER backup\r\n"),
        (False, b"331 Password required for backup\r\n"), (True, b"PASS hunter2\r\n"),
        (False, b"530 Login incorrect.\r\n"), (True, b"QUIT\r\n"), (False, b"221 Goodbye.\r\n")])
    # A healthy connection, for contrast.
    session(23.0, "10.20.0.80", 50012, 80, [
        (True, b"GET / HTTP/1.1\r\nHost: intranet\r\n\r\n"),
        (False, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")])
    frames.sort(key=lambda x: x[0])
    return frames


# ------------------------------------------------------------- the sampler

def _mysql(seq: int, payload: bytes) -> bytes:
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


def _lenenc_str(b: bytes) -> bytes:
    return bytes([len(b)]) + b


def mysql_session(client, cport, server, t0=0.0, user=b"shop_app", db=b"shop"):
    """MySQL: greeting, login, a query that works and one that fails (table missing)."""
    greeting = (b"\x0a" + b"8.0.36\x00" + struct.pack("<I", 41) + b"abcdefgh\x00" + struct.pack("<H", 0xFFFF) + b"\xff" +
                struct.pack("<H", 2) + struct.pack("<H", 0xDFFF) + b"\x15" + bytes(10) + b"ijklmnopqrst\x00" +
                b"caching_sha2_password\x00")
    login = (struct.pack("<I", 0x00AFA68D) + struct.pack("<I", 16 * 1024 * 1024) + b"\xff" + bytes(23) + user + b"\x00" +
             _lenenc_str(bytes(range(1, 33))) + db + b"\x00" + b"caching_sha2_password\x00")
    ok = b"\x00\x00\x00\x02\x00\x00\x00"
    col = (_lenenc_str(b"def") + _lenenc_str(b"") + _lenenc_str(b"") + _lenenc_str(b"") + _lenenc_str(b"1") +
           _lenenc_str(b"") + b"\x0c" + struct.pack("<HIBHB", 0x3f, 1, 8, 0x81, 0) + b"\x00\x00")
    eof = b"\xfe\x00\x00\x02\x00"
    result = (_mysql(1, b"\x01") + _mysql(2, col) + _mysql(3, eof) +
              _mysql(4, _lenenc_str(b"1")) + _mysql(5, eof))
    err = b"\xff" + struct.pack("<H", 1146) + b"#42S02" + b"Table 'shop.orderz' doesn't exist"
    return tcp_session(client, cport, server, 3306, [
        (False, _mysql(0, greeting)), (True, _mysql(1, login)), (False, _mysql(2, ok)),
        (True, _mysql(0, b"\x03SELECT 1")), (False, result),
        (True, _mysql(0, b"\x03SELECT * FROM orderz")), (False, _mysql(1, err)),
        (True, _mysql(0, b"\x01"))], t0=t0)


def _pg(tag: bytes, body: bytes) -> bytes:
    return tag + struct.pack("!I", len(body) + 4) + body


def pgsql_session(client, cport, server, t0=0.0):
    """PostgreSQL: startup, a query that works and one that fails (relation missing)."""
    startup = b"user\x00report\x00database\x00sales\x00\x00"
    startup = struct.pack("!II", len(startup) + 8, 196608) + startup
    hello = (_pg(b"R", struct.pack("!I", 0)) + _pg(b"S", b"server_version\x0016.4\x00") +
             _pg(b"K", struct.pack("!II", 4242, 99)) + _pg(b"Z", b"I"))
    rowdesc = _pg(b"T", struct.pack("!H", 1) + b"?column?\x00" + struct.pack("!IHIhih", 0, 0, 23, 4, -1, 0))
    rows = rowdesc + _pg(b"D", struct.pack("!HI", 1, 1) + b"1") + _pg(b"C", b"SELECT 1\x00") + _pg(b"Z", b"I")
    error = _pg(b"E", b"SERROR\x00VERROR\x00C42P01\x00Mrelation \"invoices\" does not exist\x00P15\x00"
                      b"Fparse_relation.c\x00L1452\x00RparserOpenTable\x00\x00") + _pg(b"Z", b"I")
    return tcp_session(client, cport, server, 5432, [
        (True, startup), (False, hello),
        (True, _pg(b"Q", b"SELECT 1\x00")), (False, rows),
        (True, _pg(b"Q", b"SELECT * FROM invoices\x00")), (False, error),
        (True, _pg(b"X", b""))], t0=t0)


def _tds(typ: int, body: bytes, status: int = 1, pid: int = 0, packet: int = 1) -> bytes:
    return struct.pack("!BBHHBB", typ, status, len(body) + 8, pid, packet, 0) + body


def _tds_batch(sql: str) -> bytes:
    headers = struct.pack("<I", 22) + struct.pack("<IH", 18, 2) + bytes(8) + struct.pack("<I", 1)
    return _tds(0x01, headers + sql.encode("utf-16-le"))


def _us_varchar(s: str) -> bytes:
    return struct.pack("<H", len(s)) + s.encode("utf-16-le")


def _b_varchar(s: str) -> bytes:
    return bytes([len(s)]) + s.encode("utf-16-le")


def tds_session(client, cport, server, t0=0.0):
    """Microsoft SQL Server (TDS 7.4): pre-login, a batch that fails (invalid object name) and one that works."""
    def prelogin(opts):
        head, data, off = b"", b"", 5 * len(opts) + 1
        for tok, val in opts:
            head += struct.pack("!BHH", tok, off + len(data), len(val))
            data += val
        return head + b"\xff" + data
    pre_c = _tds(0x12, prelogin([(0, bytes([16, 0, 0x10, 0x00, 0, 0])), (1, b"\x00"), (2, b"\x00"),
                                (3, struct.pack("!I", 1234)), (4, b"\x00")]))
    pre_s = _tds(0x04, prelogin([(0, bytes([16, 0, 0x10, 0x00, 0, 0])), (1, b"\x02"), (2, b"\x00"),
                                (3, b""), (4, b"\x00")]))
    err = (b"\xaa" + struct.pack("<H", 0) + struct.pack("<IBB", 208, 1, 16) + _us_varchar("Invalid object name 'dbo.Payroll'.") +
           _b_varchar("SQLPROD01") + _b_varchar("") + struct.pack("<I", 1))
    err = err[:1] + struct.pack("<H", len(err) - 3) + err[3:]
    done_err = b"\xfd" + struct.pack("<HHQ", 0x0002, 0xC1, 0)
    colmeta = b"\x81" + struct.pack("<H", 1) + struct.pack("<IH", 0, 0x0001) + b"\x38" + _b_varchar("n")
    row = b"\xd1" + struct.pack("<i", 1)
    done = b"\xfd" + struct.pack("<HHQ", 0x0010, 0xC1, 1)
    return tcp_session(client, cport, server, 1433, [
        (True, pre_c), (False, pre_s),
        (True, _tds_batch("SELECT * FROM dbo.Payroll")), (False, _tds(0x04, err + done_err)),
        (True, _tds_batch("SELECT 1 AS n")), (False, _tds(0x04, colmeta + row + done))], t0=t0)


def dga_lab(t0=0.0, count=36, resolve_at=20):
    """Malware with a domain-generation algorithm: one host asks for many random names
    that do not exist (NXDOMAIN), until one in the batch resolves — the live C2."""
    import random
    from anta.tools.pcapgen import dns_query
    rng = random.Random(1234)
    client, resolver = "10.60.0.15", "10.60.0.1"
    tlds = ["com", "net", "info", "org", "biz", "xyz"]
    frames, t = [], t0
    for i in range(count):
        label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(12, 20)))
        name = f"{label}.{rng.choice(tlds)}"
        txid = 0x4000 + i
        sport = 50000 + i
        frames.append((t, udp(client, resolver, sport, 53, dns_query(txid, name, 1))))
        if i == resolve_at:                       # the generated name that is live: the C2
            frames.append((t + 0.01, udp(resolver, client, 53, sport, _dns_reply(txid, name, 0, ["45.33.7.9"]))))
        else:
            frames.append((t + 0.01, udp(resolver, client, 53, sport, _dns_reply(txid, name, 3))))
        t += 0.05
    return frames


def scan_lab(t0=0.0, ports=28, hosts=28):
    """Reconnaissance: an internal host SYN-scans many ports on one target (vertical,
    closed ports answer RST) and sweeps one port across many hosts (horizontal, most
    filtered with no reply). Neither completes a handshake."""
    scanner = "10.50.0.9"
    frames, t = [], t0
    target = "10.50.0.20"
    for i in range(ports):                       # vertical: 28 ports on one host, closed → RST/ACK
        port, sport = 1 + i, 40000 + i
        frames.append((t, tcp(scanner, target, sport, port, 1000 + i, 0, SYN, opts=mss_option(1460))))
        frames.append((t + 0.001, tcp(target, scanner, port, sport, 0, 1001 + i, RST | ACK)))
        t += 0.01
    for i in range(hosts):                       # horizontal: port 445 across 28 hosts, filtered → no reply
        host, sport = f"10.50.1.{10 + i}", 41000 + i
        frames.append((t, tcp(scanner, host, sport, 445, 2000 + i, 0, SYN, opts=mss_option(1460))))
        t += 0.01
    return frames


def arp_spoof_lab(t0=0.0):
    """A LAN where an attacker (02:…:66) poisons ARP: it answers for the gateway and for
    another host, so both appear claimed by two MACs. Normal ARP from the real owners is
    present too, and a VRRP virtual MAC shares an IP legitimately (must NOT be flagged)."""
    gw, host_a, host_b, vip = "192.168.7.1", "192.168.7.50", "192.168.7.51", "192.168.7.2"
    real_gw, mac_a, mac_b, attacker = "02:00:00:00:07:01", "02:00:00:00:07:50", "02:00:00:00:07:51", "02:00:00:00:07:66"
    vrrp_master, vrrp_backup = "02:00:00:00:07:aa", "00:00:5e:00:01:07"  # VRRP virtual MAC for vip
    frames = [
        (t0 + 0.0, arp(real_gw, gw, oper=1, tpa=host_a)),                 # real gateway asks who-has
        (t0 + 0.1, arp(mac_a, host_a, tha=real_gw, tpa=gw)),              # host A announces itself
        (t0 + 0.2, arp(mac_b, host_b, tha=real_gw, tpa=gw)),             # host B announces itself
        (t0 + 1.0, arp(attacker, gw, tha=mac_a, tpa=host_a)),            # attacker claims the gateway IP
        (t0 + 1.1, arp(attacker, host_a, tha=real_gw, tpa=gw)),          # ...and host A's IP (full MITM)
        (t0 + 2.0, arp(attacker, gw, tha=mac_b, tpa=host_b)),           # keeps poisoning
        (t0 + 3.0, arp(vrrp_master, vip, oper=1, tpa=gw)),              # a router behind the VRRP virtual IP
        (t0 + 3.1, arp(vrrp_backup, vip, tha=vrrp_master, tpa=gw)),     # the VRRP virtual MAC: legitimate sharing
    ]
    return frames


def database_lab(t0=0.0):
    """A client talking to MySQL, PostgreSQL and SQL Server; one query to each fails."""
    c = "10.30.0.20"
    frames = mysql_session(c, 51001, "10.30.0.31", t0)
    frames += pgsql_session(c, 51002, "10.30.0.32", t0 + 1)
    frames += tds_session(c, 51003, "10.30.0.33", t0 + 2)
    return sorted(frames, key=lambda f: f[0])


def ts_option(tsval: int, tsecr: int = 0) -> bytes:
    """NOP, NOP, Timestamps (RFC 7323): the sender's clock reading."""
    return b"\x01\x01\x08\x0a" + struct.pack("!II", tsval & 0xFFFFFFFF, tsecr & 0xFFFFFFFF)


def clocked_session(client, cport, server, sport, t0, seconds, client_clock, server_clock, step=0.5):
    """A connection whose packets carry both sides' TCP timestamps; *_clock(t) gives a side's reading at t."""
    frames = []
    cseq, sseq = 1000, 5000
    frames.append((t0, tcp(client, server, cport, sport, cseq, 0, SYN, opts=ts_option(client_clock(t0)))))
    frames.append((t0 + 0.01, tcp(server, client, sport, cport, sseq, cseq + 1, SYN | ACK,
                                  opts=ts_option(server_clock(t0 + 0.01), client_clock(t0)))))
    cseq += 1
    sseq += 1
    t = t0 + 0.02
    while t < t0 + seconds:
        frames.append((t, tcp(client, server, cport, sport, cseq, sseq, PSH | ACK, b"q" * 40, opts=ts_option(client_clock(t)))))
        cseq += 40
        frames.append((t + 0.01, tcp(server, client, sport, cport, sseq, cseq, PSH | ACK, b"r" * 60,
                                     opts=ts_option(server_clock(t + 0.01)))))
        sseq += 60
        t += step
    return frames


def clock_lab(t0=0.0):
    """Machines behind addresses (anta/clocks.py): a travel router hiding three machines behind
    192.168.70.1 (two 1000/s clocks started at different times and one ticking 100/s), one server
    answering from three addresses with one clock, a Linux-like host that randomises its clock per
    partner, and one that randomises per connection."""
    import random
    rng = random.Random(70)

    def clock(rate, started):  # a reading at capture time t of a clock that read 0 at `started` (seconds before base)
        return lambda t: int((t + started) * rate)

    frames = []
    a, b, c = clock(1000, 3 * 86400 + 123.4), clock(1000, 9 * 3600 + 7.7), clock(100, 2 * 86400 + 50.0)
    peers = ["203.0.113.10", "203.0.113.11", "198.51.100.12", "198.51.100.13"]
    port = 40000
    for i, (clk, start) in enumerate([(a, 0.0), (b, 1.0), (c, 2.0), (a, 8.0), (b, 9.0), (c, 10.0)]):
        port += 1
        frames += clocked_session("192.168.70.1", port, peers[i % 4], 443, start, 4.0, clk, clock(1000, 777.0 + i * 1000))
    server = clock(1000, 40 * 86400 + 3.3)
    for i, addr in enumerate(["192.168.70.20", "192.168.70.21", "192.168.70.22"]):
        for j in range(2):
            frames += clocked_session(f"192.168.70.{50 + j}", 41000 + i * 10 + j, addr, 80, 20.0 + i * 5 + j * 2, 3.0,
                                      clock(1000, 5000.0 + j * 333), server)
    # Per partner: one offset for each peer, kept for that peer's connections.
    offsets = {p: rng.randrange(1 << 31) for p in peers[:2]}
    for k in range(4):
        p = peers[k % 2]
        frames += clocked_session("192.168.70.30", 42000 + k, p, 443, 40.0 + k * 3, 2.5,
                                  lambda t, o=offsets[p]: int((t + 86400) * 1000) + o, clock(1000, 999.0))
    # Per connection: a new random offset every time.
    for k in range(4):
        o = rng.randrange(1 << 31)
        frames += clocked_session("192.168.70.40", 43000 + k, peers[k % 4], 443, 60.0 + k * 3, 2.5,
                                  lambda t, o=o: int((t + 86400) * 1000) + o, clock(1000, 555.0 + k))
    frames.sort(key=lambda f: f[0])
    return [(t0 + t, f) for t, f in frames]


def dns_answer(txid: int, qname: str, address: str, ttl: int) -> bytes:
    """A DNS response with one A record and the time to live given (a resolver's cache counts it down)."""
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".") if p) + b"\0"
    return (struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + labels + struct.pack("!HH", 1, 1)
            + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + bytes(int(x) for x in address.split(".")))


def dhcp_message(mtype: int, mac: str, xid: int, ciaddr="0.0.0.0", yiaddr="0.0.0.0", options=b"") -> bytes:  # noqa: S104
    """A DHCP message (BOOTP with the magic cookie): type 3 request, 5 ack."""
    def a(ip):
        return bytes(int(x) for x in ip.split("."))
    op = 2 if mtype in (2, 5, 6) else 1
    body = (struct.pack("!BBBBIHH", op, 1, 6, 0, xid, 0, 0) + a(ciaddr) + a(yiaddr) + bytes(8)  # (siaddr, giaddr: none)
            + _mac(mac) + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63" + bytes([53, 1, mtype]) + options + b"\xff")
    return body


def before_lab(t0=0.0):
    """A capture that starts in the middle of things (anta/before.py): a connection already open, a
    device using an address it looked up earlier, the router's DNS cache answering with time used
    up, a DHCP renewal partway through a 24-hour lease, and a TLS 1.3 session resumed."""
    from anta.tools.pcapgen import BROWSER_CIPHERS, BROWSER_EXTS, tls_client_hello
    frames = []
    add = lambda t, data: frames.append((t0 + t, data))  # noqa: E731
    # 1. Already open: data both ways, no handshake.
    for i in range(3):
        add(0.1 + i, tcp("192.168.60.10", "203.0.113.5", 50000, 443, 9000 + i * 100, 77000 + i * 50, PSH | ACK, b"a" * 100))
        add(0.15 + i, tcp("203.0.113.5", "192.168.60.10", 443, 50000, 77000 + i * 50, 9100 + i * 100, PSH | ACK, b"b" * 50))
    # 2. An address known already: a TLS hello by name, no DNS for it anywhere.
    hello = tls_client_hello("files.example.net", BROWSER_CIPHERS, BROWSER_EXTS)
    frames.extend(tcp_session("192.168.60.11", 50100, "198.51.100.7", 443, [(True, hello)], t0=t0 + 4))
    # 3. The router's cache: news.example.org with 1,234 seconds left (of the usual 1,800); it also answers a fresh name.
    add(6.0, udp("192.168.60.12", "192.168.60.1", 53000, 53, dns_query_msg(0x1111, "news.example.org")))
    add(6.01, udp("192.168.60.1", "192.168.60.12", 53, 53000, dns_answer(0x1111, "news.example.org", "203.0.113.80", 1234)))
    add(6.5, udp("192.168.60.12", "192.168.60.1", 53001, 53, dns_query_msg(0x2222, "fresh.example.org")))
    add(6.52, udp("192.168.60.1", "192.168.60.12", 53, 53001, dns_answer(0x2222, "fresh.example.org", "203.0.113.81", 300)))
    # 4. A DHCP renewal: it holds 192.168.60.20; the lease is 24 hours, renewal at 12.
    mac = "02:00:00:00:60:20"
    lease = bytes([51, 4]) + struct.pack("!I", 86400) + bytes([58, 4]) + struct.pack("!I", 43200)
    add(8.0, udp("192.168.60.20", "192.168.60.1", 68, 67, dhcp_message(3, mac, 0xABCD, ciaddr="192.168.60.20")))
    add(8.01, udp("192.168.60.1", "192.168.60.20", 67, 68, dhcp_message(5, mac, 0xABCD, ciaddr="192.168.60.20",
                                                                         yiaddr="192.168.60.20", options=lease)))
    # 5. A resumed TLS 1.3 session: the hello offers a pre-shared key (extension 41).
    resume = tls_client_hello("mail.example.com", BROWSER_CIPHERS, BROWSER_EXTS + [0x0029])
    frames.extend(tcp_session("192.168.60.13", 50200, "198.51.100.9", 443, [(True, resume)], t0=t0 + 10))
    # (and a name looked up the ordinary way, which isn't "before")
    add(12.0, udp("192.168.60.14", "192.168.60.1", 53002, 53, dns_query_msg(0x3333, "seen.example.org")))
    add(12.01, udp("192.168.60.1", "192.168.60.14", 53, 53002, dns_answer(0x3333, "seen.example.org", "198.51.100.30", 300)))
    frames.extend(tcp_session("192.168.60.14", 50300, "198.51.100.30", 443,
                              [(True, tls_client_hello("seen.example.org", BROWSER_CIPHERS, BROWSER_EXTS))], t0=t0 + 12.1))
    frames.sort(key=lambda f: f[0])
    return frames


def dns_query_msg(txid: int, qname: str) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".") if p) + b"\0"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def software_lab(t0=0.0):
    """A small office whose traffic says what software it runs (anta/software.py): an old
    Windows 7 browser, an Ubuntu 20.04 machine updating, an old Python, a web server on a flawed
    Apache and an end-of-life PHP, an Ubuntu SSH server, a backdoored vsftpd (whose client's
    USER line must never be kept), and an internet server."""
    frames = []

    def http(client, cport, server, uri, agent, host="example.com", server_hdr="", powered="", t=0.0):
        req = f"GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {agent}\r\nAccept: */*\r\n\r\n".encode()
        head = ["HTTP/1.1 200 OK", "Content-Type: text/html", "Content-Length: 2"]
        if server_hdr:
            head.append(f"Server: {server_hdr}")
        if powered:
            head.append(f"X-Powered-By: {powered}")
        resp = ("\r\n".join(head) + "\r\n\r\nok").encode()
        frames.extend(tcp_session(client, cport, server, 80, [(True, req), (False, resp)], t0=t0 + t))

    win7 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
    http("192.168.50.10", 50001, "93.184.216.34", "/", win7, server_hdr="nginx/1.18.0")
    http("192.168.50.11", 50002, "91.189.91.83", "/ubuntu/dists/focal/InRelease", "Debian APT-HTTP/1.3 (2.0.10)",
         host="archive.ubuntu.com", t=1)
    http("192.168.50.12", 50003, "151.101.0.223", "/simple/requests/",
         'pip/23.0.1 {"implementation":{"name":"CPython"},"python":"3.8.10","system":{"name":"Linux"}}', host="pypi.org", t=2)
    http("192.168.50.10", 50004, "192.168.50.20", "/index.php", win7, host="intranet", server_hdr="Apache/2.4.49 (Unix)",
         powered="PHP/7.4.3", t=3)
    android = "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36"
    http("192.168.50.30", 50005, "93.184.216.34", "/", android, t=4)
    frames.extend(tcp_session("192.168.50.10", 50006, "192.168.50.21", 22,
                              [(False, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"), (True, b"SSH-2.0-OpenSSH_9.6\r\n")], t0=t0 + 5))
    frames.extend(tcp_session("192.168.50.10", 50007, "192.168.50.22", 21,
                              [(False, b"220 (vsFTPd 2.3.4)\r\n"), (True, b"USER alice\r\n"), (False, b"331 Please specify the password.\r\n")],
                              t0=t0 + 6))
    frames.sort(key=lambda f: f[0])
    return frames


def lint_lab(t0=0.0):
    """A capture that breaks the protocol spell-checker's rules (anta/lint.py) once each: crafted
    TCP flags, bad IP headers and sources, odd DNS headers, HTTP that smuggling and scanners use,
    and a TLS server name that is an address. Each frame says which rule it breaks."""
    import random

    from anta.tools.pcapgen import BROWSER_CIPHERS, BROWSER_EXTS, dns_query, tls_client_hello

    c, srv = "10.80.0.5", "10.80.0.9"
    frames = []
    add = lambda data: frames.append((t0 + len(frames) * 0.05, data))  # noqa: E731
    add(tcp(c, srv, 40001, 80, 1000, 0, 0x03))                           # tcp-syn-fin
    add(tcp(c, srv, 40002, 80, 1000, 0, 0x06))                           # tcp-syn-rst
    add(tcp(c, srv, 40003, 80, 1000, 0, 0x00))                           # tcp-null
    add(tcp(c, srv, 40004, 80, 1000, 0, 0x29))                           # tcp-xmas (FIN, PSH, URG)
    add(tcp(c, srv, 40005, 0, 1000, 0, 0x02))                            # port-zero
    add(tcp(c, srv, 40006, 80, 1000, 5, 0x10, opts=mss_option(1460)))    # tcp-mss-not-syn
    raw = bytearray(tcp(c, srv, 40007, 80, 1000, 0, 0x02))
    raw[14 + 20 + 12] |= 0x0E                                            # tcp-reserved-bits
    add(bytes(raw))
    raw = bytearray(udp(c, srv, 40008, 9, b"x"))
    raw[14 + 6] |= 0x80                                                  # ip-reserved-bit
    raw[14 + 10:14 + 12] = b"\0\0"
    raw[14 + 10:14 + 12] = struct.pack("!H", checksum(bytes(raw[14:34])))
    add(bytes(raw))
    add(udp(c, srv, 40009, 9, b"x", ttl=0))                              # ip-ttl-zero
    add(udp("224.0.0.9", srv, 40010, 9, b"x"))                           # ip-bad-source
    q = bytearray(dns_query(0x4242, "example.com"))
    q[3] |= 0x40                                                         # dns-z-bit
    add(udp(c, srv, 40011, 53, bytes(q)))
    q = bytearray(dns_query(0x4243, "example.com"))
    q[4:6] = struct.pack("!H", 2)                                        # dns-qdcount
    q += q[12:]
    add(udp(c, srv, 40012, 53, bytes(q)))
    for i, request in enumerate([b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n",                     # http-no-host
                                 b"POST /a HTTP/1.1\r\nHost: lab\r\nContent-Length: 4\r\n"
                                 b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"]):              # http-cl-te
        for ts, f in tcp_session(c, 41000 + i, srv, 80, [(True, request), (False, b"HTTP/1.1 999 Odd\r\n"
                                                                                b"Content-Length: 0\r\n\r\n")],
                                 t0=t0 + 5 + i):                                               # (and http-status-range)
            frames.append((ts, f))
    hello = tls_client_hello("10.80.0.9", BROWSER_CIPHERS, BROWSER_EXTS, rng=random.Random(5))  # tls-sni-ip
    for ts, f in tcp_session(c, 42000, srv, 443, [(True, hello)], t0=t0 + 10):
        frames.append((ts, f))
    return sorted(frames, key=lambda f: f[0])


def all_samples() -> list:
    """Every sample, one after another, in a single capture."""
    c, dc, web, c2 = "10.0.0.5", "10.0.0.10", "203.0.113.80", "198.51.100.66"
    frames = []

    def extend(more):
        base = frames[-1][0] + 0.1 if frames else 0.0
        frames.extend((base + t - more[0][0], f) for t, f in more)

    extend(http_download(c, web, 9000, "/drop/payload.exe", windows_exe()))
    extend(http_download(c, web, 80, "/files/report.bin", windows_exe(9000, seed=3), chunk=True, compress=True,
                         content_type="application/octet-stream", agent="Mozilla/5.0", cport=50101))
    extend(tcp_session(c, 50102, c2, 443, [(True, bytes.fromhex("749c90dbffffffff24af9c9e43000000") * 40),
                                           (False, bytes(range(256)) * 12)]))
    extend([(0, udp(c, dc, 50200, 88, krb_request("bdiaz", "EXAMPLE.COM", "HOST-A"))),
            (0.01, udp(dc, c, 88, 50200, krb_error(25))),
            (0.02, udp(dc, c, 88, 50201, krb_reply("bdiaz", "EXAMPLE.COM")))])
    rep = krb_reply("HOST-A$", "EXAMPLE.COM", msg_type=13)
    extend(tcp_session(c, 50203, dc, 88, [(True, struct.pack("!I", 0) + b""),
                                          (True, (lambda m: struct.pack("!I", len(m)) + m)(
                                              krb_request("HOST-A$", "EXAMPLE.COM", msg_type=12))),
                                          (False, struct.pack("!I", len(rep)) + rep)], seg=100))
    extend([(0, browser_datagram(c, ("HOST-A", 0x20), ("EXAMPLE", 0x1D), host_announcement("HOST-A"))),
            (0.01, browser_datagram(dc, ("DC-1", 0x00), ("EXAMPLE", 0x1D),
                                    host_announcement("DC-1", 0x0000100B, cmd=0x0F, comment=b"Domain controller"))),
            (0.02, browser_datagram(c, ("HOST-A", 0x00), ("EXAMPLE", 0x1D), b"\x02\x00HOST-A\x00"))])
    extend(quic_session(c, 50300, web))
    ws = "10.0.0.6"  # another domain member, so each sample's host evidence stays its own
    extend(ldap_session(ws, 50400, dc))
    extend(smb2_file_session(ws, 50500, dc, [("\\\\DC-1\\ADMIN$", "svc.exe", windows_exe(6000, seed=5), True),
                                            ("\\\\DC-1\\SYSVOL", "example.com\\scripts\\logon.bat", b"@echo off\r\n", False)]))
    extend(dcerpc_session(ws, 50600, dc))
    extend(router_lab())
    extend(troubleshooting_lab())
    return frames


def login_lab(secret: str = "Sup3rS3cret!") -> list:  # noqa: S107 - a made-up password the tests look for
    """Logins sent in clear text, one of each kind ANTA reads (FTP, POP, IMAP, SMTP AUTH LOGIN
    and PLAIN, HTTP Basic and a login form, an LDAP simple bind, Telnet, an SNMP community),
    every one with the password `secret`, so a test can check it never comes out."""
    import base64

    def b64(text: str) -> bytes:
        return base64.b64encode(text.encode())

    c, srv = "10.20.0.5", "10.20.0.80"
    frames: list = []

    def tcp(port, exchanges, cport):
        frames.extend(tcp_session(c, cport, srv, port, exchanges, t0=len(frames)))

    tcp(21, [(False, b"220 FTP ready\r\n"), (True, b"USER alice\r\n"), (False, b"331 Password required\r\n"),
             (True, f"PASS {secret}\r\n".encode()), (False, b"230 Logged in\r\n")], 40001)
    tcp(21, [(False, b"220 FTP ready\r\n"), (True, b"USER anonymous\r\n"), (False, b"331 Send email\r\n"),
             (True, b"PASS guest@example.com\r\n"), (False, b"230 OK\r\n")], 40002)
    tcp(110, [(False, b"+OK POP3\r\n"), (True, b"USER bob\r\n"), (False, b"+OK\r\n"),
              (True, f"PASS {secret}\r\n".encode()), (False, b"-ERR invalid password\r\n")], 40003)
    tcp(143, [(False, b"* OK IMAP4rev1\r\n"), (True, f'a1 LOGIN "carol smith" "{secret}"\r\n'.encode()),
              (False, b"a1 OK LOGIN completed\r\n")], 40004)
    tcp(25, [(False, b"220 mail ESMTP\r\n"), (True, b"EHLO me\r\n"), (False, b"250-mail\r\n250 AUTH LOGIN PLAIN\r\n"),
             (True, b"AUTH LOGIN\r\n"), (False, b"334 VXNlcm5hbWU6\r\n"), (True, b64("dave") + b"\r\n"),
             (False, b"334 UGFzc3dvcmQ6\r\n"), (True, b64(secret) + b"\r\n"),
             (False, b"235 Authentication successful\r\n")], 40005)
    tcp(587, [(False, b"220 mail\r\n"), (True, b"AUTH PLAIN " + b64(f"\0erin\0{secret}") + b"\r\n"),
              (False, b"535 Authentication failed\r\n")], 40006)
    basic = b64(f"frank:{secret}").decode()
    tcp(8080, [(True, b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"),
               (False, b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"),
               (True, f"GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {basic}\r\n\r\n".encode()),
               (False, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")], 40007)
    form = f"username=grace%40corp.example&password={secret}&remember=1"
    tcp(80, [(True, (f"POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                     f"Content-Length: {len(form)}\r\n\r\n{form}").encode()),
             (False, b"HTTP/1.1 302 Found\r\nLocation: /home\r\nContent-Length: 0\r\n\r\n")], 40008)
    # LDAP simple bind (BER): BindRequest id 1, version 3, name, simple password; BindResponse success.
    name, pw = b"cn=heidi,dc=corp,dc=example", secret.encode()
    bind = b"\x02\x01\x03" + b"\x04" + bytes([len(name)]) + name + b"\x80" + bytes([len(pw)]) + pw
    req = b"\x02\x01\x01" + b"\x60" + bytes([len(bind)]) + bind
    resp_body = b"\x0a\x01\x00\x04\x00\x04\x00"
    resp = b"\x02\x01\x01" + b"\x61" + bytes([len(resp_body)]) + resp_body
    tcp(389, [(True, b"\x30" + bytes([len(req)]) + req), (False, b"\x30" + bytes([len(resp)]) + resp)], 40009)
    tcp(23, [(False, b"\xff\xfd\x18Ubuntu 24.04\r\nlogin: "), (True, b"i"), (True, b"v"), (True, b"a"), (True, b"n\r"),
             (False, b"\r\nPassword: "), (True, f"{secret}\r".encode()), (False, b"\r\nLast login: Mon\r\n$ ")], 40010)
    # SNMP v2c get-request with the default "public" community.
    pdu = b"\xa0\x0e\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x03\x30\x01\x05"
    msg = b"\x02\x01\x01" + b"\x04\x06public" + pdu
    frames.append((len(frames) + 0.5, udp(c, srv, 40011, 161, b"\x30" + bytes([len(msg)]) + msg)))
    return frames


def fuzz_seeds() -> tuple[list, str]:
    """Every sample plus the database lab, the LAN/recon labs (ARP, scan, DGA), the clear-text
    logins lab and the HTTPS and HTTP/2 labs: the fuzzer's seeds, and the key log that
    decrypts them."""
    frames = all_samples()
    https, keylog = https_lab()
    h2, h2_keys = h2_lab()
    for lab in (database_lab, arp_spoof_lab, scan_lab, dga_lab, login_lab, lambda: https, lambda: h2):
        for t, f in lab():
            frames.append((frames[-1][0] + 0.1 + t, f))
    return frames, keylog + h2_keys


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--fuzz-seeds"):
        sys.exit("usage: python -m anta.tools.samples OUT.pcap [--fuzz-seeds]")
    if len(sys.argv) == 3:
        seeds, keylog = fuzz_seeds()
        write_pcap(sys.argv[1], seeds)
        with open(sys.argv[1].rsplit(".", 1)[0] + ".keys", "w") as fh:  # the fuzzer loads it beside the pcap
            fh.write(keylog)
    else:
        write_pcap(sys.argv[1], all_samples())
