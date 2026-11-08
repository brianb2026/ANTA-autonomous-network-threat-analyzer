"""Minimal pcap writer plus TCP/UDP conversation builders.

Produces byte-accurate Ethernet/IPv4/TCP/UDP frames with valid checksums so the
C++ engine can be exercised end to end without scapy or live traffic.
"""
from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass, field

ETH_SRC = bytes.fromhex("020000000001")
ETH_DST = bytes.fromhex("020000000002")


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    csum = _checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:] + payload


def _ipv6(src: str, dst: str, proto: int, payload: bytes, hop_by_hop: bool = False) -> bytes:
    next_header = proto
    if hop_by_hop:  # 8-byte hop-by-hop options header (PadN) in front of the L4 header
        payload = bytes([proto, 0, 1, 4, 0, 0, 0, 0]) + payload
        next_header = 0
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), next_header, 64,
                       socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)) + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    if ":" in src:
        return (socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
                + struct.pack("!IxxxB", length, proto))
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, length)


def _l2(src: str, l3: bytes, vlans=()) -> bytes:
    """Ethernet header (+ optional 802.1ad/802.1Q tags) for an IPv4/IPv6 packet."""
    ethertype = b"\x86\xdd" if ":" in src else b"\x08\x00"
    tags = b""
    for i, vid in enumerate(vlans):
        tpid = b"\x88\xa8" if i == 0 and len(vlans) > 1 else b"\x81\x00"
        tags += tpid + struct.pack("!H", vid & 0x0FFF)
    return ETH_DST + ETH_SRC + tags + ethertype + l3


def _ip(src, dst, proto, segment, ident, hop_by_hop=False):
    return _ipv6(src, dst, proto, segment, hop_by_hop) if ":" in src else _ipv4(src, dst, proto, segment, ident)


def tcp_frame(src, sport, dst, dport, seq, ack, flags, payload=b"", window=65535, ident=0, vlans=(),
              hop_by_hop=False) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, window, 0, 0)
    csum = _checksum(_pseudo(src, dst, 6, len(hdr) + len(payload)) + hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", csum) + hdr[18:]
    return _l2(src, _ip(src, dst, 6, hdr + payload, ident, hop_by_hop), vlans)


def udp_frame(src, sport, dst, dport, payload: bytes, ident=0, vlans=()) -> bytes:
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    csum = _checksum(_pseudo(src, dst, 17, len(hdr) + len(payload)) + hdr + payload) or 0xFFFF
    hdr = hdr[:6] + struct.pack("!H", csum)
    return _l2(src, _ip(src, dst, 17, hdr + payload, ident), vlans)


def ipv4_fragment(src, dst, proto, chunk: bytes, ident: int, offset_bytes: int, more: bool) -> bytes:
    flags = (0x2000 if more else 0) | (offset_bytes // 8)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(chunk), ident, flags, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return ETH_DST + ETH_SRC + b"\x08\x00" + header + chunk


def arp_frame() -> bytes:
    return b"\xff" * 6 + ETH_SRC + b"\x08\x06" + bytes.fromhex("0001080006040001") + ETH_SRC + bytes(4) + bytes(10)


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class PcapWriter:
    """Collects frames with timestamps and writes them sorted by time."""

    frames: list = field(default_factory=list)
    _ident: int = 0

    def add(self, ts: float, frame: bytes) -> None:
        self.frames.append((ts, len(self.frames), frame))

    def next_ident(self) -> int:
        self._ident = (self._ident + 1) & 0xFFFF
        return self._ident

    def save(self, path: str) -> int:
        self.frames.sort(key=lambda f: (f[0], f[1]))
        with open(path, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, _, frame in self.frames:
                sec = int(ts)
                usec = int(round((ts - sec) * 1e6))
                if usec >= 1_000_000:
                    sec, usec = sec + 1, usec - 1_000_000
                fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
                fh.write(frame)
        return len(self.frames)


class TcpConversation:
    """Simulates one TCP connection; timestamps advance with a per-connection RTT."""

    MSS = 1448

    def __init__(self, w: PcapWriter, client: str, cport: int, server: str, sport: int,
                 start: float, rtt: float = 0.02, rng: random.Random | None = None, vlans=(),
                 isn: tuple | None = None, hop_by_hop: bool = False):
        self.w, self.client, self.cport, self.server, self.sport = w, client, cport, server, sport
        self.t = start
        self.rtt = rtt
        self.rng = rng or random.Random()
        self.vlans = vlans
        self.hop_by_hop = hop_by_hop
        # 0 = client, 1 = server. `isn` pins initial sequence numbers (e.g. near 2**32 to test wraparound).
        self.seq = {0: isn[0], 1: isn[1]} if isn else {0: self.rng.getrandbits(32), 1: self.rng.getrandbits(32)}

    def _emit(self, ts, d, flags, payload=b"", window=65535, seq=None, ack=None):
        src, sp, dst, dp = (self.client, self.cport, self.server, self.sport) if d == 0 else \
                           (self.server, self.sport, self.client, self.cport)
        s = self.seq[d] if seq is None else seq
        a = self.seq[1 - d] if ack is None else ack
        frame = tcp_frame(src, sp, dst, dp, s, a & 0xFFFFFFFF, flags, payload, window, self.w.next_ident(),
                          self.vlans, self.hop_by_hop)
        self.w.add(ts, frame)

    def handshake(self):
        self._emit(self.t, 0, SYN)
        self.seq[0] += 1
        self.t += self.rtt / 2
        self._emit(self.t, 1, SYN | ACK)
        self.seq[1] += 1
        self.t += self.rtt / 2
        self._emit(self.t, 0, ACK)
        return self

    def send(self, d: int, data: bytes, gap: float = 0.0002, reorder: float = 0.0,
             duplicate: float = 0.0, zero_window_at: int | None = None):
        """Send `data` from side `d` in MSS segments, optionally reordering/duplicating."""
        segments = []
        for off in range(0, len(data), self.MSS):
            chunk = data[off:off + self.MSS]
            segments.append((self.seq[d], chunk))
            self.seq[d] += len(chunk)
        # The receiver ACKs every second segment half an RTT after it passes; the
        # sender keeps at most a 64 KiB window in flight, waiting for ACKs to open it.
        in_flight = 65535 // self.MSS
        times: list[float] = []
        for i in range(len(segments)):
            t = self.t + i * gap if not times else times[-1] + gap
            if i >= in_flight:
                freed = (i - in_flight) | 1  # the ACK that released enough window
                if freed < i:
                    t = max(t, times[freed] + self.rtt / 2 + 0.00005)
            times.append(t)
        # Swap adjacent timestamps to deliver segments out of order.
        i = 0
        while i < len(times) - 1:
            if self.rng.random() < reorder:
                times[i], times[i + 1] = times[i + 1], times[i]
                i += 2
            else:
                i += 1
        for idx, ((seq, chunk), ts) in enumerate(zip(segments, times, strict=True)):
            self._emit(ts, d, PSH | ACK, chunk, seq=seq)
            if self.rng.random() < duplicate:
                self._emit(ts + self.rtt, d, PSH | ACK, chunk, seq=seq)  # spurious retransmission
            if idx % 2 == 1:
                # Cumulative ACK: everything contiguous that has arrived by now.
                ack = segments[0][0]
                for (s, c), t in zip(segments, times, strict=True):
                    if s != ack or t > ts:
                        break
                    ack = s + len(c)
                win = 0 if zero_window_at is not None and idx >= zero_window_at else 65535
                self._emit(ts + self.rtt / 2, 1 - d, ACK, window=win, ack=ack)
        self.t = (max(times) if times else self.t) + self.rtt
        self._emit(self.t, 1 - d, ACK)
        return self

    def wait(self, seconds: float):
        self.t += seconds
        return self

    def close(self):
        self._emit(self.t, 0, FIN | ACK)
        self.seq[0] += 1
        self.t += self.rtt / 2
        self._emit(self.t, 1, FIN | ACK)
        self.seq[1] += 1
        self.t += self.rtt / 2
        self._emit(self.t, 0, ACK)
        return self

    def reset(self):
        self._emit(self.t, 0, RST | ACK)
        return self


# --------------------------------------------------------------- app payloads

def dns_query(txid: int, qname: str, qtype: int = 1) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".") if p) + b"\0"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def dns_response(txid: int, qname: str, qtype: int, answers: list) -> bytes:
    """`answers` holds IPv4 strings for A, IPv6 strings for AAAA, or bytes blobs for TXT."""
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".") if p) + b"\0"
    msg = struct.pack("!HHHHHH", txid, 0x8180, 1, len(answers), 0, 0) + labels + struct.pack("!HH", qtype, 1)
    for a in answers:
        if qtype == 1:
            rdata = socket.inet_aton(a)
        elif qtype == 28:
            rdata = socket.inet_pton(socket.AF_INET6, a)
        else:
            rdata = b""
            for i in range(0, len(a), 255):
                piece = a[i:i + 255]
                rdata += bytes([len(piece)]) + piece
        msg += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, len(rdata)) + rdata
    return msg


BROWSER_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
                   0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
BROWSER_EXTS = [0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x0005, 0x000D,
                0x0012, 0x0033, 0x002D, 0x002B, 0x001B, 0x4469]
MALWARE_CIPHERS = [0xC02C, 0xC02B, 0xC030, 0xC02F, 0x009F, 0x009E, 0xC024, 0xC023, 0xC028,
                   0xC027, 0xC00A, 0xC009, 0xC014, 0xC013, 0x009D, 0x009C, 0x003D, 0x003C,
                   0x0035, 0x002F, 0x000A]
MALWARE_EXTS = [0x0000, 0x000A, 0x000B, 0x000D, 0x0023, 0x0017, 0xFF01]


def tls_client_hello(sni: str, ciphers: list, exts: list, alpn=("h2", "http/1.1"),
                     grease: bool = True, rng: random.Random | None = None) -> bytes:
    rng = rng or random.Random()

    def u16(v):
        return struct.pack("!H", v)

    ext_blob = b""
    order = ([0x0A0A] if grease else []) + list(exts)
    for e in order:
        if e == 0x0000:
            name = sni.encode()
            body = u16(len(name) + 3) + b"\0" + u16(len(name)) + name
        elif e == 0x000A:
            groups = ([0x1A1A] if grease else []) + [0x001D, 0x0017, 0x0018]
            body = u16(len(groups) * 2) + b"".join(u16(g) for g in groups)
        elif e == 0x000B:
            body = b"\x01\x00"
        elif e == 0x000D:
            algs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
            body = u16(len(algs) * 2) + b"".join(u16(a) for a in algs)
        elif e == 0x0010:
            protos = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
            body = u16(len(protos)) + protos
        elif e == 0x002B:
            vers = ([0x2A2A] if grease else []) + [0x0304, 0x0303]
            body = bytes([len(vers) * 2]) + b"".join(u16(v) for v in vers)
        elif e == 0x0033:
            key = rng.randbytes(32)
            body = u16(36) + u16(0x001D) + u16(32) + key
        elif e == 0xFF01:      # renegotiation_info: an empty renegotiated_connection
            body = b"\x00"
        elif e == 0x0005:      # status_request: OCSP, no responder IDs or extensions
            body = b"\x01\x00\x00\x00\x00"
        elif e == 0x002D:      # psk_key_exchange_modes: psk_dhe_ke
            body = b"\x01\x01"
        elif e == 0x001B:      # compress_certificate: brotli
            body = b"\x02\x00\x02"
        elif e == 0x4469:      # application_settings: for h2
            body = u16(3) + b"\x02h2"
        else:                  # extended_master_secret, session_ticket, SCT, GREASE: empty
            body = b""
        ext_blob += u16(e) + u16(len(body)) + body

    cipher_list = ([0x3A3A] if grease else []) + list(ciphers)
    hello = (u16(0x0303) + rng.randbytes(32) + b"\x20" + rng.randbytes(32)
             + u16(len(cipher_list) * 2) + b"".join(u16(c) for c in cipher_list)
             + b"\x01\x00" + u16(len(ext_blob)) + ext_blob)
    hs = b"\x01" + struct.pack("!I", len(hello))[1:] + hello
    return b"\x16\x03\x01" + u16(len(hs)) + hs


def tls_server_hello(rng: random.Random, cipher=0x1301) -> bytes:
    ext = struct.pack("!HHH", 0x002B, 2, 0x0304)
    body = struct.pack("!H", 0x0303) + rng.randbytes(32) + b"\x20" + rng.randbytes(32) + \
        struct.pack("!HB", cipher, 0) + struct.pack("!H", len(ext)) + ext
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def tls_app_data(rng: random.Random, n: int) -> bytes:
    """Opaque TLS application-data records totalling ~n bytes."""
    out = b""
    while n > 0:
        size = min(n, 16384)
        out += b"\x17\x03\x03" + struct.pack("!H", size) + rng.randbytes(size)
        n -= size
    return out


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + content


def ocsp_response(rng: random.Random) -> bytes:
    """A well-formed OCSPResponse (status good) with random hashes and signature."""
    sha1 = _der(0x30, _der(0x06, bytes.fromhex("2b0e03021a")) + _der(0x05, b""))
    sha256_rsa = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d01010b")) + _der(0x05, b""))
    stamp = _der(0x18, b"20260101120000Z")
    cert_id = _der(0x30, sha1 + _der(0x04, rng.randbytes(20)) + _der(0x04, rng.randbytes(20))
                   + _der(0x02, b"\x01" + rng.randbytes(15)))
    single = _der(0x30, cert_id + bytes([0x80, 0x00]) + stamp + _der(0xA0, stamp))
    tbs = _der(0x30, _der(0xA2, _der(0x04, rng.randbytes(20))) + stamp + _der(0x30, single))
    basic = _der(0x30, tbs + sha256_rsa + _der(0x03, b"\x00" + rng.randbytes(256)))
    response_bytes = _der(0x30, _der(0x06, bytes.fromhex("2b0601050507300101")) + _der(0x04, basic))
    return _der(0x30, _der(0x0A, b"\x00") + _der(0xA0, response_bytes))
