"""Generate synthetic captures for training, validation, demos and tests.

  benign_train.pcap   30 min, 28 IPv4 + 3 IPv6 hosts: browsing, streaming, DNS, fleet
                      heartbeats, SSH, software downloads, mail uploads, video calls, IMAP IDLE
  benign_val.pcap     15 min of the same behaviours from a different seed and host count;
                      held out from training and used to calibrate the alert threshold
  benign_train_more.pcap  30 min, 32 hosts browsing at their own pace (light to heavy users) and
                      the rest of an office's day: remote desktop, database connections, a file
                      server, API polling, software updates, cloud file sync, print jobs, web apps;
                      plus 64 desks that mostly use the office's own services
  benign_val_more.pcap    15 min of the same from another seed: calibration, with benign_val
  benign_holdout.pcap     15 min more from a third seed: never trained or calibrated on; how
                      often a model alerts on benign traffic it hasn't seen
  mixed_demo.pcap     10 min of benign traffic plus five attack scenarios:
                        - HTTPS C2 beacon every 4.2 s (<1% jitter) to 192.168.1.105:443
                        - HTTPS C2 beacon every ~25 s with ±20% random jitter to 45.77.12.34:443
                        - In-session HTTP beacon every 15 s over one keep-alive connection
                        - DNS tunnel: high-entropy TXT queries under exfil-cdn.net
                        - Bulk upload exfiltration to 203.0.113.50:8443
  http_download.pcap  one 2 MB HTTP download with reordering + retransmissions,
                      plus http_download.body (the expected file) for the reassembly test
  edge_cases.pcap     VLAN/QinQ, IPv6 + extension headers, IPv6 DNS, IP fragments, ARP,
                      truncated frames, sequence-number wraparound, overlapping retransmits

Usage: python -m anta.tools.gen_traffic --out data
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import os
import random

from .pcapgen import (ACK, BROWSER_CIPHERS, BROWSER_EXTS, FIN, MALWARE_CIPHERS, MALWARE_EXTS, PSH, SYN,
                      PcapWriter, TcpConversation, arp_frame, dns_query, dns_response, ipv4_fragment, ocsp_response,
                      tcp_frame, tls_app_data, tls_client_hello, tls_server_hello, udp_frame)

RESOLVER = "10.0.0.1"
RESOLVER6 = "fd00::1"

SITES = {
    "www.google.com": "142.250.72.4", "www.wikipedia.org": "208.80.154.224",
    "github.com": "140.82.112.3", "news.ycombinator.com": "209.216.230.207",
    "www.reddit.com": "151.101.1.140", "cdn.jsdelivr.net": "151.101.129.229",
    "fonts.gstatic.com": "142.250.72.3", "www.nytimes.com": "151.101.193.164",
    "api.slack.com": "3.92.181.98", "outlook.office365.com": "52.96.36.226",
    "www.amazon.com": "54.239.28.85", "docs.python.org": "151.101.0.223",
    "stackoverflow.com": "151.101.65.69", "zoom.us": "170.114.52.2",
}
STREAMING = {"rr3.googlevideo.com": "173.194.24.8", "video.twimg.com": "152.199.20.10"}
HTTP_SITES = {"ocsp.digicert.com": "93.184.220.29", "connectivitycheck.gstatic.com": "142.250.72.35"}
SITES6 = {name: f"2001:db8:{i + 1:x}::443" for i, name in enumerate(SITES)}
# Benign periodic services many hosts share (chat websocket keepalive, endpoint agent check-in).
SLACK_WSS = ("wss-primary.slack.com", "3.92.181.120")
AGENT = ("telemetry.edr-vendor.com", "52.40.17.9")


class Scenario:
    def __init__(self, seed: int, t0: float):
        self.rng = random.Random(seed)
        self.w = PcapWriter()
        self.t0 = t0
        self.ports: dict[str, int] = {}

    def _poisson(self, lam: float) -> int:
        n, t = 0, self.rng.expovariate(1.0)
        while t < lam:
            n += 1
            t += self.rng.expovariate(1.0)
        return n

    def eport(self, client: str) -> int:
        p = self.ports.get(client, self.rng.randint(49152, 52000)) + 1
        self.ports[client] = p if p < 65000 else 49152
        return self.ports[client]

    # -------------------------------------------------------------- DNS

    def dns_lookup(self, client: str, t: float, name: str, ip: str | None, qtype=1, txt: bytes | None = None,
                   server=RESOLVER):
        txid = self.rng.getrandbits(16)
        sport = self.eport(client)
        self.w.add(t, udp_frame(client, sport, server, 53, dns_query(txid, name, qtype), self.w.next_ident()))
        answers = [ip] if qtype in (1, 28) and ip else ([txt] if txt else [])
        resp = dns_response(txid, name, qtype, answers)
        self.w.add(t + self.rng.uniform(0.004, 0.03), udp_frame(server, 53, client, sport, resp, self.w.next_ident()))

    # ------------------------------------------------------------ benign

    def https_session(self, client, t, host, ip, exchanges=None):
        rng = self.rng
        c = TcpConversation(self.w, client, self.eport(client), ip, 443, t, rtt=rng.uniform(0.008, 0.08), rng=rng)
        c.handshake()
        c.send(0, tls_client_hello(host, BROWSER_CIPHERS, BROWSER_EXTS, rng=rng))
        c.send(1, tls_server_hello(rng) + tls_app_data(rng, rng.randint(2500, 5200)))
        for _ in range(exchanges or rng.randint(1, 8)):
            c.wait(rng.expovariate(1 / 1.5))
            c.send(0, tls_app_data(rng, int(rng.lognormvariate(6.2, 0.7))))
            c.send(1, tls_app_data(rng, min(int(rng.lognormvariate(8.6, 1.2)), 250_000)), reorder=0.02,
                   duplicate=0.01)
        c.wait(rng.uniform(0.5, 15))
        c.close() if rng.random() < 0.9 else c.reset()

    def http_session(self, client, t, host, ip):
        rng = self.rng
        c = TcpConversation(self.w, client, self.eport(client), ip, 80, t, rtt=rng.uniform(0.01, 0.06), rng=rng)
        c.handshake()
        c.send(0, f"GET /check?{rng.randint(1, 99999)} HTTP/1.1\r\nHost: {host}\r\n"
                  f"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)\r\nAccept: */*\r\n\r\n".encode())
        body = ocsp_response(rng)
        c.send(1, f"HTTP/1.1 200 OK\r\nServer: ECAcc\r\nContent-Type: application/ocsp-response\r\n"
                  f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        c.close()

    def streaming_session(self, client, t, host, ip, duration):
        rng = self.rng
        c = TcpConversation(self.w, client, self.eport(client), ip, 443, t, rtt=rng.uniform(0.01, 0.04), rng=rng)
        c.handshake()
        c.send(0, tls_client_hello(host, BROWSER_CIPHERS, BROWSER_EXTS, rng=rng))
        c.send(1, tls_server_hello(rng) + tls_app_data(rng, 4000))
        end = t + duration
        while c.t < end:
            c.send(0, tls_app_data(rng, rng.randint(300, 700)))
            c.send(1, tls_app_data(rng, rng.randint(15_000, 70_000)), reorder=0.01)
            c.wait(rng.uniform(1.5, 7.0))  # segment fetch cadence varies with buffer level
        c.close()

    def browsing_client(self, client, start, end, page_rate=1 / 25):
        rng = self.rng
        v6 = ":" in client
        sites = SITES6 if v6 else SITES
        resolver, qtype = (RESOLVER6, 28) if v6 else (RESOLVER, 1)
        t = start + rng.uniform(0, 20)
        while t < end:
            host = rng.choice(list(sites))
            self.dns_lookup(client, t, host, sites[host], qtype=qtype, server=resolver)
            for i in range(rng.randint(1, 4)):
                sub = host if i == 0 else rng.choice(list(sites))
                self.https_session(client, t + 0.05 + rng.uniform(0, 0.6), sub, sites[sub])
            if not v6 and rng.random() < 0.15:
                h = rng.choice(list(HTTP_SITES))
                self.dns_lookup(client, t + 0.02, h, HTTP_SITES[h])
                self.http_session(client, t + 0.06, h, HTTP_SITES[h])
            if not v6 and rng.random() < 0.04:
                h = rng.choice(list(STREAMING))
                self.dns_lookup(client, t + 0.03, h, STREAMING[h])
                self.streaming_session(client, t + 0.1, h, STREAMING[h], rng.uniform(20, 90))
            t += rng.expovariate(page_rate)

    def websocket_keepalive(self, client, start, end, period=30.0):
        """Chat client: one long TLS connection with a ping every ~30 s (very regular, benign)."""
        rng = self.rng
        host, ip = SLACK_WSS
        self.dns_lookup(client, start, host, ip)
        c = TcpConversation(self.w, client, self.eport(client), ip, 443, start + 0.05, rtt=rng.uniform(0.02, 0.06),
                            rng=rng)
        c.handshake()
        c.send(0, tls_client_hello(host, BROWSER_CIPHERS, BROWSER_EXTS, alpn=("http/1.1",), rng=rng))
        c.send(1, tls_server_hello(rng) + tls_app_data(rng, 3800))
        c.send(0, tls_app_data(rng, rng.randint(400, 600)))
        c.send(1, tls_app_data(rng, rng.randint(2000, 9000)))
        while c.t < end - period:
            c.wait(period * (1 + rng.gauss(0, 0.01)) - 2 * c.rtt)
            c.send(0, tls_app_data(rng, rng.randint(30, 45)))
            c.send(1, tls_app_data(rng, rng.randint(30, 45)))
            if rng.random() < 0.1:  # occasional real message
                c.wait(rng.uniform(1, 10))
                c.send(1, tls_app_data(rng, rng.randint(300, 3000)))
        c.close()

    def agent_checkin(self, client, start, end, period=45.0):
        """Endpoint agent: new HTTPS connection every ~45 s to the vendor cloud (benign beacon)."""
        rng = self.rng
        host, ip = AGENT
        t = start + rng.uniform(0, period)
        self.dns_lookup(client, t - 0.2, host, ip)
        while t < end:
            c = TcpConversation(self.w, client, self.eport(client), ip, 443, t, rtt=rng.uniform(0.02, 0.05), rng=rng)
            c.handshake()
            c.send(0, tls_client_hello(host, BROWSER_CIPHERS[3:], BROWSER_EXTS, alpn=("h2",), grease=False, rng=rng))
            c.send(1, tls_server_hello(rng, cipher=0xC02F) + tls_app_data(rng, 2900))
            c.send(0, tls_app_data(rng, rng.randint(700, 900)))
            c.send(1, tls_app_data(rng, rng.randint(150, 400)))
            c.close()
            t += period * (1 + rng.gauss(0, 0.015))

    def ssh_session(self, client, start, duration):
        """Interactive SSH: small packets at human typing cadence, server echoes."""
        rng = self.rng
        c = TcpConversation(self.w, client, self.eport(client), "10.0.5.10", 22, start, rtt=0.004, rng=rng)
        c.handshake()
        c.send(0, b"SSH-2.0-OpenSSH_9.7\r\n")
        c.send(1, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
        c.send(0, rng.randbytes(1500))   # key exchange
        c.send(1, rng.randbytes(1100))
        end = start + duration
        while c.t < end:
            for _ in range(rng.randint(3, 25)):  # a typed command
                c.wait(rng.expovariate(1 / 0.18))
                c.send(0, rng.randbytes(36))
                c.send(1, rng.randbytes(36))
            c.send(1, rng.randbytes(rng.randint(100, 8000)))  # command output
            c.wait(rng.expovariate(1 / 12))  # think time
        c.close()

    def download(self, client, start, size):
        rng = self.rng
        host, ip = "dl.google.com", "142.250.72.14"
        self.dns_lookup(client, start - 0.05, host, ip)
        c = TcpConversation(self.w, client, self.eport(client), ip, 443, start, rtt=rng.uniform(0.01, 0.04), rng=rng)
        c.handshake()
        c.send(0, tls_client_hello(host, BROWSER_CIPHERS, BROWSER_EXTS, rng=rng))
        c.send(1, tls_server_hello(rng) + tls_app_data(rng, 4100))
        c.send(0, tls_app_data(rng, 450))
        c.send(1, tls_app_data(rng, size), gap=0.00006, reorder=0.01, duplicate=0.002)
        c.close()

    def mail_upload(self, client, start, size):
        """Sending an email with an attachment: one-sided, but below exfil volume."""
        rng = self.rng
        host, ip = "outlook.office365.com", SITES["outlook.office365.com"]
        c = TcpConversation(self.w, client, self.eport(client), ip, 443, start, rtt=rng.uniform(0.02, 0.05), rng=rng)
        c.handshake()
        c.send(0, tls_client_hello(host, BROWSER_CIPHERS, BROWSER_EXTS, rng=rng))
        c.send(1, tls_server_hello(rng) + tls_app_data(rng, 3900))
        c.send(0, tls_app_data(rng, size), gap=0.0001)
        c.send(1, tls_app_data(rng, rng.randint(400, 1200)))
        c.close()

    def video_call(self, client, start, duration):
        """Video call over TCP 443: steady bidirectional media both ways."""
        rng = self.rng
        host, ip = "zoom.us", SITES["zoom.us"]
        c = TcpConversation(self.w, client, self.eport(client), ip, 443, start, rtt=rng.uniform(0.02, 0.05), rng=rng)
        c.handshake()
        c.send(0, tls_client_hello(host, BROWSER_CIPHERS, BROWSER_EXTS, rng=rng))
        c.send(1, tls_server_hello(rng) + tls_app_data(rng, 4000))
        end = start + duration
        while c.t < end:
            c.send(0, tls_app_data(rng, rng.randint(600, 1300)))
            c.send(1, tls_app_data(rng, rng.randint(600, 1300)))
            c.wait(rng.uniform(0.04, 0.09))
        c.close()

    def imap_idle(self, client, start, end):
        rng = self.rng
        host, ip = "imap.gmail.com", "142.250.72.109"
        self.dns_lookup(client, start, host, ip)
        c = TcpConversation(self.w, client, self.eport(client), ip, 993, start + 0.05, rtt=0.03, rng=rng)
        c.handshake()
        c.send(0, tls_client_hello(host, BROWSER_CIPHERS, BROWSER_EXTS, alpn=("imap",), rng=rng))
        c.send(1, tls_server_hello(rng) + tls_app_data(rng, 3500))
        c.send(0, tls_app_data(rng, 300))
        c.send(1, tls_app_data(rng, rng.randint(2000, 20000)))
        while True:
            c.wait(rng.expovariate(1 / 240))  # new-mail notifications arrive at random
            if c.t >= end:
                break
            c.send(1, tls_app_data(rng, rng.randint(80, 200)))
            c.send(0, tls_app_data(rng, rng.randint(100, 300)))
            c.send(1, tls_app_data(rng, rng.randint(1000, 60000)))
        c.close()

    # ------------------------------------------- more of an office's day (benign_*_more)

    def rdp_session(self, client, start, duration):
        """Remote desktop to an internal server: input events up, screen updates down."""
        rng = self.rng
        c = TcpConversation(self.w, client, self.eport(client), "10.0.5.20", 3389, start, rtt=rng.uniform(0.002, 0.01),
                            rng=rng)
        c.handshake()
        c.send(0, bytes.fromhex("0300002b26e00000000000436f6f6b69653a206d737473686173683d75736572310d0a0100080003000000"))
        c.send(1, bytes.fromhex("0300001300d000001234000201080001000000"))
        c.send(0, tls_client_hello("rdp.corp.lan", BROWSER_CIPHERS, BROWSER_EXTS, alpn=(), rng=rng))
        c.send(1, tls_server_hello(rng) + tls_app_data(rng, rng.randint(1500, 3000)))
        c.send(1, tls_app_data(rng, rng.randint(40_000, 160_000)))  # the first full screen
        end = start + duration
        while c.t < end:
            for _ in range(rng.randint(2, 30)):  # a burst of typing or mouse moves, each repainting a little
                c.wait(rng.expovariate(1 / 0.12))
                c.send(0, tls_app_data(rng, rng.randint(20, 120)))
                c.send(1, tls_app_data(rng, int(rng.lognormvariate(7.0, 1.1))))
            if rng.random() < 0.2:  # a window opened or scrolled
                c.send(1, tls_app_data(rng, rng.randint(20_000, 200_000)))
            c.wait(rng.expovariate(1 / 8))
        c.close()

    def db_client(self, client, start, duration):
        """An application's pooled connection to the database: queries and result sets."""
        rng = self.rng
        c = TcpConversation(self.w, client, self.eport(client), "10.0.5.30", 5432, start, rtt=rng.uniform(0.0005, 0.003),
                            rng=rng)
        c.handshake()
        c.send(0, b"\x00\x00\x00\x08\x04\xd2\x16\x2f")  # SSLRequest
        c.send(1, b"S")
        c.send(0, tls_client_hello("db.corp.lan", BROWSER_CIPHERS, BROWSER_EXTS, alpn=("postgresql",), rng=rng))
        c.send(1, tls_server_hello(rng) + tls_app_data(rng, 1800))
        end = start + duration
        while c.t < end:
            for _ in range(rng.randint(1, 12)):  # one request's queries
                c.send(0, tls_app_data(rng, int(rng.lognormvariate(5.3, 0.8))))
                c.wait(rng.uniform(0.0005, 0.02))
                c.send(1, tls_app_data(rng, min(int(rng.lognormvariate(6.5, 1.6)), 400_000)))
            c.wait(rng.expovariate(1 / 3.0))
        c.close()

    def file_share(self, client, start, duration):
        """Working on an internal file server over SMB: listings, opens, reads, a few saves."""
        rng = self.rng
        c = TcpConversation(self.w, client, self.eport(client), "10.0.5.40", 445, start, rtt=rng.uniform(0.0005, 0.004),
                            rng=rng)
        c.handshake()

        def msg(n: int) -> bytes:  # NetBIOS session framing around an opaque (signed) SMB3 exchange
            body = rng.randbytes(max(n, 64))
            return len(body).to_bytes(4, "big") + body

        c.send(0, msg(rng.randint(170, 260)))   # negotiate
        c.send(1, msg(rng.randint(250, 400)))
        c.send(0, msg(rng.randint(400, 900)))   # session setup
        c.send(1, msg(rng.randint(250, 500)))
        end = start + duration
        while c.t < end:
            for _ in range(rng.randint(1, 6)):  # browsing folders
                c.send(0, msg(rng.randint(100, 220)))
                c.send(1, msg(rng.randint(300, 9000)))
                c.wait(rng.expovariate(1 / 0.6))
            if rng.random() < 0.5:  # opening a document: 64 KiB reads
                for _ in range(rng.randint(2, 24)):
                    c.send(0, msg(rng.randint(100, 140)))
                    c.send(1, msg(65_536), gap=0.00004)
            if rng.random() < 0.35:  # saving one (in chunks, each acknowledged)
                for _ in range(rng.randint(1, 8)):
                    c.send(0, msg(rng.randint(20_000, 300_000)), gap=0.00006)
                    c.send(1, msg(rng.randint(80, 140)))
            c.wait(rng.expovariate(1 / 30))
        c.close()

    def api_poll(self, client, start, end):
        """A dashboard or app polling a REST API: a small request, a JSON answer, every so often."""
        rng = self.rng
        host, ip = rng.choice([("api.github.com", "140.82.112.6"), ("graph.microsoft.com", "20.190.151.68"),
                               ("status.atlassian.com", "185.199.108.153")])
        period = rng.uniform(10, 120)
        keep = rng.random() < 0.5  # one kept-alive connection, or a new one each time
        self.dns_lookup(client, start, host, ip)
        t = start + rng.uniform(0.05, period)
        c = None
        while t < end:
            if c is None or not keep:
                c = TcpConversation(self.w, client, self.eport(client), ip, 443, t, rtt=rng.uniform(0.01, 0.07), rng=rng)
                c.handshake()
                c.send(0, tls_client_hello(host, BROWSER_CIPHERS, BROWSER_EXTS, rng=rng))
                c.send(1, tls_server_hello(rng) + tls_app_data(rng, rng.randint(2600, 4800)))
            else:
                c.wait(max(0.0, t - c.t))
            c.send(0, tls_app_data(rng, rng.randint(250, 900)))
            c.send(1, tls_app_data(rng, min(int(rng.lognormvariate(8.0, 1.0)), 120_000)))
            if not keep:
                c.close()
            t += period * (1 + rng.uniform(-0.15, 0.15))
        if keep and c is not None:
            c.close()

    def software_update(self, client, start):
        """An OS or app update: a catalogue fetch, then the update in a few large pieces."""
        rng = self.rng
        host, ip = rng.choice([("swcdn.apple.com", "17.253.144.10"), ("tlu.dl.delivery.mp.microsoft.com", "23.48.200.11"),
                               ("dl.google.com", "142.250.72.14")])
        self.dns_lookup(client, start - 0.05, host, ip)
        self.https_session(client, start, host, ip, exchanges=rng.randint(1, 3))
        t = start + rng.uniform(1, 6)
        for _ in range(rng.randint(1, 4)):
            c = TcpConversation(self.w, client, self.eport(client), ip, 443, t, rtt=rng.uniform(0.01, 0.05), rng=rng)
            c.handshake()
            c.send(0, tls_client_hello(host, BROWSER_CIPHERS, BROWSER_EXTS, rng=rng))
            c.send(1, tls_server_hello(rng) + tls_app_data(rng, 4200))
            c.send(0, tls_app_data(rng, rng.randint(400, 700)))  # a range request
            c.send(1, tls_app_data(rng, rng.randint(1_000_000, 6_000_000)), gap=0.00005, reorder=0.005, duplicate=0.001)
            c.close()
            t = c.t + rng.uniform(0.2, 3)

    def cloud_sync(self, client, start, end):
        """A file-sync client: a long-poll for changes, and small edits uploaded as they happen."""
        rng = self.rng
        host, ip = rng.choice([("client.dropbox.com", "162.125.6.20"), ("my.microsoftpersonalcontent.com", "13.107.42.12")])
        self.dns_lookup(client, start, host, ip)
        t = start + rng.uniform(1, 60)
        while t < end:
            c = TcpConversation(self.w, client, self.eport(client), ip, 443, t, rtt=rng.uniform(0.02, 0.06), rng=rng)
            c.handshake()
            c.send(0, tls_client_hello(host, BROWSER_CIPHERS, BROWSER_EXTS, rng=rng))
            c.send(1, tls_server_hello(rng) + tls_app_data(rng, 3600))
            if rng.random() < 0.6:  # the long-poll: held open until something changes
                c.send(0, tls_app_data(rng, rng.randint(300, 600)))
                c.wait(rng.uniform(20, 90))
                c.send(1, tls_app_data(rng, rng.randint(60, 400)))
            else:  # a changed file
                c.send(0, tls_app_data(rng, rng.randint(400, 900)))
                c.send(1, tls_app_data(rng, rng.randint(200, 800)))
                c.send(0, tls_app_data(rng, int(min(rng.lognormvariate(10.5, 1.3), 900_000))), gap=0.0001)
                c.send(1, tls_app_data(rng, rng.randint(300, 1200)))
            c.close()
            t = c.t + rng.expovariate(1 / 50)

    def print_job(self, client, start, size):
        """A document sent to the office printer (raw port 9100): one way, then a status line."""
        rng = self.rng
        c = TcpConversation(self.w, client, self.eport(client), "10.0.5.50", 9100, start, rtt=rng.uniform(0.0005, 0.003),
                            rng=rng)
        c.handshake()
        c.send(0, b"\x1b%-12345X@PJL JOB\r\n" + rng.randbytes(size), gap=0.0003)
        c.send(1, b"@PJL USTATUS JOB\r\nEND\r\n")
        c.close()

    def web_app(self, client, start, duration):
        """A single-page web app (docs, tickets) on one HTTP/2 connection: bursts as the user works."""
        rng = self.rng
        host, ip = rng.choice([("docs.google.com", "142.250.72.46"), ("acme.atlassian.net", "185.166.143.1"),
                               ("app.asana.com", "52.38.122.44")])
        self.dns_lookup(client, start - 0.05, host, ip)
        c = TcpConversation(self.w, client, self.eport(client), ip, 443, start, rtt=rng.uniform(0.01, 0.06), rng=rng)
        c.handshake()
        c.send(0, tls_client_hello(host, BROWSER_CIPHERS, BROWSER_EXTS, rng=rng))
        c.send(1, tls_server_hello(rng) + tls_app_data(rng, rng.randint(3000, 5200)))
        c.send(0, tls_app_data(rng, rng.randint(600, 1500)))
        c.send(1, tls_app_data(rng, rng.randint(80_000, 900_000)), gap=0.00008)  # the app itself
        end = start + duration
        while c.t < end:
            for _ in range(rng.randint(1, 10)):  # edits saved as typed, small answers
                c.wait(rng.expovariate(1 / 1.2))
                c.send(0, tls_app_data(rng, rng.randint(150, 2500)))
                c.send(1, tls_app_data(rng, rng.randint(60, 4000)))
            c.wait(rng.expovariate(1 / 15))
        c.close()

    def office_day(self, hosts: list[str], duration: float):
        """The rest of an office's traffic, on top of benign(): each host does some of it.
        Rates are per host per hour, high enough that each kind of connection is common in
        the capture (a model learns what is normal from how often it sees it)."""
        rng = self.rng
        start, end = self.t0, self.t0 + duration
        hours = duration / 3600

        def at(tail: float = 0.0) -> float:
            return start + rng.uniform(0, max(1.0, duration - tail))

        for h in hosts:
            for _ in range(self._poisson(hours * 1.5)):  # remote desktop to a server
                self.rdp_session(h, at(60), rng.uniform(45, 480))
            for _ in range(self._poisson(hours * 4)):    # an application's database connections
                self.db_client(h, at(30), rng.uniform(20, 300))
            for _ in range(self._poisson(hours * 4)):    # the file server
                self.file_share(h, at(30), rng.uniform(20, 300))
            if rng.random() < 0.5:
                self.api_poll(h, start, end)
            for _ in range(self._poisson(hours * 0.6)):
                self.software_update(h, at(60))
            if rng.random() < 0.4:
                self.cloud_sync(h, start, end)
            for _ in range(self._poisson(hours * 6)):    # the office printer
                self.print_job(h, at(5), int(min(rng.lognormvariate(11.8, 1.0), 900_000)) + 20_000)
            for _ in range(self._poisson(hours * 2)):
                self.web_app(h, at(60), rng.uniform(30, 600))

    def workstations(self, count: int, duration: float, first_host: int):
        """Desks that mostly use the office's own services (file server, printer, database,
        remote desktop) and little else: a bigger office's share of that traffic."""
        hosts = [f"10.0.1.{first_host + i}" for i in range(count)]
        for h in hosts:
            if self.rng.random() < 0.7:
                self.agent_checkin(h, self.t0, self.t0 + duration)
        self.office_day(hosts, duration)
        return hosts

    def benign(self, clients: int, duration: float, first_host=10, v6_clients=0, page_rates=None):
        rng = self.rng
        start, end = self.t0, self.t0 + duration
        hosts = [f"10.0.0.{first_host + i}" for i in range(clients)]
        for h in hosts:
            # (light and heavy users when asked for; everyone at one rate otherwise, as the original sets were made)
            self.browsing_client(h, start, end, *([rng.uniform(*page_rates)] if page_rates else []))
            if rng.random() < 0.6:
                self.websocket_keepalive(h, start + rng.uniform(0, 30), end)
            if rng.random() < 0.7:
                self.agent_checkin(h, start, end)
            # Office-realistic rates: a few attachments and downloads per host per hour.
            for _ in range(self._poisson(duration / 3600 * 2.0)):
                self.download(h, start + rng.uniform(0, duration * 0.95), rng.randint(1_000_000, 8_000_000))
            for _ in range(self._poisson(duration / 3600 * 3.0)):
                self.mail_upload(h, start + rng.uniform(0, duration * 0.95), rng.randint(200_000, 4_000_000))
            if rng.random() < 0.15:
                self.video_call(h, start + rng.uniform(0, duration * 0.7), rng.uniform(60, 180))
            if rng.random() < 0.3:
                self.imap_idle(h, start + rng.uniform(0, 60), end)
            if rng.random() < 0.08:
                self.ssh_session(h, start + rng.uniform(0, duration * 0.6), rng.uniform(120, 480))
        for i in range(v6_clients):
            self.browsing_client(f"fd00::{first_host + i:x}", start, end)
        return hosts

    # ----------------------------------------------------------- attacks

    def c2_beacon(self, client="10.0.0.23", server="192.168.1.105", period=4.2, jitter=0.004, duration=600):
        rng = self.rng
        domain = "update.cdn-telemetry.net"
        t = self.t0 + 5
        self.dns_lookup(client, t, domain, server)
        t += 0.2
        while t < self.t0 + duration:
            c = TcpConversation(self.w, client, self.eport(client), server, 443, t, rtt=0.03, rng=rng)
            c.handshake()
            c.send(0, tls_client_hello(domain, MALWARE_CIPHERS, MALWARE_EXTS, alpn=(), grease=False, rng=rng))
            c.send(1, tls_server_hello(rng, cipher=0xC02F) + tls_app_data(rng, 1800))
            c.send(0, tls_app_data(rng, rng.randint(180, 196)))   # check-in
            tasking = rng.random() < 0.05
            c.send(1, tls_app_data(rng, rng.randint(1400, 2600) if tasking else 64))
            c.close()
            t += period * (1 + rng.gauss(0, jitter))

    def c2_jittered(self, client="10.0.0.61", server="45.77.12.34", period=25.0, jitter=0.20, duration=600):
        """Cobalt-Strike-style sleep with uniform random jitter (sleep * (1 ± jitter))."""
        rng = self.rng
        domain = "cdn.static-assets-eu.com"
        t = self.t0 + 30
        self.dns_lookup(client, t - 0.1, domain, server)
        while t < self.t0 + duration:
            c = TcpConversation(self.w, client, self.eport(client), server, 443, t, rtt=0.06, rng=rng)
            c.handshake()
            c.send(0, tls_client_hello(domain, MALWARE_CIPHERS[:12], MALWARE_EXTS, alpn=("http/1.1",), grease=False,
                                       rng=rng))
            c.send(1, tls_server_hello(rng, cipher=0xC030) + tls_app_data(rng, 2400))
            c.send(0, tls_app_data(rng, rng.randint(310, 330)))
            c.send(1, tls_app_data(rng, rng.randint(80, 96)))
            c.close()
            t += period * (1 + rng.uniform(-jitter, jitter))

    def dns_tunnel(self, client="10.0.0.31", base="exfil-cdn.net", queries=260, duration=600):
        rng = self.rng
        secret = rng.randbytes(queries * 32)
        t = self.t0 + 40
        for i in range(queries):
            chunk = base64.b32encode(secret[i * 32:(i + 1) * 32]).decode().rstrip("=").lower()
            name = f"{chunk[:48]}.{chunk[48:]}{i:04x}.x7k.{base}"
            reply = base64.b64encode(rng.randbytes(rng.randint(90, 160)))
            self.dns_lookup(client, t, name, None, qtype=16, txt=reply)
            t += rng.uniform(0.3, 2.0)
            if t > self.t0 + duration:
                break

    def exfil(self, client="10.0.0.44", server="203.0.113.50", size=6_000_000):
        rng = self.rng
        t = self.t0 + 220
        domain = "backup-sync.io"
        self.dns_lookup(client, t - 0.1, domain, server)
        c = TcpConversation(self.w, client, self.eport(client), server, 8443, t, rtt=0.05, rng=rng)
        c.handshake()
        c.send(0, tls_client_hello(domain, MALWARE_CIPHERS, MALWARE_EXTS, alpn=("http/1.1",), grease=False, rng=rng))
        c.send(1, tls_server_hello(rng, cipher=0xC030) + tls_app_data(rng, 2100))
        sent = 0
        while sent < size:
            n = rng.randint(200_000, 400_000)
            c.send(0, tls_app_data(rng, n), gap=0.00012, reorder=0.02, duplicate=0.005)
            c.send(1, tls_app_data(rng, 33))
            sent += n
        c.close()

    def http_keepalive_beacon(self, client="10.0.0.52", server="198.51.100.7", period=15.0, duration=600):
        rng = self.rng
        c = TcpConversation(self.w, client, self.eport(client), server, 8080, self.t0 + 12, rtt=0.04, rng=rng)
        c.handshake()
        while c.t < self.t0 + duration - period:
            body = rng.randbytes(48).hex().encode()
            c.send(0, b"POST /api/v2/status HTTP/1.1\r\nHost: 198.51.100.7:8080\r\n"
                      b"User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)\r\n"
                      b"Content-Type: application/octet-stream\r\nContent-Length: " + str(len(body)).encode() +
                   b"\r\nConnection: keep-alive\r\n\r\n" + body)
            c.send(1, b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 2\r\n\r\nOK")
            c.wait(period * (1 + rng.gauss(0, 0.008)) - 2 * c.rtt)
        c.close()


def http_download(out_dir: str, t0: float, size=2_000_000):
    s = Scenario(seed=7, t0=t0)
    body = s.rng.randbytes(size)
    c = TcpConversation(s.w, "10.1.0.5", 51515, "10.1.0.80", 80, t0, rtt=0.01, rng=s.rng)
    c.handshake()
    c.send(0, b"GET /large-file.bin HTTP/1.1\r\nHost: files.lab\r\nUser-Agent: curl/8.6.0\r\n\r\n")
    c.send(1, f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\n\r\n"
           .encode() + body, reorder=0.2, duplicate=0.05, zero_window_at=600)
    c.close()
    s.w.save(os.path.join(out_dir, "http_download.pcap"))
    with open(os.path.join(out_dir, "http_download.body"), "wb") as fh:
        fh.write(body)


def edge_cases(out_dir: str, t0: float):
    """Unusual-but-valid (and some invalid) traffic for dissector/reassembly tests."""
    s = Scenario(seed=11, t0=t0)
    rng, w = s.rng, s.w

    # 802.1Q-tagged HTTP, and QinQ-tagged TLS
    c = TcpConversation(w, "10.2.0.5", 40001, "10.2.0.80", 80, t0, rng=rng, vlans=(100,))
    c.handshake().send(0, b"GET /vlan HTTP/1.1\r\nHost: vlan.lab\r\n\r\n").send(1, b"HTTP/1.1 204 No Content\r\n\r\n")
    c.close()
    c = TcpConversation(w, "10.2.0.6", 40002, "10.2.0.81", 443, t0 + 1, rng=rng, vlans=(200, 300))
    c.handshake().send(0, tls_client_hello("qinq.lab", BROWSER_CIPHERS, BROWSER_EXTS, rng=rng))
    c.send(1, tls_server_hello(rng)).close()

    # IPv6 with a hop-by-hop extension header, and IPv6 DNS (AAAA)
    c = TcpConversation(w, "fd00::5", 40003, "2001:db8::443", 443, t0 + 2, rng=rng, hop_by_hop=True)
    c.handshake().send(0, tls_client_hello("v6.lab", BROWSER_CIPHERS, BROWSER_EXTS, rng=rng))
    c.send(1, tls_server_hello(rng)).close()
    s.dns_lookup("fd00::5", t0 + 3, "v6dns.lab", "2001:db8::53", qtype=28, server=RESOLVER6)

    # Fragmented UDP datagram (2 fragments), ARP, and a frame truncated inside the IP header
    w.add(t0 + 4, ipv4_fragment("10.2.0.7", "10.2.0.1", 17, rng.randbytes(1480), 0x4242, 0, True))
    w.add(t0 + 4.001, ipv4_fragment("10.2.0.7", "10.2.0.1", 17, rng.randbytes(500), 0x4242, 1480, False))
    w.add(t0 + 5, arp_frame())
    w.add(t0 + 6, tcp_frame("10.2.0.8", 1, "10.2.0.9", 2, 0, 0, SYN)[:30])

    # Sequence numbers that wrap past 2**32 mid-transfer, with reordering and retransmits
    body = rng.randbytes(300_000)
    c = TcpConversation(w, "10.2.0.10", 40004, "10.2.0.82", 80, t0 + 7, rng=rng,
                        isn=(2**32 - 1000, 2**32 - 50_000))
    c.handshake().send(0, b"GET /wrap HTTP/1.1\r\nHost: wrap.lab\r\n\r\n")
    c.send(1, b"HTTP/1.1 200 OK\r\nContent-Length: 300000\r\n\r\n" + body, reorder=0.3, duplicate=0.1)
    c.close()

    # Overlapping retransmission: [0,1000) then [500,1500) then [1500,2000)
    data = rng.randbytes(2000)
    cs, ss = 1_000_000, 5_000_000
    cli, srv = ("10.2.0.11", 40005), ("10.2.0.83", 9000)
    t = t0 + 9
    w.add(t, tcp_frame(*cli, *srv, cs, 0, SYN))
    w.add(t + 0.001, tcp_frame(*srv, *cli, ss, cs + 1, SYN | ACK))
    w.add(t + 0.002, tcp_frame(*cli, *srv, cs + 1, ss + 1, ACK))
    for i, (a, b) in enumerate([(0, 1000), (500, 1500), (1500, 2000)]):
        w.add(t + 0.01 * (i + 1), tcp_frame(*cli, *srv, cs + 1 + a, ss + 1, PSH | ACK, data[a:b]))
    w.add(t + 0.05, tcp_frame(*cli, *srv, cs + 2001, ss + 1, FIN | ACK))
    w.add(t + 0.06, tcp_frame(*srv, *cli, ss + 1, cs + 2002, FIN | ACK))
    w.add(t + 0.07, tcp_frame(*cli, *srv, cs + 2002, ss + 2, ACK))

    w.save(os.path.join(out_dir, "edge_cases.pcap"))
    with open(os.path.join(out_dir, "edge_wrap.body"), "wb") as fh:
        fh.write(body)
    with open(os.path.join(out_dir, "edge_overlap.body"), "wb") as fh:
        fh.write(data)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="data")
    ap.add_argument("--train-minutes", type=float, default=30)
    ap.add_argument("--only", choices=["train", "val", "demo", "tests", "train-more", "val-more", "holdout"],
                    help="generate just one set")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    t0 = dt.datetime(2026, 10, 6, 14, 0, tzinfo=dt.timezone.utc).timestamp()

    if args.only in (None, "train"):
        train = Scenario(seed=1, t0=t0 - 7200)
        train.benign(clients=28, duration=args.train_minutes * 60, v6_clients=3)
        print(f"benign_train.pcap: {train.w.save(os.path.join(args.out, 'benign_train.pcap'))} frames")

    if args.only in (None, "val"):
        val = Scenario(seed=3, t0=t0 - 3600)
        val.benign(clients=20, duration=900, first_host=100, v6_clients=2)
        print(f"benign_val.pcap: {val.w.save(os.path.join(args.out, 'benign_val.pcap'))} frames")

    if args.only in (None, "train-more"):
        more = Scenario(seed=4, t0=t0 - 10800)
        hosts = more.benign(clients=32, duration=args.train_minutes * 60, first_host=60, v6_clients=3,
                            page_rates=(1 / 70, 1 / 12))
        more.office_day(hosts, args.train_minutes * 60)
        more.workstations(64, args.train_minutes * 60, first_host=10)
        print(f"benign_train_more.pcap: {more.w.save(os.path.join(args.out, 'benign_train_more.pcap'))} frames")

    if args.only in (None, "val-more"):
        more = Scenario(seed=5, t0=t0 - 5400)
        hosts = more.benign(clients=20, duration=900, first_host=150, v6_clients=2, page_rates=(1 / 70, 1 / 12))
        more.office_day(hosts, 900)
        more.workstations(40, 900, first_host=100)
        print(f"benign_val_more.pcap: {more.w.save(os.path.join(args.out, 'benign_val_more.pcap'))} frames")

    if args.only in (None, "holdout"):
        held = Scenario(seed=6, t0=t0 - 1800)
        hosts = held.benign(clients=20, duration=900, first_host=200, v6_clients=2, page_rates=(1 / 70, 1 / 12))
        held.office_day(hosts, 900)
        held.workstations(40, 900, first_host=180)
        print(f"benign_holdout.pcap: {held.w.save(os.path.join(args.out, 'benign_holdout.pcap'))} frames")

    if args.only in (None, "demo"):
        demo = Scenario(seed=2, t0=t0)
        demo.benign(clients=14, duration=600, v6_clients=2)
        demo.c2_beacon()
        demo.c2_jittered()
        demo.dns_tunnel()
        demo.exfil()
        demo.http_keepalive_beacon()
        print(f"mixed_demo.pcap: {demo.w.save(os.path.join(args.out, 'mixed_demo.pcap'))} frames")

    if args.only in (None, "tests"):
        http_download(args.out, t0 - 600)
        edge_cases(args.out, t0 - 300)
        print("http_download.pcap, edge_cases.pcap (+ expected bodies)")


if __name__ == "__main__":
    main()
