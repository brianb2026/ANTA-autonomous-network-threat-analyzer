"""Per-host baselines: what each internal host normally does, minute by minute, and
the moments it suddenly does something else.

Every finished session is counted in its client's time bucket (30 s of capture
time): bytes sent and received, sessions opened, distinct hosts and ports
contacted, applications used. When a bucket closes it is compared with that host's
own history (once there are at least six minutes of it): a value far above the
host's usual level (median + 8 × MAD, ten times its 90th percentile, and above an
absolute floor) is a deviation, as is the first use of a protocol like SMB, RDP or
SSH by a host that never used it before. Each host is only compared with itself,
so a busy server and a quiet laptop each have their own normal.
"""
from __future__ import annotations

import ipaddress
import statistics
from collections import OrderedDict

BUCKET_S = 30.0
MIN_HISTORY = 12          # buckets of history before a host is judged (6 minutes)
MAX_HISTORY = 240         # buckets remembered per host (2 hours)
MAX_HOSTS = 5000

# metric: (absolute floor, what it means, severity)
METRICS = {
    "bytes_out": (5_000_000, "sent {value} in {window}, against a usual {usual}", "medium"),
    "dst_hosts": (25, "contacted {value} different hosts in {window}, against a usual {usual}", "medium"),
    "dst_ports": (20, "connected to {value} different ports in {window}, against a usual {usual}", "medium"),
    "sessions": (300, "opened {value} connections in {window}, against a usual {usual}", "medium"),
    "bytes_in": (100_000_000, "received {value} in {window}, against a usual {usual}", "low"),
}
NOTABLE_APPS = {"ssh": "SSH", "rdp": "RDP", "smb": "SMB", "telnet": "Telnet", "vnc": "VNC", "socks": "SOCKS proxy",
                "ftp": "FTP", "irc": "IRC", "bittorrent": "BitTorrent", "tftp": "TFTP", "openvpn": "OpenVPN",
                "wireguard": "WireGuard", "mssql": "Microsoft SQL", "mysql": "MySQL", "postgresql": "PostgreSQL",
                "mongodb": "MongoDB", "redis": "Redis", "dcerpc": "DCE/RPC", "ldap": "LDAP", "winrm": "WinRM"}


def _fmt(metric: str, v: float) -> str:
    if metric.startswith("bytes"):
        for unit in ("B", "KB", "MB", "GB"):
            if v < 1024 or unit == "GB":
                return f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
            v /= 1024
    return f"{v:.0f}"


def _internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not a.is_loopback and not a.is_multicast and not a.is_unspecified


class _Bucket:
    __slots__ = ("bytes_out", "bytes_in", "sessions", "hosts", "ports", "apps", "examples")

    def __init__(self):
        self.bytes_out = self.bytes_in = self.sessions = 0
        self.hosts: set = set()
        self.ports: set = set()
        self.apps: set = set()
        self.examples: list = []   # a few sessions behind it, for the alert's evidence

    def value(self, metric: str) -> float:
        if metric == "dst_hosts":
            return len(self.hosts)
        if metric == "dst_ports":
            return len(self.ports)
        return getattr(self, metric)


class _Host:
    __slots__ = ("buckets", "first", "judged", "apps_seen")

    def __init__(self, first: int):
        self.buckets: OrderedDict[int, _Bucket] = OrderedDict()
        self.first = first
        self.judged = first - 1          # buckets up to here have been compared
        self.apps_seen: set = set()


class Baselines:
    def __init__(self, bucket_s: float = BUCKET_S, min_history: int = MIN_HISTORY):
        self.bucket_s = bucket_s
        self.min_history = min_history
        self.hosts: OrderedDict[str, _Host] = OrderedDict()

    def observe(self, rec: dict) -> None:
        """A finished session, counted for its (internal) client."""
        ip = rec["src_ip"]
        if not rec.get("final", True) or not _internal(ip):
            return
        b = int(rec["start"] // self.bucket_s)
        h = self.hosts.get(ip)
        if h is None:
            h = self.hosts[ip] = _Host(b)
            while len(self.hosts) > MAX_HOSTS:
                self.hosts.popitem(last=False)
        if b <= h.judged:  # arrives after its bucket was judged (a long session): count it in the latest open one
            b = h.judged + 1
        bk = h.buckets.get(b)
        if bk is None:
            bk = h.buckets[b] = _Bucket()
            while len(h.buckets) > MAX_HISTORY:
                h.buckets.popitem(last=False)
        bk.bytes_out += rec["c2s"]["bytes"]
        bk.bytes_in += rec["s2c"]["bytes"]
        bk.sessions += 1
        if len(bk.hosts) < 5000:
            bk.hosts.add(rec["dst_ip"])
        if len(bk.ports) < 5000:
            bk.ports.add(rec["dst_port"])
        if rec.get("app"):
            bk.apps.add(rec["app"])
        if len(bk.examples) < 5:
            bk.examples.append(rec)

    def judge(self, now: float, final: bool = False) -> list[dict]:
        """Compare every bucket that has closed (or all, at the end of a capture) with its host's past."""
        current = int(now // self.bucket_s)
        out = []
        for ip, h in self.hosts.items():
            last = max(h.buckets) if h.buckets else h.judged
            upto = last if final else current - 2  # sessions are reported when they end: allow a minute
            for b in range(h.judged + 1, upto + 1):
                bk = h.buckets.get(b)
                history = [h.buckets.get(x) for x in range(max(h.first, b - MAX_HISTORY), b)]
                if bk is not None:
                    out += self._judge(ip, h, b, bk, history)
                    h.apps_seen |= bk.apps
                h.judged = b
        return out

    def _judge(self, ip: str, h: _Host, b: int, bk: _Bucket, history: list) -> list[dict]:
        if len(history) < self.min_history:
            return []
        found = []
        window = f"{self.bucket_s:.0f} seconds"
        for metric, (floor, text, severity) in METRICS.items():
            value = bk.value(metric)
            if value < floor:
                continue
            past = [x.value(metric) if x else 0 for x in history]
            med = statistics.median(past)
            mad = statistics.median([abs(v - med) for v in past]) * 1.4826
            p90 = sorted(past)[int(0.9 * (len(past) - 1))]
            if value > med + 8 * mad and value > 10 * max(p90, 1):
                usual = f"{_fmt(metric, med)} (at most {_fmt(metric, max(past))} before)"
                found.append({"ip": ip, "metric": metric, "severity": severity, "bucket": b,
                              "start": b * self.bucket_s, "value": value, "median": med, "p90": p90,
                              "text": text.format(value=_fmt(metric, value), window=window, usual=usual),
                              "history": len(past), "examples": bk.examples})
        new_apps = sorted(a for a in bk.apps - h.apps_seen if a in NOTABLE_APPS)
        if new_apps and len(h.apps_seen) >= 1:
            found.append({"ip": ip, "metric": "new_app", "severity": "low", "bucket": b, "start": b * self.bucket_s,
                          "value": len(new_apps), "apps": new_apps, "history": len(history),
                          "text": f"used {', '.join(NOTABLE_APPS[a] for a in new_apps)} for the first time, after "
                                  f"{len(history) * self.bucket_s / 60:.0f} minutes of never using it",
                          "examples": [e for e in bk.examples if e.get("app") in new_apps] or bk.examples})
        return found
