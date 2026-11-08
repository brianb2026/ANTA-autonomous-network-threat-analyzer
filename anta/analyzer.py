"""Detection pipeline: consumes engine records, maintains state, produces alerts.

Detectors
  beacon      statistical timing analysis across all sessions on a channel
              (client, server, port). Bursts of activity are the unit, so one
              algorithm covers reconnect-every-N-seconds and check-ins over one
              persistent connection. Scoring is robust to configured jitter
              (Bowley skew + MAD of intervals, RITA-style) and to missed check-ins.
  shared      the same periodic behaviour seen from many internal hosts to one
              destination - usually software heartbeats; reported as low severity
  dns_tunnel  subdomain entropy/length analysis per (client, registered domain)
  exfil       large, one-sided uploads to a destination few hosts talk to
  download    executables and scripts fetched over plain HTTP, rated by how they
              were fetched (bare IP address, unusual port, command-line tool,
              a name or type that hides what the file is); the file's SHA-256
              comes with the alert
  tls_port    a TLS port (443, 8443, 993, ...) carrying something that isn't TLS:
              remote-access trojans and custom C2 protocols hide there
  anomaly     Isolation Forest (ONNX) score per TCP session
"""
from __future__ import annotations

import dataclasses
import ipaddress
import re
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field

import numpy as np

from . import baseline, devices, eta, explain, filetypes, ignore, intel
from .features import (bursts, feature_vector, jitter, registered_domain, session_bytes, session_features,
                       string_entropy)
from .security import InvalidRecord, validate_session

SEVERITY = {"beacon": "critical", "dns_tunnel": "high", "exfil": "high", "anomaly": "medium", "shared": "low",
            "download": "high", "tls_port": "high", "smb_file": "high", "dns_poison": "critical",
            "crafted_tcp": "high", "ftp_file": "medium", "compromised_device": "critical",
            "port_mismatch": "high", "intel_match": "critical", "baseline": "medium",
            "arp_spoof": "critical", "scan": "medium", "dga": "high", "agent": "high",
            "cleartext_login": "medium"}
TITLES = {"beacon": "C2 Beaconing", "dns_tunnel": "High-Entropy DNS / Tunneling", "exfil": "Data Exfiltration",
          "anomaly": "Statistical Anomaly", "shared": "Shared Periodic Traffic",
          "download": "Suspicious Executable Download", "tls_port": "Non-TLS Traffic on a TLS Port",
          "smb_file": "Program Copied Over SMB", "dns_poison": "Poisoned DNS Answers",
          "crafted_tcp": "Crafted TCP Traffic", "ftp_file": "Sensitive File Over Unencrypted FTP",
          "compromised_device": "Compromised Device", "port_mismatch": "Protocol on an Unexpected Port",
          "intel_match": "Known Malicious Indicator", "baseline": "Deviation from Host Baseline",
          "arp_spoof": "ARP Spoofing / Gateway Impersonation", "scan": "Port / Host Scan",
          "dga": "Algorithmic Domain Generation (DGA)", "agent": "Flagged by the Detection Agent",
          "cleartext_login": "Password Sent in Clear Text"}
SUMMARY_FIELDS = ("id", "kind", "severity", "title", "headline", "confidence", "src_ip", "dst_ip", "dst_port",
                  "target", "first_seen", "last_seen", "updates", "hosts", "addresses", "triage", "geo", "offender")
# An analyst's verdict on an alert, kept with it and carried into the incident report.
TRIAGE_STATUSES = ("new", "investigating", "confirmed", "false_positive")


@dataclass
class Config:
    # Beacon detection
    beacon_min_events: int = 8              # check-ins needed before judging regularity
    beacon_min_span_s: float = 60.0
    beacon_min_period_s: float = 1.0
    beacon_score_threshold: float = 0.80    # combined timing/size regularity score (0-1)
    beacon_ignore_ports: list = field(default_factory=lambda: [53, 67, 68, 123, 137, 138, 1900, 5353, 5355])
    # A destination many internal hosts talk to on the same cadence is almost
    # always a software heartbeat, not C2: it is reported once, as low severity.
    shared_min_hosts: int = 4
    shared_min_fraction: float = 0.25
    # DNS tunneling
    dns_min_queries: int = 12
    dns_min_entropy: float = 3.6
    dns_min_len: float = 24.0
    dns_allowlist: list = field(default_factory=lambda: ["in-addr.arpa", "ip6.arpa", "local", "home.arpa"])
    # Exfiltration
    exfil_min_bytes: int = 5_000_000
    exfil_min_asymmetry: float = 0.85
    exfil_max_hosts: int = 2                # destination contacted by at most this many internal hosts
    # Detection agent (when it replaces the session model): what it is handed to review.
    agent_min_bytes: int = 2000             # sessions that moved at least this much
    agent_command: list = field(default_factory=list)  # your own agent program (argv); config file only
    # Downloads: executables from these vendors' update and certificate servers are
    # expected, unless something else about the download is off.
    download_trusted_domains: list = field(default_factory=lambda: [
        "windowsupdate.com", "microsoft.com", "msftconnecttest.com", "office.net", "digicert.com", "lencr.org",
        "sectigo.com", "apple.com", "mzstatic.com", "adobe.com", "google.com", "gvt1.com", "mozilla.net",
        "ubuntu.com", "canonical.com", "debian.org"])
    download_standard_ports: list = field(default_factory=lambda: [80, 8080, 8000])
    download_tls_ports: list = field(default_factory=lambda: [443, 8443])  # HTTPS read with a key log
    # Non-TLS traffic on TLS ports. A long, two-way session there looks like remote control.
    tls_ports: list = field(default_factory=lambda: [443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 5061,
                                                     5223, 8443, 8883])
    tls_port_min_bytes: int = 512
    remote_control_min_s: float = 300.0
    remote_control_min_bytes: int = 10_000  # each way
    # Port / host scanning: a source whose connection attempts mostly fail to
    # complete a handshake, spread across many ports (one host) or many hosts (one
    # port). A high failed fraction separates a scan from ordinary fan-out.
    scan_min_targets: int = 20              # distinct ports (vertical) or hosts (horizontal)
    scan_min_fail_ratio: float = 0.8        # fraction of attempts that never completed a handshake
    # DGA: a host asking for many distinct, random-looking registered domains that
    # mostly do not exist — malware cycling through generated names to find its C2.
    dga_min_nxdomains: int = 30             # distinct registered domains that returned NXDOMAIN
    dga_min_entropy: float = 3.2            # average Shannon entropy (bits/char) of their second-level labels
    # Global allowlists (all detectors): CIDRs, and domain suffixes matched
    # against SNI, HTTP Host, DNS names and resolved names.
    allowlist_cidrs: list = field(default_factory=list)
    allowlist_domains: list = field(default_factory=list)
    # State limits
    max_flows_per_channel: int = 300
    max_alerts: int = 2000
    state_ttl_s: float = 7200.0             # forget channels/DNS groups idle this long (capture time)

    @classmethod
    def load(cls, path: str | None) -> Config:
        cfg = cls()
        if not path:
            return cfg
        import tomllib

        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        known = {f.name: f for f in dataclasses.fields(cls)}
        for section in data.values() if all(isinstance(v, dict) for v in data.values()) else [data]:
            for key, value in section.items():
                if key not in known:
                    raise ValueError(f"{path}: unknown setting '{key}'")
                default = getattr(cfg, key)
                if isinstance(default, list) and not isinstance(value, list):
                    raise ValueError(f"{path}: '{key}' must be a list")
                if isinstance(default, (int, float)) and not isinstance(default, bool):
                    if not isinstance(value, (int, float)) or isinstance(value, bool):
                        raise ValueError(f"{path}: '{key}' must be a number")
                    value = type(default)(value)
                setattr(cfg, key, value)
        return cfg


def flow_spec(rec: dict) -> str:
    proto = 6 if rec["proto"] == "tcp" else 17
    return f"{proto},{rec['src_ip']},{rec['src_port']},{rec['dst_ip']},{rec['dst_port']}"


def five_tuple(rec: dict) -> str:
    return f"{rec['proto'].upper()} {rec['src_ip']}:{rec['src_port']} → {rec['dst_ip']}:{rec['dst_port']}"


def alert_summary(alert: dict) -> dict:
    """The lightweight form sent to the threat feed; details are fetched on demand."""
    return {k: alert.get(k) for k in SUMMARY_FIELDS}


DOMAIN_SERVICE_PORTS = {53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 5722, 5985, 9389}


def _internal_service(rec: dict) -> bool:
    try:
        src, dst = ipaddress.ip_address(rec["src_ip"]), ipaddress.ip_address(rec["dst_ip"])
    except ValueError:
        return False
    return src.is_private and dst.is_private and rec["dst_port"] in DOMAIN_SERVICE_PORTS


def _not_routable_target(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if addr.is_multicast or addr.is_unspecified:
        return True
    return addr.version == 4 and (ip == "255.255.255.255" or ip.endswith(".255"))  # (subnet) broadcast


@dataclass
class FlowSummary:
    """What the beacon detector keeps per session (not the whole record)."""
    spec: str
    start: float
    end: float
    bursts: list
    bytes_out: int
    bytes_in: int
    packets: int
    tls: dict | None
    http: dict | None
    stream: dict


@dataclass
class Channel:
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    flows: OrderedDict = field(default_factory=OrderedDict)  # flow_id -> FlowSummary
    last_seen: float = 0.0
    periodic: tuple | None = None  # last regularity verdict (metrics, chart, …), for the shared-destination view


@dataclass
class DnsGroup:
    src_ip: str
    domain: str
    queries: OrderedDict = field(default_factory=OrderedDict)  # (flow_id, qname, idx) -> dict
    resolvers: set = field(default_factory=set)
    specs: OrderedDict = field(default_factory=OrderedDict)
    last_seen: float = 0.0


class Analyzer:
    def __init__(self, model=None, config: Config | None = None, intel=None, geo=None):
        self.model = model
        self.agent_submit = None                  # with a detection agent in the model's place: hands it sessions
        self.cfg = config or Config()
        self.intel = intel                        # IntelStore: known-bad indicators to match sessions against
        self.geo = geo                            # GeoDB: country and AS of public addresses
        self.baselines = baseline.Baselines()
        self.eta: OrderedDict[str, dict] = OrderedDict()   # encrypted sessions, classified by their shape
        self.host_apps: dict[str, dict] = {}      # ip -> {"uses": {app: n}, "serves": {app: n}} (asset inventory)
        self._allow_nets = [ipaddress.ip_network(c, strict=False) for c in self.cfg.allowlist_cidrs]
        self._allow_domains = [d.lower().strip(".") for d in self.cfg.allowlist_domains]
        self.alerts: OrderedDict[str, dict] = OrderedDict()
        # Alerts from sources the analyst chose to ignore: kept aside (not shown, not counted),
        # and back in `alerts` when the rule goes.
        self.ignored: OrderedDict[str, dict] = OrderedDict()
        self.ignoring = ignore.Matcher([])
        self.alert_ids: dict[str, str] = {}
        self.export_index: dict[str, dict] = {}  # alert id -> {capture, flows}
        self.channels: dict[tuple, Channel] = {}
        self.channels_by_dest: dict[tuple, set] = defaultdict(set)  # (dst_ip, port) -> channel keys
        self.dns_groups: dict[tuple, DnsGroup] = {}
        self.resolved: OrderedDict[str, dict] = OrderedDict()  # ip -> {domain, ts}
        # (name, qtype) -> resolver -> {"answers", "clients", "rec"}: what each resolver says a name is
        self.dns_answers: OrderedDict[tuple, dict] = OrderedDict()
        self.poisoned: dict[str, object] = {}     # address a poisoned answer pointed to -> its (name, qtype)
        self.crafted: OrderedDict[str, dict] = OrderedDict()  # crafted-TCP alert key -> its latest record
        self.compromised: dict[str, dict] = {}    # compromised-device alert key -> its causes, last shown form
        # resolver -> {"public": names answered with public addresses, "never": with impossible ones}
        self.resolver_names: dict[str, dict[str, set]] = {}
        self.devices: OrderedDict[str, dict] = OrderedDict()  # devices described by files seen in traffic
        self.device_by_ip: dict[str, str] = {}
        self.dest_hosts: dict[tuple, dict] = {}   # (dst_ip, port) -> {src_ip: last_seen}
        self.domain_hosts: dict[str, dict] = {}   # registered domain -> {src_ip: last_seen}
        self.scan_vert: dict[tuple, dict] = {}    # (src, dst_ip) -> ports scanned, attempts, failures
        self.scan_horiz: dict[tuple, dict] = {}   # (src, dst_port) -> hosts swept, attempts, failures
        self.dga: dict[str, dict] = {}            # src -> NXDOMAIN registered domains and their entropy
        self.clients: dict[str, float] = {}       # internal hosts seen initiating sessions
        # (client, server, port, service) -> the accounts seen logging in in clear text, and the logins counted
        self.logins: OrderedDict[tuple, dict] = OrderedDict()
        self.captures: set[str] = set()           # capture files announced by engine `hello`s
        self.engine_stats: dict = {}
        self.source: str | None = None
        self.counters = defaultdict(int)
        self.now = 0.0                            # latest capture timestamp seen
        self.started = time.time()
        self._next_id = 1

    # ------------------------------------------------------------ public

    def ingest(self, rec: dict) -> list[dict]:
        """Process one record. Returns alerts created/updated (or {"id", "retracted"} markers)."""
        changed = self._set_aside(self._ingest(rec))  # (an ignored alert implicates no device)
        if changed:
            changed += self._set_aside(self._implicate(changed) + self._absorb_agent_alerts(changed))
        return changed

    def set_ignored(self, rules: list[dict]) -> list[dict]:
        """Apply the ignore rules (anta/ignore.py) to the alerts so far. Returns what the browser
        must change: a retraction for each alert now ignored, and each alert back in view."""
        self.ignoring = ignore.Matcher(rules)
        out: list[dict] = []
        for aid, alert in list(self.alerts.items()):
            if self.ignoring.match(alert) is not None:
                del self.alerts[aid]
                self.ignored[aid] = alert
                out.append({"id": aid, "retracted": True})
        back = [a for a in self.ignored.values() if self.ignoring.match(a) is None]
        for alert in sorted(back, key=lambda a: a.get("last_seen") or 0):
            del self.ignored[alert["id"]]
            self.alerts[alert["id"]] = alert
            out.append(alert)
        return out

    def ignored_counts(self) -> list[int]:
        """How many alerts each ignore rule is holding back (an alert counts for its first rule)."""
        counts = [0] * len(self.ignoring.rules)
        for alert in self.ignored.values():
            i = self.ignoring.match(alert)
            if i is not None:
                counts[i] += 1
        return counts

    def _set_aside(self, changed: list[dict]) -> list[dict]:
        """Alerts from an ignored source leave the shown list (a retraction if it was shown)."""
        if not self.ignoring:
            return changed
        out = []
        for alert in changed:
            if alert.get("retracted") or self.ignoring.match(alert) is None:
                out.append(alert)
                continue
            aid = alert["id"]
            self.alerts.pop(aid, None)
            self.ignored[aid] = alert
            self.ignored.move_to_end(aid)
            while len(self.ignored) > self.cfg.max_alerts:
                old, _ = self.ignored.popitem(last=False)
                self.export_index.pop(old, None)
            out.append({"id": aid, "retracted": True})  # (harmless if the browser never had it)
        return out

    def _known(self, alert_id: str) -> dict | None:
        """An alert by id, shown or ignored."""
        return self.alerts.get(alert_id) or self.ignored.get(alert_id)

    def _ingest(self, rec: dict) -> list[dict]:
        kind = rec.get("type")
        if kind == "hello":
            if isinstance(rec.get("capture"), str) and rec["capture"]:
                self.captures.add(rec["capture"])
            self.source = str(rec.get("source"))[:256]
            return []
        if kind == "stats":
            out = self._check_arp_spoof(rec) if rec.get("final") else []
            self.engine_stats = {k: v for k, v in rec.items() if isinstance(v, (int, float, bool, str))}
            # The capture is over: every host's last buckets can be judged now.
            if rec.get("final"):
                out += self._baseline_alerts(final=True)
            return out
        if kind != "session":
            return []
        try:
            rec = validate_session(rec)
        except (InvalidRecord, TypeError, ValueError) as exc:
            self.counters["invalid"] += 1
            if self.counters["invalid"] <= 5:
                import sys
                print(f"anta: dropping invalid session record: {exc}", file=sys.stderr)
            return []

        self.counters["records"] += 1
        if rec["final"]:
            self.counters["sessions"] += 1
        self.now = max(self.now, rec["end"])
        if self.counters["records"] % 2000 == 0:
            self._expire_state()

        changed: list[dict] = []
        if rec.get("dns"):
            self._learn_dns(rec)
            changed += self._check_dns(rec)
            changed += self._check_dns_answers(rec)
            changed += self._check_dga(rec)
        if rec.get("ftp_data"):
            changed += self._check_ftp(rec)
        if (rec.get("tcp") or {}).get("null_flags"):
            changed += self._check_crafted_tcp(rec)
        if rec["final"]:
            self._observe_session(rec)
            changed += self._baseline_alerts()
        if self._allowlisted(rec):
            self.counters["allowlisted"] += 1
            return changed
        if rec.get("logins"):
            changed += self._check_logins(rec)
        if rec["final"] and rec.get("app_expected") is not None:
            changed += self._check_port_mismatch(rec)
        if rec["final"] and self.intel is not None:
            changed += self._check_intel(rec)
        self._track_prevalence(rec)
        if rec["dst_ip"] in self.poisoned:
            changed += self._poisoned_contact(rec)
        if rec.get("http_files"):
            changed += self._check_downloads(rec)
        if rec.get("smb_files"):
            changed += self._check_smb_files(rec)
        if rec["proto"] == "tcp" and rec.get("stream_head") and rec["dst_port"] in self.cfg.tls_ports:
            changed += self._check_tls_port(rec)
        if rec["dst_port"] not in self.cfg.beacon_ignore_ports and not _not_routable_target(rec["dst_ip"]):
            changed += self._check_beacon(rec)
        if rec["proto"] == "tcp" and rec.get("events"):
            changed += self._check_session(rec)
        if rec["final"] and rec["proto"] == "tcp":
            changed += self._check_scan(rec)
        if self.agent_submit is not None and not changed and rec["final"] and self._agent_candidate(rec):
            self.agent_submit(rec)
        return changed

    # ------------------------------------------------- the detection agent

    def _agent_candidate(self, rec: dict) -> bool:
        """A session for the agent: no detector flagged it, it moved data, few internal hosts
        use its destination, and it isn't routine local service traffic."""
        out_b, in_b = session_bytes(rec)
        if out_b + in_b < self.cfg.agent_min_bytes or _internal_service(rec):
            return False
        if rec["dst_port"] in (53, 67, 68, 123, 137, 138, 1900, 5353, 5355):
            return False
        return self._prevalence(rec["dst_ip"], rec["dst_port"], self._domain_of(rec)) <= self.cfg.exfil_max_hosts

    AGENT_FIELDS = ("verdict", "confidence", "headline", "reasons", "next_steps", "reviewer", "model", "usage",
                    "reviewed_at")

    def _alert_on_pair(self, src: str, dst: str, port: int) -> dict | None:
        """The newest alert from ANTA's own detectors on this host, destination and port."""
        for alert in reversed(self.alerts.values()):
            if alert["kind"] != "agent" and (alert.get("src_ip"), alert.get("dst_ip"), alert.get("dst_port")) == \
                    (src, dst, port):
                return alert
        return None

    def _absorb_agent_alerts(self, changed: list[dict]) -> list[dict]:
        """A detector alerting on a pair the agent flagged first: the agent's verdict moves
        onto that alert and its own row goes (unless the analyst has triaged it)."""
        out = []
        for alert in changed:
            if alert.get("retracted") or alert["kind"] == "agent":
                continue
            key = f"agent:{alert.get('src_ip')}:{alert.get('dst_ip')}:{alert.get('dst_port')}"
            agent = self.alerts.get(self.alert_ids.get(key, ""))
            if agent is None or agent.get("triage"):
                continue
            alert.setdefault("agent_review", agent["agent"])
            out += self._retract(key)
        return out

    def agent_alert(self, rec: dict, verdict: dict) -> dict | None:
        """The agent's verdict on a session: an alert unless it judged the session benign.
        One alert per host and destination: later sessions of the same pair update it. On a
        pair one of ANTA's detectors already alerts on, the verdict goes on that alert."""
        if verdict["verdict"] == "benign":
            self.counters["agent_benign"] += 1
        existing = self._alert_on_pair(rec["src_ip"], rec["dst_ip"], rec["dst_port"])
        if existing is not None:
            existing["agent_review"] = {k: verdict.get(k) for k in self.AGENT_FIELDS}
            return existing
        if verdict["verdict"] == "benign":
            return None
        out_b, in_b = session_bytes(rec)
        m = {"confidence": verdict["confidence"], "src_ip": rec["src_ip"], "dst_ip": rec["dst_ip"],
             "dst_port": rec["dst_port"], "target": f"{rec['dst_ip']}:{rec['dst_port']}",
             "verdict": verdict["verdict"], "reviewer": verdict.get("reviewer"), "bytes_out": out_b, "bytes_in": in_b,
             "duration": rec["end"] - rec["start"], "domain": self._domain_of(rec),
             "hosts": self._prevalence(rec["dst_ip"], rec["dst_port"], self._domain_of(rec))}
        head, details = explain.agent(m, verdict)
        alert = self._alert(f"agent:{rec['src_ip']}:{rec['dst_ip']}:{rec['dst_port']}", "agent", m, head, details,
                            rec["end"], self._throughput(rec), self._session_timeline(rec), self._stream_info(rec),
                            [flow_spec(rec)], rec.get("capture"))
        alert["severity"] = "high" if verdict["verdict"] == "malicious" else "medium"
        alert["agent"] = {k: verdict.get(k) for k in self.AGENT_FIELDS}
        if self._set_aside([alert]) != [alert]:
            return None  # (from an ignored source)
        return alert

    # ------------------------------------------ context: geography, encrypted shape, baselines, apps

    def _geo_of(self, *ips) -> dict:
        """Country and AS of each public address among `ips` (empty without a GeoIP database)."""
        if self.geo is None:
            return {}
        out = {}
        for ip in ips:
            if isinstance(ip, str) and ip and devices.address_kind(ip) == "public":
                g = self.geo.lookup(ip)
                if g:
                    out[ip] = g
        return out

    def _observe_session(self, rec: dict) -> None:
        if eta.is_encrypted(rec):
            verdict = eta.classify(rec)
            row = eta.row(rec, verdict)
            row["geo"] = self._geo_of(rec["dst_ip"]).get(rec["dst_ip"])
            key = f"{rec['flow_id']}:{rec['start']}"
            self.eta[key] = row
            self.eta.move_to_end(key)
            while len(self.eta) > 20_000:
                self.eta.popitem(last=False)
        app = rec.get("app")
        if app:
            for ip, side in ((rec["src_ip"], "uses"), (rec["dst_ip"], "serves")):
                entry = self.host_apps.setdefault(ip, {"uses": {}, "serves": {}})
                if len(entry[side]) < 32 or app in entry[side]:
                    entry[side][app] = entry[side].get(app, 0) + 1
            while len(self.host_apps) > 20_000:
                self.host_apps.pop(next(iter(self.host_apps)))
        self.baselines.observe(rec)

    def _baseline_alerts(self, final: bool = False) -> list[dict]:
        out = []
        for d in self.baselines.judge(self.now, final):
            examples = d["examples"]
            rec = max(examples, key=lambda r: r["c2s"]["bytes"] + r["s2c"]["bytes"]) if examples else None
            if rec is None:
                continue
            m = {"confidence": 0.7 if d["metric"] != "new_app" else 0.6, "src_ip": d["ip"], "dst_ip": rec["dst_ip"],
                 "dst_port": rec["dst_port"], "target": d["ip"], "metric": d["metric"], "text": d["text"],
                 "start": d["start"], "history_min": round(d["history"] * self.baselines.bucket_s / 60),
                 "examples": [f"{e['proto'].upper()} {e['src_ip']}:{e['src_port']} → {e['dst_ip']}:{e['dst_port']}"
                              + (f" ({e['app']})" if e.get("app") else "") for e in examples[:5]]}
            head, details = explain.baseline(m)
            alert = self._alert(f"baseline:{d['ip']}:{d['metric']}", "baseline", m, head, details, rec["end"],
                                self._throughput(rec), self._session_timeline(rec), self._stream_info(rec),
                                [flow_spec(e) for e in examples], rec.get("capture"))
            alert["severity"] = d["severity"]
            out.append(alert)
        return out

    # Remote access, tunnels and proxies: on another service's port, they are how a
    # remote shell gets through a firewall that only lets that service out.
    REMOTE_APPS = {"ssh", "rdp", "vnc", "telnet", "socks", "openvpn", "wireguard", "irc", "smb", "dcerpc", "http-proxy"}

    def _check_port_mismatch(self, rec: dict) -> list[dict]:
        app, expected, port = rec["app"], rec["app_expected"], rec["dst_port"]
        if rec["proto"] == "tcp" and port in self.cfg.tls_ports:
            return []  # the TLS-port detector reads these
        head = rec.get("stream_head") or {}
        sample = ""
        for d in ("c2s", "s2c"):
            try:
                raw = bytes.fromhex(head.get(d) or "")
            except ValueError:
                raw = b""
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in raw).strip(".")
            if len(text) >= 4:
                sample = text
                break
        m = {"confidence": 0.85, "src_ip": rec["src_ip"], "dst_ip": rec["dst_ip"], "dst_port": port,
             "target": f"{rec['dst_ip']}:{port}", "app": rec.get("app_label") or app.upper(),
             "expected": expected.upper(), "sample": sample, "remote": app in self.REMOTE_APPS,
             "bytes": rec["c2s"]["payload_bytes"] + rec["s2c"]["payload_bytes"], "proto": rec["proto"].upper()}
        head_text, details = explain.port_mismatch(m)
        alert = self._alert(f"port_mismatch:{rec['src_ip']}:{rec['dst_ip']}:{port}:{app}", "port_mismatch", m,
                            head_text, details, rec["end"], self._throughput(rec), self._session_timeline(rec),
                            self._stream_info(rec), [flow_spec(rec)], rec.get("capture"))
        alert["severity"] = "high" if app in self.REMOTE_APPS else "medium"
        return [alert]

    def _check_intel(self, rec: dict, kinds: tuple | None = None) -> list[dict]:
        out = []
        for match in self.intel.match_session(rec):
            if kinds and match["kind"] not in kinds:
                continue
            hits = match["hits"]
            feeds = sorted({h["feed"] for h in hits})
            reasons = sorted({h["reason"] for h in hits if h["reason"]})
            kind = match["kind"]
            c2 = any("c2" in h["reason"].lower() or "botnet" in h["reason"].lower() for h in hits)
            if kind == "sha256" or (kind in ("ip", "ip_port", "domain") and (c2 or "feodo" in feeds)):
                severity = "critical"
            elif kind in ("ja3", "ja4"):
                severity = "medium"
            else:
                severity = "high"
            m = {"confidence": 0.95 if severity == "critical" else 0.8 if severity == "high" else 0.5,
                 "src_ip": rec["src_ip"], "dst_ip": rec["dst_ip"], "dst_port": rec["dst_port"],
                 "target": match["value"], "indicator": match["value"], "kind": kind, "where": match["where"],
                 "feeds": [self.intel.meta.get(f, {}).get("name") or intel.SOURCES.get(f, {}).get("name", f)
                           for f in feeds],
                 "reasons": reasons, "first_seen": min((h["first_seen"] for h in hits if h["first_seen"]), default=""),
                 "session": five_tuple(rec)}
            head, details = explain.intel_match(m)
            alert = self._alert(f"intel:{kind}:{match['value']}", "intel_match", m, head, details, rec["end"],
                                self._throughput(rec), self._session_timeline(rec), self._stream_info(rec),
                                [flow_spec(rec)], rec.get("capture"))
            alert["severity"] = severity
            alert["intel"] = {"indicator": match["value"], "kind": kind, "feeds": m["feeds"], "reasons": reasons}
            out.append(alert)
        return out

    def recheck_intel(self, sessions: list[dict]) -> list[dict]:
        """Match sessions already seen against the feeds as they are now (after an update)."""
        if self.intel is None:
            return []
        out = []
        for rec in sessions:
            out += self._check_intel(rec)
        return out

    def check_decrypted(self, sessions: list[dict]) -> list[dict]:
        """Sessions a TLS key log the user loaded made readable: the HTTP inside them is
        checked as plain HTTP is (programs downloaded, threat-feed URLs and file hashes).
        What was visible without the keys (addresses, server names) was checked already."""
        out = []
        for rec in sessions:
            if not (rec.get("tls") or {}).get("decrypted"):
                continue
            if rec.get("http_files"):
                out += self._check_downloads(rec)
            if self.intel is not None:
                out += self._check_intel(rec, ("url", "sha256"))
        return out

    def set_triage(self, alert_id: str, status: str, note: str) -> dict | None:
        alert = self.alerts.get(alert_id)
        if alert is None:
            return None
        if status not in TRIAGE_STATUSES:
            raise ValueError(f"status must be one of {', '.join(TRIAGE_STATUSES)}")
        note = note.strip()[:4000]
        alert["triage"] = None if status == "new" and not note else {"status": status, "note": note, "ts": time.time()}
        return alert

    def summary(self) -> dict:
        by_sev = defaultdict(int)
        for a in self.alerts.values():
            by_sev[a["severity"]] += 1
        return {
            "sessions": self.counters["sessions"],
            "records": self.counters["records"],
            "invalid_records": self.counters["invalid"],
            "alerts": len(self.alerts),
            "ignored": len(self.ignored),
            "by_severity": dict(by_sev),
            "channels": len(self.channels),
            "engine": self.engine_stats,
            "source": self.source,
            "model": bool(self.model),
            "detector": self.model.name if self.model else "Detection agent" if self.agent_submit else None,
            "uptime": time.time() - self.started,
        }

    # ---------------------------------------------------- context state

    def _domain_of(self, rec: dict) -> str | None:
        tls = rec.get("tls") or {}
        if tls.get("sni"):
            return tls["sni"].lower()
        http = (rec.get("http") or [{}])[0]
        if http.get("host"):
            return http["host"].split(":")[0].lower()
        ctx = self.resolved.get(rec["dst_ip"])
        return ctx["domain"] if ctx else None

    def _domain_allowed(self, name: str | None) -> bool:
        if not name or not self._allow_domains:
            return False
        name = name.lower().rstrip(".")
        return any(name == d or name.endswith("." + d) for d in self._allow_domains)

    def _allowlisted(self, rec: dict) -> bool:
        if self._allow_nets:
            addr = ipaddress.ip_address(rec["dst_ip"])
            if any(addr in net for net in self._allow_nets):
                return True
        return self._domain_allowed(self._domain_of(rec))

    def _track_prevalence(self, rec: dict) -> None:
        src, t = rec["src_ip"], rec["end"]
        self.clients[src] = t
        hosts = self.dest_hosts.setdefault((rec["dst_ip"], rec["dst_port"]), {})
        if len(hosts) < 2048 or src in hosts:
            hosts[src] = t
        domain = self._domain_of(rec)
        if domain:
            dh = self.domain_hosts.setdefault(registered_domain(domain), {})
            if len(dh) < 2048 or src in dh:
                dh[src] = t

    def _prevalence(self, dst_ip: str, dst_port: int, domain: str | None) -> int:
        n = len(self.dest_hosts.get((dst_ip, dst_port), ()))
        if domain:
            n = max(n, len(self.domain_hosts.get(registered_domain(domain), ())))
        return n

    def _is_shared(self, prevalence: int) -> bool:
        return prevalence >= max(self.cfg.shared_min_hosts, self.cfg.shared_min_fraction * len(self.clients))

    def _expire_state(self) -> None:
        cutoff = self.now - self.cfg.state_ttl_s
        for key in [k for k, c in self.channels.items() if c.last_seen < cutoff]:
            del self.channels[key]
            dest = self.channels_by_dest.get((key[1], key[2]))
            if dest is not None:
                dest.discard(key)
                if not dest:
                    del self.channels_by_dest[(key[1], key[2])]
        for key in [k for k, g in self.dns_groups.items() if g.last_seen < cutoff]:
            del self.dns_groups[key]
        for table in (self.dest_hosts, self.domain_hosts):
            for key in list(table):
                hosts = table[key]
                for h in [h for h, t in hosts.items() if t < cutoff]:
                    del hosts[h]
                if not hosts:
                    del table[key]
        for h in [h for h, t in self.clients.items() if t < cutoff]:
            del self.clients[h]
        for table in (self.scan_vert, self.scan_horiz):
            for key in [k for k, v in table.items() if v["last"] < cutoff]:
                del table[key]
        for src in [s for s, v in self.dga.items() if v["last"] < cutoff]:
            del self.dga[src]
        live = set(self.alerts) | set(self.ignored)
        for key in [k for k, v in self.alert_ids.items() if v not in live]:
            del self.alert_ids[key]

    # ---------------------------------------------------------- alerts

    def _alert(self, key: str, kind: str, metrics: dict, head: str, details: list, rec_time: float,
               chart: dict, timeline: list, stream: dict, flows: list, capture: str | None) -> dict:
        alert_id = self.alert_ids.get(key)
        if alert_id is None:
            alert_id = f"A{self._next_id:05d}"
            self._next_id += 1
            self.alert_ids[key] = alert_id
        prev = self._known(alert_id)
        exportable_capture = capture if capture and capture in self.captures else None
        alert = {
            "id": alert_id,
            "kind": kind,
            "severity": SEVERITY[kind],
            "title": TITLES[kind],
            "headline": head,
            "details": details,
            "confidence": round(float(metrics["confidence"]), 3),
            "src_ip": metrics.get("src_ip"),
            "dst_ip": metrics.get("dst_ip"),
            "dst_port": metrics.get("dst_port"),
            "target": metrics.get("target"),
            "hosts": metrics.get("hosts"),
            "first_seen": prev["first_seen"] if prev else rec_time,
            "last_seen": max(rec_time, prev["last_seen"]) if prev else rec_time,
            "updates": (prev["updates"] + 1) if prev else 1,
            "chart": chart,
            "timeline": timeline[-300:],
            "timeline_total": len(timeline),
            "stream": stream,
            "exportable": bool(exportable_capture and flows),
            "export_flows": len(flows[-400:]),
            "metrics": {k: v for k, v in metrics.items() if isinstance(v, (int, float, str)) or v is None},
        }
        for kept in ("triage", "agent_review"):  # an update keeps the analyst's verdict and the agent's
            if prev and prev.get(kept):
                alert[kept] = prev[kept]
        geo = self._geo_of(metrics.get("src_ip"), metrics.get("dst_ip"))
        if geo:
            alert["geo"] = geo
        self.alerts[alert_id] = alert
        self.alerts.move_to_end(alert_id)
        self.export_index[alert_id] = {"capture": exportable_capture, "flows": flows[-400:]}
        while len(self.alerts) > self.cfg.max_alerts:
            old, _ = self.alerts.popitem(last=False)
            self.export_index.pop(old, None)
        return alert

    def _retract(self, key: str) -> list[dict]:
        alert_id = self.alert_ids.pop(key, None)
        if alert_id and self.alerts.pop(alert_id, None) is not None:
            self.export_index.pop(alert_id, None)
            return [{"id": alert_id, "retracted": True}]
        if alert_id and self.ignored.pop(alert_id, None) is not None:
            self.export_index.pop(alert_id, None)
        return []

    def _dns_context(self, ip: str) -> list[str]:
        r = self.resolved.get(ip)
        return [r["domain"]] if r else []

    def _stream_info(self, rec: dict, flows: int = 1, bytes_out=None, bytes_in=None, packets=None,
                     duration=None) -> dict:
        out_b, in_b = session_bytes(rec)
        tls = rec.get("tls") or {}
        http = (rec.get("http") or [{}])[0]
        return {
            "five_tuple": five_tuple(rec),
            "proto": rec["proto"],
            "src": f"{rec['src_ip']}:{rec['src_port']}",
            "dst": f"{rec['dst_ip']}:{rec['dst_port']}",
            "flows": flows,
            "bytes_out": bytes_out if bytes_out is not None else out_b,
            "bytes_in": bytes_in if bytes_in is not None else in_b,
            "packets": packets if packets is not None else rec["c2s"]["packets"] + rec["s2c"]["packets"],
            "duration": duration if duration is not None else rec["end"] - rec["start"],
            "ja3": tls.get("ja3"),
            "ja3_string": tls.get("ja3_string"),
            "ja4": tls.get("ja4"),
            "sni": tls.get("sni"),
            "alpn": tls.get("alpn"),
            "http": {k: http.get(k) for k in ("method", "host", "uri", "user_agent")} if http else None,
            "http_status": (rec.get("http_response") or {}).get("status"),
            "dns_context": self._dns_context(rec["dst_ip"]),
            "tcp": rec.get("tcp"),
            "payload_entropy": rec.get("payload_entropy"),
        }

    # -------------------------------------------------------------- DNS

    def _learn_dns(self, rec: dict) -> None:
        for q in rec["dns"]:
            for ans in q.get("answers", []):
                try:
                    ip = str(ipaddress.ip_address(ans))  # canonical form, as flow records use
                except ValueError:
                    continue
                self.resolved[ip] = {"domain": q["qname"], "ts": rec["start"]}
                self.resolved.move_to_end(ip)
        while len(self.resolved) > 50_000:
            self.resolved.popitem(last=False)

    def _dns_allowed(self, domain: str) -> bool:
        return any(domain == d or domain.endswith("." + d) for d in self.cfg.dns_allowlist) or \
            self._domain_allowed(domain)

    def _check_dns(self, rec: dict) -> list[dict]:
        touched = set()
        for idx, q in enumerate(rec["dns"]):
            qname = q["qname"].lower().rstrip(".")
            domain = registered_domain(qname)
            if not qname or domain == qname or self._dns_allowed(domain):
                continue
            key = (rec["src_ip"], domain)
            g = self.dns_groups.get(key)
            if g is None:
                if len(self.dns_groups) > 200_000:
                    continue
                g = self.dns_groups[key] = DnsGroup(rec["src_ip"], domain)
            sub = qname[: -len(domain) - 1]
            g.queries[(rec["flow_id"], qname, idx)] = {
                "t": rec["start"], "sub": sub, "qtype": q["qtype"], "txt": q.get("txt_bytes", 0),
                "entropy": string_entropy(sub.replace(".", "")),
            }
            while len(g.queries) > 2000:
                g.queries.popitem(last=False)
            if len(g.resolvers) < 16:
                g.resolvers.add(rec["dst_ip"])
            g.specs[flow_spec(rec)] = True
            while len(g.specs) > 400:
                g.specs.popitem(last=False)
            g.last_seen = rec["end"]
            touched.add(key)

        alerts = []
        for key in touched:
            g = self.dns_groups[key]
            qs = list(g.queries.values())
            if len(qs) < self.cfg.dns_min_queries:
                continue
            subs = [q["sub"] for q in qs]
            unique = len(set(subs))
            mean_len = float(np.mean([len(s) for s in subs]))
            mean_entropy = float(np.mean([q["entropy"] for q in qs]))
            txt_ratio = sum(1 for q in qs if q["qtype"] == 16) / len(qs)
            if mean_entropy < self.cfg.dns_min_entropy or mean_len < self.cfg.dns_min_len:
                continue
            if unique / len(qs) < 0.5:  # repeated identical names are caching, not tunneling
                continue
            score = (min(1, (mean_entropy - 3.0) / 1.5) * 0.45 + min(1, mean_len / 50) * 0.3
                     + min(1, len(qs) / 100) * 0.15 + txt_ratio * 0.1)
            m = {
                "confidence": min(0.99, 0.4 + score * 0.6), "src_ip": g.src_ip, "domain": g.domain,
                "target": g.domain, "dst_ip": next(iter(g.resolvers)), "dst_port": 53,
                "queries": len(qs), "unique": unique, "mean_len": mean_len, "mean_entropy": mean_entropy,
                "txt_ratio": txt_ratio, "txt_bytes": sum(q["txt"] for q in qs),
                "qname_bytes": sum(len(s) for s in subs), "span": qs[-1]["t"] - qs[0]["t"],
                "resolvers": sorted(g.resolvers), "sample": f"{subs[-1]}.{g.domain}",
            }
            head, details = explain.dns_tunnel(m)
            chart = {"kind": "entropy_histogram", "title": "Subdomain entropy per query (bits/char)",
                     "values": [round(q["entropy"], 3) for q in qs[-500:]], "baseline": 3.0,
                     "unit": "bits/char"}
            timeline = [{"t": q["t"], "out": len(q["sub"]), "in": q["txt"], "label": q["sub"][:40]} for q in qs]
            stream = self._stream_info(rec, flows=len(g.specs))
            stream.update({"dns_queries": [f"{s}.{g.domain}" for s in subs[-12:]],
                           "dns_context": [g.domain], "bytes_out": m["qname_bytes"], "bytes_in": m["txt_bytes"],
                           "duration": m["span"], "packets": len(qs) * 2})
            alerts.append(self._alert(f"dns:{g.src_ip}:{g.domain}", "dns_tunnel", m, head, details, rec["end"],
                                      chart, timeline, stream, list(g.specs), rec.get("capture")))
        return alerts

    # ----------------------------------------------------------- beacon

    @staticmethod
    def _regularity(values: np.ndarray, mad_scale: float) -> tuple[float, float, float]:
        """RITA-style regularity: (score, bowley_skew, mad/median) of a sample."""
        q1, q2, q3 = np.percentile(values, [25, 50, 75])
        bowley = float((q1 + q3 - 2 * q2) / (q3 - q1)) if q3 > q1 else 0.0
        madm = float(np.median(np.abs(values - q2)) / q2) if q2 > 0 else 1.0
        return ((1 - abs(bowley)) + max(0.0, 1 - madm / mad_scale)) / 2, bowley, madm

    def _check_beacon(self, rec: dict) -> list[dict]:
        key = (rec["src_ip"], rec["dst_ip"], rec["dst_port"], rec["proto"])
        ch = self.channels.get(key)
        if ch is None:
            if len(self.channels) > 200_000:
                return []
            ch = self.channels[key] = Channel(rec["src_ip"], rec["dst_ip"], rec["dst_port"], rec["proto"])
            self.channels_by_dest[(rec["dst_ip"], rec["dst_port"])].add(key)
        out_b, in_b = session_bytes(rec)
        http = (rec.get("http") or [None])[0]
        ch.flows[rec["flow_id"]] = FlowSummary(
            flow_spec(rec), rec["start"], rec["end"], bursts(rec)[:1000], out_b, in_b,
            rec["c2s"]["packets"] + rec["s2c"]["packets"], rec.get("tls"), http, self._stream_info(rec))
        ch.flows.move_to_end(rec["flow_id"])
        ch.last_seen = rec["end"]
        while len(ch.flows) > self.cfg.max_flows_per_channel:
            ch.flows.popitem(last=False)

        verdict = self._beacon_verdict(ch)
        ch.periodic = verdict
        beacon_key = f"beacon:{key}"
        if verdict is None:
            return []

        domain = self._domain_of(rec)
        prevalence = self._prevalence(ch.dst_ip, ch.dst_port, domain)
        if self._is_shared(prevalence):
            # Many hosts, same cadence: fold into one low-severity destination alert.
            return self._retract(beacon_key) + self._shared_alert(ch, domain, rec)

        m, chart, timeline, stream, flows = verdict
        m = dict(m, domain=(self._dns_context(ch.dst_ip) or [None])[0], hosts=prevalence)
        head, details = explain.beacon(m)
        return [self._alert(beacon_key, "beacon", m, head, details, rec["end"], chart, timeline, stream, flows,
                            rec.get("capture"))]

    def _beacon_verdict(self, ch: Channel):
        all_bursts = sorted(b for f in ch.flows.values() for b in f.bursts)
        if len(all_bursts) < self.cfg.beacon_min_events:
            return None
        times = np.array([b[0] for b in all_bursts])
        span = float(times[-1] - times[0])
        if span < self.cfg.beacon_min_span_s:
            return None
        intervals = np.diff(times)
        median = float(np.median(intervals))
        if median < self.cfg.beacon_min_period_s:
            return None

        # Missed or extra check-ins shouldn't hide a beacon: score the intervals
        # near the dominant period, and how many of them there are.
        near = (intervals > 0.5 * median) & (intervals < 1.5 * median)
        presence = float(near.mean())
        kept = intervals[near]
        if len(kept) < self.cfg.beacon_min_events - 1:
            return None
        ts_score, bowley, madm = self._regularity(kept, mad_scale=0.25)
        timing = (2 * ts_score + presence) / 3

        outs = np.array([b[1] for b in all_bursts], dtype=float)
        ins = np.array([b[2] for b in all_bursts], dtype=float)
        size_score = self._regularity(outs, mad_scale=0.5)[0] if np.median(outs) > 0 else 0.5
        score = 0.75 * timing + 0.25 * size_score
        if timing < 0.75 or score < self.cfg.beacon_score_threshold:
            return None

        _, std, cv = jitter(kept)
        p5, p95 = np.percentile(kept, [5, 95])
        evidence = min(1.0, len(kept) / 20)
        confidence = min(0.99, score) * (0.8 + 0.2 * evidence)
        median_in = float(np.median(ins))
        tasking = int(np.sum(ins > max(4 * median_in, median_in + 1000)))
        mode = "connections" if len(ch.flows) >= 0.5 * len(all_bursts) else "persistent"
        last = next(reversed(ch.flows.values()))
        tls = next((f.tls for f in reversed(ch.flows.values()) if f.tls), None) or {}
        http = next((f.http for f in reversed(ch.flows.values()) if f.http), None) or {}
        m = {
            "confidence": confidence, "score": score, "timing_score": timing, "size_score": size_score,
            "src_ip": ch.src_ip, "dst_ip": ch.dst_ip, "dst_port": ch.dst_port,
            "target": f"{ch.dst_ip}:{ch.dst_port}", "period": median, "std": std, "cv": cv,
            "jitter_pct": float((p95 - p5) / (2 * median) * 100), "skew": bowley, "madm": madm,
            "presence": presence, "count": len(all_bursts), "span": span, "mode": mode,
            "size_cv": float(outs.std() / outs.mean()) if outs.mean() > 0 else 0.0,
            "median_out": float(np.median(outs)), "median_in": median_in, "tasking": tasking,
            "ja3": tls.get("ja3"), "sni": tls.get("sni"), "user_agent": http.get("user_agent"),
        }
        chart = {"kind": "iat_histogram", "title": "Inter-arrival time between check-ins",
                 "values": [round(float(v), 4) for v in intervals[-500:]], "period": median, "unit": "s"}
        timeline = [{"t": float(b[0]), "out": int(b[1]), "in": int(b[2])} for b in all_bursts]
        first = next(iter(ch.flows.values())).start
        stream = dict(last.stream)
        stream.update({
            "flows": len(ch.flows),
            "bytes_out": int(sum(f.bytes_out for f in ch.flows.values())),
            "bytes_in": int(sum(f.bytes_in for f in ch.flows.values())),
            "packets": int(sum(f.packets for f in ch.flows.values())),
            "duration": ch.last_seen - first,
        })
        if tls:
            stream.update({k: tls.get(k) for k in ("ja3", "ja3_string", "ja4", "sni", "alpn")})
        flows = [f.spec for f in ch.flows.values()]
        return m, chart, timeline, stream, flows

    def _shared_alert(self, ch: Channel, domain: str | None, rec: dict) -> list[dict]:
        """One low-severity alert per destination listing every periodic client."""
        periodic = [c for k in self.channels_by_dest.get((ch.dst_ip, ch.dst_port), ())
                    if (c := self.channels.get(k)) is not None and c.periodic]
        if not periodic:
            return []
        hosts = sorted({c.src_ip for c in periodic})
        periods = [c.periodic[0]["period"] for c in periodic]
        prevalence = self._prevalence(ch.dst_ip, ch.dst_port, domain)
        m = {"confidence": 0.5, "src_ip": f"{len(hosts)} hosts", "dst_ip": ch.dst_ip, "dst_port": ch.dst_port,
             "target": f"{ch.dst_ip}:{ch.dst_port}", "hosts": len(hosts), "clients": len(self.clients),
             "prevalence": prevalence, "period": float(np.median(periods)), "domain": domain,
             "host_list": ", ".join(hosts[:12]) + ("…" if len(hosts) > 12 else "")}
        head, details = explain.shared(m)
        _, chart, _, stream, _ = periodic[-1].periodic
        timeline = sorted(({"t": float(b[0]), "out": int(b[1]), "in": int(b[2])}
                           for c in periodic for f in c.flows.values() for b in f.bursts), key=lambda e: e["t"])
        flows = [f.spec for c in periodic for f in c.flows.values()]
        return [self._alert(f"shared:{ch.dst_ip}:{ch.dst_port}", "shared", m, head, details, rec["end"], chart,
                            timeline, stream, flows, rec.get("capture"))]

    # ------------------------------------------------- downloaded files

    def _trusted_download(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(host == d or host.endswith("." + d) for d in self.cfg.download_trusted_domains)

    def _check_downloads(self, rec: dict) -> list[dict]:
        out = []
        https = bool((rec.get("tls") or {}).get("decrypted"))  # HTTPS the user's key log decrypted
        scheme, default_port = ("https", 443) if https else ("http", 80)
        standard_ports = self.cfg.download_tls_ports if https else self.cfg.download_standard_ports
        for f in rec["http_files"]:
            if not 200 <= f["status"] < 300:
                continue
            name = filetypes.name_of(f["uri"], f["filename"])
            ext = filetypes.extension(name)
            desc, kind = filetypes.describe(f["magic"])
            risky_name = ext in filetypes.EXEC_EXT | filetypes.SCRIPT_EXT | filetypes.MACRO_EXT
            if kind not in ("executable", "script") and not risky_name:
                continue
            host = f["host"] or (https and (rec.get("tls") or {}).get("sni")) or \
                (f"{rec['dst_ip']}:{rec['dst_port']}" if rec["dst_port"] != default_port else rec["dst_ip"])
            hostname = "" if filetypes.is_ip_host(host) else host.rsplit(":", 1)[0].lower()
            agent = f["user_agent"]
            ctype = (f["content_type"] or "").split(";")[0].strip().lower()
            strong: list[str] = []
            if not hostname:
                strong.append(f"It came from a bare IP address ({rec['dst_ip']}), not a domain name.")
            if rec["dst_port"] not in standard_ports:
                strong.append(f"It was served on unusual TCP port {rec['dst_port']}, not a standard web port.")
            if agent and filetypes.SCRIPTED_AGENTS.search(agent):
                strong.append(f"It was fetched by a command-line tool (User-Agent \"{agent[:80]}\"), as droppers "
                              "and scripts do, not by a browser.")
            if kind in ("executable", "script") and ext and not risky_name:
                strong.append(f"Its name \"{name}\" hides that it is a {desc}.")
            if kind == "executable" and ctype and ctype not in filetypes.EXEC_TYPES and not ctype.startswith("binary/"):
                strong.append(f"The server labelled it {ctype}, although it is a {desc}.")
            if hostname and self._trusted_download(hostname) and not strong:
                continue  # vendor updates and certificates
            if kind not in ("executable", "script") and ext in filetypes.WEAK_EXT and not strong:
                continue  # a web page's script, most likely
            domain = hostname or (self._dns_context(rec["dst_ip"]) or [None])[0]
            prevalence = self._prevalence(rec["dst_ip"], rec["dst_port"], domain)
            severity = "critical" if len(strong) >= 2 else "high" if strong else "medium"
            url = f"{scheme}://{host}{f['uri']}" if f["uri"] else f"{scheme}://{host}/"
            m = {"confidence": min(0.98, 0.6 + 0.1 * len(strong) + (0.05 if prevalence <= 1 else 0)),
                 "src_ip": rec["src_ip"], "dst_ip": rec["dst_ip"], "dst_port": rec["dst_port"],
                 "target": f"{rec['dst_ip']}:{rec['dst_port']}", "hosts": prevalence, "url": url, "name": name,
                 "file_type": desc or f".{ext} file", "size": f["size"], "sha256": f["sha256"],
                 "content_type": ctype, "user_agent": agent, "complete": f["complete"], "indicators": strong,
                 "domain": domain, "decrypted": https}
            head, details = explain.download(m)
            alert = self._alert(f"download:{rec['src_ip']}:{f['sha256']}", "download", m, head, details,
                                rec["end"], self._throughput(rec), self._session_timeline(rec), self._stream_info(rec),
                                [flow_spec(rec)], rec.get("capture"))
            alert["severity"] = severity
            alert["file"] = {"name": name, "url": url, "sha256": f["sha256"], "size": f["size"],
                             "type": desc or (f".{ext} file" if ext else "file"), "content_type": ctype,
                             "complete": f["complete"], "decoded": bool(f.get("encoded_size"))}
            out.append(alert)
        return out

    # ------------------------------------------ programs copied over SMB

    def _check_smb_files(self, rec: dict) -> list[dict]:
        """Programs and scripts read from or written to a Windows file share. Writing one
        to an administrative share (ADMIN$, C$) is how PsExec-style tools move laterally."""
        out = []
        for f in rec["smb_files"]:
            path = f["name"].replace("/", "\\")
            name = path.rsplit("\\", 1)[-1]
            ext = filetypes.extension(name)
            desc, kind = filetypes.describe(f["magic"])
            risky_name = ext in filetypes.EXEC_EXT | filetypes.SCRIPT_EXT | filetypes.MACRO_EXT
            if kind not in ("executable", "script") and not risky_name:
                continue
            share = f["share"]
            share_name = share.rstrip("\\").rsplit("\\", 1)[-1].upper()
            admin = share_name.endswith("$") and share_name != "IPC$"
            write = f["op"] == "write"
            hidden = kind in ("executable", "script") and bool(ext) and not risky_name
            if not write and share_name in ("SYSVOL", "NETLOGON") and kind != "executable" and \
                    ext not in filetypes.EXEC_EXT:
                continue  # logon scripts and group policy: every domain member reads these
            indicators: list[str] = []
            if write and admin:
                indicators.append(f"It was written to the administrative share {share}: how PsExec and similar "
                                  "tools put a program on another machine to run it as a service.")
            elif write:
                indicators.append(f"It was uploaded to the share {share}.")
            if hidden:
                indicators.append(f"Its name \"{name}\" hides that it is a {desc}.")
            severity = "critical" if write and admin else "high" if write or hidden else "medium"
            location = share.rstrip("\\") + "\\" + path.lstrip("\\")
            m = {"confidence": 0.95 if write and admin else 0.8 if severity == "high" else 0.6,
                 "src_ip": rec["src_ip"], "dst_ip": rec["dst_ip"], "dst_port": rec["dst_port"],
                 "target": f"{rec['dst_ip']}:{rec['dst_port']}", "name": name, "location": location, "share": share,
                 "op": f["op"], "admin_share": admin, "file_type": desc or f".{ext} file", "size": f["size"],
                 "sha256": f["sha256"], "complete": f["complete"], "indicators": indicators}
            head, details = explain.smb_file(m)
            alert = self._alert(f"smb_file:{rec['src_ip']}:{rec['dst_ip']}:{f['sha256'] or location}", "smb_file", m,
                                head, details, rec["end"], self._throughput(rec), self._session_timeline(rec),
                                self._stream_info(rec), [flow_spec(rec)], rec.get("capture"))
            alert["severity"] = severity
            alert["file"] = {"name": name, "url": location, "sha256": f["sha256"], "size": f["size"],
                             "type": desc or (f".{ext} file" if ext else "file"), "content_type": "",
                             "complete": f["complete"], "decoded": False}
            out.append(alert)
        return out

    # ------------------------------------------ poisoned DNS answers

    _LOCAL_SUFFIXES = (".local", ".lan", ".home.arpa", ".internal", ".localdomain", ".arpa", ".corp", ".home",
                       ".lab", ".test", ".example", ".invalid", ".localhost")  # and RFC 6761's special-use names

    def _check_dns_answers(self, rec: dict) -> list[dict]:
        """A resolver answering a name with an address no real host can have (or that
        contradicts every other resolver) is lying to its clients: that device is the
        attacker's, whatever else it does."""
        if rec["dst_port"] != 53:
            return []
        resolver, client = rec["dst_ip"], rec["src_ip"]
        out = []
        for q in rec["dns"]:
            if q.get("qtype") not in (1, 28) or not q.get("answers"):
                continue
            name = q["qname"].lower().rstrip(".")
            if "." not in name or name.endswith(self._LOCAL_SUFFIXES):
                continue
            addrs = []
            for a in q["answers"]:
                try:
                    addrs.append(str(ipaddress.ip_address(a)))
                except ValueError:
                    continue
            if not addrs:
                continue
            key = (name, q["qtype"])
            entry = self.dns_answers.get(key)
            if entry is None:
                entry = self.dns_answers[key] = {}
                while len(self.dns_answers) > 20_000:
                    self.dns_answers.popitem(last=False)
            r = entry.setdefault(resolver, {"answers": set(), "clients": set(), "rec": rec})
            r["answers"].update(addrs[:16])
            seen = self.resolver_names.setdefault(resolver, {"public": set(), "never": set()})
            kinds = {devices.address_kind(a) for a in addrs}
            for bucket, hit in (("public", "public" in kinds), ("never", bool(kinds & devices.NEVER_VALID))):
                if hit and len(seen[bucket]) < 5000:
                    seen[bucket].add(name)
            r["clients"].add(client)
            r["rec"] = rec
            out += self._judge_dns(name, q["qtype"], entry)
        return out

    def _judge_dns(self, name: str, qtype: int, entry: dict) -> list[dict]:
        out = []
        for resolver, r in entry.items():
            kinds = {a: devices.address_kind(a) for a in r["answers"]}
            bad = sorted(a for a, k in kinds.items() if k != "public")
            if not bad:
                continue
            others = {res: sorted(o["answers"]) for res, o in entry.items() if res != resolver}
            other_public = sorted({a for o in others.values() for a in o if devices.address_kind(a) == "public"})
            own_public = sorted(a for a, k in kinds.items() if k == "public")
            never = [a for a in bad if kinds[a] in devices.NEVER_VALID]
            sink = [a for a in bad if kinds[a] in devices.SINKHOLE]
            if never and other_public:
                severity, confidence = "critical", 0.97   # impossible address, contradicted by other resolvers
            elif never and own_public:
                severity, confidence = "high", 0.85       # the same resolver answered it truthfully too
            elif other_public and not sink:
                severity, confidence = "medium", 0.6      # internal address vs public: split DNS, or redirection
            elif other_public:
                severity, confidence = "low", 0.4         # blocked here, resolved elsewhere: a filtering resolver
            elif never and self._real_resolver(resolver):
                severity, confidence = "low", 0.5         # an impossible address from a resolver that's otherwise real
            else:
                continue                                  # an internal name, or a filtering resolver
            key = f"dns_poison:{resolver}:{name}:{qtype}"
            for a in bad:
                self.poisoned[a] = (name, qtype)
            out += self._escalate_crafted(bad)
            rec = r["rec"]
            m = {"confidence": confidence, "src_ip": resolver, "dst_ip": sorted(r["clients"])[0], "dst_port": 53,
                 "target": sorted(r["clients"])[0], "name": name, "qtype": "AAAA" if qtype == 28 else "A",
                 "resolver": resolver, "bad": bad, "kinds": {a: kinds[a] for a in bad}, "clients": sorted(r["clients"]),
                 "others": others, "own_public": own_public, "contacts": self._contacts(bad)}
            head, details = explain.dns_poison(m)
            alert = self._alert(key, "dns_poison", m, head, details, rec["end"], self._throughput(rec),
                                self._session_timeline(rec), self._stream_info(rec), [flow_spec(rec)],
                                rec.get("capture"))
            alert["severity"] = severity
            alert["offender"] = resolver
            alert["victims"] = sorted(r["clients"])
            alert["dns"] = {"name": name, "qtype": m["qtype"], "answers": bad, "others": others}
            self._attach_device(alert)
            out.append(alert)
        return out

    def _real_resolver(self, resolver: str) -> bool:
        """Mostly real answers: not a lab whose resolver hands out documentation addresses for everything."""
        seen = self.resolver_names.get(resolver) or {"public": set(), "never": set()}
        return len(seen["public"]) >= 4 * max(1, len(seen["never"]))

    def _contacts(self, addrs: list[str]) -> list[str]:
        """Who connected to these addresses: '192.168.3.89 -> 203.0.113.108:14159'."""
        out = []
        for (dst, port), srcs in self.dest_hosts.items():
            if dst in addrs:
                out += [f"{s} -> {dst}:{port}" for s in sorted(srcs)]
        return out[:20]

    def _poisoned_contact(self, rec: dict) -> list[dict]:
        """Someone connected to an address a false answer pointed to: say so on that alert."""
        ref = self.poisoned[rec["dst_ip"]]
        if isinstance(ref, tuple):  # an answer seen on the wire: judge it again, contacts included
            entry = self.dns_answers.get(ref)
            return self._judge_dns(ref[0], ref[1], entry) if entry else []
        alert = self._known(self.alert_ids.get(ref, ""))
        line = f"Connection to the false address: {rec['src_ip']} -> {rec['dst_ip']}:{rec['dst_port']}."
        if not alert or line in alert["details"]:
            return []
        alert["details"] = alert["details"] + [line]
        alert["updates"] += 1
        return [alert]

    # ------------------------------------------ ARP spoofing (LAN MITM)

    # Virtual-router protocols share one IP between real routers with a well-known
    # virtual MAC, so a second MAC for that IP is expected, not an attack.
    _VIRTUAL_MAC_PREFIXES = ("00:00:5e:00:01", "00:00:5e:00:02",  # VRRP (IPv4/IPv6), CARP
                             "00:00:0c:07:ac", "00:00:0c:9f",     # HSRP v1, v2
                             "00:07:b4:00:01")                    # GLBP

    @classmethod
    def _virtual_mac(cls, mac: str) -> bool:
        return mac.lower().startswith(cls._VIRTUAL_MAC_PREFIXES)

    def _check_arp_spoof(self, stats: dict) -> list[dict]:
        """An IP address claimed over ARP by more than one hardware address is ARP cache
        poisoning: an attacker telling the LAN that the victim's IP (often the gateway)
        is at the attacker's MAC, so traffic for it is delivered to the attacker instead.
        Nearly nothing else does this, so it is reported with high confidence. The engine
        lists each conflicted IP and the MACs that claimed it in the final stats record."""
        conflicts = stats.get("arp_conflicts")
        if not isinstance(conflicts, list):
            return []
        # A MAC appearing for several conflicted IPs is the likely spoofer: a real host
        # owns one address, an attacker answers for the gateway and others.
        claims: dict[str, set[str]] = defaultdict(set)
        cleaned = []
        for c in conflicts:
            ip = c.get("ip")
            macs = [m for m in (c.get("macs") or []) if isinstance(m, str) and not self._virtual_mac(m)]
            if not isinstance(ip, str) or len(macs) < 2:
                continue
            try:
                if not ipaddress.ip_address(ip).is_private:
                    continue   # ARP is link-local; a public IP here is noise, not a LAN attack
            except ValueError:
                continue
            for mac in macs:
                claims[mac].add(ip)
            cleaned.append((ip, macs))
        out = []
        for ip, macs in cleaned:
            owners = {mac: "" for mac in sorted(macs)}
            ranked = sorted(macs, key=lambda mc: (-len(claims[mc]), mc))
            spoofer = ranked[0] if len(claims[ranked[0]]) > 1 else None
            extra = sorted(claims[spoofer] - {ip}) if spoofer else []
            confidence = 0.95 if spoofer and extra else 0.8
            m = {"confidence": confidence, "src_ip": ip, "dst_ip": None, "dst_port": None,
                 "target": ip, "ip": ip, "owners": owners, "spoofer": spoofer, "also_claims": extra,
                 "hosts": len(owners)}
            head, details = explain.arp_spoof(m)
            alert = self._alert(f"arp_spoof:{ip}", "arp_spoof", m, head, details, self.now,
                                {"kind": "arp"}, [], {}, [], None)
            if spoofer:
                alert["offender"] = spoofer
            out.append(alert)
        return out

    # ------------------------------------------ port / host scanning

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _check_scan(self, rec: dict) -> list[dict]:
        """A source making many connection attempts that rarely complete a handshake —
        across many ports of one host (vertical) or many hosts on one port (horizontal) —
        is scanning. A SYN scan never finishes the handshake even on an open port, so a
        high no-handshake fraction over many distinct targets is the signal; ordinary
        fan-out completes its handshakes and stays far below the failure threshold."""
        tcp = rec.get("tcp") or {}
        src, dst, port = rec["src_ip"], rec["dst_ip"], rec["dst_port"]
        if not port or _not_routable_target(dst) or dst == src:
            return []
        failed = not tcp.get("handshake")
        out = self._scan_side(self.scan_vert, (src, dst), "ports", port, failed, rec, "vertical")
        out += self._scan_side(self.scan_horiz, (src, port), "hosts", dst, failed, rec, "horizontal")
        return out

    def _scan_side(self, table: dict, key: tuple, field: str, target, failed: bool, rec: dict, kind: str) -> list[dict]:
        st = table.get(key)
        if st is None:
            if len(table) >= 20_000:  # keep the most recent; drop the stalest quarter
                for k in sorted(table, key=lambda k: table[k]["last"])[:5_000]:
                    del table[k]
            st = table[key] = {field: set(), "priv": set(), "attempts": 0, "failed": 0,
                               "last": rec["end"], "examples": [], "alerted": False}
        st["last"] = rec["end"]
        st["attempts"] += 1
        st["failed"] += int(failed)
        if len(st[field]) < 100_000:
            st[field].add(target)
            if kind == "horizontal" and self._is_private(target) and len(st["priv"]) < 100_000:
                st["priv"].add(target)
        if failed and len(st["examples"]) < 6:
            st["examples"].append(f"{rec['dst_ip']}:{rec['dst_port']}")
        n = len(st[field])
        if (n < self.cfg.scan_min_targets or st["attempts"] < self.cfg.scan_min_targets
                or st["failed"] / st["attempts"] < self.cfg.scan_min_fail_ratio):
            return []
        src = key[0]
        internal_src = self._is_private(src)
        if kind == "vertical":
            m = {"src_ip": src, "dst_ip": key[1], "dst_port": None, "target": f"{key[1]} ({n} ports)",
                 "kind": "vertical", "count": n, "attempts": st["attempts"], "failed": st["failed"],
                 "examples": sorted(st["examples"]), "internal_src": internal_src, "hosts": 1}
        else:
            m = {"src_ip": src, "dst_ip": None, "dst_port": key[1], "target": f"{n} hosts on port {key[1]}",
                 "kind": "horizontal", "count": n, "attempts": st["attempts"], "failed": st["failed"],
                 "examples": sorted(st["examples"]), "internal_src": internal_src,
                 "internal_targets": len(st["priv"]), "hosts": n}
        m["confidence"] = round(min(0.95, 0.6 + 0.3 * (st["failed"] / st["attempts"])), 3)
        head, details = explain.scan(m)
        alert = self._alert(f"scan:{kind}:{src}:{key[1]}", "scan", m, head, details, rec["end"],
                            {"kind": "scan"}, [], {}, [flow_spec(rec)], rec.get("capture"))
        # An internal host scanning is lateral movement or a compromised device: the
        # worrying case. An external source scanning us is usually stopped at the edge.
        alert["severity"] = "high" if internal_src else "medium"
        if internal_src:
            alert["offender"] = src
        return [alert]

    # ------------------------------------------ DGA / NXDOMAIN storm

    def _check_dga(self, rec: dict) -> list[dict]:
        """Malware that generates its command-and-control domain by algorithm asks for
        many random-looking names until one resolves. Most of them do not exist, so a
        host collecting many distinct NXDOMAIN registered domains whose names look random
        is almost certainly running a DGA. High entropy separates generated names from an
        ordinary run of typos or a misconfigured search suffix."""
        src = rec["src_ip"]
        out = []
        for q in rec["dns"]:
            if not q.get("answered") or q.get("rcode") != 3:  # NXDOMAIN responses only
                continue
            if q.get("qtype") not in (1, 28, 5, 15, 16, 255):  # A, AAAA, CNAME, MX, TXT, ANY
                continue
            name = q["qname"].lower().rstrip(".")
            domain = registered_domain(name)
            if not name or "." not in domain or self._dns_allowed(domain):
                continue
            st = self.dga.get(src)
            if st is None:
                if len(self.dga) >= 20_000:
                    for s in sorted(self.dga, key=lambda s: self.dga[s]["last"])[:5_000]:
                        del self.dga[s]
                st = self.dga[src] = {"domains": {}, "last": rec["end"], "examples": [], "alerted_at": 0}
            st["last"] = rec["end"]
            if domain not in st["domains"] and len(st["domains"]) < 5_000:
                st["domains"][domain] = string_entropy(domain.split(".")[0])
                if len(st["examples"]) < 10:
                    st["examples"].append(domain)
            n = len(st["domains"])
            if n < self.cfg.dga_min_nxdomains or n < st["alerted_at"] + 10:
                continue
            avg_entropy = sum(st["domains"].values()) / n
            if avg_entropy < self.cfg.dga_min_entropy:
                continue
            st["alerted_at"] = n
            m = {"confidence": round(min(0.95, 0.55 + 0.1 * avg_entropy), 3), "src_ip": src, "dst_ip": rec["dst_ip"],
                 "dst_port": 53, "target": src, "count": n, "entropy": round(avg_entropy, 2),
                 "examples": sorted(st["examples"]), "hosts": 1}
            head, details = explain.dga(m)
            alert = self._alert(f"dga:{src}", "dga", m, head, details, rec["end"],
                                {"kind": "dga"}, [], {}, [flow_spec(rec)], rec.get("capture"))
            alert["offender"] = src
            out.append(alert)
        return out

    # ------------------------------------------ crafted TCP

    def _check_crafted_tcp(self, rec: dict) -> list[dict]:
        n = rec["tcp"]["null_flags"]
        payload = rec["c2s"]["payload_bytes"] + rec["s2c"]["payload_bytes"]
        poisoned = rec["dst_ip"] in self.poisoned or rec["src_ip"] in self.poisoned
        severity = "critical" if poisoned else "high" if payload else "medium"
        m = {"confidence": 0.9 if payload else 0.7, "src_ip": rec["src_ip"], "dst_ip": rec["dst_ip"],
             "dst_port": rec["dst_port"], "target": f"{rec['dst_ip']}:{rec['dst_port']}", "segments": n,
             "payload": payload, "handshake": rec["tcp"]["handshake"], "poisoned": poisoned,
             "domain": (self._dns_context(rec["dst_ip"]) or [None])[0]}
        head, details = explain.crafted_tcp(m)
        key = f"crafted_tcp:{rec['src_ip']}:{rec['dst_ip']}"
        alert = self._alert(key, "crafted_tcp", m, head, details, rec["end"],
                            self._throughput(rec), self._session_timeline(rec), self._stream_info(rec),
                            [flow_spec(rec)], rec.get("capture"))
        alert["severity"] = severity
        self._attach_device(alert)
        self.crafted[key] = rec
        self.crafted.move_to_end(key)
        while len(self.crafted) > 500:
            self.crafted.popitem(last=False)
        return [alert]

    def _escalate_crafted(self, addrs: list[str]) -> list[dict]:
        """Hand-built TCP seen before the answer that made its address suspect: judged again."""
        out = []
        for key, rec in list(self.crafted.items()):
            if rec["dst_ip"] in addrs or rec["src_ip"] in addrs:
                alert = self._known(self.alert_ids.get(key, ""))
                if alert and alert["severity"] != "critical":
                    out += self._check_crafted_tcp(rec)
        return out

    # ------------------------------------------ files over FTP, and the devices they describe

    _SECRET_NAMES = ("passwd", "shadow", "id_rsa", "id_ecdsa", "id_ed25519", ".pem", ".key", ".kdbx", ".ovpn",
                     "ntds.dit", "credentials", ".htpasswd", "wallet.dat", ".env", "secrets")

    def _check_ftp(self, rec: dict) -> list[dict]:
        d = rec["ftp_data"]
        if d["command"] not in ("STOR", "APPE", "STOU", "RETR"):
            return []
        client = d["control"].split(" -> ")[0].rsplit(":", 1)[0] if " -> " in d["control"] else rec["src_ip"]
        server = d["control"].split(" -> ")[1].rsplit(":", 1)[0] if " -> " in d["control"] else rec["dst_ip"]
        out: list[dict] = []
        dev = devices.parse(d["text"], d["name"]) if d.get("text") else None
        if dev:
            out += self._learn_device(dev, d, client if d["upload"] else server, rec)
        name = re.split(r"[\\/]", d["name"])[-1]
        ext = filetypes.extension(name)
        desc, kind = filetypes.describe(d["magic"])
        program = kind in ("executable", "script") or ext in filetypes.EXEC_EXT | filetypes.SCRIPT_EXT
        secret = any(x in name.lower() for x in self._SECRET_NAMES)
        if not (dev or program or secret):
            return out
        what = (f"the configuration of {dev.kind} {dev.name}" if dev else
                f"a {desc or 'program'}" if program else "a file holding secrets or keys")
        m = {"confidence": 0.8, "src_ip": client, "dst_ip": server, "dst_port": 21, "target": f"{server}:21",
             "name": name, "path": d["name"], "upload": d["upload"], "user": d["user"] or "?", "what": what,
             "size": d["size"], "sha256": d["sha256"], "complete": d["complete"],
             "tls_refused": bool(d.get("tls_refused"))}
        head, details = explain.ftp_file(m)
        alert = self._alert(f"ftp_file:{client}:{server}:{d['name']}", "ftp_file", m, head, details, rec["end"],
                            self._throughput(rec), self._session_timeline(rec), self._stream_info(rec),
                            [flow_spec(rec)], rec.get("capture"))
        alert["severity"] = "high" if program else "medium"
        alert["file"] = {"name": name, "url": f"ftp://{server}/{d['name'].lstrip('/')}", "sha256": d["sha256"],
                         "size": d["size"], "type": desc or (f".{ext} file" if ext else "text file"),
                         "content_type": "", "complete": d["complete"], "decoded": False}
        own = next((a for a in dev.addresses() if a not in self._GENERIC), None) if dev else None
        if own and self._device_info(own):
            alert["device"] = self._device_info(own)
        else:
            self._attach_device(alert)
        out.append(alert)
        return out

    # ------------------------------------------ logins sent in clear text

    def _check_logins(self, rec: dict) -> list[dict]:
        """A password (or SNMP community) sent where anyone on the path can read it: one alert
        per client, server and service, naming the accounts. The engine never hands over the
        password itself; anonymous logins carry none and are left out."""
        changed = []
        for l in rec["logins"]:
            if l["anonymous"]:
                continue
            key = (rec["src_ip"], rec["dst_ip"], rec["dst_port"], l["proto"])
            entry = self.logins.get(key)
            if entry is None:
                entry = self.logins[key] = {"users": {}, "seen": set(), "flows": [], "methods": set(),
                                            "default_secret": False}
                while len(self.logins) > 4096:
                    self.logins.popitem(last=False)
            self.logins.move_to_end(key)
            mark = (rec["flow_id"], l["method"], l["user"], l["ts"])
            if mark in entry["seen"]:
                continue  # (an update of a session already counted)
            if len(entry["seen"]) < 10_000:
                entry["seen"].add(mark)
            user = entry["users"].setdefault(l["user"], {"accepted": 0, "refused": 0, "unknown": 0})
            user["accepted" if l["accepted"] else "unknown" if l["accepted"] is None else "refused"] += 1
            entry["methods"].add(l["method"])
            entry["default_secret"] |= l["default_secret"]
            spec = flow_spec(rec)
            if spec not in entry["flows"]:
                entry["flows"] = (entry["flows"] + [spec])[-400:]
            changed.append(key)
        out = []
        for key in dict.fromkeys(changed):
            entry = self.logins[key]
            client, server, port, proto = key
            users = entry["users"]
            total = {k: sum(u[k] for u in users.values()) for k in ("accepted", "refused", "unknown")}
            named = [u for u in users if u]
            m = {"confidence": 0.95, "src_ip": client, "dst_ip": server, "dst_port": port,
                 "target": f"{server}:{port}", "service": proto, "method": ", ".join(sorted(entry["methods"])),
                 "users": ", ".join(named[:10]) + (f" and {len(named) - 10} more" if len(named) > 10 else ""),
                 "accounts": len(users), "logins": sum(total.values()), **total,
                 "default_secret": entry["default_secret"], "safer": explain.SAFER_SERVICE.get(proto, "an encrypted form")}
            head, details = explain.cleartext_login(m)
            alert = self._alert(f"cleartext_login:{client}:{server}:{port}:{proto}", "cleartext_login", m, head,
                                details, rec["end"], self._throughput(rec), self._session_timeline(rec),
                                self._stream_info(rec, flows=len(entry["flows"])), entry["flows"], rec.get("capture"))
            self._attach_device(alert)
            out.append(alert)
        return out

    _GENERIC = {"127.0.0.1", "::1", "0.0.0.0", "::"}

    def _learn_device(self, dev: "devices.Device", d: dict, sender: str, rec: dict) -> list[dict]:
        """Remember a device a file described, and give every alert about any of its
        addresses the whole list."""
        addrs = dev.addresses()
        key = f"{dev.kind}|{dev.name}|{','.join(sorted(addrs))}"
        info = dev.to_dict()
        info["addresses"] = addrs
        info["evidence"] = (f"{d['name']}, {'uploaded' if d['upload'] else 'downloaded'} over FTP "
                            f"{'from' if d['upload'] else 'by'} {sender}"
                            + (" (one of its own addresses)" if sender in addrs else ""))
        info["sha256"] = d["sha256"]
        self.devices[key] = {"device": info, "ts": rec["start"]}
        while len(self.devices) > 500:
            self.devices.popitem(last=False)
        for a in addrs:
            if a not in self._GENERIC:
                self.device_by_ip[a] = key
        changed = []
        for alert in self.alerts.values():
            if self._attach_device(alert):
                alert["updates"] += 1
                changed.append(alert)
        # A configuration that makes the device answer names itself: its own DNS lies.
        for qname, addr in dev.dns_overrides:
            kind = devices.address_kind(addr)
            if kind in devices.NEVER_VALID or (kind != "public" and not qname.endswith(self._LOCAL_SUFFIXES)):
                changed += self._override_alert(info, qname, addr, kind, rec)
        return changed

    def _override_alert(self, info: dict, qname: str, addr: str, kind: str, rec: dict) -> list[dict]:
        offender = next((a for a in info["addresses"] if a not in self._GENERIC), rec["src_ip"])
        key = f"dns_poison:{offender}:{qname}:config"
        self.poisoned[addr] = key
        escalated = self._escalate_crafted([addr])
        m = {"confidence": 0.9, "src_ip": offender, "dst_ip": rec["dst_ip"], "dst_port": 53, "target": qname,
             "name": qname, "qtype": "A", "resolver": offender, "bad": [addr], "kinds": {addr: kind}, "clients": [],
             "others": {}, "own_public": [], "contacts": self._contacts([addr]), "configured": info["source"]}
        head, details = explain.dns_poison(m)
        alert = self._alert(key, "dns_poison", m, head, details, rec["end"], self._throughput(rec),
                            self._session_timeline(rec), self._stream_info(rec), [flow_spec(rec)], rec.get("capture"))
        alert["severity"] = "critical" if kind in devices.NEVER_VALID else "high"
        alert["offender"] = offender
        alert["device"] = info
        return [alert] + escalated

    # Alerts in which the named address is the attacker's own device, not its victim.
    _ACTOR = {"dns_poison": "offender", "crafted_tcp": "src_ip", "beacon": "src_ip", "tls_port": "src_ip"}

    def _implicate(self, changed: list[dict]) -> list[dict]:
        """A device a configuration described, caught doing what only a compromised device
        does: one alert that names it and lists every address assigned to it."""
        out = []
        for alert in changed:
            field = self._ACTOR.get(alert.get("kind", ""))
            if not field or alert.get("severity") not in ("critical", "high"):
                continue
            ip = alert.get(field)
            key = self.device_by_ip.get(ip or "")
            entry = self.devices.get(key) if key else None
            if entry:
                out += self._device_alert(key, entry["device"], ip, alert)
        return out

    def _device_alert(self, key: str, info: dict, ip: str, cause: dict) -> list[dict]:
        dkey = f"compromised_device:{key}"
        state = self.compromised.setdefault(dkey, {"causes": {}, "shown": None})
        if cause["kind"] == "dns_poison" and cause.get("dns"):
            d = cause["dns"]
            reason = f"as {ip} it answered {d['name']} with {', '.join(d['answers'])}, an address no real host has."
        elif cause["kind"] == "crafted_tcp":
            reason = f"as {ip} it sent TCP packets built by hand to {cause['target']}."
        else:
            reason = f"as {ip} it raised \u201c{cause['title']}\u201d."
        state["causes"].setdefault(cause["id"], (reason, f"{cause['title']} ({cause['id']}): {cause['headline']}"))
        # The address it acted from first, loopbacks (never on the wire) last.
        addrs = [ip] + sorted((a for a in info["addresses"] if a != ip),
                              key=lambda a: devices.address_kind(a) == "loopback")
        shown = (tuple(state["causes"]), tuple(addrs), cause["severity"])
        if shown == state["shown"]:
            return []
        state["shown"] = shown
        first = next(iter(state["causes"].values()))
        m = {"confidence": max((c["confidence"] for c in self.alerts.values() if c["id"] in state["causes"]),
                               default=cause["confidence"]),
             "src_ip": ip, "dst_ip": None, "dst_port": None, "target": info["name"], "device": info, "ip": ip,
             "addresses": addrs, "reason": first[0][0].upper() + first[0][1:],
             "causes": [c[1] for c in state["causes"].values()]}
        head, details = explain.compromised_device(m)
        exp = self.export_index.get(cause["id"]) or {}
        alert = self._alert(dkey, "compromised_device", m, head, details, cause["last_seen"], cause["chart"],
                            cause["timeline"], cause["stream"], exp.get("flows") or [], exp.get("capture"))
        alert["severity"] = "critical"
        alert["offender"] = ip
        alert["addresses"] = addrs
        alert["device"] = info
        alert["causes"] = list(state["causes"])
        alert["victims"] = cause.get("victims") or []
        return [alert]

    def _device_info(self, ip: str | None) -> dict | None:
        key = self.device_by_ip.get(ip or "")
        entry = self.devices.get(key) if key else None
        return entry["device"] if entry else None

    def _attach_device(self, alert: dict) -> bool:
        """The device behind an alert's offender (or source/destination), once a file described it."""
        if alert.get("device"):
            return False
        for ip in (alert.get("offender"), alert.get("src_ip"), alert.get("dst_ip")):
            info = self._device_info(ip)
            if info:
                alert["device"] = info
                alert["details"] = alert["details"] + [
                    f"{ip} is {info['kind']} {info['name']}: its configuration ({info['evidence']}) gives it these "
                    "addresses: " + ", ".join(f"{i['address']}" + (f"/{i['prefix']}" if i["prefix"] is not None else "")
                                              + f" ({i['name']})" for i in info["interfaces"]) + "."]
                return True
        return False

    # ------------------------------------------ non-TLS on a TLS port

    @staticmethod
    def _looks_tls(head: bytes) -> bool:
        if len(head) >= 3 and head[0] in (0x14, 0x15, 0x16, 0x17) and head[1] == 3 and head[2] <= 4:
            return True
        return len(head) >= 3 and bool(head[0] & 0x80) and head[2] == 1  # SSLv2-style Client Hello

    @staticmethod
    def _identify(head: bytes) -> str | None:
        if head.startswith(b"SSH-"):
            return "SSH"
        if head.split(b" ", 1)[0] in (b"GET", b"POST", b"HEAD", b"PUT", b"OPTIONS", b"CONNECT", b"DELETE",
                                     b"PATCH") or head.startswith(b"HTTP/"):
            return "HTTP"
        if len(head) >= 3 and (head[2] >> 3) in (7, 10) and int.from_bytes(head[:2], "big") + 2 >= 14:
            return "OpenVPN"  # length prefix + P_CONTROL_HARD_RESET_CLIENT_V2/V3
        return None

    def _check_tls_port(self, rec: dict) -> list[dict]:
        h = rec["stream_head"]
        side = {"client": "c2s", "server": "s2c"}.get(h["first"])
        if not side or not h[f"{side}_from_start"] or not h[side]:
            return []  # the start of the conversation wasn't captured
        first = bytes.fromhex(h[side])
        other = bytes.fromhex(h["s2c" if side == "c2s" else "c2s"])
        if self._looks_tls(first) or (side == "s2c" and self._looks_tls(other)):
            return []
        out_b, in_b = session_bytes(rec)
        if rec["c2s"]["payload_bytes"] + rec["s2c"]["payload_bytes"] < self.cfg.tls_port_min_bytes:
            return []
        duration = rec["end"] - rec["start"]
        proto = self._identify(first)
        domain = self._domain_of(rec)
        prevalence = self._prevalence(rec["dst_ip"], rec["dst_port"], domain)
        remote_control = (duration >= self.cfg.remote_control_min_s and
                          min(rec["c2s"]["payload_bytes"], rec["s2c"]["payload_bytes"]) >= self.cfg.remote_control_min_bytes)
        severity = "medium" if proto else "critical" if remote_control else "high"
        m = {"confidence": 0.7 if proto else min(0.97, 0.8 + (0.1 if remote_control else 0) +
                                                 (0.05 if not domain else 0)),
             "src_ip": rec["src_ip"], "dst_ip": rec["dst_ip"], "dst_port": rec["dst_port"],
             "target": f"{rec['dst_ip']}:{rec['dst_port']}", "hosts": prevalence, "protocol": proto,
             "first_bytes": first.hex(" "), "speaker": "client" if side == "c2s" else "server",
             "bytes_out": out_b, "bytes_in": in_b, "payload_out": rec["c2s"]["payload_bytes"],
             "payload_in": rec["s2c"]["payload_bytes"], "duration": duration, "remote_control": remote_control,
             "domain": domain, "entropy": (rec.get("payload_entropy") or {}).get("c2s"),
             "open": not (rec.get("tcp") or {}).get("closed", False)}
        head, details = explain.tls_port(m)
        alert = self._alert(f"tls_port:{flow_spec(rec)}:{rec['start']}", "tls_port", m, head, details, rec["end"],
                            self._throughput(rec), self._session_timeline(rec), self._stream_info(rec),
                            [flow_spec(rec)], rec.get("capture"))
        alert["severity"] = severity
        if proto:
            alert["title"] = f"{proto} on a TLS Port"
        elif remote_control:
            alert["title"] = "Possible Remote-Access Trojan (custom protocol on a TLS port)"
        return [alert]

    # ----------------------------------------------- per-session checks

    def _check_session(self, rec: dict) -> list[dict]:
        feats = session_features(rec)
        x = feature_vector(feats)
        score = None
        if self.model is not None:
            score = float(self.model.scores(x)[0])
            self.counters["inferences"] += 1

        out_b, in_b = session_bytes(rec)
        duration = max(rec["end"] - rec["start"], 1e-3)
        asym = feats["byte_asymmetry"]
        timeline = self._session_timeline(rec)
        capture = rec.get("capture")
        domain = self._domain_of(rec)
        sni = (rec.get("tls") or {}).get("sni")
        entropy = (rec.get("payload_entropy") or {}).get("c2s")
        key_suffix = f"{flow_spec(rec)}:{rec['start']}"

        if out_b >= self.cfg.exfil_min_bytes and asym >= self.cfg.exfil_min_asymmetry:
            prevalence = self._prevalence(rec["dst_ip"], rec["dst_port"], domain)
            if prevalence <= self.cfg.exfil_max_hosts:
                ml_hit = score is not None and self.model.is_anomaly(score)
                conf = min(0.99, 0.55 + 0.25 * min(1, out_b / 50e6) + 0.1 * (asym - 0.85) / 0.15
                           + (0.1 if ml_hit else 0))
                m = {"confidence": conf, "src_ip": rec["src_ip"], "dst_ip": rec["dst_ip"],
                     "dst_port": rec["dst_port"], "target": f"{rec['dst_ip']}:{rec['dst_port']}",
                     "bytes_out": out_b, "bytes_in": in_b, "duration": duration,
                     "asymmetry": out_b / (out_b + in_b), "rate": out_b / duration, "hosts": prevalence,
                     "domain": (self._dns_context(rec["dst_ip"]) or [None])[0], "sni": sni, "ml_score": score,
                     "entropy": entropy}
                head, details = explain.exfil(m)
                return [self._alert(f"exfil:{key_suffix}", "exfil", m, head, details, rec["end"],
                                    self._throughput(rec), timeline, self._stream_info(rec), [flow_spec(rec)],
                                    capture)]

        if score is not None and self.model.is_anomaly(score):
            # An unusual-looking session to a service much of the network uses
            # (mail, CDNs, update servers) is overwhelmingly benign; rarity of the
            # destination is what separates exfil from an email attachment.
            prevalence = self._prevalence(rec["dst_ip"], rec["dst_port"], domain)
            if self._is_shared(prevalence):
                self.counters["anomaly_common_destination"] += 1
                return []
            m = {"confidence": self.model.confidence(score), "src_ip": rec["src_ip"], "dst_ip": rec["dst_ip"],
                 "dst_port": rec["dst_port"], "target": f"{rec['dst_ip']}:{rec['dst_port']}", "score": score,
                 "detector": getattr(self.model, "name", None),
                 "threshold": self.model.threshold, "bytes_out": out_b, "bytes_in": in_b, "duration": duration,
                 "deviations": self.model.top_deviations(x), "hosts": prevalence}
            head, details = explain.anomaly(m)
            chart = {"kind": "feature_deviation", "title": "Deviation from benign baseline (z-score)",
                     "items": self.model.top_deviations(x, k=len(x))}
            alert = self._alert(f"anomaly:{key_suffix}", "anomaly", m, head, details, rec["end"], chart, timeline,
                                self._stream_info(rec), [flow_spec(rec)], capture)
            if prevalence >= 2:
                # Other hosts use this destination too: worth a look, not an incident.
                alert["severity"] = "low"
                details.append("Other internal hosts contact this destination as well, so this is kept at low "
                               "severity; on its own a statistical outlier is weak evidence.")
            elif _internal_service(rec):
                # The model learned what internet sessions look like; a Windows domain
                # member talking to its domain controller looks nothing like that.
                alert["severity"] = "low"
                details.append(f"Both ends are on the local network and port {rec['dst_port']} is a Windows "
                               "domain service (SMB, LDAP, Kerberos, RPC), so this is kept at low severity: "
                               "unusual for the model, but usually routine.")
            return [alert]
        return []

    @staticmethod
    def _session_timeline(rec: dict) -> list[dict]:
        return [{"t": rec["start"] + e[0] / 1000.0, "out": max(e[1], 0), "in": max(-e[1], 0)}
                for e in rec.get("events", [])]

    @staticmethod
    def _throughput(rec: dict) -> dict:
        """Per-bucket bytes from the engine's uncapped rate histogram."""
        rate = rec.get("rate") or {}
        width = rate.get("bucket_ms", 1000.0) / 1000.0
        series = [[round(i * width, 3), o, n] for i, (o, n) in enumerate(zip(rate.get("out", []), rate.get("in", []), strict=False))]
        return {"kind": "throughput", "title": f"Bytes per {width:g} s interval (out vs. in)",
                "bucket_s": width, "series": series}
