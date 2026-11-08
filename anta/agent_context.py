"""What the detection agent is told about a session, and what its lookup tools answer:
facts the analyzer already holds (who uses a destination, what names it answered to,
where it is, threat-intel matches, alerts, a conversation's history). Read-only; query
strings are never included (they can carry secrets)."""
from __future__ import annotations

import datetime as dt
import ipaddress

from . import devices
from .agent import INTERNAL_KINDS
from .analyzer import registered_domain
from .features import session_bytes, session_features


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class AgentContext:
    def __init__(self, analyzer_getter, baseline_model_getter=None):
        self._analyzer = analyzer_getter        # the current analyzer (a new one per session)
        self._baseline = baseline_model_getter  # the built-in model: its benign feature baseline

    @property
    def a(self):
        return self._analyzer()

    def session_summary(self, rec: dict) -> dict:
        a = self.a
        out_b, in_b = session_bytes(rec)
        tls = rec.get("tls") or {}
        feats = session_features(rec) if rec.get("events") else {}
        summary = {
            "client": rec["src_ip"], "client_port": rec["src_port"], "server": rec["dst_ip"],
            "server_port": rec["dst_port"], "transport": rec["proto"],
            "application": rec.get("app_label") or rec.get("app"),
            "started": _iso(rec["start"]), "duration_s": round(rec["end"] - rec["start"], 3),
            "bytes_to_server": out_b, "bytes_to_client": in_b,
            "packets": rec["c2s"]["packets"] + rec["s2c"]["packets"],
            "server_name": a._domain_of(rec),
            "internal_hosts_using_destination": a._prevalence(rec["dst_ip"], rec["dst_port"], a._domain_of(rec)),
        }
        t = {k: tls.get(k) for k in ("sni", "ja3", "ja4", "ja3s", "decrypted") if tls.get(k)}
        if tls.get("alpn"):
            t["alpn"] = tls["alpn"]
        if t:
            summary["tls"] = t
        http = [{"method": h.get("method"), "host": h.get("host"), "path": (h.get("uri") or "").split("?", 1)[0][:300],
                 "user_agent": (h.get("user_agent") or "")[:200]} for h in (rec.get("http") or [])[:5]]
        if http:
            summary["http_requests"] = http
        files = [{"name": f.get("filename") or (f.get("uri") or "").split("?", 1)[0][-120:], "size": f.get("size"),
                  "content_type": f.get("content_type"), "sha256": f.get("sha256")}
                 for f in (rec.get("http_files") or [])[:5]]
        if files:
            summary["files_downloaded"] = files
        if rec.get("payload_entropy"):
            summary["payload_entropy_bits_per_byte"] = rec["payload_entropy"]
        if feats:
            summary["timing"] = {"inter_arrival_variation": round(feats.get("iat_cv", 0.0), 3)}
        model = self._baseline() if self._baseline else None
        if model is not None and feats:
            from .features import feature_vector
            summary["unusual_compared_to_benign_traffic"] = [
                {"feature": d["feature"], "value": round(d["value"], 3), "typical": round(d["baseline"], 3),
                 "standard_deviations": round(d["z"], 1)} for d in model.top_deviations(feature_vector(feats), k=4)]
        return summary

    def _alerts_about(self, *values: str) -> list[dict]:
        out = []
        for alert in reversed(self.a.alerts.values()):
            if any(v and v in (alert.get("src_ip"), alert.get("dst_ip"), alert.get("target"),
                               (alert.get("metrics") or {}).get("domain")) for v in values):
                out.append({"title": alert["title"], "severity": alert["severity"], "headline": alert["headline"][:300]})
            if len(out) >= 8:
                break
        return out

    def destination_profile(self, address: str) -> dict:
        a = self.a
        address = address.strip().lower().rstrip(".")
        if not address:
            raise ValueError("no address given")
        profile: dict = {"address": address}
        intel = getattr(a.intel, "index", None) if a.intel is not None else None
        if _is_ip(address):
            hosts = sorted({h for (ip, _), srcs in list(a.dest_hosts.items()) if ip == address for h in srcs})
            ports = sorted({p for (ip, p) in list(a.dest_hosts) if ip == address})
            profile.update(internal_hosts=hosts[:20], internal_host_count=len(hosts), ports_used=ports[:20])
            named = a.resolved.get(address)
            if named:
                profile["dns_name"] = named["domain"]
            if a.geo is not None and devices.address_kind(address) == "public":
                geo = a.geo.lookup(address)
                if geo:
                    profile["location"] = {k: geo.get(k) for k in ("country", "asn", "org") if geo.get(k)}
            if intel:
                hits = intel.get("ip", {}).get(address) or []
                profile["threat_intel"] = [{"feed": h.get("feed"), "reason": h.get("reason")} for h in hits[:5]]
        else:
            reg = registered_domain(address)
            hosts = sorted(a.domain_hosts.get(reg, {}))
            addrs = sorted(ip for ip, r in list(a.resolved.items())
                           if r["domain"].lower().rstrip(".") in (address,) or r["domain"].lower().endswith("." + reg))
            profile.update(registered_domain=reg, internal_hosts=hosts[:20], internal_host_count=len(hosts),
                           addresses=addrs[:20])
            if intel:
                hits = []
                labels = address.split(".")
                for i in range(len(labels) - 1):
                    hits += intel.get("domain", {}).get(".".join(labels[i:])) or []
                profile["threat_intel"] = [{"feed": h.get("feed"), "reason": h.get("reason")} for h in hits[:5]]
        profile["alerts"] = self._alerts_about(address)
        return profile

    def host_profile(self, host: str) -> dict:
        a = self.a
        host = host.strip()
        apps = a.host_apps.get(host) or {}
        dests = {(k[1], k[2]) for k in list(a.channels) if k[0] == host}
        return {"host": host, "is_internal": devices.address_kind(host) in INTERNAL_KINDS,
                "uses": dict(sorted((apps.get("uses") or {}).items(), key=lambda kv: -kv[1])[:10]),
                "serves": dict(sorted((apps.get("serves") or {}).items(), key=lambda kv: -kv[1])[:10]),
                "destinations_contacted": len(dests), "alerts": self._alerts_about(host)}

    def history(self, host: str, destination: str, port: int) -> dict:
        a = self.a
        for proto in ("tcp", "udp"):
            ch = a.channels.get((host, destination, int(port), proto))
            if ch is not None:
                flows = list(ch.flows.values())[-20:]
                starts = [f.start for f in flows]
                gaps = [round(b - s, 1) for s, b in zip(starts, starts[1:], strict=False)]
                out = {"sessions_seen": len(ch.flows), "transport": proto,
                       "recent": [{"started": _iso(f.start), "duration_s": round(f.end - f.start, 2),
                                   "bytes_to_server": f.bytes_out, "bytes_to_client": f.bytes_in} for f in flows],
                       "seconds_between_sessions": gaps}
                if ch.periodic:
                    out["regularity"] = {k: v for k, v in ch.periodic[0].items() if isinstance(v, (int, float, str, bool))}
                return out
        return {"sessions_seen": 0, "note": "ANTA has no earlier sessions between these on that port"}
