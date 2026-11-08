"""The speed-of-light check: where each server could physically be, from how fast it answered.

A TCP handshake's SYN -> SYN/ACK time, measured where the capture was made, is at least the
time light needs to reach the server and come back: nothing travels faster, and every router,
cable detour and busy server only adds to it. So the server is at most
    c x round trip / 2
away from the capture point. When the country its network is registered in (the bundled
ip2asn table, geoip.py) is entirely farther than that, the server cannot be there: a CDN, a
cloud region, a VPN exit, or something on the path answering for it.

The claim is kept safe: the speed of light in vacuum (light in fibre is a third slower), the
fastest handshake seen, and a country's nearest edge less a margin for the simplified borders
(anta/geo/borders.json.gz, tools/gen_borders.py). The SYN/ACK -> ACK time does the same for
clients from the internet connecting in.

Where the capture was made comes from the user (a place, or coordinates), by default the place
the computer's time zone is named after; it is saved owner-only in the data folder.
"""
from __future__ import annotations

import contextlib
import gzip
import ipaddress
import json
import math
import os
import re
import tempfile
import threading

from . import paths

C_KM_PER_MS = 299.792458        # light in vacuum, km per millisecond
FIBRE_KM_PER_MS = 204.0         # light in optical fibre (refractive index about 1.47)
EARTH_KM = 6371.0088
HALF_EARTH_KM = math.pi * EARTH_KM  # no two places on Earth are farther apart than this
MARGIN_KM = 100.0               # extra caution on top of the borders' own error
LOCAL_MS = 1.0                  # a handshake faster than this: the same building or town

_borders: dict | None = None
_lock = threading.Lock()


class PhysicsError(ValueError):
    pass


def borders() -> dict:
    """The bundled outlines and time-zone places (read once)."""
    global _borders
    with _lock:
        if _borders is None:
            with gzip.open(os.path.join(os.path.dirname(__file__), "geo", "borders.json.gz"), "rt", encoding="utf-8") as fh:
                data = json.load(fh)
            rings = {}
            for cc, rs in data["countries"].items():
                out = []
                for flat in rs:
                    xs, ys = flat[0::2], flat[1::2]
                    out.append((xs, ys, (min(xs), max(xs), min(ys), max(ys))))
                rings[cc] = out
            deg_km = EARTH_KM * math.pi / 180
            # How far a point of the real border can be from the nearest stored point: half the
            # longest edge, the simplification and the rounding.
            slack = (data["max_edge_deg"] / 2 + data["simplify_deg"] + 10 ** -data["digits"]) * deg_km
            _borders = {"rings": rings, "zones": data["zones"], "slack_km": slack, "source": data["source"]}
        return _borders


def distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance (haversine)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_KM * math.asin(min(1.0, math.sqrt(a)))


def _inside(x: float, y: float, xs: list, ys: list) -> bool:
    inside = False
    j = len(xs) - 1
    for i in range(len(xs)):
        if (ys[i] > y) != (ys[j] > y) and x < (xs[j] - xs[i]) * (y - ys[i]) / ((ys[j] - ys[i]) or 1e-12) + xs[i]:
            inside = not inside
        j = i
    return inside


def country_km(cc: str, lat: float, lon: float) -> float | None:
    """At least how far the country is from a point (0 when the point is in it); None when the
    country isn't in the table."""
    b = borders()
    rings = b["rings"].get((cc or "").upper())
    if not rings:
        return None
    best = math.inf
    for xs, ys, (x0, x1, y0, y1) in rings:
        if x0 <= lon <= x1 and y0 <= lat <= y1 and _inside(lon, lat, xs, ys):
            return 0.0
    for xs, ys, _ in rings:
        for x, y in zip(xs, ys, strict=True):
            d = distance_km(lat, lon, y, x)
            if d < best:
                best = d
    return max(0.0, best - b["slack_km"] - MARGIN_KM)


def limit_km(rtt_ms: float) -> float:
    """The farthest a thing that answered in rtt_ms can be (light in vacuum, there and back)."""
    return min(HALF_EARTH_KM, C_KM_PER_MS * max(0.0, rtt_ms) / 2)


# ------------------------------------------------------------- where the capture was made

def point_path() -> str:
    return os.path.join(paths.app_data_dir(), "capture-point.json")


def _place_name(zone: str) -> str:
    return zone.split("/")[-1].replace("_", " ")


def clean_point(value) -> dict:
    """{"mode": "auto"} (from the time zone), {"mode": "zone", "zone"}, {"mode": "coords",
    "lat", "lon", "label"} or {"mode": "off"}."""
    if not isinstance(value, dict):
        raise PhysicsError("give where the capture was made")
    mode = value.get("mode")
    if mode in ("auto", "off"):
        return {"mode": mode}
    if mode == "zone":
        zone = str(value.get("zone") or "")
        if zone not in borders()["zones"]:
            raise PhysicsError(f"no such place: {zone!r}")
        return {"mode": "zone", "zone": zone}
    if mode == "coords":
        try:
            lat, lon = float(value.get("lat")), float(value.get("lon"))
        except (TypeError, ValueError):
            raise PhysicsError("latitude and longitude are numbers") from None
        if not (-90 <= lat <= 90 and -180 <= lon <= 180) or math.isnan(lat) or math.isnan(lon):
            raise PhysicsError("latitude is -90 to 90 and longitude -180 to 180")
        label = " ".join(re.sub(r"[\x00-\x1f\x7f]+", " ", str(value.get("label") or "")).split())[:80]
        return {"mode": "coords", "lat": round(lat, 4), "lon": round(lon, 4), "label": label}
    raise PhysicsError("mode is auto, zone, coords or off")


def load_point() -> dict:
    try:
        with open(point_path(), encoding="utf-8") as fh:
            return clean_point(json.load(fh))
    except (OSError, ValueError, TypeError):
        return {"mode": "auto"}


def save_point(value) -> dict:
    point = clean_point(value)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(point_path()), prefix=".capture-point-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(point, fh)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, point_path())
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return point


def resolve_point(setting: dict, tz: str | None) -> dict | None:
    """{"lat", "lon", "label", "how"} for the capture point, or None (off, or no time zone known)."""
    zones = borders()["zones"]
    mode = setting.get("mode")
    if mode == "coords":
        return {"lat": setting["lat"], "lon": setting["lon"], "how": "set",
                "label": setting.get("label") or f"{setting['lat']:.2f}, {setting['lon']:.2f}"}
    if mode == "zone" and setting.get("zone") in zones:
        lat, lon, _ = zones[setting["zone"]]
        return {"lat": lat, "lon": lon, "label": _place_name(setting["zone"]), "how": "set", "zone": setting["zone"]}
    if mode == "auto" and tz in zones:
        lat, lon, _ = zones[tz]
        return {"lat": lat, "lon": lon, "label": _place_name(tz), "how": "time zone", "zone": tz}
    return None


def places() -> list[dict]:
    """The places a capture point can be picked from (the time zones' cities)."""
    return sorted(({"zone": z, "label": f"{_place_name(z)} ({z.split('/')[0].replace('_', ' ')})", "country": v[2]}
                   for z, v in borders()["zones"].items()), key=lambda p: p["label"])


# ------------------------------------------------------------- the check

def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _filter(ip: str) -> str:
    return f"{'ipv6' if ':' in ip else 'ip'}.addr == {ip}"


def check(sessions: list[dict], geo, point: dict | None, names: dict | None = None) -> dict:
    """Every internet address with a timed handshake: how far it can be, and whether the country
    its network is registered in is possible."""
    names = names or {}
    seen: dict[str, dict] = {}
    for s in sessions:
        tcp = s.get("tcp") or {}
        ends = ((s.get("dst_ip"), tcp.get("syn_rtt_ms"), "server"), (s.get("src_ip"), tcp.get("ack_rtt_ms"), "client"))
        for ip, rtt, role in ends:
            if rtt is None or not isinstance(ip, str) or not _public(ip):
                continue
            e = seen.setdefault(ip, {"addr": ip, "role": role, "rtts": [], "name": ""})
            e["rtts"].append(float(rtt))
            sni = (s.get("tls") or {}).get("sni") if role == "server" else None
            if sni and not e["name"]:
                e["name"] = str(sni)[:120]
    rows = []
    for e in seen.values():
        rtts = sorted(e["rtts"])
        fastest = rtts[0]
        reach = limit_km(fastest)
        g = geo.lookup(e["addr"]) if geo is not None else None
        cc = (g or {}).get("country") or ""
        row = {"addr": e["addr"], "role": e["role"], "name": e["name"] or names.get(e["addr"], ""), "handshakes": len(rtts),
               "fastest_ms": round(fastest, 3), "median_ms": round(rtts[len(rtts) // 2], 3), "limit_km": round(reach),
               "fibre_km": round(min(HALF_EARTH_KM, FIBRE_KM_PER_MS * fastest / 2)), "country": cc,
               "country_name": (g or {}).get("country_name") or "", "asn": (g or {}).get("asn"),
               "as_name": (g or {}).get("as_name") or "",
               "filter": _filter(e["addr"]), "min_km": None}
        far = country_km(cc, point["lat"], point["lon"]) if point and cc else None
        row["min_km"] = None if far is None else round(far)
        where = row["country_name"] or cc
        if not point:
            row["verdict"], row["why"] = "unknown", "Set where the capture was made to judge where it can be."
        elif far is not None and far > reach:
            row["verdict"] = "impossible"
            row["why"] = (f"Can't be in {where}, where its network is registered: {where} is at least {far:,.0f} km from the "
                          f"capture point, and in {fastest:.1f} ms light covers only {reach:,.0f} km there and back. It answers "
                          "from nearer: a CDN, a cloud region, a VPN exit, or something on the path answering for it.")
        elif fastest < LOCAL_MS:
            row["verdict"] = "local"
            row["why"] = f"Answered in {fastest:.3f} ms: within {reach:,.0f} km of the capture point, the same building or town."
        elif far is None:
            row["verdict"] = "unknown"
            row["why"] = f"Within {reach:,.0f} km of the capture point (where its network is registered isn't known)."
        else:
            row["verdict"] = "possible"
            row["why"] = (f"Could be in {where}: within {reach:,.0f} km of the capture point "
                          f"(likely within {row['fibre_km']:,} km by fibre).")
        rows.append(row)
    order = {"impossible": 0, "local": 1, "possible": 2, "unknown": 3}
    rows.sort(key=lambda r: (order[r["verdict"]], r["fastest_ms"]))
    impossible = [r for r in rows if r["verdict"] == "impossible"]
    judged = [r for r in rows if r["verdict"] != "unknown"]
    near = [r for r in impossible if r["fastest_ms"] < 3]
    note = ""
    if len(near) >= 5 and len(near) >= 0.5 * max(1, len(judged)):
        note = (f"{len(near)} of {len(judged)} internet servers answer in under 3 ms though their networks are far away: "
                "something close to the capture point is probably answering for them (a transparent proxy, a VPN, or a "
                "security appliance).")
    return {"point": point, "rows": rows, "counts": {k: sum(r["verdict"] == k for r in rows) for k in order},
            "note": note, "speed": {"vacuum_km_per_ms": C_KM_PER_MS, "fibre_km_per_ms": FIBRE_KM_PER_MS, "margin_km": MARGIN_KM}}


def outlines(step: int = 2) -> dict:
    """The outlines for drawing a world map (every `step`-th point; drawing needs less than judging)."""
    out = {}
    for cc, rings in borders()["rings"].items():
        rs = []
        for xs, ys, _ in rings:
            pts = [[xs[i], ys[i]] for i in range(0, len(xs), step)] + [[xs[-1], ys[-1]]]
            if len(pts) >= 4:
                rs.append(pts)
        if rs:
            out[cc] = rs
    return out
