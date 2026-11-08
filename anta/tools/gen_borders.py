"""Build anta/geo/borders.json.gz, the country outlines the speed-of-light check (anta/physics.py)
measures distances to, and the places the time-zone database names (where a capture was made,
by default).

Inputs: Natural Earth's 1:50m admin-0 countries as GeoJSON (public domain;
https://www.naturalearthdata.com) and the tz database's zone.tab (public domain; on macOS and
Linux at /usr/share/zoneinfo/zone.tab).

    python -I -m anta.tools.gen_borders ne_50m_admin_0_countries.geojson /usr/share/zoneinfo/zone.tab

The outlines are simplified (at most SIMPLIFY degrees off) and then cut so that no edge is
longer than MAX_EDGE degrees; physics.py allows for both when it says how far a country is
at least. Only outer rings are kept (a hole only makes a country look nearer, never farther).
"""
from __future__ import annotations

import gzip
import itertools
import json
import math
import os
import sys

SIMPLIFY = 0.04    # degrees: Douglas-Peucker tolerance (about 4.5 km)
MAX_EDGE = 0.5     # degrees: longer edges get extra points
DIGITS = 2         # coordinates kept to 0.01 degrees (about 1.1 km)
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "geo", "borders.json.gz")


def _simplify(points: list[tuple[float, float]], tol: float) -> list[tuple[float, float]]:
    """Douglas-Peucker on one ring (iterative)."""
    if len(points) < 5:
        return points
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    while stack:
        a, b = stack.pop()
        (x1, y1), (x2, y2) = points[a], points[b]
        dx, dy = x2 - x1, y2 - y1
        norm = math.hypot(dx, dy)
        worst, at = -1.0, -1
        for i in range(a + 1, b):
            x, y = points[i]
            d = abs(dy * (x - x1) - dx * (y - y1)) / norm if norm else math.hypot(x - x1, y - y1)
            if d > worst:
                worst, at = d, i
        if worst > tol:
            keep[at] = True
            stack += [(a, at), (at, b)]
    return [p for p, k in zip(points, keep, strict=True) if k]


def _densify(points: list[tuple[float, float]], step: float) -> list[tuple[float, float]]:
    out = []
    for (x1, y1), (x2, y2) in itertools.pairwise(points):
        n = max(1, math.ceil(math.hypot(x2 - x1, y2 - y1) / step))
        out += [(x1 + (x2 - x1) * k / n, y1 + (y2 - y1) * k / n) for k in range(n)]
    out.append(points[-1])
    return out


def _rings(geometry: dict) -> list[list[list[float]]]:
    if geometry["type"] == "Polygon":
        return [geometry["coordinates"][0]]
    if geometry["type"] == "MultiPolygon":
        return [poly[0] for poly in geometry["coordinates"]]
    return []


def countries(geojson_path: str) -> dict[str, list[list[float]]]:
    with open(geojson_path, encoding="utf-8") as fh:
        data = json.load(fh)
    out: dict[str, list[list[float]]] = {}
    for feature in data["features"]:
        props = feature["properties"]
        code = next((props.get(k) for k in ("ISO_A2_EH", "ISO_A2", "WB_A2") if str(props.get(k) or "-99") != "-99"), None)
        if not code or len(code) != 2:
            continue
        for ring in _rings(feature["geometry"]):
            pts = [(float(x), float(y)) for x, y in ring]
            if pts[0] != pts[-1]:
                pts.append(pts[0])
            pts = _densify(_simplify(pts, SIMPLIFY), MAX_EDGE)
            flat = []
            for x, y in pts:
                flat += [round(x, DIGITS), round(y, DIGITS)]
            out.setdefault(code.upper(), []).append(flat)
    return out


def zones(zone_tab: str) -> dict[str, list]:
    """tz name -> [latitude, longitude, country code], from zone.tab's ±DDMM[SS]±DDDMM[SS]."""
    def coord(text: str, deg_digits: int) -> float:
        sign = -1 if text[0] == "-" else 1
        digits = text[1:]
        d, m, s = int(digits[:deg_digits]), int(digits[deg_digits:deg_digits + 2]), int(digits[deg_digits + 2:] or 0)
        return sign * (d + m / 60 + s / 3600)

    out = {}
    with open(zone_tab, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            cc, coords, tz = line.split("\t")[:3]
            split = max(coords.rfind("+"), coords.rfind("-"))
            lat = coord(coords[:split], 2)
            lon = coord(coords[split:], 3)
            out[tz.strip()] = [round(lat, 3), round(lon, 3), cc.strip()]
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    table = {"version": 1, "source": "Natural Earth 1:50m admin-0 countries and the tz database's zone.tab (both public domain)",
             "simplify_deg": SIMPLIFY, "max_edge_deg": MAX_EDGE, "digits": DIGITS,
             "countries": countries(argv[1]), "zones": zones(argv[2])}
    with gzip.open(OUT, "wt", encoding="utf-8") as fh:
        json.dump(table, fh, separators=(",", ":"))
    points = sum(len(r) // 2 for rings in table["countries"].values() for r in rings)
    print(f"{OUT}: {len(table['countries'])} countries, {points} points, {len(table['zones'])} places, "
          f"{os.path.getsize(OUT) // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
