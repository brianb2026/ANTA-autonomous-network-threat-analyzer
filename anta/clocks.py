"""Machines behind addresses, from their clocks: several machines answering from one address
(devices hidden behind a router or travel router), and one machine answering from several
addresses (servers that are really one box).

A TCP timestamp (RFC 7323) is a reading of the sender's own clock, ticking at a fixed rate its
system chose (1000 a second on Linux and macOS, 100 or 250 on older or embedded systems, 10 on
others). Two readings a few seconds apart give the rate; any reading and the rate give the
moment the clock read zero, its starting point. Every machine's clock has its own starting
point, so:

  One address, several starting points (each seen on more than one connection), or clocks
  ticking at different rates: several machines are behind that address.
  Several addresses, one starting point and rate: one machine (one operating system) answers
  for all of them.

Some systems hide their starting point by adding a random amount: Linux and Android per pair of
addresses (so connections to the same partner still agree), others per connection. That's
recognised from the readings themselves and the conclusions adapt: per pair, only connections
to the same partner are compared; per connection, the clock can't count machines and says so.
Virtual machines run their own clocks, so they count as separate machines here.

The tolerance allows for each crystal's error (at most a few hundred parts per million of the
time since the clock started) and for delays on the way.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from . import netmap

DEVICE = {"private", "link-local", "cgnat"}
NOMINAL = (1, 2, 4, 10, 100, 128, 200, 250, 256, 300, 512, 1000, 1024)
MIN_SPAN = 1.5      # seconds between two readings for a rate
MIN_TICKS = 40      # ticks between them (the rate's resolution)
PPM = 300e-6        # a crystal's worst error, as a share of the time since its clock started
WRAP = 2 ** 32


def _nominal(rate: float) -> int | None:
    for n in NOMINAL:
        if abs(rate / n - 1) <= 0.06:
            return n
    return None


def _diff(a: float, b: float, period: float) -> float:
    """a - b, the shorter way round a clock that wraps every `period` seconds."""
    d = (a - b) % period
    return d - period if d > period / 2 else d


def _span_text(lo: float, hi: float) -> str:
    return f"{lo:,.0f}" if hi - lo < 0.1 * lo else f"{lo:,.0f} to {hi:,.0f} times"


def readings(sessions: list[dict]) -> dict[str, list[dict]]:
    """Each sender's clock readings, one per connection side: rate (if measurable), times, peer."""
    out: dict[str, list[dict]] = defaultdict(list)
    for s in sessions:
        clock = (s.get("tcp") or {}).get("clock") or {}
        for side, me, peer in (("c2s", s.get("src_ip"), s.get("dst_ip")), ("s2c", s.get("dst_ip"), s.get("src_ip"))):
            c = clock.get(side)
            if not c or not me:
                continue
            t0, v0, t1, v1, n = c
            rate = None
            span = t1 - t0
            ticks = (v1 - v0) % WRAP
            if n >= 2 and span >= MIN_SPAN and ticks >= MIN_TICKS and ticks < WRAP // 2:
                rate = ticks / span
            out[me].append({"t0": t0, "v0": v0, "t1": t1, "v1": v1, "n": n, "rate": rate, "peer": peer or "",
                            "port": s.get("src_port") if side == "c2s" else s.get("dst_port"), "span": span})
    return out


def _clusters(items: list[dict], period: float) -> list[list[dict]]:
    """Readings grouped by starting point, within each one's tolerance."""
    groups: list[list[dict]] = []
    for it in sorted(items, key=lambda x: x["origin"] % period):
        for g in groups:
            ref = g[0]
            tol = max(1.0, PPM * max(ref["uptime"], it["uptime"]))
            if abs(_diff(it["origin"], ref["origin"], period)) <= tol:
                g.append(it)
                break
        else:
            groups.append([it])
    return groups


def analyse(sessions: list[dict], scope_of=None) -> dict:
    scope_of = scope_of or netmap.scope_of
    per = readings(sessions)
    addresses = []
    all_clocks = []  # (address, rate, cluster) for the across-addresses comparison
    for ip, rs in per.items():
        rated = [r for r in rs if r["rate"]]
        classes = Counter(n for n in (_nominal(r["rate"]) for r in rated) if n)
        across = False
        if not classes and len(rs) >= 2:
            # Each connection too short to time: if all its readings fall on one line, that line is one clock.
            pts = sorted({(r["t0"], r["v0"]) for r in rs} | {(r["t1"], r["v1"]) for r in rs})
            span, ticks = pts[-1][0] - pts[0][0], (pts[-1][1] - pts[0][1]) % WRAP
            n = _nominal(ticks / span) if span >= MIN_SPAN and MIN_TICKS <= ticks < WRAP // 2 else None
            if n and all(abs(((v - pts[0][1]) % WRAP) / n - (t - pts[0][0])) <= 0.25 + PPM * (t - pts[0][0])
                         for t, v in pts):
                classes = Counter({n: len(rs)})
                across = True
        odd = [r["rate"] for r in rated if not _nominal(r["rate"])]
        if odd and len(odd) * 2 >= len(rated):
            # Most timed connections tick at no standard rate: the clock (or the capture's timing) isn't steady.
            lo, hi = min(odd), max(odd)
            addresses.append({"ip": ip, "scope": scope_of(ip), "local": scope_of(ip) in DEVICE, "connections": len(rs),
                              "rates": [], "mode": "unsteady", "clocks": [], "machines": None, "odd": [round(lo), round(hi)],
                              "verdict": "Its clock isn't steady",
                              "why": f"Against the capture's time its clock ticks about {_span_text(lo, hi)} a second, which no "
                                     "system uses: a virtual or emulated machine whose clock runs unevenly, or a capture whose "
                                     "own timing is off. Its clock can't count machines.",
                              "filter": f"{'ipv6' if ':' in ip else 'ip'}.src == {ip} && tcp.options.timestamp.tsval"})
            continue
        if not classes:
            if len(rs) >= 2:
                addresses.append({"ip": ip, "scope": scope_of(ip), "local": scope_of(ip) in DEVICE, "connections": len(rs),
                                  "rates": [], "mode": "unknown", "clocks": [], "machines": None,
                                  "verdict": "Not enough to tell", "why": "Its connections were too short to time its clock.",
                                  "filter": f"{'ipv6' if ':' in ip else 'ip'}.src == {ip} && tcp.options.timestamp.tsval"})
            continue
        main_rate = classes.most_common(1)[0][0]
        items = []
        for r in rs:
            n = _nominal(r["rate"]) if r["rate"] else main_rate
            if not n:
                continue
            uptime = r["v0"] / n
            items.append({**r, "nominal": n, "origin": r["t0"] - uptime, "uptime": uptime})
        machines = 0
        clocks = []
        modes = []
        whys = []
        for n in sorted({x["nominal"] for x in items}):
            group = [x for x in items if x["nominal"] == n]
            period = WRAP / n
            cl = _clusters(group, period)
            multi = [c for c in cl if len(c) >= 2]
            spanning = [c for c in multi if len({x["peer"] for x in c}) >= 2]
            peers = defaultdict(list)
            for x in group:
                peers[x["peer"]].append(x)
            if across:
                mode, k, usable = "shared", 1, [group]
            elif len(peers) == 1 and multi:
                mode = "one-peer"
                k = len(multi)
                if k >= 2:
                    whys.append(f"{k} separate clocks ticking {n} times a second, each seen on several connections")
                usable = multi
            elif spanning:
                mode = "shared"
                k = len(multi)
                if k >= 2:
                    whys.append(f"{k} separate clocks ticking {n} times a second, each seen on several connections")
                usable = multi
            else:
                # Starting points may be randomised per partner: compare connections to the same partner only.
                best, best_peer = 0, ""
                agree = False
                for peer, xs in peers.items():
                    if len(xs) < 2:
                        continue
                    pc = [c for c in _clusters(xs, period) if len(c) >= 2]
                    agree = agree or bool(pc)
                    if len(pc) > best:
                        best, best_peer = len(pc), peer
                if agree:
                    mode = "per-peer"
                    k = best
                    if k >= 2:
                        whys.append(f"to {best_peer} alone, {k} separate clocks ticking {n} times a second")
                    usable = multi
                elif len(group) >= 3 and not multi:
                    mode = "per-connection"
                    k = 1
                    usable = []
                else:
                    mode = "unknown"
                    k = 1 if group else 0
                    usable = multi
            modes.append(mode)
            machines += k if mode != "per-connection" else 1  # (clocks at different rates are different machines)
            for c in usable:
                clk = {"rate": n, "origin": min(x["origin"] for x in c), "connections": len(c),
                       "peers": sorted({x["peer"] for x in c})[:8], "started": c[0]["origin"] if mode == "shared" else None,
                       "mode": mode}
                clocks.append(clk)
                if mode == "shared":
                    all_clocks.append((ip, n, c))
        if len(classes) >= 2:
            rates = sorted(classes)
            whys.append("clocks ticking at different rates (" + " and ".join(f"{r}/s" for r in rates) + "), which one system never does")
        mode = next((m for m in ("shared", "one-peer", "per-peer", "per-connection") if m in modes), "unknown")
        if machines >= 2:
            verdict = f"At least {machines} machines behind this address"
            why = "; ".join(whys) + "."
        elif mode == "per-connection":
            verdict, machines = "Can't tell from its clock", None
            why = "It starts its clock at a new random point for every connection, which hides how many machines there are."
        elif len(items) >= 2 and (across or any(c["connections"] >= 2 for c in clocks)):
            verdict, machines = "One machine", 1
            why = f"Its connections share one clock ({main_rate} ticks a second)" + \
                  (", per partner (randomised, as Linux and Android do)." if mode == "per-peer"
                   else ", timed across its connections." if across else ".")
        else:
            verdict, machines = "Not enough to tell", None
            why = "Too few connections to compare."
        addresses.append({"ip": ip, "scope": scope_of(ip), "local": scope_of(ip) in DEVICE, "connections": len(rs),
                          "rates": sorted(classes), "mode": mode, "clocks": sorted(clocks, key=lambda c: -c["connections"])[:12],
                          "machines": machines, "verdict": verdict, "why": why,
                          "filter": f"{'ipv6' if ':' in ip else 'ip'}.src == {ip} && tcp.options.timestamp.tsval"})

    # One clock, several addresses: the same rate and starting point (within tolerance) on different addresses.
    shared = []
    used = set()
    for i, (ip_a, n_a, c_a) in enumerate(all_clocks):
        if i in used:
            continue
        group = [(ip_a, c_a)]
        for j in range(i + 1, len(all_clocks)):
            ip_b, n_b, c_b = all_clocks[j]
            if j in used or ip_b == ip_a or n_b != n_a or any(ip_b == g[0] for g in group):
                continue
            oa, ob = c_a[0]["origin"], c_b[0]["origin"]
            tol = max(1.0, PPM * max(c_a[0]["uptime"], c_b[0]["uptime"]))
            if abs(_diff(oa, ob, WRAP / n_a)) <= tol:
                group.append((ip_b, c_b))
                used.add(j)
        if len(group) >= 2:
            used.add(i)
            ips = sorted(g[0] for g in group)
            shared.append({"addresses": ips, "rate": n_a, "started": c_a[0]["origin"],
                           "connections": sum(len(g[1]) for g in group),
                           "local": all(scope_of(x) in DEVICE for x in ips),
                           "why": f"Their clocks tick {n_a} times a second and started at the same moment: one operating system "
                                  "answers for all of them.",
                           "filter": " || ".join(f"{'ipv6' if ':' in x else 'ip'}.src == {x}" for x in ips[:16])})
    addresses.sort(key=lambda a: (not a["local"], -(a["machines"] or 0), -a["connections"], a["ip"]))
    shared.sort(key=lambda g: (not g["local"], -len(g["addresses"])))
    behind = [a for a in addresses if (a["machines"] or 0) >= 2]
    timed = [a for a in addresses if a["mode"] != "unknown"]
    unsteady = [a for a in timed if a["mode"] == "unsteady"]
    capture_off = len(timed) >= 3 and len(unsteady) >= 0.7 * len(timed)
    return {"addresses": addresses[:3000], "behind": behind, "shared": shared[:200],
            "capture_off": capture_off,
            "capture_note": (f"{len(unsteady)} of the {len(timed)} timed clocks look unsteady against this capture's time. "
                             "When most do, the capture's own timing is the likelier cause: an emulated network, or a capture "
                             "tool that stamps packets late and in batches. Clock-based counts aren't reliable here.")
            if capture_off else "",
            "counted": sum(1 for a in addresses if a["machines"]),
            "hidden": sum(1 for a in addresses if a["mode"] == "per-connection"),
            "unsteady": sum(1 for a in addresses if a["mode"] == "unsteady"),
            "notes": ["A TCP timestamp is a reading of the sender's own clock; each machine's clock has its own rate and "
                      "starting point.",
                      "Virtual machines run their own clocks, so they count as separate machines.",
                      "Systems that randomise their clock's starting point for every connection can't be counted this way; "
                      "Linux and Android randomise per partner, which still works for connections to the same partner.",
                      "Windows usually sends no TCP timestamps, so Windows machines don't appear here.",
                      "A long capture gives firmer answers: rates need a few seconds of each connection."]}
