// Statistics → Speed of light: where each internet server can physically be, from how fast its
// TCP handshake came back (anta/physics.py). Nothing outruns light, so a server that answered in
// 6 ms is within 900 km of the capture point; when the country its network is registered in is
// entirely farther than that, it can't be there. A world map draws the reachable circle and
// the country; the table says why for each address. Where the capture was made is a setting
// (by default the place this computer's time zone is named after).
// Everything from the network is rendered with textContent only.
"use strict";

const physicsView = { selected: "", world: null, worldLoading: false, editing: false };
const PHYS_VERDICT = { impossible: "✗ Can't be there", local: "Same building or town", possible: "Possible", unknown: "Unknown" };
const PHYS_W = 1000, PHYS_H = 500;

function physTz() {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch { return ""; }
}

function physProject(lon, lat) {
  return [((lon + 180) / 360) * PHYS_W, ((90 - lat) / 180) * PHYS_H];
}

// The places at most `km` from (lat, lon): a circle on the globe, as rings split where they
// cross the 180° meridian.
function physCircle(lat, lon, km) {
  const R = 6371.0088, d = km / R, p1 = (lat * Math.PI) / 180, l1 = (lon * Math.PI) / 180;
  const rings = [[]];
  let prev = null;
  for (let b = 0; b <= 360; b += 2) {
    const t = (b * Math.PI) / 180;
    const p2 = Math.asin(Math.sin(p1) * Math.cos(d) + Math.cos(p1) * Math.sin(d) * Math.cos(t));
    let l2 = l1 + Math.atan2(Math.sin(t) * Math.sin(d) * Math.cos(p1), Math.cos(d) - Math.sin(p1) * Math.sin(p2));
    l2 = ((((l2 * 180) / Math.PI) + 540) % 360) - 180;
    const pt = [l2, (p2 * 180) / Math.PI];
    if (prev && Math.abs(pt[0] - prev[0]) > 180) rings.push([]);
    rings[rings.length - 1].push(pt);
    prev = pt;
  }
  return rings;
}

function physPath(points, close) {
  return points.map(([lon, lat], i) => {
    const [x, y] = physProject(lon, lat);
    return `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
  }).join("") + (close ? "Z" : "");
}

function physMap(d) {
  const box = el("div", { class: "phys-map" });
  const map = svg("svg", { viewBox: `0 0 ${PHYS_W} ${PHYS_H}`, role: "img", "aria-label": "World map: the capture point and how far the selected server can be" });
  box.append(map);
  if (!physicsView.world) {
    if (!physicsView.worldLoading) {
      physicsView.worldLoading = true;
      api("/api/physics/world").then((w) => { physicsView.world = w.countries; RX.rerender(); })
        .catch(() => {}).finally(() => { physicsView.worldLoading = false; });
    }
    box.append(el("p", { class: "muted small" }, "Drawing the map…"));
    return box;
  }
  const row = d.rows.find((r) => r.addr === physicsView.selected);
  map.append(svg("rect", { x: 0, y: 0, width: PHYS_W, height: PHYS_H, class: "phys-sea" }));
  const g = svg("g", { class: "phys-land" });
  for (const [cc, rings] of Object.entries(physicsView.world)) {
    const cls = row && cc === row.country ? (row.verdict === "impossible" ? "phys-country bad" : "phys-country good") : "phys-country";
    g.append(svg("path", { d: rings.map((r) => physPath(r, true)).join(""), class: cls }, ""));
  }
  map.append(g);
  if (d.point) {
    if (row) {
      if (row.limit_km >= 20015) {
        map.append(svg("rect", { x: 0, y: 0, width: PHYS_W, height: PHYS_H, class: "phys-reach" }));
      } else {
        for (const ring of physCircle(d.point.lat, d.point.lon, row.limit_km)) {
          if (ring.length > 1) map.append(svg("path", { d: physPath(ring, false), class: "phys-reach-line" }));
        }
      }
    }
    const [x, y] = physProject(d.point.lon, d.point.lat);
    map.append(svg("circle", { cx: x.toFixed(1), cy: y.toFixed(1), r: 4, class: "phys-point" }),
      svg("text", { x: (x > PHYS_W * 0.75 ? x - 7 : x + 7).toFixed(1), y: (y - 6).toFixed(1), class: "phys-label",
        "text-anchor": x > PHYS_W * 0.75 ? "end" : "start" }, `Capture point: ${d.point.label}`));
  }
  const caption = el("p", { class: "small phys-caption" });
  if (row) {
    caption.append(el("strong", { class: "mono" }, row.addr), document.createTextNode(`${row.name ? ` (${row.name})` : ""}: ${row.why} `));
    const go = el("button", { type: "button", class: "link" }, "Show its packets");
    go.addEventListener("click", () => RX.showPackets(row.filter));
    caption.append(go);
  } else {
    caption.textContent = "Click a row to draw how far that server can be (the circle) and the country its network is registered in "
      + "(red when it can't be there).";
  }
  box.append(caption);
  return box;
}

function physPointBar(d) {
  const bar = el("div", { class: "phys-point-bar" });
  const s = d.setting || { mode: "auto" };
  const where = !d.point ? (s.mode === "off" ? "not set (nothing is judged)" : "unknown (set it to judge where servers can be)")
    : `${d.point.label} (${d.point.how === "time zone" ? "from this computer's time zone" : "set by you"})`;
  bar.append(el("span", {}, "Where the capture was made: "), el("strong", {}, where), document.createTextNode(" "));
  const change = el("button", { type: "button", class: "link" }, physicsView.editing ? "Cancel" : "Change…");
  change.addEventListener("click", () => { physicsView.editing = !physicsView.editing; RX.rerender(); });
  bar.append(change);
  if (!physicsView.editing) return bar;

  const form = el("form", { class: "phys-point-form" });
  const pick = el("select", { class: "tb", "aria-label": "A place" });
  pick.append(el("option", { value: "auto" }, `This computer's time zone (${physTz() || "unknown"})`),
    el("option", { value: "coords" }, "Coordinates…"), el("option", { value: "off" }, "Don't judge (off)"));
  for (const p of d.places || []) pick.append(el("option", { value: `zone:${p.zone}` }, p.label));
  pick.value = s.mode === "zone" ? `zone:${s.zone}` : s.mode;
  const lat = el("input", { type: "text", class: "tb mono", placeholder: "latitude, e.g. 40.71", "aria-label": "Latitude", size: "12" });
  const lon = el("input", { type: "text", class: "tb mono", placeholder: "longitude, e.g. -74.01", "aria-label": "Longitude", size: "12" });
  const label = el("input", { type: "text", class: "tb", placeholder: "name (optional)", "aria-label": "Name of the place", maxlength: "80" });
  if (s.mode === "coords") { lat.value = s.lat; lon.value = s.lon; label.value = s.label || ""; }
  const coords = el("span", { class: "phys-coords" });
  coords.append(lat, lon, label);
  const sync = () => { coords.hidden = pick.value !== "coords"; };
  pick.addEventListener("change", sync);
  sync();
  const save = el("button", { type: "submit", class: "tb tb-primary" }, "Save");
  const err = el("span", { class: "error small" });
  form.append(pick, coords, save, err);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const v = pick.value;
    const point = v.startsWith("zone:") ? { mode: "zone", zone: v.slice(5) }
      : v === "coords" ? { mode: "coords", lat: lat.value, lon: lon.value, label: label.value } : { mode: v };
    try {
      await api("/api/physics/point", "PUT", { point });
      physicsView.editing = false;
      for (const k of Object.keys(invData)) if (k.startsWith("physics|")) delete invData[k];
      RX.rerender();
    } catch (ex) { err.textContent = ex.message; }
  });
  bar.append(form);
  return bar;
}

TOOLS.physics = (box) => {
  const slot = invGet("physics", `/api/physics?places=1&tz=${encodeURIComponent(physTz())}`);
  if (invPending(box, slot, "the handshakes")) return;
  const d = slot.data;
  box.append(el("p", { class: "tool-note" }, "Nothing travels faster than light. A server's TCP handshake can't come back sooner than light "
    + "takes to reach it and return, so a server that answered in 6 ms is at most 900 km from where the capture was made. When the "
    + "country its network is registered in is farther than that, the server can't be there: a CDN, a cloud region, a VPN exit, or "
    + "something on the path answering for it. The check uses light in a vacuum, the fastest handshake, and a margin for the map's "
    + "borders, so a “can't be there” is a fact, not a guess."));
  box.append(physPointBar(d));
  if (!d.rows.length) {
    box.append(el("p", { class: "empty" }, "No internet servers with a complete TCP handshake in these packets."));
    return;
  }
  const c = d.counts;
  tiles(box, [["Can't be where registered", fmtNum(c.impossible), "physically impossible"], ["Same building or town", fmtNum(c.local), "under 1 ms"],
    ["Possible", fmtNum(c.possible), "the registered country is in reach"], ["Unknown", fmtNum(c.unknown), "no country, or no capture point"]]);
  if (d.note) box.append(el("p", { class: "phys-note" }, `⚠ ${d.note}`));
  if (!physicsView.selected || !d.rows.some((r) => r.addr === physicsView.selected)) {
    physicsView.selected = (d.rows.find((r) => r.verdict === "impossible") || d.rows[0]).addr;
  }
  box.append(physMap(d));
  section(box, "Servers and clients", "fastest handshake first within each verdict; click a row to draw it");
  dataTable(box, "physics", [
    { label: "Address", type: "text", get: (r) => r.addr + (r.name ? ` (${r.name})` : "") },
    { label: "Role", type: "text", get: (r) => r.role },
    { label: "Network (registered in)", type: "text", get: (r) => [r.as_name, r.country_name || r.country].filter(Boolean).join(" · ") },
    { label: "Fastest handshake (ms)", type: "num", get: (r) => r.fastest_ms, title: "SYN to SYN/ACK (a server), SYN/ACK to ACK (a client)" },
    { label: "At most (km)", type: "num", get: (r) => r.limit_km, title: "Light in a vacuum, there and back, in the fastest handshake" },
    { label: "Country at least (km)", type: "num", get: (r) => r.min_km, title: "The registered country's nearest edge, less a safety margin" },
    { label: "Verdict", type: "text", get: (r) => PHYS_VERDICT[r.verdict] || r.verdict },
  ], d.rows, { defaultSort: { col: -1, dir: 1 }, onRow: (e, r) => { physicsView.selected = r.addr; RX.rerender(); } });
};
