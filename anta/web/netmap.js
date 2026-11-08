// Network map: every host in the capture as a node, conversations as lines,
// each node labelled with what the capture says it is (router, DNS server, web
// server, client device, internet host…) and why. Shape and text carry the
// role as well as color, so it never relies on color alone.
// Clicking a host offers its packets and the map's own focus: some hosts, each alone or
// with everything it talks with (nmap.focus: id → { peers }), lit up while the rest of the
// map fades back (nmap.lit). Shift-click adds a host to the focus or takes it out.
"use strict";

const nmap = {
  layout: "grouped", limit: 80, showGroups: false, labels: true, selected: null, query: "",
  nodes: [], edges: [], pos: new Map(), view: { x: 0, y: 0, k: 1 }, key: null, focus: new Map(), lit: null,
};

const KIND_STYLE = {
  router: { label: "Router / gateway", color: "--text", shape: "diamond" },
  infra: { label: "Infrastructure (DNS, DHCP, domain controller)", color: "--accent", shape: "triangle" },
  server: { label: "Server", color: "--accent", shape: "square" },
  client: { label: "Client device", color: "--dim", shape: "circle" },
  internet: { label: "Internet host", color: "--dim", shape: "hexagon" },
  multicast: { label: "Multicast group", color: "--dim", shape: "ring" },
  broadcast: { label: "Broadcast", color: "--dim", shape: "ring" },
  unspecified: { label: "Unconfigured (0.0.0.0)", color: "--rule", shape: "ring" },
};
const GROUP_KINDS = new Set(["multicast", "broadcast", "unspecified"]);
const LOCAL_SCOPES = new Set(["private", "link-local", "cgnat", "loopback", "unknown"]);

function nodeColor(n) { return cssVar(KIND_STYLE[n.kind]?.color || "--dim"); }

function shapePath(shape, r) {
  switch (shape) {
    case "square": return `M${-r * 0.88},${-r * 0.88}h${r * 1.76}v${r * 1.76}h${-r * 1.76}z`;
    case "diamond": return `M0,${-r * 1.15}L${r * 1.15},0L0,${r * 1.15}L${-r * 1.15},0z`;
    case "triangle": return `M0,${-r * 1.2}L${r * 1.1},${r * 0.8}L${-r * 1.1},${r * 0.8}z`;
    case "hexagon": {
      let d = "";
      for (let i = 0; i < 6; i++) {
        const a = (Math.PI / 3) * i + Math.PI / 6;
        d += `${i ? "L" : "M"}${(r * Math.cos(a)).toFixed(1)},${(r * Math.sin(a)).toFixed(1)}`;
      }
      return `${d}z`;
    }
    default: return `M${r},0A${r},${r} 0 1,1 ${-r},0A${r},${r} 0 1,1 ${r},0z`;
  }
}

// ------------------------------------------------------------- data

function mapModel() {
  const s = window.statsData();
  return s && s.map;
}

function visibleGraph() {
  const model = mapModel();
  if (!model) return { nodes: [], edges: [] };
  let nodes = model.nodes.filter((n) => nmap.showGroups || !GROUP_KINDS.has(n.kind));
  nodes = nodes.slice(0, nmap.limit);
  const ids = new Set(nodes.map((n) => n.id));
  // The selected host and everything in the focus are on the map even past "Show top".
  for (const id of [nmap.selected, ...(focusLit(model) || [])]) {
    const x = id && !ids.has(id) && model.nodes.find((n) => n.id === id);
    if (x) { nodes.push(x); ids.add(id); }
  }
  const edges = model.edges.filter((e) => ids.has(e.a) && ids.has(e.b));
  return { nodes, edges };
}

// The hosts a host talks with, either way (multicast and broadcast only when they are shown).
function peersOf(model, id) {
  const kinds = new Map(model.nodes.map((n) => [n.id, n.kind]));
  const out = new Set();
  for (const e of model.edges) {
    const other = e.a === id ? e.b : e.b === id ? e.a : null;
    if (other && kinds.has(other) && (nmap.showGroups || !GROUP_KINDS.has(kinds.get(other)))) out.add(other);
  }
  return out;
}

// What the focus lights up: the focused hosts and, for those opened up, every host they talk
// with (null: no focus). Lit conversations are those of a focused host with another lit one.
function focusLit(model) {
  if (!nmap.focus.size || !model) return null;
  const known = new Set(model.nodes.map((n) => n.id));
  const lit = new Set();
  for (const [id, f] of nmap.focus) {
    if (!known.has(id)) continue;
    lit.add(id);
    if (f.peers) for (const p of peersOf(model, id)) lit.add(p);
  }
  return lit;
}
function edgeLit(e) {
  return nmap.lit && nmap.lit.has(e.a) && nmap.lit.has(e.b) && (nmap.focus.has(e.a) || nmap.focus.has(e.b));
}

// ---------------------------------------------------------- layouts

function ipSortKey(addr) {
  if (addr.includes(".")) return addr.split(".").map((p) => p.padStart(3, "0")).join(".");
  return addr;
}

function layoutGrouped(nodes, W, H) {
  const pos = new Map();
  const local = [], gateways = [], internet = [], groups = [];
  for (const n of nodes) {
    if (GROUP_KINDS.has(n.kind)) groups.push(n);
    else if (n.kind === "router") gateways.push(n);
    else if (LOCAL_SCOPES.has(n.scope)) local.push(n);
    else internet.push(n);
  }
  const order = { infra: 0, server: 1, client: 2 };
  local.sort((a, b) => (order[a.kind] ?? 3) - (order[b.kind] ?? 3) || ipSortKey(a.addr).localeCompare(ipSortKey(b.addr)));
  internet.sort((a, b) => b.tx_bytes + b.rx_bytes - (a.tx_bytes + a.rx_bytes));
  gateways.sort((a, b) => ipSortKey(a.addr).localeCompare(ipSortKey(b.addr)));
  // Busier columns get more room, so crowded labels stay readable.
  const weight = (n, lo, hi) => Math.max(lo, Math.min(hi, Math.sqrt(n) / 2));
  const cols = [];
  if (groups.length) cols.push({ name: "Broadcast & multicast", list: groups, weight: weight(groups.length, 0.5, 1) });
  cols.push({ name: "Local network", list: local, weight: weight(local.length, 0.9, 3) });
  if (gateways.length) cols.push({ name: "Gateways", list: gateways, weight: weight(gateways.length, 0.6, 1) });
  if (internet.length) cols.push({ name: "Internet", list: internet, weight: weight(internet.length, 0.9, 3) });
  const totalW = cols.reduce((a, c) => a + c.weight, 0);
  const rowH = 58;
  let x0 = 40;
  const span = W - 80;
  const headers = [];
  for (const c of cols) {
    const cw = (span * c.weight) / totalW;
    const perCol = Math.max(1, Math.floor((H - 90) / rowH));
    const sub = Math.max(1, Math.ceil(c.list.length / perCol));
    const subW = cw / sub;
    const rows = Math.min(perCol, c.list.length);
    const startY = 70 + Math.max(0, ((H - 90) - rows * rowH) / 2);
    c.list.forEach((n, i) => {
      const col = Math.floor(i / perCol), row = i % perCol;
      pos.set(n.id, { x: x0 + subW * (col + 0.5), y: startY + row * rowH + rowH / 2, room: subW });
    });
    headers.push({ name: c.name, x: x0 + cw / 2, count: c.list.length });
    x0 += cw;
  }
  return { pos, headers };
}

function layoutForce(nodes, edges, W, H, seed) {
  const pts = nodes.map((n, i) => {
    const p = seed.get(n.id) || { x: W / 2 + Math.cos(i) * 100, y: H / 2 + Math.sin(i) * 100 };
    return { id: n.id, x: p.x, y: p.y, vx: 0, vy: 0, w: Math.sqrt(1 + (n.tx_bytes + n.rx_bytes) / 1e5) };
  });
  const index = new Map(pts.map((p, i) => [p.id, i]));
  const links = edges.map((e) => [index.get(e.a), index.get(e.b), e.bytes]);
  const degree = new Array(pts.length).fill(0);
  for (const [i, j] of links) { degree[i]++; degree[j]++; }
  const ticks = pts.length > 250 ? 70 : pts.length > 120 ? 140 : 260;
  const k = Math.sqrt((W * H) / Math.max(1, pts.length)) * 0.75;
  const reach = 9 * k * k;  // repulsion only within three ideal edge lengths, so loners don't fly off
  for (let t = 0; t < ticks; t++) {
    const alpha = 1 - t / ticks;
    for (let i = 0; i < pts.length; i++) {
      const a = pts[i];
      for (let j = i + 1; j < pts.length; j++) {
        const b = pts[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy;
        if (d2 > reach) continue;
        if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
        const f = (k * k) / d2;
        a.vx += dx * f * 0.02; a.vy += dy * f * 0.02;
        b.vx -= dx * f * 0.02; b.vy -= dy * f * 0.02;
      }
    }
    for (const [i, j] of links) {
      const a = pts[i], b = pts[j];
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const f = ((d - k) / d) * 0.06;
      a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
    }
    pts.forEach((p, i) => {
      const pull = degree[i] ? 0.004 : 0.03;  // hosts with no drawn conversation stay near the middle
      p.vx += (W / 2 - p.x) * pull; p.vy += (H / 2 - p.y) * pull;
      const v = Math.sqrt(p.vx * p.vx + p.vy * p.vy);
      const cap = 30 * alpha + 1;
      if (v > cap) { p.vx *= cap / v; p.vy *= cap / v; }
      p.x += p.vx; p.y += p.vy;
      p.vx *= 0.6; p.vy *= 0.6;
    });
  }
  return new Map(pts.map((p) => [p.id, { x: p.x, y: p.y }]));
}

// ----------------------------------------------------------- render

const mapSvg = $("map-svg");
let mapHeaders = [];

function mapRender(relayout = true) {
  const model = mapModel();
  const canvas = $("map-canvas");
  $("map-empty").hidden = !!(model && model.nodes.length);
  if (!model || !model.nodes.length) {
    $("map-empty").textContent = !sessionActive() ? "Open a capture to map the hosts in it."
      : window.statsData().loading ? "Mapping hosts…" : "No IP hosts in this capture.";
    mapSvg.replaceChildren();
    $("map-legend").replaceChildren();
    return;
  }
  const { nodes, edges } = visibleGraph();
  nmap.nodes = nodes;
  nmap.edges = edges;
  nmap.lit = focusLit(model);
  mapSvg.classList.toggle("map-focused", Boolean(nmap.lit));
  renderFocusStrip();
  const W = canvas.clientWidth || 900, H = canvas.clientHeight || 600;
  mapSvg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  if (relayout) {
    const g = layoutGrouped(nodes, W, H);
    mapHeaders = nmap.layout === "grouped" ? g.headers : [];
    nmap.pos = nmap.layout === "grouped" ? g.pos : layoutForce(nodes, edges, W, H, g.pos);
  }
  $("map-limit-text").textContent = `${nodes.length} of ${model.nodes.length} hosts`;

  const maxBytes = Math.max(1, ...nodes.map((n) => n.tx_bytes + n.rx_bytes));
  const maxEdge = Math.max(1, ...edges.map((e) => e.bytes));
  const radius = (n) => 7 + 13 * Math.sqrt((n.tx_bytes + n.rx_bytes) / maxBytes);

  const title = mapSvg.querySelector("title");
  const vp = svg("g", { class: "map-vp", transform: `translate(${nmap.view.x},${nmap.view.y}) scale(${nmap.view.k})` });
  for (const h of mapHeaders) vp.append(svg("text", { x: h.x, y: 34, class: "map-col", "text-anchor": "middle" }, `${h.name} (${h.count})`));
  const ge = svg("g", { class: "edges" }), gn = svg("g", { class: "nodes" });
  for (const e of edges) {
    const a = nmap.pos.get(e.a), b = nmap.pos.get(e.b);
    if (!a || !b) continue;
    const w = 1 + 4 * (Math.log(1 + e.bytes) / Math.log(1 + maxEdge));
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2 - (nmap.layout === "grouped" ? Math.abs(b.x - a.x) * 0.08 : 0);
    const path = svg("path", { d: `M${a.x},${a.y}Q${mx},${my} ${b.x},${b.y}`, class: `edge${edgeLit(e) ? " lit" : ""}`, "stroke-width": w.toFixed(2),
      "data-a": e.a, "data-b": e.b });
    path.addEventListener("mousemove", (evt) => {
      const apps = Object.entries(e.apps || {}).sort((x, y) => y[1] - x[1]).slice(0, 4).map(([k, v]) => `${k} ${fmtBytes(v)}`).join(", ");
      showTip(evt, [[`${labelOf(e.a)} ↔ ${labelOf(e.b)}`], ["Traffic", `${fmtBytes(e.bytes)} in ${fmtNum(e.packets)} packets`],
        [`${e.a} → ${e.b}`, fmtBytes(e.a_to_b)], [`${e.b} → ${e.a}`, fmtBytes(e.b_to_a)], ...(apps ? [["Protocols", apps]] : [])]);
      path.classList.add("hover");
    });
    path.addEventListener("mouseleave", () => { hideTip(); path.classList.remove("hover"); });
    path.addEventListener("click", () => showPacketsFor(`${e.a.includes(":") ? "ipv6" : "ip"}.addr == ${e.a} && ${e.a.includes(":") ? "ipv6" : "ip"}.addr == ${e.b}`));
    ge.append(path);
  }
  const q = nmap.query.toLowerCase();
  for (const n of nodes) {
    const p = nmap.pos.get(n.id);
    if (!p) continue;
    const st = KIND_STYLE[n.kind] || KIND_STYLE.client;
    const r = radius(n);
    const g = svg("g", { class: `node k-${n.kind}`, transform: `translate(${p.x.toFixed(1)},${p.y.toFixed(1)})`, "data-id": n.id,
      "data-q": n.addr });
    if (n.id === nmap.selected) g.classList.add("selected");
    if (nmap.focus.has(n.id)) g.classList.add("focused");
    if (nmap.lit && nmap.lit.has(n.id)) g.classList.add("lit");
    if (q && (n.addr.toLowerCase().includes(q) || (n.name || "").toLowerCase().includes(q) ||
        n.names.some(([nm]) => nm.toLowerCase().includes(q)))) g.classList.add("found");
    const shape = svg("path", { d: shapePath(st.shape, r), class: st.shape === "ring" ? "shape ring" : "shape" });
    shape.style.setProperty("--node", nodeColor(n));
    const alerts = alertsFor(n.addr);
    g.append(svg("circle", { r: r + 8, class: "node-hit" }));
    if (nmap.focus.has(n.id)) g.append(svg("circle", { r: r + 10, class: "focus-ring" }));
    if (alerts.length) {  // severity ring, plus a marker in the label so it isn't color alone
      g.classList.add("alerted");
      g.append(svg("circle", { r: r + 5, class: `alert-ring ${alerts[0].severity}` }));
    }
    g.append(shape);
    if (nmap.labels) {
      // Labels get the width of their column (a crowded column gets short labels).
      const chars = p.room ? Math.max(8, Math.floor((p.room - 8) / 6.4)) : 26;
      const name = truncate(n.name || n.addr, Math.min(26, chars));
      const sub = n.name ? `${n.addr} · ${n.role}` : n.role;
      g.append(svg("text", { y: r + 13, class: "nlabel", "text-anchor": "middle" }, alerts.length ? `⚠ ${name}` : name));
      if (!p.room || p.room >= 120) g.append(svg("text", { y: r + 25, class: "nsub", "text-anchor": "middle" }, truncate(sub, chars + 4)));
    }
    g.addEventListener("mouseenter", () => highlight(n.id, true));
    g.addEventListener("mouseleave", () => highlight(n.id, false));
    g.addEventListener("mousemove", (evt) => showTip(evt, [[n.name || n.addr], ["Role", n.role], ["Address", n.addr],
      ["Traffic", `${fmtBytes(n.tx_bytes)} sent · ${fmtBytes(n.rx_bytes)} received`]]));
    g.addEventListener("mouseleave", hideTip);
    g.addEventListener("contextmenu", (evt) => {
      evt.preventDefault();
      mapSelect(n.id);
      nodeMenu(n, evt.clientX, evt.clientY);
    });
    nodeDrag(g, n);
    gn.append(g);
  }
  vp.append(ge, gn);
  mapSvg.replaceChildren(title, vp);
  renderLegend(model, nodes);
  if (nmap.selected) renderSide(model.nodes.find((n) => n.id === nmap.selected));
}

function truncate(s, n) { return s.length > n ? `${s.slice(0, n - 1)}…` : s; }
function labelOf(id) { const n = nmap.nodes.find((x) => x.id === id); return n ? n.name || n.addr : id; }

function highlight(id, on) {
  const near = new Set([id]);
  if (on) for (const e of nmap.edges) { if (e.a === id) near.add(e.b); if (e.b === id) near.add(e.a); }
  mapSvg.classList.toggle("focusing", on);
  for (const g of mapSvg.querySelectorAll(".node")) g.classList.toggle("near", on && near.has(g.dataset.id));
  for (const p of mapSvg.querySelectorAll(".edge")) p.classList.toggle("near", on && (p.dataset.a === id || p.dataset.b === id));
}

function renderLegend(model, nodes) {
  const legend = $("map-legend");
  legend.replaceChildren();
  const counts = {};
  for (const n of model.nodes) counts[n.kind] = (counts[n.kind] || 0) + 1;
  for (const [kind, st] of Object.entries(KIND_STYLE)) {
    if (!counts[kind]) continue;
    const item = el("span", { class: "key" });
    const sw = svg("svg", { width: "16", height: "16", viewBox: "-9 -9 18 18", "aria-hidden": "true" });
    const p = svg("path", { d: shapePath(st.shape, 6), class: st.shape === "ring" ? "shape ring" : "shape" });
    p.style.setProperty("--node", cssVar(st.color));
    sw.append(p);
    item.append(sw, document.createTextNode(`${st.label} · ${counts[kind]}`));
    legend.append(item);
  }
  if (model.nodes.some((n) => alertsFor(n.addr).length)) {
    const item = el("span", { class: "key" });
    const sw = svg("svg", { width: "16", height: "16", viewBox: "-9 -9 18 18", "aria-hidden": "true" });
    sw.append(svg("circle", { r: 6, class: "alert-ring critical" }));
    item.append(sw, document.createTextNode("⚠ In an alert"));
    legend.append(item);
  }
  legend.append(el("span", { class: "muted small" }, "Size: traffic · Lines: conversations (click one for its packets) · Click a host for its packets and to focus on it; Shift-click adds it to the focus"));
}

// ----------------------------------------------------------- details

// Alerts (medium and above) that involve an address, most severe first.
const ALERT_RANK = { critical: 0, high: 1, medium: 2 };
function alertsFor(addr) {
  return [...state.alerts.values()]
    .filter((a) => a.severity in ALERT_RANK && (a.src_ip === addr || a.dst_ip === addr))
    .sort((x, y) => ALERT_RANK[x.severity] - ALERT_RANK[y.severity]);
}

function renderSide(n) {
  const side = $("map-side");
  side.replaceChildren();
  if (!n) { side.append(el("p", { class: "muted" }, "Select a host to see what it is and why.")); return; }
  const st = KIND_STYLE[n.kind] || KIND_STYLE.client;
  const head = el("div", { class: "side-head" });
  const sw = svg("svg", { width: "22", height: "22", viewBox: "-11 -11 22 22", "aria-hidden": "true" });
  const p = svg("path", { d: shapePath(st.shape, 8), class: st.shape === "ring" ? "shape ring" : "shape" });
  p.style.setProperty("--node", nodeColor(n));
  sw.append(p);
  head.append(sw, el("h2", {}, n.name || n.addr));
  side.append(head);
  side.append(el("p", { class: "side-role" }, n.role));
  const alerts = alertsFor(n.addr);
  if (alerts.length) {
    const box = el("div", { class: "side-alerts" });
    box.append(el("h4", {}, `⚠ ${alerts.length === 1 ? "1 alert involves" : `${alerts.length} alerts involve`} this host`));
    for (const a of alerts.slice(0, 6)) {
      const b = el("button", { type: "button", class: "link side-alert" });
      b.append(el("span", { class: `sev-dot ${a.severity}` }), document.createTextNode(`${a.title} — ${a.target || ""}`));
      b.addEventListener("click", () => { setView("alerts"); select(a.id); });
      box.append(b);
    }
    side.append(box);
  }
  const dl = el("dl", { class: "kv" });
  const add = (k, v) => { if (v !== null && v !== undefined && v !== "") dl.append(el("dt", {}, k), el("dd", {}, v)); };
  add("Address", n.addr);
  add("Kind of address", n.tags.join(" · "));
  add("Operating system (guess)", n.os ? `${n.os} — from ${n.os_reason}` : null);
  add("Hardware vendor", n.vendor);
  add("Network owner", n.geo ? geoText(n.geo) : null);
  add("MAC address", (n.macs || []).join(", "));
  add("User account", (n.users || []).join(", "));
  add("Domain", (n.domains || []).join(", "));
  add("Sent", `${fmtBytes(n.tx_bytes)} in ${fmtNum(n.tx_packets)} packets`);
  add("Received", `${fmtBytes(n.rx_bytes)} in ${fmtNum(n.rx_packets)} packets`);
  add("Talks to", `${fmtNum(n.peers)} hosts`);
  add("Seen", n.first ? `${fmtDateTime(n.first)} – ${fmtTime(n.last)}` : null);
  side.append(dl);
  if (n.reasons.length) {
    side.append(el("h4", {}, "Why this label"));
    const ul = el("ul", { class: "reasons" });
    for (const r of n.reasons) ul.append(el("li", {}, r));
    side.append(ul);
  }
  if (n.device) {
    const d = n.device;
    side.append(el("h4", {}, `${d.kind} ${d.name}: all its addresses`));
    const ul = el("ul", { class: "mono-list" });
    for (const i of d.interfaces || []) {
      const li = el("li");
      li.append(el("span", {}, `${i.address}${i.prefix !== null && i.prefix !== undefined ? `/${i.prefix}` : ""}`),
        el("span", { class: "muted small" }, `  ${i.name}`));
      ul.append(li);
    }
    side.append(ul, el("p", { class: "muted small" }, `From ${d.evidence || d.source}`));
  }
  if (n.names.length) {
    side.append(el("h4", {}, "Names"));
    const ul = el("ul", { class: "mono-list" });
    for (const [name, src] of n.names) {
      const li = el("li");
      li.append(el("span", {}, name), el("span", { class: "muted small" }, `  from ${src}`));
      ul.append(li);
    }
    side.append(ul);
  }
  if (n.services.length) {
    side.append(el("h4", {}, "Services it answers"));
    const ul = el("ul", { class: "mono-list" });
    for (const s of n.services) ul.append(el("li", {}, `${s.name} — ${s.proto.toUpperCase()} ${s.port} (${fmtNum(s.count)})`));
    side.append(ul);
  }
  const peers = nmap.edges.filter((e) => e.a === n.id || e.b === n.id).sort((a, b) => b.bytes - a.bytes).slice(0, 8);
  if (peers.length) {
    side.append(el("h4", {}, "Busiest conversations"));
    const ul = el("ul", { class: "peer-list" });
    for (const e of peers) {
      const other = e.a === n.id ? e.b : e.a;
      const b = el("button", { type: "button", class: "link" }, labelOf(other));
      b.addEventListener("click", () => mapSelect(other, true));
      const li = el("li");
      li.append(b, el("span", { class: "muted small" }, `  ${fmtBytes(e.bytes)}`));
      ul.append(li);
    }
    side.append(ul);
  }
  const fam = n.addr.includes(":") ? "ipv6" : "ip";
  const actions = el("div", { class: "side-actions" });
  const btn = (label, fn, primary) => {
    const b = el("button", { type: "button", class: `tb${primary ? " tb-primary" : ""}` }, label);
    b.addEventListener("click", fn);
    actions.append(b);
  };
  btn("Show its packets", () => showPacketsFor(`${fam}.addr == ${n.addr}`), true);
  btn("Packets it sent", () => showPacketsFor(`${fam}.src == ${n.addr}`));
  btn("Conversations", () => {
    const s = window.statsData();
    s.tool = "conversations";
    s.convTab = fam === "ipv6" ? "ipv6" : "ipv4";
    s.search[`conv-${s.convTab}`] = n.addr;
    setView("stats");
  });
  btn("Focus ▾", (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    showMenu(r.left, r.bottom + 4, focusItems(n));
  });
  btn("Copy address", () => copyText(n.addr));
  side.append(actions);
}

function mapSelect(id, center = false) {
  nmap.selected = id;
  if (typeof assetsView !== "undefined" && ADDR_TOKEN.test(id || "")) assetsView.selected = id;  // (the table picks it too)
  for (const g of mapSvg.querySelectorAll(".node")) g.classList.toggle("selected", g.dataset.id === id);
  const model = mapModel();
  if (!nmap.nodes.find((n) => n.id === id)) mapRender(true);
  renderSide(model && model.nodes.find((n) => n.id === id));
  if (center) centerOn(id);
}

function centerOn(id) {
  const p = nmap.pos.get(id);
  if (!p) return;
  const canvas = $("map-canvas");
  nmap.view.x = canvas.clientWidth / 2 - p.x * nmap.view.k;
  nmap.view.y = canvas.clientHeight / 2 - p.y * nmap.view.k;
  applyView();
}

function applyView() {
  mapSvg.querySelector(".map-vp")?.setAttribute("transform", `translate(${nmap.view.x},${nmap.view.y}) scale(${nmap.view.k})`);
}

// Frame the whole map, or only some hosts (a Set of ids: the focus).
function fit(only) {
  const some = only instanceof Set ? [...only].map((id) => nmap.pos.get(id)).filter(Boolean) : null;
  const pts = some && some.length ? some : [...nmap.pos.values()];
  const canvas = $("map-canvas");
  if (!pts.length) return;
  const xs = pts.map((p) => p.x), ys = pts.map((p) => p.y);
  const minX = Math.min(...xs) - 60, maxX = Math.max(...xs) + 60, maxY = Math.max(...ys) + 60;
  const minY = Math.min(Math.min(...ys) - 50, mapHeaders.length && !some ? 14 : Infinity);  // keep the column titles
  // The legend floats over the bottom of the canvas: frame the map above it.
  const legend = $("map-legend");
  const reserved = legend && legend.childElementCount ? legend.offsetHeight + 16 : 0;
  const strip = $("map-focus");  // (and the focus strip over its top)
  const top = strip && !strip.hidden ? strip.offsetHeight + 8 : 0;
  const W = canvas.clientWidth, H = Math.max(120, canvas.clientHeight - reserved - top);
  const k = Math.min(2, Math.max(0.2, Math.min(W / (maxX - minX), H / (maxY - minY))));
  nmap.view = { k, x: (W - (minX + maxX) * k) / 2, y: top + (H - (minY + maxY) * k) / 2 };
  applyView();
}

// --------------------------------------------------------- interaction

function svgPoint(evt) {
  const r = mapSvg.getBoundingClientRect();
  const vb = mapSvg.viewBox.baseVal;
  return { x: ((evt.clientX - r.left) / r.width) * vb.width, y: ((evt.clientY - r.top) / r.height) * vb.height };
}

let drag = null;
function nodeDrag(g, n) {
  g.addEventListener("pointerdown", (evt) => {
    evt.stopPropagation();
    g.setPointerCapture(evt.pointerId);
    const p0 = svgPoint(evt);
    const start = { ...nmap.pos.get(n.id) };
    drag = { node: n, g, p0, start, moved: false };
  });
  g.addEventListener("pointermove", (evt) => {
    if (!drag || drag.node !== n) return;
    const p = svgPoint(evt);
    const dx = (p.x - drag.p0.x) / nmap.view.k, dy = (p.y - drag.p0.y) / nmap.view.k;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    if (!drag.moved) return;
    const pos = { ...drag.start, x: drag.start.x + dx, y: drag.start.y + dy };
    nmap.pos.set(n.id, pos);
    g.setAttribute("transform", `translate(${pos.x.toFixed(1)},${pos.y.toFixed(1)})`);
    for (const path of mapSvg.querySelectorAll(".edge")) {
      if (path.dataset.a !== n.id && path.dataset.b !== n.id) continue;
      const a = nmap.pos.get(path.dataset.a), b = nmap.pos.get(path.dataset.b);
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2 - (nmap.layout === "grouped" ? Math.abs(b.x - a.x) * 0.08 : 0);
      path.setAttribute("d", `M${a.x},${a.y}Q${mx},${my} ${b.x},${b.y}`);
    }
  });
  g.addEventListener("pointerup", (evt) => {
    if (drag && drag.node === n && !drag.moved && evt.button === 0) {
      mapSelect(n.id);
      if (evt.shiftKey) mapFocusToggle(n.id);  // (Shift-click: in or out of the focus, no menu)
      else nodeMenu(n, evt.clientX, evt.clientY);
    }
    drag = null;
  });
}

let pan = null;
mapSvg.addEventListener("pointerdown", (evt) => {
  if (evt.button !== 0 || evt.target.classList.contains("edge")) return;
  pan = { p0: svgPoint(evt), v0: { ...nmap.view } };
  mapSvg.setPointerCapture(evt.pointerId);
  mapSvg.classList.add("panning");
});
mapSvg.addEventListener("pointermove", (evt) => {
  if (!pan) return;
  const p = svgPoint(evt);
  nmap.view.x = pan.v0.x + (p.x - pan.p0.x);
  nmap.view.y = pan.v0.y + (p.y - pan.p0.y);
  applyView();
});
mapSvg.addEventListener("pointerup", () => { pan = null; mapSvg.classList.remove("panning"); });
mapSvg.addEventListener("wheel", (evt) => {
  evt.preventDefault();
  const p = svgPoint(evt);
  const k = Math.min(4, Math.max(0.15, nmap.view.k * Math.exp(-evt.deltaY * 0.0015)));
  nmap.view.x = p.x - ((p.x - nmap.view.x) * k) / nmap.view.k;
  nmap.view.y = p.y - ((p.y - nmap.view.y) * k) / nmap.view.k;
  nmap.view.k = k;
  applyView();
}, { passive: false });
$("map-canvas").addEventListener("keydown", (e) => {
  if (e.target !== e.currentTarget) return;  // (the focus strip's own buttons)
  const step = 40;
  if (e.key === "ArrowLeft") nmap.view.x += step;
  else if (e.key === "ArrowRight") nmap.view.x -= step;
  else if (e.key === "ArrowUp") nmap.view.y += step;
  else if (e.key === "ArrowDown") nmap.view.y -= step;
  else if (e.key === "+" || e.key === "=") nmap.view.k = Math.min(4, nmap.view.k * 1.2);
  else if (e.key === "-") nmap.view.k = Math.max(0.15, nmap.view.k / 1.2);
  else if (e.key === "0") return fit();
  else if ((e.key === "Enter" || e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey)) && nmap.selected) {
    e.preventDefault();
    const n = nmap.nodes.find((x) => x.id === nmap.selected);
    const g = mapSvg.querySelector(`.node[data-id="${CSS.escape(nmap.selected)}"]`);
    if (n && g) { const r = g.getBoundingClientRect(); nodeMenu(n, r.left + r.width / 2, r.top + r.height / 2); }
    return;
  } else return;
  e.preventDefault();
  applyView();
});

// ------------------------------------------------------- menu & focus

function nodeMenu(n, x, y) {
  hideTip();
  const v = n.addr.includes(":") ? "ipv6" : "ip";
  const others = [...nmap.focus.keys()].filter((id) => id !== n.id && ADDR_TOKEN.test(id));
  const some = [
    { label: "What it sent", action: () => showPacketsFor(`${v}.src == ${n.addr}`) },
    { label: "What was sent to it", action: () => showPacketsFor(`${v}.dst == ${n.addr}`) },
  ];
  if (others.length) {
    some.push({ label: "Between it and the other focused hosts", action: () => showPacketsFor(
      `${v}.addr == ${n.addr} && (${others.map((o) => `${o.includes(":") ? "ipv6" : "ip"}.addr == ${o}`).join(" || ")})`) });
  }
  showMenu(x, y, [
    { caption: n.name ? `${n.name} · ${n.addr}` : n.addr, kind: n.role },
    { label: "See its packets", action: () => showPacketsFor(`${v}.addr == ${n.addr}`) },
    { label: "See some of its packets", submenu: some },
    { separator: true },
    ...focusItems(n),
    { separator: true },
    { label: "Host details", action: () => window.openHost(n.addr) },
    { label: "Block it…", hint: "network rules", action: () => window.openPolicy({ add: `block ${n.addr}` }) },
    { label: "Copy address", action: () => copyText(n.addr) },
  ]);
}

// What the map can focus on from a host, given the focus it already has.
function focusItems(n) {
  const model = mapModel();
  const count = model ? peersOf(model, n.id).size : 0;
  const peersHint = `${fmtNum(count)} host${count === 1 ? "" : "s"}`;
  const f = nmap.focus.get(n.id);
  const keep = () => [...nmap.focus.entries()].map(([id, x]) => [id, x.peers]);
  if (!nmap.focus.size) {
    return [{ label: "Focus on this", hint: "⇧-click", action: () => mapFocusSet([[n.id, false]]) },
      { label: "Focus on this + what it talks to and what talks to it", hint: peersHint, action: () => mapFocusSet([[n.id, true]]) }];
  }
  const only = f && nmap.focus.size === 1;
  const items = [];
  if (!f) {
    items.push({ label: "Add it to the focus", hint: "⇧-click", action: () => mapFocusSet([...keep(), [n.id, false]]) },
      { label: "Add it + what it talks to and what talks to it", hint: peersHint, action: () => mapFocusSet([...keep(), [n.id, true]]) });
  } else {
    items.push({ label: f.peers ? "Stop lighting up what it talks with" : "Add what it talks to and what talks to it",
      hint: f.peers ? "" : peersHint, action: () => mapFocusSet(keep().map(([id, p]) => [id, id === n.id ? !p : p])) });
    if (!only) items.push({ label: "Remove it from the focus", hint: "⇧-click", action: () => mapFocusSet(keep().filter(([id]) => id !== n.id)) });
  }
  if (!(only && !f.peers)) items.push({ label: "Focus on only this", action: () => mapFocusSet([[n.id, false]]) });
  if (!(only && f.peers)) {
    items.push({ label: "Focus on only this + what it talks to and what talks to it", hint: peersHint, action: () => mapFocusSet([[n.id, true]]) });
  }
  items.push({ label: "Clear the focus", action: () => mapFocusSet([]) });
  return items;
}

// Shift-click: a host joins the focus (alone), or leaves it.
function mapFocusToggle(id) {
  const keep = [...nmap.focus.entries()].map(([k, x]) => [k, x.peers]);
  mapFocusSet(nmap.focus.has(id) ? keep.filter(([k]) => k !== id) : [...keep, [id, false]]);
}

// Set the map's focus ([[id, with what it talks with], …]; none = no focus). The map stays
// where it is; it is laid out again only when hosts past "Show top" join or leave it.
function mapFocusSet(list, frame = false) {
  const before = nmap.nodes.map((n) => n.id).join("|");
  nmap.focus = new Map(list.map(([id, peers]) => [id, { peers: Boolean(peers) }]));
  const changed = visibleGraph().nodes.map((n) => n.id).join("|") !== before;
  mapRender(changed);
  if (frame && nmap.lit && nmap.lit.size) fit(nmap.lit);
  else if (changed) fit();
  if (nmap.selected) {
    const model = mapModel();
    renderSide(model && model.nodes.find((x) => x.id === nmap.selected));
  }
}

// The strip over the map while it is focused: on what, how many hosts are lit, and the way back.
function renderFocusStrip() {
  let strip = $("map-focus");
  if (!strip) {
    strip = el("div", { class: "map-focus", id: "map-focus", role: "region", "aria-label": "What the map is focused on", hidden: "" });
    $("map-canvas").append(strip);
  }
  strip.hidden = !nmap.focus.size;
  if (!nmap.focus.size) { strip.replaceChildren(); return; }
  const parts = [el("strong", {}, "Map focused on")];
  for (const [id, f] of nmap.focus) {
    const chip = el("span", { class: "map-focus-chip" });
    const go = el("button", { type: "button", class: "link mono", title: "Select it on the map" },
      `${labelOf(id)}${f.peers ? " + what it talks with" : ""}`);
    go.addEventListener("click", () => mapSelect(id, true));
    const x = el("button", { type: "button", class: "map-focus-x", title: "Remove it from the focus", "aria-label": `Remove ${id} from the focus` }, "×");
    x.addEventListener("click", () => mapFocusSet([...nmap.focus.entries()].filter(([k]) => k !== id).map(([k, v]) => [k, v.peers])));
    chip.append(go, x);
    parts.push(chip);
  }
  const lit = nmap.lit ? nmap.lit.size : 0;
  parts.push(el("span", { class: "muted" }, lit ? `${fmtNum(lit)} host${lit === 1 ? "" : "s"} lit up · Shift-click hosts to add or remove them`
    : "None of them are in the traffic shown."));
  const zoom = el("button", { type: "button", class: "tb small", title: "Zoom the map to the hosts that are lit up" }, "Zoom to them");
  zoom.disabled = !lit;
  zoom.addEventListener("click", () => fit(nmap.lit));
  const all = el("button", { type: "button", class: "tb small" }, "Clear the focus");
  all.addEventListener("click", () => mapFocusSet([]));
  parts.push(zoom, all);
  strip.replaceChildren(...parts);
}

// From elsewhere (the host panel): the map, focused on a host (and what it talks with).
window.mapFocusOn = (addr, peers = true) => {
  nmap.focus = new Map([[addr, { peers }]]);
  nmap.selected = addr;
  if (!viewIs("map")) setView("map");
  setTimeout(() => { mapRender(true); fit(nmap.lit || undefined); mapSelect(addr); }, 50);
};

// A new capture: the whole map again.
window.mapFocusReset = () => { nmap.focus = new Map(); };

// --------------------------------------------------------------- wiring

// A new layout puts nodes in new places: frame them again.
$("map-layout").addEventListener("change", (e) => { nmap.layout = e.target.value; mapRender(true); fit(); });
$("map-limit").addEventListener("input", (e) => { nmap.limit = Number(e.target.value); mapRender(true); fit(); });
$("map-groups").addEventListener("change", (e) => { nmap.showGroups = e.target.checked; mapRender(true); fit(); });
$("map-labels").addEventListener("change", (e) => { nmap.labels = e.target.checked; mapRender(false); });
$("map-fit").addEventListener("click", fit);
$("map-refresh").addEventListener("click", () => window.statsLoad(true));
$("map-search").addEventListener("input", (e) => {
  nmap.query = e.target.value.trim();
  mapRender(false);
  const first = mapSvg.querySelector(".node.found");
  if (first && nmap.query) centerOn(first.dataset.id);
});
$("map-search").addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const first = mapSvg.querySelector(".node.found");
  if (first) mapSelect(first.dataset.id, true);
});

window.mapStatsUpdated = () => {
  const model = mapModel();
  $("map-status").textContent = model ? `${fmtNum(model.total_hosts)} hosts${window.statsData().filter ? " (filtered)" : ""}` : "";
  if (viewIs("map")) { nmap.view = { x: 0, y: 0, k: 1 }; mapRender(true); fit(); }
};

window.mapFocus = (addr) => {
  nmap.selected = addr;
  setView("map");
  setTimeout(() => mapSelect(addr, true), 50);
};

viewHooks.map = () => {
  const s = window.statsData();
  if (!s.data || s.key !== statsKey()) {
    mapRender(true);
    window.statsLoad();
  } else {
    mapRender(true);
    fit();
  }
};
let mapResize;
window.addEventListener("resize", () => {
  clearTimeout(mapResize);
  mapResize = setTimeout(() => { if (viewIs("map")) mapRender(true); }, 150);
});
