// ANTA dashboard: WebSocket alert feed, explanation view, SVG charts, stream panel.
// All network-derived strings (SNI, DNS names, user agents...) are attacker-controlled,
// so everything is rendered with textContent / DOM APIs, never innerHTML.
"use strict";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
let authFailures = 0;
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const FEATURE_LABELS = {
  log_duration: "Duration", log_bytes_out: "Bytes uploaded", log_bytes_in: "Bytes downloaded",
  byte_asymmetry: "Byte asymmetry", size_entropy: "Size entropy", iat_cv: "Timing jitter (CV)",
  log_iat_mean: "Mean inter-arrival", log_mean_payload: "Mean payload size", log_packets: "Packet count",
  out_pkt_ratio: "Client packet share",
};

const state = {
  view: "alerts",
  ws: null,
  alerts: new Map(),   // id -> alert summary (feed)
  order: [],           // ids, newest detection first
  selected: null,
  involving: null,     // the alert table narrowed to alerts naming this host, domain or hash
  detail: null,        // full record of the selected alert, fetched on demand
  session: null,       // engine session state (idle / running / finished / error …)
  app: {},             // capabilities: native window, quit button
  filter: "all",
  sort: { key: "severity", dir: 1 },
  tableView: false,
  summary: null,
};

const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";

function el(tag, attrs = {}, text) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "dataset") Object.assign(node.dataset, v);
    else node.setAttribute(k, v);
  }
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function svg(tag, attrs = {}, text) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
}

// ------------------------------------------------------------ formatting

function fmtBytes(n) {
  if (n === null || n === undefined) return "–";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (Math.abs(n) >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return i === 0 ? `${Math.round(n)} B` : `${n.toFixed(1)} ${units[i]}`;
}
function fmtNum(n) { return n === undefined || n === null ? "–" : Number(n).toLocaleString(); }
function fmtDuration(s) {
  if (s === undefined || s === null) return "–";
  if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
  if (s < 60) return `${s.toFixed(1)} s`;
  if (s < 3600) return `${(s / 60).toFixed(1)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}
function fmtTime(epoch) {
  if (!epoch) return "–";
  return new Date(epoch * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function fmtDateTime(epoch) {
  if (!epoch) return "–";
  return new Date(epoch * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "medium" });
}
function niceTicks(min, max, count = 5) {
  if (max <= min) return [min];
  const span = max - min;
  const step0 = Math.pow(10, Math.floor(Math.log10(span / count)));
  const err = (span / count) / step0;
  const step = step0 * (err >= 7.5 ? 10 : err >= 3.5 ? 5 : err >= 1.5 ? 2 : 1);
  const ticks = [];
  for (let v = Math.ceil(min / step) * step; v <= max + step * 1e-9; v += step) ticks.push(+v.toFixed(10));
  return ticks;
}
function fmtTick(v, unit) {
  if (unit === "bytes") return fmtBytes(v);
  if (unit === "s") return v < 1 ? `${(v * 1000).toFixed(0)}ms` : `${+v.toFixed(3)}s`;
  if (Math.abs(v) >= 1000) return `${(v / 1000).toFixed(1)}k`;
  return `${+v.toFixed(2)}`;
}

// --------------------------------------------------------------- tooltip

const tooltip = $("tooltip");
function showTip(evt, rows) {
  tooltip.replaceChildren();
  rows.forEach(([label, value], i) => {
    const line = el("div");
    if (i === 0 && value === undefined) { line.append(el("strong", {}, label)); }
    else { line.append(document.createTextNode(`${label}: `), el("strong", {}, value)); }
    tooltip.append(line);
  });
  tooltip.hidden = false;
  const pad = 14;
  let x = evt.clientX + pad, y = evt.clientY + pad;
  const r = tooltip.getBoundingClientRect();
  if (x + r.width > window.innerWidth - 8) x = evt.clientX - r.width - pad;
  if (y + r.height > window.innerHeight - 8) y = evt.clientY - r.height - pad;
  tooltip.style.left = `${x}px`;
  tooltip.style.top = `${y}px`;
}
function hideTip() { tooltip.hidden = true; }

function addHit(g, mark, x, y, w, h, rows) {
  // Hit target larger than the mark itself (min 8px wide, full plot height).
  const hit = svg("rect", { x, y, width: Math.max(w, 8), height: h, class: "hit" });
  hit.addEventListener("mousemove", (e) => { mark.classList.add("hover"); showTip(e, rows); });
  hit.addEventListener("mouseleave", () => { mark.classList.remove("hover"); hideTip(); });
  g.append(hit);
}

// Bar path with 4px rounded data-end, square at the baseline.
function barPath(x, y, w, h, up = true) {
  const r = Math.min(4, w / 2, Math.abs(h));
  if (h <= 0) return "";
  if (up) {
    return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
  }
  return `M${x},${y}V${y + h - r}Q${x},${y + h} ${x + r},${y + h}H${x + w - r}Q${x + w},${y + h} ${x + w},${y + h - r}V${y}Z`;
}

function chartWidth(container) { return Math.max(280, container.clientWidth || 600); }

// ------------------------------------------------------------ histogram

function histogram(container, values, opts) {
  container.replaceChildren();
  if (!values.length) { container.append(el("p", { class: "muted" }, "Not enough data yet.")); return []; }
  const W = chartWidth(container), H = 220;
  const m = { l: 44, r: 12, t: 22, b: 30 };
  let lo = Math.min(...values), hi = Math.max(...values);
  if (opts.ref !== undefined) { lo = Math.min(lo, opts.ref); hi = Math.max(hi, opts.ref); }
  const pad = (hi - lo) * 0.08 || Math.max(Math.abs(hi) * 0.02, 0.01);
  lo -= pad; hi += pad;
  if (opts.floorZero && lo < 0) lo = 0;
  const nb = Math.min(40, Math.max(8, Math.round(Math.sqrt(values.length) * 2)));
  const bw = (hi - lo) / nb;
  const bins = Array.from({ length: nb }, (_, i) => ({ x0: lo + i * bw, x1: lo + (i + 1) * bw, n: 0 }));
  for (const v of values) bins[Math.min(nb - 1, Math.max(0, Math.floor((v - lo) / bw)))].n++;
  const maxN = Math.max(...bins.map((b) => b.n));

  const pw = W - m.l - m.r, ph = H - m.t - m.b;
  const sx = (v) => m.l + ((v - lo) / (hi - lo)) * pw;
  const sy = (n) => m.t + ph - (n / maxN) * ph;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": opts.title });

  for (const t of niceTicks(0, maxN, 4)) {
    root.append(svg("line", { x1: m.l, x2: W - m.r, y1: sy(t), y2: sy(t), class: "gridline" }));
    root.append(svg("text", { x: m.l - 6, y: sy(t) + 4, "text-anchor": "end" }, fmtNum(t)));
  }
  for (const t of niceTicks(lo, hi, 6)) {
    root.append(svg("text", { x: sx(t), y: H - 10, "text-anchor": "middle" }, fmtTick(t, opts.unit)));
  }
  root.append(svg("text", { x: m.l - 6, y: m.t - 8, "text-anchor": "end" }, "count"));

  const g = svg("g");
  const gap = 2;  // surface gap between adjacent bars
  for (const b of bins) {
    const x = sx(b.x0) + gap / 2, w = Math.max(1, sx(b.x1) - sx(b.x0) - gap);
    const mark = svg("path", { d: barPath(x, sy(b.n), w, m.t + ph - sy(b.n)), fill: "var(--bar)", class: "mark" });
    g.append(mark);
    addHit(g, mark, sx(b.x0), m.t, sx(b.x1) - sx(b.x0), ph, [
      [`${fmtTick(b.x0, opts.unit)} – ${fmtTick(b.x1, opts.unit)}`],
      [opts.countLabel || "Count", fmtNum(b.n)],
    ]);
  }
  root.append(g);
  root.append(svg("line", { x1: m.l, x2: W - m.r, y1: m.t + ph, y2: m.t + ph, class: "baseline" }));
  if (opts.ref !== undefined) {
    const x = sx(opts.ref);
    root.append(svg("line", { x1: x, x2: x, y1: m.t - 4, y2: m.t + ph, class: "ref" }));
    const anchor = x > W - 140 ? "end" : "start";
    root.append(svg("text", { x: x + (anchor === "start" ? 5 : -5), y: m.t - 8, "text-anchor": anchor, class: "ref-label" },
      opts.refLabel));
  }
  container.append(root);
  return bins.filter((b) => b.n > 0).map((b) => [`${fmtTick(b.x0, opts.unit)} – ${fmtTick(b.x1, opts.unit)}`, b.n]);
}

// ---------------------------------------------- mirrored out/in bars

function mirrored(container, points, opts) {
  // points: [{x, out, in}] ; x in seconds (relative or absolute)
  container.replaceChildren();
  if (!points.length) { container.append(el("p", { class: "muted" }, "No payload events recorded.")); return; }
  const W = chartWidth(container), H = opts.height || 200;
  const m = { l: 56, r: 12, t: 12, b: 28 };
  const pw = W - m.l - m.r, ph = H - m.t - m.b;
  const xs = points.map((p) => p.x);
  let x0 = Math.min(...xs), x1 = Math.max(...xs);
  if (x1 === x0) x1 = x0 + 1;
  const maxOut = Math.max(1, ...points.map((p) => p.out));
  const maxIn = Math.max(1, ...points.map((p) => p.in));
  const M = Math.max(maxOut, maxIn);
  // One shared linear scale; each side keeps at least 20% of the height so the
  // smaller direction stays readable while the asymmetry remains truthful.
  const upShare = Math.min(0.8, Math.max(0.2, maxOut / (maxOut + maxIn)));
  const upH = ph * upShare, downH = ph - upH;
  const scale = Math.min(upH / maxOut, downH / maxIn, ph / M);
  const zero = m.t + upH;

  const slot = pw / Math.max(points.length, 1);
  const bw = Math.max(1.5, Math.min(14, slot * 0.6));
  const sx = (x) => m.l + bw / 2 + ((x - x0) / (x1 - x0)) * (pw - bw);

  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": opts.title || "timeline" });
  // Tick density follows each half's pixel height so labels never collide.
  const sideTicks = (px) => (px < 34 ? [] : niceTicks(0, px / scale, Math.max(1, Math.floor(px / 34)))
    .slice(1).filter((t) => t * scale <= px));
  for (const t of sideTicks(upH)) {
    root.append(svg("line", { x1: m.l, x2: W - m.r, y1: zero - t * scale, y2: zero - t * scale, class: "gridline" }));
    root.append(svg("text", { x: m.l - 6, y: zero - t * scale + 4, "text-anchor": "end" }, fmtBytes(t)));
  }
  for (const t of sideTicks(downH)) {
    root.append(svg("line", { x1: m.l, x2: W - m.r, y1: zero + t * scale, y2: zero + t * scale, class: "gridline" }));
    root.append(svg("text", { x: m.l - 6, y: zero + t * scale + 4, "text-anchor": "end" }, fmtBytes(t)));
  }
  const ticks = niceTicks(x0, x1, 6);
  for (const t of ticks) {
    root.append(svg("text", { x: sx(t), y: H - 8, "text-anchor": "middle" }, opts.xFormat(t)));
  }

  const g = svg("g");
  for (const p of points) {
    const x = sx(p.x) - bw / 2;
    const hu = p.out * scale, hd = p.in * scale;
    const up = svg("path", { d: barPath(x, zero - hu - 1, bw, hu), fill: "var(--series-out)", class: "mark" });
    const down = svg("path", { d: barPath(x, zero + 1, bw, hd, false), fill: "var(--series-in)", class: "mark" });
    g.append(up, down);
    const rows = [[opts.tipTitle(p)], ["Client → server", fmtBytes(p.out)], ["Server → client", fmtBytes(p.in)]];
    if (p.label) rows.push(["Detail", p.label]);
    addHit(g, up, x - 2, m.t, bw + 4, ph, rows);
  }
  root.append(g);
  root.append(svg("line", { x1: m.l, x2: W - m.r, y1: zero, y2: zero, class: "baseline" }));
  container.append(root);
}

// --------------------------------------------- diverging deviation bars

function deviation(container, items) {
  container.replaceChildren();
  const W = chartWidth(container);
  const rowH = 26, m = { l: 150, r: 56, t: 8, b: 26 };
  const H = m.t + m.b + rowH * items.length;
  const maxZ = Math.max(3, ...items.map((d) => Math.abs(d.z)));
  const pw = W - m.l - m.r;
  const sx = (z) => m.l + ((z + maxZ) / (2 * maxZ)) * pw;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Feature deviation from baseline" });
  for (const t of niceTicks(-maxZ, maxZ, 6)) {
    root.append(svg("line", { x1: sx(t), x2: sx(t), y1: m.t, y2: H - m.b, class: "gridline" }));
    root.append(svg("text", { x: sx(t), y: H - 8, "text-anchor": "middle" }, `${t > 0 ? "+" : ""}${t}σ`));
  }
  const g = svg("g");
  items.forEach((d, i) => {
    const y = m.t + i * rowH + 5, h = rowH - 10;
    const xz = sx(0), xv = sx(d.z);
    const x = Math.min(xz, xv), w = Math.max(1, Math.abs(xv - xz));
    const r = Math.min(4, w / 2);
    const path = d.z >= 0
      ? `M${x},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h - r}Q${x + w},${y + h} ${x + w - r},${y + h}H${x}Z`
      : `M${x + w},${y}H${x + r}Q${x},${y} ${x},${y + r}V${y + h - r}Q${x},${y + h} ${x + r},${y + h}H${x + w}Z`;
    const mark = svg("path", { d: path, fill: d.z >= 0 ? "var(--pos)" : "var(--neg)", class: "mark" });
    g.append(mark);
    root.append(svg("text", { x: m.l - 8, y: y + h / 2 + 4, "text-anchor": "end" }, FEATURE_LABELS[d.feature] || d.feature));
    root.append(svg("text", { x: d.z >= 0 ? xv + 6 : xv - 6, y: y + h / 2 + 4, "text-anchor": d.z >= 0 ? "start" : "end" },
      `${d.z > 0 ? "+" : ""}${d.z.toFixed(1)}σ`));
    addHit(g, mark, m.l, y - 4, pw, rowH, [
      [FEATURE_LABELS[d.feature] || d.feature], ["z-score", d.z.toFixed(2)],
      ["Value", d.value.toFixed(3)], ["Benign mean", d.baseline.toFixed(3)],
    ]);
  });
  root.append(g);
  root.append(svg("line", { x1: sx(0), x2: sx(0), y1: m.t, y2: H - m.b, class: "baseline" }));
  container.append(root);
}

function renderTable(container, headers, rows) {
  container.replaceChildren();
  const table = el("table");
  const tr = el("tr");
  headers.forEach((h) => tr.append(el("th", {}, h)));
  const thead = el("thead");
  thead.append(tr);
  table.append(thead);
  const body = el("tbody");
  rows.forEach((r) => {
    const row = el("tr");
    r.forEach((c) => row.append(el("td", {}, c)));
    body.append(row);
  });
  table.append(body);
  container.append(table);
}

// ------------------------------------------------------------ saving files

// Everything the page saves is prepared by the server and then downloaded: the
// native window shows a Save dialog for it, a browser saves it like any download.
function saveDownload(prepared) {
  const link = el("a", { href: prepared.download, download: prepared.name });
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
}

async function saveTextFile(name, type, content) {
  const prepared = await api("/api/save/text", "POST", { name, type, content });
  saveDownload(prepared);
  return prepared;
}

// CSV, quoted where needed. Text from the network that starts with = + - or @ would
// run as a formula when the file is opened in a spreadsheet, so it gets a leading '.
function csvText(headers, rows) {
  const cell = (v) => {
    if (v === null || v === undefined) return "";
    let s = String(v);
    if (typeof v !== "number" && /^[=+\-@\t\r]/.test(s)) s = `'${s}`;
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [headers, ...rows].map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}

function isoTime(epoch) { return epoch ? new Date(epoch * 1000).toISOString() : ""; }

// ------------------------------------------------------------ alert table

function passesFilter(a) {
  return (state.filter === "all" || a.severity === state.filter) && (!state.involving || alertInvolves(a, state.involving)) &&
    (!state.focusAlerts || state.focusAlerts.has(a.id));  // (within a focus: the alerts about it)
}

// Whether an alert names a host, domain or hash (its addresses, target or title).
function alertInvolves(a, q) {
  const v = q.toLowerCase();
  const values = [a.src_ip, a.dst_ip, a.target, ...(a.addresses || [])].filter(Boolean).map((x) => String(x).toLowerCase());
  return values.some((x) => x === v || x.endsWith(`.${v}`) || x.startsWith(`${v}:`)) ||
    (v.length > 5 && String(a.title || "").toLowerCase().includes(v));
}

// The alert table narrowed to one host, domain or hash (from the right-click menus).
function showAlertsInvolving(q) {
  state.involving = q || null;
  const chip = $("alerts-involving");
  chip.hidden = !q;
  chip.textContent = q ? `Involving ${q} ✕` : "";
  setView("list");  // (the table, filtered)
  renderFeed();
  const n = [...state.alerts.values()].filter(passesFilter).length;
  if (q && !n) notice(`No alert involves ${q}${state.filter === "all" ? "" : ` at ${state.filter} severity`}.`);
}
window.showAlertsInvolving = showAlertsInvolving;

const VERDICT_LABEL = { new: "New", investigating: "Investigating", confirmed: "Confirmed", false_positive: "False positive" };
function verdictOf(a) { return (a.triage && a.triage.status) || "new"; }

// A compromised device's row lists every address assigned to it.
function alertSource(a) { return a.addresses && a.addresses.length ? a.addresses.join(", ") : (a.src_ip || "–"); }

// Each column's first click sorts the useful way round (most severe, newest, most confident first).
const SORT_KEYS = {
  severity: { value: (a) => SEV_ORDER[a.severity], first: 1 },
  last_seen: { value: (a) => a.last_seen, first: -1 },
  title: { value: (a) => a.title, first: 1 },
  verdict: { value: (a) => ["confirmed", "investigating", "new", "false_positive"].indexOf(verdictOf(a)), first: 1 },
  source: { value: alertSource, first: 1 },
  target: { value: (a) => a.target || "", first: 1 },
  confidence: { value: (a) => a.confidence, first: -1 },
  updates: { value: (a) => a.updates, first: -1 },
  id: { value: (a) => a.id, first: 1 },
};
const collator = new Intl.Collator(undefined, { numeric: true });

function compareAlerts(x, y) {
  const key = SORT_KEYS[state.sort.key];
  const vx = key.value(x), vy = key.value(y);
  const c = typeof vx === "number" ? vx - vy : collator.compare(vx, vy);
  // Ties: the most severe, then a device verdict (it sums up the alerts under it), then the surest, then the newest.
  return c * state.sort.dir || SEV_ORDER[x.severity] - SEV_ORDER[y.severity]
    || (y.kind === "compromised_device") - (x.kind === "compromised_device")
    || y.confidence - x.confidence || y.last_seen - x.last_seen;
}

function cellWith(td, content) {
  td.append(content);
  return td;
}

function alertRow(a) {
  const tr = el("tr", { class: "alert-row", tabindex: "0", dataset: { id: a.id, sev: a.severity } });
  tr.setAttribute("aria-selected", String(a.id === state.selected));
  if (a.id === state.selected) tr.classList.add("selected");
  if (verdictOf(a) === "false_positive") tr.classList.add("dismissed");
  const sev = el("td");
  sev.append(el("span", { class: `sev sev-${a.severity}` }, SEV_LABEL[a.severity]));
  const src = alertSource(a);
  tr.append(sev,
    el("td", { class: "mono" }, fmtTime(a.last_seen)),
    el("td", { title: a.title }, a.title),
    el("td", { class: `verdict v-${verdictOf(a)}` }, VERDICT_LABEL[verdictOf(a)]),
    cellWith(el("td", { class: "mono", title: src }), addrLinks(src)),
    cellWith(el("td", { class: "mono", title: a.target || "" }), a.target ? addrLinks(a.target) : "–"),
    el("td", { class: "num" }, `${Math.round(a.confidence * 100)}%`),
    el("td", { class: "num" }, String(a.updates || 1)),
    el("td", { class: "mono c-id" }, a.id));
  tr.addEventListener("click", () => select(a.id));
  tr.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(a.id); }
    if (e.key === "ArrowDown") { e.preventDefault(); tr.nextElementSibling?.focus(); }
    if (e.key === "ArrowUp") { e.preventDefault(); tr.previousElementSibling?.focus(); }
  });
  return tr;
}

function renderFeed() {
  const body = $("feed");
  const items = [...state.alerts.values()].filter(passesFilter).sort(compareAlerts);
  const focusedId = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.id : null;
  body.replaceChildren(...items.map(alertRow));
  if (focusedId) body.querySelector(`[data-id="${CSS.escape(focusedId)}"]`)?.focus();
  $("feed-empty").hidden = items.length > 0;
  $("alert-count").textContent = state.alerts.size
    ? (items.length === state.alerts.size ? String(items.length) : `${items.length} of ${state.alerts.size}`) : "";
  document.querySelectorAll("#alert-head th").forEach((th) => {
    const key = th.querySelector(".sort")?.dataset.key;
    if (key === state.sort.key) th.setAttribute("aria-sort", state.sort.dir === 1 ? "ascending" : "descending");
    else th.removeAttribute("aria-sort");
  });
}

function upsert(alerts, retracted = []) {
  let changedSelected = false;
  for (const id of retracted) {
    state.alerts.delete(id);
    state.order = state.order.filter((x) => x !== id);
    if (id === state.selected) { state.selected = null; state.detail = null; renderDetail(); }
  }
  for (const a of alerts) {
    if (!state.alerts.has(a.id)) state.order.unshift(a.id);
    state.alerts.set(a.id, a);
    if (a.id === state.selected) changedSelected = true;
  }
  renderFeed();
  if (window.storyChanged) window.storyChanged();
  if (changedSelected) scheduleDetailRefresh();
  // (no alert opens by itself: the detail pane lists what to look at first until one is chosen)
  if (!state.selected && window.firstLookChanged) window.firstLookChanged();
}

// A path with the focus (the selection the analysis is limited to; selection.js) added.
function withFocus(path) {
  const scope = window.focusScope ? window.focusScope() : "";
  return scope ? `${path}${path.includes("?") ? "&" : "?"}scope=${encodeURIComponent(scope)}` : path;
}

async function api(path, method = "GET", body = undefined) {
  const opts = { method, credentials: "same-origin", cache: "no-store" };
  if (method !== "GET") {
    opts.headers = { "Content-Type": "application/json" };
    opts.body = JSON.stringify(body || {});
  }
  const resp = await fetch(path, opts);
  if (resp.status === 401) { location.reload(); throw new Error("session expired"); }
  let data = null;
  try { data = await resp.json(); } catch { /* empty body */ }
  if (resp.status === 410 && data && data.scope_gone && window.focusLost) window.focusLost(data.error);
  if (!resp.ok) throw new Error((data && data.error) || `${path}: ${resp.status}`);
  return data;
}

let detailTimer = null;
function scheduleDetailRefresh() {
  // Busy alerts update several times a second; refetch details at most twice a second.
  if (detailTimer) return;
  detailTimer = setTimeout(() => { detailTimer = null; loadDetail(state.selected); }, 500);
}

async function loadDetail(id) {
  if (!id) return;
  try {
    const full = await api(`/api/alerts/${encodeURIComponent(id)}`);
    if (id === state.selected) { state.detail = full; renderDetail(); }
  } catch (err) {
    console.warn(err);
  }
}

function select(id) {
  state.selected = id;
  state.detail = null;
  document.querySelectorAll(".alert-row").forEach((tr) => {
    tr.classList.toggle("selected", tr.dataset.id === id);
    tr.setAttribute("aria-selected", String(tr.dataset.id === id));
  });
  loadDetail(id);
}

// ------------------------------------------------------------ main view

function renderDetail() {
  const a = state.detail && state.detail.id === state.selected ? state.detail : null;
  const idle = !state.alerts.size && (!state.session || ["idle", "error", "stopped"].includes(state.session.state));
  $("ph-start").hidden = !idle;
  $("ph-select").hidden = idle;
  $("placeholder").hidden = !!a;
  if (!a && !idle && !state.selected && window.firstLook) window.firstLook();  // (what to look at first, when no alert is open)
  $("detail").hidden = !a;
  if (!a) {
    $("stream").hidden = true;
    $("stream-empty").hidden = false;
    return;
  }

  const badge = $("d-badge");
  badge.className = `badge ${a.severity}`;
  badge.textContent = SEV_LABEL[a.severity];
  $("d-id").textContent = a.id;
  $("d-time").textContent = `first seen ${fmtDateTime(a.first_seen)} · last ${fmtTime(a.last_seen)}`;
  $("d-title").textContent = a.title;
  $("d-headline").textContent = a.headline;
  $("d-conf").textContent = `${Math.round(a.confidence * 100)}%`;
  $("d-conf-bar").style.width = `${Math.round(a.confidence * 100)}%`;
  $("d-details").replaceChildren(...a.details.map((d) => el("li", {}, d)));

  renderChart(a);
  renderTimeline(a);
  renderStream(a);
  if (window.renderAlertContext) window.renderAlertContext(a);
  if (window.renderAlertGeo) window.renderAlertGeo(a);
  if (window.renderTriage) window.renderTriage(a);
  if (window.renderAlertAgent) window.renderAlertAgent(a);
}

function renderChart(a) {
  const c = a.chart || {};
  const chart = $("chart"), table = $("chart-table"), legend = $("chart-legend");
  $("chart-title").textContent = c.title || "Statistical trigger";
  legend.replaceChildren();
  let headers = [], rows = [];

  if (c.kind === "iat_histogram") {
    legend.append(keySwatch("s-bar", "Intervals"), keySwatch("s-ref", `Median period ${c.period.toFixed(3)} s`));
    rows = histogram(chart, c.values, { title: c.title, unit: "s", ref: c.period, refLabel: `${c.period.toFixed(2)} s`,
      floorZero: true, countLabel: "Check-in intervals" });
    headers = ["Interval", "Count"];
  } else if (c.kind === "entropy_histogram") {
    legend.append(keySwatch("s-bar", "Queries"), keySwatch("s-ref", "Typical hostname entropy"));
    rows = histogram(chart, c.values, { title: c.title, unit: "bits", ref: c.baseline, refLabel: "typical ≈ 3.0",
      floorZero: true, countLabel: "Queries" });
    headers = ["Entropy (bits/char)", "Queries"];
  } else if (c.kind === "throughput") {
    legend.append(keySwatch("s-out", "Client → server"), keySwatch("s-in", "Server → client"));
    const pts = c.series.map(([s, o, i]) => ({ x: s, out: o, in: i }));
    const w = c.bucket_s || 1;
    const span = pts.length ? pts[pts.length - 1].x + w : 1;
    const fmtS = (t) => (span < 10 ? `${t.toFixed(1)}s` : span < 180 ? `${Math.round(t)}s` : `${(t / 60).toFixed(1)}m`);
    mirrored(chart, pts, { title: c.title, xFormat: fmtS,
      tipTitle: (p) => `${p.x.toFixed(2)}s – ${(p.x + w).toFixed(2)}s` });
    headers = ["Interval start (s)", "Out", "In"];
    rows = c.series.map(([s, o, i]) => [s.toFixed(2), fmtBytes(o), fmtBytes(i)]);
  } else if (c.kind === "feature_deviation") {
    legend.append(keySwatch("s-out", "Below baseline"), (() => {
      const k = keySwatch("s-in", "Above baseline");
      k.querySelector(".swatch").style.background = "var(--pos)";
      return k;
    })());
    deviation(chart, c.items);
    headers = ["Feature", "z-score", "Value", "Benign mean"];
    rows = c.items.map((d) => [FEATURE_LABELS[d.feature] || d.feature, d.z.toFixed(2), d.value.toFixed(3), d.baseline.toFixed(3)]);
  } else {
    chart.replaceChildren(el("p", { class: "muted" }, "No chart for this alert type."));
  }
  renderTable(table, headers, rows);
  chart.hidden = state.tableView;
  table.hidden = !state.tableView;
}

function keySwatch(cls, label) {
  const k = el("span", { class: "key" });
  k.append(el("span", { class: `swatch ${cls}` }), document.createTextNode(label));
  return k;
}

function renderTimeline(a) {
  const tl = a.timeline || [];
  const t0 = tl.length ? tl[0].t : 0;
  const total = a.timeline_total || tl.length;
  const count = total > tl.length ? `latest ${tl.length} of ${fmtNum(total)} events` : `${tl.length} events`;
  $("timeline-sub").textContent = tl.length
    ? `${count} · ${fmtTime(t0)} – ${fmtTime(tl[tl.length - 1].t)}` : "";
  const pts = tl.map((e) => ({ x: e.t - t0, out: e.out, in: e.in, label: e.label, abs: e.t }));
  mirrored($("timeline"), pts, {
    title: "Session timeline", height: 170,
    xFormat: (t) => (t >= 120 ? `+${(t / 60).toFixed(1)}m` : `+${+t.toFixed(1)}s`),
    tipTitle: (p) => fmtTime(p.abs) + `.${String(Math.floor((p.abs % 1) * 1000)).padStart(3, "0")}`,
  });
}

function entropyText(pe) {
  if (!pe) return null;
  const f = (v) => (v === null || v === undefined ? "–" : `${v.toFixed(2)}`);
  if (pe.c2s == null && pe.s2c == null) return null;
  return `out ${f(pe.c2s)} / in ${f(pe.s2c)} bits/byte`;
}

function kvRows(dl, rows) {
  dl.replaceChildren();
  for (const [k, v] of rows) {
    if (v === undefined || v === null || v === "") continue;
    const dt = el("dt", {}, k);
    const dd = el("dd", {}, String(v));
    if (String(v).length > 60) dd.title = String(v);
    dl.append(dt, dd);
  }
  return dl.childElementCount > 0;
}

function renderStream(a) {
  $("show-packets").hidden = !a.export_flows;
  const s = a.stream || {};
  $("stream-empty").hidden = true;
  $("stream").hidden = false;
  const http = s.http || {};
  kvRows($("stream-kv"), [
    ["5-tuple", s.five_tuple],
    ["Client", s.src],
    ["Server", s.dst],
    ["Sessions", s.flows > 1 ? fmtNum(s.flows) : null],
    ["Bytes out", s.bytes_out !== undefined ? `${fmtBytes(s.bytes_out)} (${fmtNum(s.bytes_out)})` : null],
    ["Bytes in", s.bytes_in !== undefined ? `${fmtBytes(s.bytes_in)} (${fmtNum(s.bytes_in)})` : null],
    ["Packets", fmtNum(s.packets)],
    ["Duration", fmtDuration(s.duration)],
    ["Payload entropy", entropyText(s.payload_entropy)],
    ["HTTP", http.method ? `${http.method} ${http.uri || ""}` : null],
    ["Host", http.host],
    ["User-Agent", http.user_agent],
    ["HTTP status", s.http_status],
  ]);

  const dns = [...(s.dns_context || []), ...(s.dns_queries || [])];
  $("dns-section").hidden = dns.length === 0;
  $("dns-list").replaceChildren(...[...new Set(dns)].map((d) => el("li", {}, d)));

  $("tls-section").hidden = !kvRows($("tls-kv"), [
    ["SNI", s.sni], ["JA3", s.ja3], ["JA3 string", s.ja3_string], ["JA4", s.ja4],
    ["ALPN", s.alpn && s.alpn.length ? s.alpn.join(", ") : null],
  ]);

  const tcp = s.tcp;
  $("tcp-section").hidden = !tcp || !kvRows($("tcp-kv"), tcp ? [
    ["Handshake", tcp.handshake ? "seen" : "not seen"],
    ["Closed", tcp.rst ? "RST" : tcp.closed ? "FIN" : "open"],
    ["Retransmits", fmtNum(tcp.retransmissions)],
    ["Out of order", fmtNum(tcp.out_of_order)],
    ["Zero window", fmtNum(tcp.zero_window)],
    ["Gap bytes", fmtNum(tcp.gap_bytes)],
  ] : []);

  const btn = $("export");
  btn.href = `/api/export/${encodeURIComponent(a.id)}`;
  btn.setAttribute("aria-disabled", a.exportable ? "false" : "true");
  $("export-note").textContent = a.exportable
    ? `Exports only the ${a.export_flows} flow${a.export_flows === 1 ? "" : "s"} behind this alert, not the full capture.`
    : "No capture file is recorded for this source. Run the engine with -w FILE to enable exports.";
}

// ------------------------------------------------------------- summary

function renderSummary(s) {
  state.summary = s;
  const e = s.engine || {};
  $("kpi-sessions").textContent = fmtNum(s.sessions);
  $("kpi-packets").textContent = fmtNum(e.packets ?? 0);
  $("kpi-drops").textContent = fmtNum((e.kernel_dropped ?? 0) + (e.ipc_dropped ?? 0));
  $("kpi-alerts").textContent = fmtNum(s.alerts);
  $("kpi-model").textContent = s.detector || "rules only";
  if (window.ignoredSummary) window.ignoredSummary(s);
}

// ------------------------------------------------------------ websocket

let retry = 500;
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  const conn = $("conn"), text = $("conn-text");
  ws.onopen = () => {
    conn.dataset.state = "live"; text.textContent = "Live"; retry = 500; authFailures = 0;
    state.ws = ws;
    if (pkt.follow) ws.send(JSON.stringify({ type: "follow", on: true }));
  };
  ws.onclose = () => {
    conn.dataset.state = "down";
    // A refused upgrade (expired token after a server restart) looks like a close: check once.
    if (++authFailures === 3) fetch("/api/summary", { credentials: "same-origin" }).then((r) => {
      if (r.status === 401) location.reload();
    }).catch(() => {});
    text.textContent = "Disconnected – retrying";
    setTimeout(connect, retry);
    retry = Math.min(retry * 2, 8000);
  };
  ws.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    if (msg.type === "snapshot") {
      state.alerts.clear();
      state.order = [];
      state.app = msg.app || {};
      if (msg.session) renderSession(msg.session);
      pktSessionChanged();  // (a packet list waiting for the capture loads it now)
      const sorted = [...msg.alerts].sort((x, y) => x.first_seen - y.first_seen);
      upsert(sorted);
      renderSummary(msg.summary);
      renderDetail();
    } else if (msg.type === "session") {
      renderSession(msg.session);
      pktSessionChanged();
    } else if (msg.type === "packets") {
      pktFeed(msg);
    } else if (msg.type === "reset") {
      resetView();
      pktReset();
    } else if (msg.type === "alerts") {
      upsert(msg.alerts, msg.retracted || []);
    } else if (msg.type === "summary") {
      renderSummary(msg.summary);
    } else if (msg.type === "status") {
      text.textContent = `Live · ${msg.message}`;
    }
  };
}

// --------------------------------------------------------------- sessions

const SESSION_TEXT = {
  idle: () => "No capture loaded",
  preparing: (s) => s.message || "Preparing…",
  starting: (s) => `Starting ${s.source || ""}…`,
  authorizing: () => "Waiting for administrator approval…",
  running: (s) => (s.mode === "live" ? `Capturing on ${s.source}` : `Analysing ${s.source}`),
  stopping: () => "Stopping…",
  finished: (s) => `Finished: ${s.source}`,
  stopped: (s) => `Stopped: ${s.source || "capture"}` + (s.message ? ` — ${s.message}` : ""),
  error: (s) => `Error: ${s.message || "capture failed"}`,
};

function renderSession(s) {
  const before = state.session ? `${state.session.started}|${state.session.source}|${state.session.state}` : "";
  state.session = s;
  const el = $("session");
  el.dataset.state = s.state;
  $("session-text").textContent = (SESSION_TEXT[s.state] || (() => s.state))(s);
  el.title = s.message || "";
  const active = ["preparing", "starting", "authorizing", "running", "stopping"].includes(s.state);
  $("btn-stop").hidden = !active;
  $("btn-save").hidden = !["running", "stopping", "finished", "stopped"].includes(s.state);
  $("feed-empty-sub").textContent = active ? "Analysing. Alerts appear here as soon as they are detected."
    : "Open a capture, start a live capture, or run the demo.";
  renderDetail();
  if (`${s.started}|${s.source}|${s.state}` !== before) sessionShifted();
}

// A capture became known (the first message after a window opens), started, finished or
// stopped: the view on screen reads its data again. A pop-out window shows its view before
// it has heard which capture is open; without this it would stay empty.
function sessionShifted() {
  if (state.view === "packets") return;  // (pktSessionChanged loads the packet list)
  runViewHook();
  if (window.caseChanged) window.caseChanged();
  if (window.policyChanged) window.policyChanged();
}

function resetView() {
  state.involving = null;
  $("alerts-involving").hidden = true;
  state.alerts.clear();
  state.order = [];
  state.selected = null;
  state.detail = null;
  renderFeed();
  renderDetail();
}

async function startSession(body) {
  try {
    renderSession(await api("/api/session", "POST", body));
    return null;
  } catch (err) {
    renderSession({ ...(state.session || {}), state: "error", message: err.message });
    return err.message;
  }
}

async function openCapture() {
  if (state.app && state.app.native) {  // the system's Open dialog, shown by the desktop app
    try {
      const r = await api("/api/native/choose-capture", "POST", {});
      if (r.path) await startSession({ mode: "file", path: r.path });
      return;
    } catch { /* fall back to typing the path */ }
  }
  $("open-error").textContent = "";
  $("open-dialog").showModal();
  $("open-path").focus();
}

async function openLiveDialog() {
  const dialog = $("live-dialog");
  const select = $("live-iface");
  $("live-error").textContent = "";
  $("live-note").textContent = "Loading interfaces…";
  select.replaceChildren();
  dialog.showModal();
  try {
    const devices = await api("/api/interfaces");
    for (const d of devices) {
      const parts = [d.name];
      if (d.description) parts.push(d.description);
      if (d.addresses && d.addresses.length) parts.push(d.addresses.slice(0, 2).join(", "));
      if (!d.up) parts.push("(down)");
      select.append(el("option", { value: d.name }, parts.join(" — ")));
    }
    const p = (state.app && state.app.platform) || "";
    $("live-note").textContent = p === "win32"
      ? "Capture uses Npcap. If it is missing, install it from npcap.com."
      : "If your account can't capture yet, your system will ask for an administrator password once per capture; "
        + "ANTA then drops back to your account immediately.";
  } catch (err) {
    $("live-note").textContent = "";
    $("live-error").textContent = err.message;
  }
}

// ----------------------------------------------------------- packet view

const PAGE = 200;
const MAX_FOLLOW_ROWS = 600;
const pkt = {
  from: 1, starts: [], next: null, total: null, before: 0, filter: "", alert: null, alertLabel: "",
  rows: [], selected: null, follow: false, t0: null, loadedKey: null, loading: false, detail: null,
  filterKind: "display",  // "display" (Wireshark syntax) or "bpf"
  colorize: true,
  tmpColors: [],          // "Colorize conversation" rules: {filter, bg, fg, name}, ahead of the saved ones
  colors: [],             // the saved rules the last page was colored with
  marks: new Set(),       // marked frame numbers (Ctrl+M)
  timeFormat: "relative",
  columns: loadColumns(), // custom columns: [{field, title}], shown before Info ("Apply as column")
  refs: new Map(),        // time references: frame -> its time (relative times count from the latest one)
  shift: 0,               // time shift in seconds, for the absolute time formats (display only)
  timeKey: "",            // the capture the references and shift belong to
  names: false,           // show host names instead of addresses
  nameMap: {},
};

function loadColumns() {
  try {
    const c = JSON.parse(localStorage.getItem("anta.columns") || "[]");
    return Array.isArray(c) ? c.filter((x) => x && typeof x.field === "string").slice(0, 12) : [];
  } catch { return []; }
}

function saveColumns() {
  try { localStorage.setItem("anta.columns", JSON.stringify(pkt.columns)); } catch { /* private window */ }
}

// The references and the shift belong to one capture: a new one starts without them.
function pktTimeState() {
  const key = sessionKey();
  if (pkt.timeKey !== key) {
    pkt.timeKey = key;
    pkt.refs.clear();
    pkt.shift = 0;
  }
}

function pktHost(addr) {
  return pkt.names && addr && pkt.nameMap[addr] ? pkt.nameMap[addr] : addr;
}

function pktRowColor(p) {
  if (!pkt.colorize || p.color === undefined || p.color === null) return null;
  const i = p.color;
  return i < pkt.tmpColors.length ? pkt.tmpColors[i] : pkt.colors[i - pkt.tmpColors.length] || null;
}

function pktFormatTime(p, prev) {
  if (p.ts == null) return "";
  pktTimeState();
  if (pkt.refs.has(p.n) && (pkt.timeFormat === "relative" || pkt.timeFormat === "delta")) return "*REF*";
  const ts = p.ts + pkt.shift;  // (absolute times show the shift; differences don't change)
  switch (pkt.timeFormat) {
    case "relative": {  // since the capture start, or the latest time reference before this packet
      let base = null, baseN = 0;
      for (const [n, t] of pkt.refs) if (n < p.n && n > baseN) { base = t; baseN = n; }
      return base != null ? (p.ts - base).toFixed(6) : pktTime(p.ts);
    }
    case "delta": return prev && prev.ts != null ? (p.ts - prev.ts).toFixed(6) : "0.000000";
    case "local": {
      const d = new Date(ts * 1000);
      return d.toLocaleTimeString([], { hour12: false }) + "." + String(Math.floor((ts % 1) * 1e6)).padStart(6, "0");
    }
    case "datetime": {
      const d = new Date(ts * 1000);
      return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour12: false })}.${String(Math.floor((ts % 1) * 1e6)).padStart(6, "0")}`;
    }
    case "utc": return new Date(ts * 1000).toISOString().replace("T", " ").replace("Z", "") +
      String(Math.floor((ts % 1) * 1e6)).padStart(6, "0").slice(3);
    case "epoch": return ts.toFixed(6);
    default: return pktTime(p.ts);
  }
}

function pktProtoClass(p) {
  const proto = (p.proto || "").toLowerCase();
  if (/\[[^\]]*rst/i.test(p.info || "")) return "p-rst";
  if (/\[(syn|fin)/i.test(p.info || "")) return "p-handshake";
  if (["dns", "mdns", "llmnr"].includes(proto)) return "p-dns";
  if (proto === "tls") return "p-tls";
  if (proto === "http") return "p-http";
  if (proto === "arp") return "p-arp";
  if (proto.startsWith("icmp")) return "p-icmp";
  if (proto === "udp") return "p-udp";
  return proto === "tcp" ? "p-tcp" : "p-other";
}

function pktTime(ts) {
  if (pkt.t0 == null || ts == null) return "";
  return (ts - pkt.t0).toFixed(6);
}

function pktRow(p, prev) {
  const color = pktRowColor(p);
  const tr = el("tr", { class: color ? "colored" : (pkt.colorize ? "" : pktProtoClass(p)), tabindex: "-1",
    dataset: { n: String(p.n) } });
  if (color) { tr.style.setProperty("--row-bg", color.bg); tr.style.setProperty("--row-fg", color.fg); tr.title = color.name || ""; }
  if (pkt.marks.has(p.n)) tr.classList.add("marked");
  const src = pktHost(p.src), dst = pktHost(p.dst);
  tr.append(el("td", { class: "c-no" }, String(p.n)), el("td", { class: "c-time" }, pktFormatTime(p, prev)),
    el("td", { class: "c-addr", title: src !== p.src ? p.src : "", dataset: { q: p.src || "" } }, src),
    el("td", { class: "c-addr", title: dst !== p.dst ? p.dst : "", dataset: { q: p.dst || "" } }, dst),
    el("td", { class: "c-proto" }, p.proto), el("td", { class: "c-len" }, String(p.len)));
  for (const c of pkt.columns) {  // custom columns: every value of the field, as Wireshark joins them
    const v = ((p.f || {})[c.field] || []).join(",");
    tr.append(el("td", { class: "c-custom", title: v }, v));
  }
  tr.append(el("td", { class: "c-info" }, p.info));
  if (pkt.refs.has(p.n)) tr.classList.add("time-ref");
  if (p.n === pkt.selected) tr.classList.add("selected");
  return tr;  // (clicks, drags and the right-click menu: selection.js, on the table body)
}

// The packet list's header: the fixed columns, then the custom ones (right-click to remove or move).
function pktHeader() {
  const tr = document.querySelector(".pkt-table thead tr");
  if (!tr) return;
  const key = JSON.stringify(pkt.columns);
  if (tr.dataset.cols === key) return;
  tr.dataset.cols = key;
  tr.querySelectorAll("th.c-custom").forEach((th) => th.remove());
  const info = tr.lastElementChild;
  pkt.columns.forEach((c, i) => {
    const th = el("th", { class: "c-custom", title: `${c.field} (right-click to remove or move)`, dataset: { col: String(i) } }, c.title || c.field);
    th.addEventListener("contextmenu", (e) => { e.preventDefault(); if (window.columnMenu) window.columnMenu(e, i); });
    tr.insertBefore(th, info);
  });
}

function pktRender() {
  pktHeader();
  document.querySelector(".pkt-table").dataset.time = pkt.timeFormat;
  const body = $("pkt-rows");
  body.replaceChildren(...pkt.rows.map((p, i) => pktRow(p, pkt.rows[i - 1])));
  $("pkt-marks").hidden = !pkt.marks.size;
  $("pkt-marks-text").textContent = `${pkt.marks.size} marked`;
  $("pkt-tmp-colors").hidden = !pkt.tmpColors.length;
  $("pkt-tmp-colors-text").textContent = `${pkt.tmpColors.length} colorized conversation${pkt.tmpColors.length === 1 ? "" : "s"}`;
  const session = state.session;
  const has = pkt.rows.length > 0;
  $("pkt-empty").hidden = has;
  if (!has) {
    const active = session && ["running", "starting", "authorizing"].includes(session.state);
    $("pkt-empty").firstChild.textContent = pkt.filter || pkt.alert ? "No packets match." :
      active ? "Waiting for packets…" : "No capture loaded.";
    $("pkt-empty").querySelector("span").textContent = pkt.filter ? "Change the filter, or press Clear to show every packet." :
      pkt.alert ? "No packets in this capture belong to the alert." :
      active ? "" : "Open a capture file or start a live capture to see packets.";
  }
  const first = pkt.rows.length ? pkt.rows[0].n : 0;
  let count = "";
  if (pkt.follow) {
    count = `Live · showing the latest ${fmtNum(pkt.rows.length)} packets`;
  } else if (has) {
    const a = pkt.before + 1;
    const b = pkt.before + pkt.rows.length;
    count = `${pkt.filter || pkt.alert ? "Matches" : "Packets"} ${fmtNum(a)}–${fmtNum(b)}` +
      (pkt.total != null ? ` of ${fmtNum(pkt.total)}` : "") + ` · frames ${fmtNum(first)}–${fmtNum(pkt.rows[pkt.rows.length - 1].n)}`;
  }
  $("pkt-count").textContent = count;
  $("pkt-prev").disabled = pkt.follow || !pkt.starts.length;
  $("pkt-first").disabled = pkt.follow || pkt.from <= 1;
  $("pkt-next").disabled = pkt.follow || pkt.next == null;
  $("pkt-scope").hidden = !pkt.alert;
  $("pkt-scope-text").textContent = pkt.alert ? `Only ${pkt.alertLabel}` : "";
  $("pkt-follow-wrap").hidden = !(session && session.feed);
  $("pkt-follow").checked = pkt.follow;
  if (window.selListChanged) window.selListChanged();
}

async function pktLoad(from, { keepStack = false, before = null } = {}) {
  if (pkt.loading) { pkt.again = [from, { keepStack, before }]; return; }  // (after the one running)
  pkt.loading = true;
  const params = new URLSearchParams({ from: String(from), limit: String(PAGE) });
  if (pkt.filter) params.set(pkt.filterKind === "display" ? "dfilter" : "filter", pkt.filter);
  if (pkt.alert) params.set("alert", pkt.alert);
  if (pkt.colorize) {
    params.set("colorize", "1");
    for (const t of pkt.tmpColors) params.append("tmpcolor", t.filter);
  }
  for (const c of pkt.columns) params.append("col", c.field);
  const scope = window.focusScope ? window.focusScope() : "";
  if (scope) params.set("scope", scope);
  const key = `${pkt.filterKind}|${pkt.filter}|${pkt.alert}|${scope}`;
  if (pkt.total == null || pkt.countKey !== key) params.set("count", "1");
  $("pkt-count").textContent = "Loading…";
  try {
    const page = await api(`/api/packets?${params}`);
    if (!keepStack && from === 1) pkt.starts = [];
    pkt.from = from;
    pkt.rows = page.packets;
    pkt.colors = page.colors || [];
    pkt.next = page.next;
    // The engine only counts matches before `from` on counting requests; otherwise we know it.
    pkt.before = page.matched_total != null ? (page.matched_before || 0) : (before ?? 0);
    if (page.matched_total != null) { pkt.total = page.matched_total; pkt.countKey = key; }
    if (page.first_ts) pkt.t0 = page.first_ts;
    pkt.loadedKey = sessionKey();
    if (pkt.names && window.refreshNames) await window.refreshNames();
    pktRender();
    $("pkt-list").scrollTop = 0;
  } catch (err) {
    pkt.rows = [];
    pktRender();
    $("pkt-count").textContent = err.message;
  } finally {
    pkt.loading = false;
    if (pkt.again) {
      const [f, o] = pkt.again;
      pkt.again = null;
      pktLoad(f, o);
    }
  }
}

function sessionKey() { return state.session ? `${state.session.started}|${state.session.source}` : ""; }

// Show frame `n` in the list as it is filtered (Find Packet, Go to a match), and select it.
async function pktReveal(n) {
  if (!pkt.rows.some((p) => p.n === n)) {
    if (pkt.rows.length) pkt.starts.push(pkt.from);
    pkt.total = null;  // (count again: the matches before it number the rows)
    await pktLoad(n, { keepStack: true });
  }
  await pktSelect(n);
  document.querySelector(`#pkt-rows tr[data-n="${n}"]`)?.scrollIntoView({ block: "center" });
}

// The packet shown in the detail panes. Unless `keep`, it is also all that is selected.
async function pktSelect(n, { keep = false } = {}) {
  if (!keep && window.selSingle) window.selSingle(n);
  pkt.selected = n;
  document.querySelectorAll("#pkt-rows tr").forEach((tr) => tr.classList.toggle("selected", tr.dataset.n === String(n)));
  try {
    const d = await api(`/api/packets/${n}`);
    if (pkt.selected === n) pktDetail(d);
  } catch (err) {
    $("pkt-tree").replaceChildren(el("p", { class: "muted" }, err.message));
    $("pkt-hex").replaceChildren();
  }
}

function pktDetail(d) {
  pkt.detail = d;
  const tree = $("pkt-tree");
  tree.replaceChildren();
  const frame = el("details", { open: "" });
  const fs = el("summary", {}, `Frame ${d.n}: ${fmtNum(d.len)} bytes on wire, ${fmtNum(d.cap)} bytes captured`);
  frame.append(fs);
  const fdl = el("dl");
  const when = new Date(d.ts * 1000);
  for (const [k, v] of [["Arrival time", `${when.toLocaleString()}.${String(Math.floor((d.ts % 1) * 1e6)).padStart(6, "0")}`],
    ["Time since capture start", pkt.t0 != null ? `${(d.ts - pkt.t0).toFixed(6)} s` : "–"],
    ["Protocols", d.layers.map((l) => l.name).join(" → ")], ["Summary", d.info]]) {
    fdl.append(el("dt", {}, k), el("dd", {}, v));
  }
  frame.append(fdl);
  frame.addEventListener("click", (e) => { if (e.target === fs) pktHighlight(0, d.cap); });
  if (window.packetExplainBox) tree.append(window.packetExplainBox(d));  // the packet in plain words, first
  tree.append(frame);
  for (const layer of d.layers) {
    const det = el("details", { open: "" });
    const sum = el("summary", {}, layer.name);
    sum.append(el("span", { class: "muted" }, `  ${layer.length} bytes @ ${layer.offset}`));
    const help = window.layerHelp && window.layerHelp(layer.name);  // (? : what this protocol is, in Help)
    if (help) sum.append(help);
    sum.addEventListener("click", () => pktHighlight(layer.offset, layer.length));
    det.append(sum);
    const dl = el("dl");
    for (const [name, value, off, len] of layer.fields) {
      const dt = el("dt", {}, name);
      const dd = el("dd");
      const btn = el("button", { type: "button", class: "field" }, value);
      // Fields decoded from a structure (e.g. SNI) have no byte range of their own: show the layer.
      btn.addEventListener("click", () => (len ? pktHighlight(off, len) : pktHighlight(layer.offset, layer.length)));
      dd.append(btn);
      dl.append(dt, dd);
    }
    det.append(dl);
    tree.append(det);
  }
  if (d.malformed) tree.append(el("p", { class: "error" }, "Malformed or truncated packet."));
  if (d.fields && d.fields.length) {
    const det = el("details", { class: "filter-fields" });
    det.append(el("summary", {}, `Filter fields (${d.fields.length})`));
    if (d.protocols) det.append(el("p", { class: "muted small mono" }, d.protocols));
    const list = el("ul", { class: "ff-list" });
    for (const [name, value] of d.fields) {
      const expr = value === "" ? name : `${name} == ${value}`;
      const b = el("button", { type: "button", class: "field ff", title: "Click for filter actions" });
      b.append(el("span", { class: "ff-name" }, name), document.createTextNode(value === "" ? "" : " == "),
        el("span", { class: "ff-value" }, value));
      b.addEventListener("click", (e) => window.filterMenu && window.filterMenu(e, expr));
      b.addEventListener("contextmenu", (e) => { e.preventDefault(); if (window.filterMenu) window.filterMenu(e, expr); });
      const li = el("li");
      li.append(b);
      list.append(li);
    }
    det.append(list);
    tree.append(det);
  }
  pktHex(d.hex, false);
}

function pktHex(hex, all) {
  const box = $("pkt-hex");
  const total = hex.length / 2;
  const shown = all ? total : Math.min(total, 4096);
  const frag = document.createDocumentFragment();
  for (let row = 0; row < shown; row += 16) {
    const line = el("div", { class: "hex-line" });
    line.append(el("span", { class: "hex-off" }, row.toString(16).padStart(4, "0")));
    const hx = el("span", { class: "hex-bytes" });
    const asc = el("span", { class: "hex-ascii" });
    for (let i = row; i < Math.min(row + 16, shown); i++) {
      const byte = parseInt(hex.substr(i * 2, 2), 16);
      hx.append(el("span", { "data-i": String(i) }, hex.substr(i * 2, 2)));
      if ((i - row) === 7) hx.append(document.createTextNode(" "));
      asc.append(el("span", { "data-i": String(i) }, byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : "."));
    }
    line.append(hx, asc);
    frag.append(line);
  }
  box.replaceChildren(frag);
  if (shown < total) {
    const more = el("button", { type: "button", class: "link" }, `Show all ${fmtNum(total)} bytes`);
    more.addEventListener("click", () => pktHex(hex, true));
    box.append(more);
  }
}

function pktHighlight(offset, length) {
  const box = $("pkt-hex");
  box.querySelectorAll(".hl").forEach((n) => n.classList.remove("hl"));
  if (!length) return;
  let first = null;
  for (let i = offset; i < offset + length; i++) {
    box.querySelectorAll(`[data-i="${i}"]`).forEach((n) => { n.classList.add("hl"); first = first || n; });
  }
  first?.scrollIntoView({ block: "nearest" });
}

function pktFeed(msg) {
  if (!pkt.follow) return;
  if (msg.first_ts && pkt.t0 == null) pkt.t0 = msg.first_ts;
  const list = $("pkt-list");
  const atBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 40;
  pkt.rows = pkt.rows.concat(msg.packets).slice(-MAX_FOLLOW_ROWS);
  pktRender();
  if (atBottom) list.scrollTop = list.scrollHeight;
}

function pktSetFollow(on) {
  pkt.follow = on;
  if (state.ws && state.ws.readyState === 1) state.ws.send(JSON.stringify({ type: "follow", on }));
  if (on) { pkt.rows = []; pkt.filter = ""; pkt.alert = null; $("pkt-filter").value = ""; }
  pktRender();
  if (!on) pktLoad(pkt.rows.length ? pkt.rows[0].n : 1);
}

function pktReset() {
  if (window.selSessionReset) window.selSessionReset();
  if (window.mapFocusReset) window.mapFocusReset();
  Object.assign(pkt, { from: 1, starts: [], next: null, total: null, before: 0, rows: [], selected: null,
    t0: null, loadedKey: null, detail: null, alert: null, filter: "", userUnfollowed: false, tmpColors: [] });
  pkt.marks.clear();
  $("pkt-filter").value = "";
  $("pkt-tree").replaceChildren(el("p", { class: "muted" }, "Select a packet to see its layers."));
  $("pkt-hex").replaceChildren();
  pktRender();
}

function pktSessionChanged() {
  const s = state.session;
  if (!s) return;
  if (s.feed && s.state === "running" && !pkt.follow && !pkt.rows.length && !pkt.userUnfollowed) {
    pktSetFollow(true);  // live capture / replay: stream by default
  }
  if (["stopped", "finished", "error"].includes(s.state) && pkt.follow) {
    pktSetFollow(false);
  }
  if (state.view === "packets" && !pkt.follow && pkt.loadedKey !== sessionKey() &&
      ["running", "finished", "stopped"].includes(s.state)) {
    pktLoad(1);
  }
}

const VIEWS = ["alerts", "packets", "stats", "hosts", "files"];
// The views two tabs show in two ways: the alerts as a list or as each device's story, the
// hosts as a table or a map. The old names still work (setView("map") shows the map).
const VIEW_ALIAS = { story: ["alerts", "story"], list: ["alerts", "list"], map: ["hosts", "map"], assets: ["hosts", "table"] };
const viewHooks = {};  // view (or "story", "map", "assets") -> function called when it is shown
state.alertsMode = "list";
state.hostsMode = "table";

function setView(view) {
  if (view === "hunt") { window.openHunt(); return; }  // (the indicator sweep is a dialog now)
  const alias = VIEW_ALIAS[view];
  if (alias) {
    view = alias[0];
    if (view === "alerts") setAlertsMode(alias[1], false);
    else setHostsMode(alias[1], false);
  }
  state.view = view;
  for (const v of VIEWS) $(`view-${v}`).hidden = v !== view;
  for (const tab of document.querySelectorAll(".view-tab")) {
    const on = tab.dataset.view === view;
    tab.setAttribute("aria-selected", String(on));
    tab.tabIndex = on ? 0 : -1;
  }
  if (view === "packets" && !pkt.follow && pkt.loadedKey !== sessionKey() && state.session &&
      state.session.state !== "idle") {
    pktLoad(1);
  }
  if (view === "alerts" && state.selected) renderDetail();
  runViewHook();
}

// Whether a view (by its old name too: "story", "map", "assets") is the one on screen.
function viewIs(name) {
  if (name === "story") return state.view === "alerts" && state.alertsMode === "story";
  if (name === "map") return state.view === "hosts" && state.hostsMode === "map";
  if (name === "assets") return state.view === "hosts" && state.hostsMode !== "map";
  return state.view === name;
}

// Read the data of what is on screen (a view's hook, or the shown way of a two-way view).
function runViewHook() {
  const v = state.view === "alerts" ? (state.alertsMode === "story" ? "story" : "alerts")
    : state.view === "hosts" ? (state.hostsMode === "map" ? "map" : "assets") : state.view;
  if (viewHooks[v]) viewHooks[v]();
}

function setAlertsMode(mode, show = true) {
  state.alertsMode = mode === "story" ? "story" : "list";
  const story = state.alertsMode === "story";
  document.querySelectorAll("#alerts-mode .chip").forEach((c) => {
    const on = c.dataset.mode === state.alertsMode;
    c.classList.toggle("active", on);
    c.setAttribute("aria-pressed", String(on));
  });
  $("story-wrap").hidden = !story;
  document.querySelector(".alert-scroll").hidden = story;
  $("sev-filter").hidden = story;
  $("alert-count").hidden = story;
  $("story-count").hidden = !story;
  $("view-alerts").classList.toggle("story-mode", story);
  if (show && state.view === "alerts") runViewHook();
}

function setHostsMode(mode, show = true) {
  const was = state.hostsMode;
  state.hostsMode = mode === "map" ? "map" : "table";
  const map = state.hostsMode === "map";
  document.querySelectorAll(".hosts-mode .chip").forEach((c) => {
    const on = c.dataset.hosts === state.hostsMode;
    c.classList.toggle("active", on);
    c.setAttribute("aria-pressed", String(on));
  });
  $("hosts-table").hidden = map;
  $("hosts-map").hidden = !map;
  if (show && state.view === "hosts") runViewHook();
  // From the table to the map: the same host, now on the map (only then: mapFocus shows the map again).
  if (map && was !== "map" && typeof nmap !== "undefined" && typeof assetsView !== "undefined" && assetsView.selected) {
    setTimeout(() => window.mapFocus(assetsView.selected), 0);
  }
}
document.querySelectorAll("#alerts-mode .chip").forEach((c) => c.addEventListener("click", () => setAlertsMode(c.dataset.mode)));
document.querySelectorAll(".hosts-mode .chip").forEach((c) => c.addEventListener("click", () => setHostsMode(c.dataset.hosts)));
setHostsMode("table", false);

// Addresses in a line of text as links that open the host panel (the rest stays text).
const ADDR_TOKEN = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})$/i;
function addrLinks(text) {
  const frag = document.createDocumentFragment();
  for (const part of String(text || "").split(/([\s,]+)/)) {
    if (ADDR_TOKEN.test(part) && window.openHost) {
      const b = el("button", { type: "button", class: "addr-link", title: `${part}: host details` }, part);
      b.addEventListener("click", (e) => { e.stopPropagation(); window.openHost(part); });
      frag.append(b);
    } else if (part) frag.append(document.createTextNode(part));
  }
  return frag;
}

// Show packets matching a display filter (from statistics, the map, menus).
function showPacketsFor(expr) {
  if (pkt.follow) pktSetFollow(false);
  pkt.alert = null;
  pkt.filterKind = "display";
  $("pkt-filter-kind").value = "display";
  pkt.filter = expr;
  $("pkt-filter").value = expr;
  pkt.total = null;
  pkt.starts = [];
  setView("packets");
  pktLoad(1);
}

function showAlertPackets() {
  const a = state.detail;
  if (!a) return;
  if (pkt.follow) pktSetFollow(false);
  pkt.alert = a.id;
  pkt.alertLabel = `${a.title} ${a.id} (${a.export_flows} flow${a.export_flows === 1 ? "" : "s"})`;
  pkt.filter = "";
  $("pkt-filter").value = "";
  pkt.total = null;
  pkt.starts = [];
  setView("packets");
  pktLoad(1);
}

// ---------------------------------------------------------------- wiring

for (const tab of document.querySelectorAll(".view-tab")) {
  tab.addEventListener("click", () => setView(tab.dataset.view));
  tab.addEventListener("keydown", (e) => {
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      const i = VIEWS.indexOf(tab.dataset.view);
      const next = VIEWS[(i + (e.key === "ArrowRight" ? 1 : VIEWS.length - 1)) % VIEWS.length];
      setView(next);
      $(`tab-${next}`).focus();
    }
  });
}
$("show-packets").addEventListener("click", showAlertPackets);
$("pkt-filter-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const kind = $("pkt-filter-kind").value;
  const text = $("pkt-filter").value.trim();
  if (kind === "display" && text && window.validateDisplayFilter && !(await window.validateDisplayFilter(text))) return;
  if (pkt.follow) pktSetFollow(false);
  pkt.filterKind = kind;
  pkt.filter = text;
  pkt.total = null;
  pkt.starts = [];
  if (window.rememberFilter && pkt.filter) window.rememberFilter(pkt.filterKind, pkt.filter);
  pktLoad(1);
});
$("pkt-colorize").addEventListener("change", (e) => {
  pkt.colorize = e.target.checked;
  if (!pkt.follow) pktLoad(pkt.from, { keepStack: true, before: pkt.before });
  else pktRender();
});
$("pkt-time-format").addEventListener("change", (e) => { pkt.timeFormat = e.target.value; pktRender(); });
$("pkt-marks-clear").addEventListener("click", () => { pkt.marks.clear(); pktRender(); });
$("pkt-tmp-colors-clear").addEventListener("click", () => {
  pkt.tmpColors = [];
  if (!pkt.follow) pktLoad(pkt.from, { keepStack: true, before: pkt.before });
});
$("pkt-clear").addEventListener("click", () => {
  $("pkt-filter").value = "";
  $("pkt-filter").dataset.valid = "";
  $("pkt-filter-msg").textContent = "";
  pkt.filter = "";
  pkt.total = null;
  pkt.starts = [];
  if (!pkt.follow) pktLoad(1);
});
$("pkt-scope-clear").addEventListener("click", () => {
  pkt.alert = null;
  pkt.total = null;
  pkt.starts = [];
  pktLoad(1);
});
$("pkt-follow").addEventListener("change", (e) => {
  pkt.userUnfollowed = !e.target.checked;
  pktSetFollow(e.target.checked);
});
$("pkt-next").addEventListener("click", () => {
  if (pkt.next == null) return;
  pkt.starts.push({ from: pkt.from, before: pkt.before });
  pktLoad(pkt.next, { keepStack: true, before: pkt.before + pkt.rows.length });
});
$("pkt-prev").addEventListener("click", () => {
  if (!pkt.starts.length) return;
  const prev = pkt.starts.pop();
  pktLoad(prev.from, { keepStack: true, before: prev.before });
});
$("pkt-first").addEventListener("click", () => { pkt.starts = []; pktLoad(1); });
$("pkt-list").addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "m" && pkt.selected != null) {
    e.preventDefault();
    if (pkt.marks.has(pkt.selected)) pkt.marks.delete(pkt.selected);
    else pkt.marks.add(pkt.selected);
    pktRender();
    return;
  }
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  e.preventDefault();
  const i = pkt.rows.findIndex((p) => p.n === pkt.selected);
  const j = Math.max(0, Math.min(pkt.rows.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)));
  if (pkt.rows[j]) {
    pktSelect(pkt.rows[j].n);
    document.querySelector(`#pkt-rows tr[data-n="${pkt.rows[j].n}"]`)?.scrollIntoView({ block: "nearest" });
  }
});


$("btn-open").addEventListener("click", openCapture);
$("start-open").addEventListener("click", openCapture);
$("btn-live").addEventListener("click", openLiveDialog);
$("start-live").addEventListener("click", openLiveDialog);
window.runDemo = () => startSession({ mode: "demo" });
$("start-demo").addEventListener("click", window.runDemo);
$("btn-stop").addEventListener("click", async () => {
  try { renderSession(await api("/api/session", "DELETE")); } catch (err) { console.warn(err); }
});
window.quitApp = async () => {
  try { await api("/api/quit", "POST"); } catch { /* server is going away */ }
  document.body.replaceChildren(el("main", { class: "locked" }, "ANTA has stopped. You can close this tab."));
};
$("live-cancel").addEventListener("click", () => $("live-dialog").close());
$("open-cancel").addEventListener("click", () => $("open-dialog").close());
$("live-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("live-start").disabled = true;
  const error = await startSession({
    mode: "live", iface: $("live-iface").value, filter: $("live-filter").value.trim(), record: $("live-record").checked,
  });
  $("live-start").disabled = false;
  if (error) $("live-error").textContent = error;
  else $("live-dialog").close();
});
$("open-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const error = await startSession({ mode: "file", path: $("open-path").value.trim() });
  if (error) $("open-error").textContent = error;
  else $("open-dialog").close();
});


$("alerts-involving").addEventListener("click", () => showAlertsInvolving(null));
document.querySelectorAll("#sev-filter .chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    state.filter = chip.dataset.sev;
    document.querySelectorAll("#sev-filter .chip").forEach((c) => {
      c.classList.toggle("active", c === chip);
      c.setAttribute("aria-pressed", String(c === chip));
    });
    renderFeed();
  });
});
document.querySelectorAll("#alert-head .sort").forEach((btn) => {
  btn.addEventListener("click", () => {
    const key = btn.dataset.key;
    state.sort = key === state.sort.key ? { key, dir: -state.sort.dir } : { key, dir: SORT_KEYS[key].first };
    renderFeed();
  });
});
$("chart-table-toggle").addEventListener("click", (e) => {
  state.tableView = !state.tableView;
  e.target.setAttribute("aria-pressed", String(state.tableView));
  e.target.textContent = state.tableView ? "View as chart" : "View as table";
  $("chart").hidden = state.tableView;
  $("chart-table").hidden = !state.tableView;
});
let resizeTimer;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => state.selected && renderDetail(), 150);
});

connect();
