// Statistics → Rhythm: one row per channel (a client to one server and port), time across,
// a darker cell where it checked in more. People browse in bursts; malware calling home
// does it on a timer, which shows as evenly spaced stripes. Rows are sorted steadiest
// first; pick one for the gaps between its check-ins (a flat line is a timer).
// Everything from the network is rendered with textContent, never innerHTML.
"use strict";

const rhythm = { only: false, table: false, shown: 60, sel: "" };
const RHYTHM_LEVELS = [[1, 1, "1"], [2, 3, "2–3"], [4, 7, "4–7"], [8, Infinity, "8+"]];
const RHYTHM_MIX = [32, 56, 80, 100];  // % of --viz-1 over the surface: one hue, light to dark
const RHYTHM_LABEL = 248, RHYTHM_META = 176, RHYTHM_ROW = 18;

const rhythmKey = (r) => `${r.src}|${r.dst}|${r.port}|${r.proto}`;
const rhythmExpr = (r) => {
  const ip = (a) => `${a.includes(":") ? "ipv6" : "ip"}.addr == ${a}`;
  return `${ip(r.src)} && ${ip(r.dst)} && ${r.proto}.port == ${r.port}`;
};
const rhythmLevel = (n) => RHYTHM_LEVELS.findIndex(([lo, hi]) => n >= lo && n <= hi);

function rhythmEvery(r) {
  if (!r.period) return "–";
  return `every ${fmtDuration(r.period)}` + (r.jitter_pct != null && r.rhythm !== "irregular" ? ` ±${Math.round(r.jitter_pct)}%` : "");
}

function rhythmVerdict(r) {
  if (r.regularity == null) return "too few check-ins to judge";
  return `${r.rhythm} (${Math.round(r.regularity * 100)}%)`;
}

TOOLS.rhythm = (body) => {
  const rx = RX;
  const slot = invGet("rhythm", "/api/rhythm");
  body.append(el("p", { class: "muted small" }, `When each device talked to each server, over ${rx.scope() ? "the selection" : "the whole capture"}. People browse in `
    + "bursts; software calling home does it on a timer, which shows here as evenly spaced stripes. Steadiest first. "
    + "Click a row for the gaps between its check-ins; right-click it for its packets."));
  if (invPending(body, slot, "the channels")) return;
  const d = slot.data;
  if (!d.total) {
    body.append(el("p", { class: "empty" }, "No channel has checked in more than twice yet. Rhythms come from the analysis: "
      + "open a capture file or start a capture, then look again."));
    return;
  }
  const flagged = d.rows.filter((r) => r.alert && r.alert.severity !== "low").length;
  tiles(body, [["Channels", fmtNum(d.total), "a client to one server and port"],
    ["Steady rhythms", fmtNum(d.steady), "check-ins on a timer"],
    ["Raised as beacons", fmtNum(flagged), flagged ? "calling home on a timer: see their alerts" : "no timer looked like malware"]]);

  const bar = el("div", { class: "rhythm-bar" });
  const toggle = (label, on, fn) => {
    const b = el("button", { type: "button", class: `tb small${on ? " active" : ""}`, "aria-pressed": String(on) }, label);
    b.addEventListener("click", fn);
    return b;
  };
  bar.append(
    toggle("Steady only", rhythm.only, () => { rhythm.only = !rhythm.only; rhythm.shown = 60; rx.rerender(); }),
    toggle("Table", rhythm.table, () => { rhythm.table = !rhythm.table; rx.rerender(); }),
    el("span", { class: "spacer" }),
    el("span", { class: "muted small" }, `one column = ${fmtDuration(d.bin_s)}`));
  const refresh = el("button", { type: "button", class: "tb small" }, "Refresh");
  refresh.addEventListener("click", () => { invForget("rhythm"); rx.rerender(); });
  bar.append(refresh);
  body.append(bar);

  const rows = rhythm.only ? d.rows.filter((r) => r.rhythm === "steady") : d.rows;
  if (!rows.length) {
    body.append(el("p", { class: "empty" }, "No steady rhythm in this capture."));
    return;
  }
  const detail = el("div", { class: "rhythm-detail" });
  if (rhythm.table) rhythmTable(body, rows, detail);
  else rhythmMap(body, d, rows, detail);
  body.append(detail);
  const sel = rows.find((r) => rhythmKey(r) === rhythm.sel);
  if (sel) rhythmDetail(detail, d, sel);
};

function rhythmMap(body, d, rows, detail) {
  const rx = RX;
  const box = el("div", { class: "io-chart rhythm-map" });
  body.append(box);
  const shown = rows.slice(0, rhythm.shown);
  const W = chartWidth(box), top = 22;
  const plot = Math.max(120, W - RHYTHM_LABEL - RHYTHM_META);
  const cw = plot / d.bins;
  const H = top + shown.length * RHYTHM_ROW + 4;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", height: String(H), role: "img",
    "aria-label": `Check-ins over time for ${shown.length} channels` });
  const span = d.bin_s * d.bins;
  for (const t of niceTicks(0, span, Math.max(2, Math.floor(plot / 110)))) {
    if (t < 0 || t > span) continue;
    const x = RHYTHM_LABEL + (t / span) * plot;
    root.append(svg("line", { x1: x, x2: x, y1: top - 4, y2: H, class: "grid" }));
    root.append(svg("text", { x, y: 12, class: "tick", "text-anchor": "middle" }, fmtTime(d.start + t)));
  }
  const mix = (lvl) => `color-mix(in srgb, var(--viz-1) ${RHYTHM_MIX[lvl]}%, var(--surface))`;
  shown.forEach((r, i) => {
    const y = top + i * RHYTHM_ROW;
    const key = rhythmKey(r);
    const g = svg("g", { class: `rhythm-row${key === rhythm.sel ? " selected" : ""}`, tabindex: "0", role: "button",
      "aria-label": `${r.src} to ${r.dst} port ${r.port}: ${r.events} check-ins, ${rhythmEvery(r)}, ${rhythmVerdict(r)}` });
    g.append(svg("rect", { x: 0, y, width: W, height: RHYTHM_ROW, class: "rhythm-band" }));
    const name = r.dst_name || hostName(r.dst);
    const full = `${r.src_name || r.src} → ${name ? `${name} (${r.port})` : `${r.dst}:${r.port}`}`;
    const fit = Math.floor((RHYTHM_LABEL - 10) / 6.7);  // (11px monospace)
    const label = svg("text", { x: 4, y: y + 13, class: "rhythm-label" }, full.length > fit ? `${full.slice(0, fit - 1)}…` : full);
    label.append(svg("title", {}, `${r.src} → ${r.dst}:${r.port}${name ? ` (${name})` : ""}`));
    g.append(label);
    for (const [bin, n, out, inb] of r.cells) {
      const lvl = rhythmLevel(n);
      const cell = svg("rect", { x: RHYTHM_LABEL + bin * cw + (cw >= 4 ? 0.5 : 0), y: y + 3,
        width: Math.max(1, cw - (cw >= 4 ? 1 : 0)), height: RHYTHM_ROW - 6, rx: cw >= 6 ? 1.5 : 0, class: "rhythm-cell" });
      cell.style.fill = mix(lvl);
      cell.addEventListener("mousemove", (evt) => showTip(evt, [[`${fmtTime(d.start + bin * d.bin_s)} – ${fmtTime(d.start + (bin + 1) * d.bin_s)}`],
        ["Check-ins", fmtNum(n)], ["Sent", fmtBytes(out)], ["Received", fmtBytes(inb)]]));
      cell.addEventListener("mouseleave", hideTip);
      g.append(cell);
    }
    const mx = RHYTHM_LABEL + plot + 8;
    g.append(svg("text", { x: mx, y: y + 13, class: "rhythm-meta" }, rhythmEvery(r)));
    const verdict = svg("text", { x: W - 4, y: y + 13, class: `rhythm-meta${r.rhythm === "steady" ? " strong" : ""}`, "text-anchor": "end" },
      r.alert && r.alert.severity !== "low" ? `⚠ ${r.alert.id}`
        : r.rhythm === "steady" && r.shared_by > 2 ? `shared ×${r.shared_by}` : r.rhythm);
    g.append(verdict);
    const pick = () => { rhythm.sel = key; rx.rerender(); };
    g.addEventListener("click", pick);
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    g.addEventListener("contextmenu", (e) => { e.preventDefault(); window.filterMenu(e, rhythmExpr(r)); });
    root.append(g);
  });
  box.append(root);
  // The legend: what a cell's shade means (the hue is one, so it reads in grey too).
  const legend = el("div", { class: "legend rhythm-legend" }, "Check-ins per column: ");
  RHYTHM_LEVELS.forEach(([, , label], i) => {
    const sw = el("span", { class: "swatch" });
    sw.style.background = mix(i);
    const item = el("span");
    item.append(sw, document.createTextNode(` ${label}`));
    legend.append(item);
  });
  box.append(legend, el("p", { class: "muted small" }, "On the right: how steady the rhythm is; ⚠ and an alert number when it "
    + "was raised as a beacon; shared ×N when N devices keep the same timer with one server (usually a cloud service's keep-alive)."));
  if (rows.length > shown.length) {
    const more = el("button", { type: "button", class: "tb small" }, `Show ${Math.min(60, rows.length - shown.length)} more of ${fmtNum(rows.length - shown.length)}`);
    more.addEventListener("click", () => { rhythm.shown += 60; rx.rerender(); });
    box.append(more);
  }
}

function rhythmTable(body, rows, detail) {
  const rx = RX;
  section(body, "Channels", "click a row for its check-ins; right-click for its packets");
  dataTable(body, "rhythm", [
    { label: "Client", type: "text", get: (r) => r.src, render: (r) => addrCell(r.src) },
    { label: "Server", type: "text", get: (r) => `${r.dst}:${r.port}`, render: (r) => addrCell(`${r.dst}`) },
    { label: "Port", type: "num", get: (r) => r.port },
    { label: "Check-ins", type: "num", get: (r) => r.events },
    { label: "Period (s)", type: "num", get: (r) => (r.period != null ? Math.round(r.period * 100) / 100 : null) },
    { label: "Rhythm", type: "text", get: (r) => r.rhythm },
    { label: "Steadiness", type: "pct", get: (r) => r.regularity },
    { label: "Devices using it", type: "num", get: (r) => r.shared_by },
    { label: "First", type: "num", get: (r) => r.first, render: (r) => el("span", {}, fmtTime(r.first)) },
    { label: "Last", type: "num", get: (r) => r.last, render: (r) => el("span", {}, fmtTime(r.last)) },
    { label: "Sent", type: "bytes", get: (r) => r.bytes_out },
    { label: "Received", type: "bytes", get: (r) => r.bytes_in },
    { label: "Alert", type: "text", get: (r) => (r.alert ? r.alert.id : "") },
  ], rows, { limit: 400, defaultSort: { col: 6, dir: -1 }, onRow: (e, r) => {
    if (e.type === "contextmenu" || e.button === 2) { window.filterMenu(e, rhythmExpr(r)); return; }
    rhythm.sel = rhythmKey(r);
    rx.rerender();
  } });
}

function rhythmDetail(box, d, r) {
  const head = el("div", { class: "st-head" });
  head.append(el("h3", {}, `Gaps between check-ins: ${r.src} → ${r.dst}:${r.port}`),
    el("span", { class: "muted small" }, `${fmtNum(r.events)} check-ins, ${rhythmEvery(r)}: ${rhythmVerdict(r)}`
      + (r.shared_by > 1 ? `; ${fmtNum(r.shared_by)} devices use this server` : "")));
  const tools = el("div", { class: "rhythm-bar" });
  const btn = (label, fn) => { const b = el("button", { type: "button", class: "tb small" }, label); b.addEventListener("click", fn); return b; };
  const rx = RX;
  tools.append(btn("Show packets", () => rx.showPackets(rhythmExpr(r))));
  if (r.alert) tools.append(btn(`Open alert ${r.alert.id}`, () => { setView("alerts"); select(r.alert.id); }));
  const chart = el("div", { class: "io-chart tcp-chart rhythm-chart" });
  box.replaceChildren(head, tools, chart);
  if (!r.intervals.length) return;
  xyChart(chart, {
    label: `Seconds between check-ins of ${r.src} to ${r.dst}:${r.port}`, yFmt: (v) => fmtDuration(v),
    series: [{ name: "Gap since the check-in before", kind: "dots", color: "--viz-1",
      points: r.intervals.map(([t, g]) => ({ x: t, y: g, tip: [[fmtTime(d.start + t)], ["Gap since the one before", fmtDuration(g)]] })) }],
  });
  chart.append(el("p", { class: "muted small" }, "x: seconds since the first check-in in the capture. A timer draws a flat line "
    + "(its jitter is how far the dots stray); browsing scatters them."));
}
