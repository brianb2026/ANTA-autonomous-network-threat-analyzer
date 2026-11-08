// Statistics → Flow graph and TCP stream graphs, after Wireshark's.
//   Flow graph: who sent what to whom, in order: one lane per address, one arrow per
//   packet, labelled with its ports and Info. Click an arrow to open the packet.
//   TCP stream graphs: one direction of one TCP stream as Wireshark draws it: sequence
//   numbers over time (Stevens), throughput, round-trip time and window scaling, with a
//   crosshair and tooltip; click a point to open its packet.
// Everything from the network is rendered with textContent, never innerHTML.
"use strict";

const graphs = {
  flowFilter: null, flowRows: null, flowKey: "", flowTotal: null, flowT0: null,
  tcpStream: null, tcpDir: 0, tcpKind: "stevens", tcpData: null, tcpKey: "", seq: 0,
};
const FLOW_LIMIT = 600;
const FLOW_LANE = 168, FLOW_ROW = 26, FLOW_GUTTER = 136, FLOW_MAX_LANES = 12;

// ------------------------------------------------------------ flow graph

TOOLS.flow = (body) => {
  const rx = RX;
  const st = rx.main ? graphs : rx.state;  // (a quick-tool window keeps its own graph)
  const form = el("form", { class: "graph-form" });
  const input = el("input", { type: "text", class: "mono", spellcheck: "false", "aria-label": "Display filter for the flow graph",
    placeholder: rx.main ? "A display filter, e.g. tcp.stream eq 3 (empty: the first packets of the capture)"
      : "Narrow it with a display filter (empty: every packet of the selection)" });
  if (st.flowFilter == null) st.flowFilter = rx.main && pkt.filterKind === "display" ? pkt.filter : "";
  input.value = st.flowFilter ?? "";
  form.append(el("label", { class: "inline" }, "Packets"), input, el("button", { type: "submit", class: "tb small tb-primary" }, "Show"));
  const note = el("p", { class: "muted small", role: "status" });
  const box = el("div", { class: "flow-box" });
  if (rx.main) {
    body.append(el("p", { class: "muted small" }, "Who sent what to whom, in order, like Wireshark's Flow Graph: one lane per " +
      "address, one arrow per packet. A filter for one conversation (right-click a packet → Flow graph of this conversation) " +
      "reads best. Click an arrow to open its packet."));
  }
  body.append(form, note, box);
  form.addEventListener("submit", (e) => { e.preventDefault(); st.flowFilter = input.value.trim(); flowLoad(box, note, true, st, rx); });
  flowLoad(box, note, false, st, rx);
};

async function flowLoad(box, note, force, st = graphs, rx = MAIN_RX) {
  const filter = st.flowFilter ?? "";
  const scope = rx.scope();
  const key = `${sessionKey()}|${scope}|${filter}`;
  if (!force && st.flowRows && st.flowKey === key) { flowRender(box, note, st); return; }
  const seq = st.seq = (st.seq || 0) + 1;
  note.textContent = "Reading the packets…";
  box.replaceChildren();
  const params = new URLSearchParams({ from: "1", limit: String(FLOW_LIMIT), count: "1" });
  if (filter) params.set("dfilter", filter);
  if (scope) params.set("scope", scope);
  for (const f of ["tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]) params.append("col", f);
  try {
    const page = await api(`/api/packets?${params}`);
    if (seq !== st.seq) return;
    st.flowRows = page.packets;
    st.flowTotal = page.matched_total;
    st.flowT0 = page.first_ts;
    st.flowKey = key;
    flowRender(box, note, st);
  } catch (err) {
    if (seq === st.seq) note.textContent = err.message;
  }
}

function flowPorts(p) {
  const f = p.f || {};
  const s = (f["tcp.srcport"] || f["udp.srcport"] || [])[0], d = (f["tcp.dstport"] || f["udp.dstport"] || [])[0];
  return [s || "", d || ""];
}

function flowRender(box, note, st = graphs) {
  const rows = st.flowRows || [];
  if (!rows.length) {
    note.textContent = "No packets match.";
    box.replaceChildren();
    return;
  }
  // Lanes: addresses in order of first appearance; past twelve, the busiest twelve and "other hosts".
  const count = new Map(), order = [];
  for (const p of rows) {
    for (const a of [p.src, p.dst]) {
      if (!count.has(a)) order.push(a);
      count.set(a, (count.get(a) || 0) + 1);
    }
  }
  let lanes = order;
  const OTHER = "\u0000other";
  if (order.length > FLOW_MAX_LANES) {
    const keep = new Set([...order].sort((a, b) => count.get(b) - count.get(a)).slice(0, FLOW_MAX_LANES - 1));
    lanes = [...order.filter((a) => keep.has(a)), OTHER];
  }
  const laneOf = (a) => { const i = lanes.indexOf(a); return i >= 0 ? i : lanes.length - 1; };
  // Lanes share the width there is (room for the Info text), at least FLOW_LANE each.
  const lane = Math.max(FLOW_LANE, Math.min(440, Math.floor(((box.clientWidth || 800) - FLOW_GUTTER - 40) / lanes.length)));
  const W = FLOW_GUTTER + lanes.length * lane + 24;
  const H = rows.length * FLOW_ROW + 16;
  const xLane = (i) => FLOW_GUTTER + lane / 2 + i * lane;
  const ink = cssVar("--text"), accent = cssVar("--accent");

  // The lane names stay on top while the arrows scroll under them.
  const head = svg("svg", { width: W, height: 34, class: "flow-head", "aria-hidden": "true" });
  head.append(svg("text", { x: 8, y: 21, class: "flow-gutter-head" }, "Time · No."));
  lanes.forEach((a, i) => {
    const name = a === OTHER ? `${order.length - lanes.length + 1} other hosts` : pktHost(a);
    const t = svg("text", { x: xLane(i), y: 21, "text-anchor": "middle", class: "flow-lane-name" },
      name.length > 22 ? `${name.slice(0, 21)}…` : name);
    if (a !== OTHER) t.append(svg("title", {}, a));
    head.append(t);
  });

  const root = svg("svg", { width: W, height: H, class: "flow-svg", role: "img",
    "aria-label": `Flow graph of ${rows.length} packets between ${lanes.length} hosts` });
  const defs = svg("defs");
  for (const [id, color] of [["flow-arrow", ink], ["flow-arrow-sel", accent]]) {
    const m = svg("marker", { id, viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "8", markerHeight: "8", orient: "auto-start-reverse" });
    m.append(svg("path", { d: "M0,0L10,5L0,10z", fill: color }));
    defs.append(m);
  }
  root.append(defs);
  lanes.forEach((_, i) => root.append(svg("line", { x1: xLane(i), x2: xLane(i), y1: 0, y2: H, class: "flow-lane" })));
  const t0 = st.flowT0 ?? (rows[0] && rows[0].ts);
  rows.forEach((p, r) => {
    const y = 18 + r * FLOW_ROW;
    const g = svg("g", { class: `flow-row${p.n === pkt.selected ? " selected" : ""}`, "data-n": String(p.n) });
    g.append(svg("rect", { x: 0, y: y - 15, width: W, height: FLOW_ROW, class: "flow-hit" }));
    g.append(svg("text", { x: 8, y: y + 4, class: "flow-time" }, `${(p.ts - t0).toFixed(6)}  ${p.n}`));
    const a = laneOf(p.src), b = laneOf(p.dst);
    const xa = xLane(a), xb = xLane(b);
    const [sp, dp] = flowPorts(p);
    if (a === b) {  // (both ends in one lane: a loop)
      g.append(svg("path", { d: `M${xa},${y - 4}h24v8h-24`, class: "flow-arrow", "marker-end": "url(#flow-arrow)" }));
    } else {
      g.append(svg("line", { x1: xa, x2: xb + (xb > xa ? -1 : 1), y1: y, y2: y, class: "flow-arrow",
        "marker-end": `url(#${p.n === pkt.selected ? "flow-arrow-sel" : "flow-arrow"})` }));
      const room = Math.max(6, Math.floor((Math.abs(xb - xa) - 24) / 6.4));
      const info = p.info || p.proto || "";
      g.append(svg("text", { x: (xa + xb) / 2, y: y - 4, "text-anchor": "middle", class: "flow-label" },
        info.length > room ? `${info.slice(0, room - 1)}…` : info));
      if (sp) g.append(svg("text", { x: xa + (xb > xa ? -4 : 4), y: y + 12, "text-anchor": xb > xa ? "end" : "start", class: "flow-port" }, sp));
      if (dp) g.append(svg("text", { x: xb + (xb > xa ? 4 : -4), y: y + 12, "text-anchor": xb > xa ? "start" : "end", class: "flow-port" }, dp));
    }
    g.addEventListener("mousemove", (e) => showTip(e, [[`Packet ${p.n} · ${p.proto}`],
      [`${p.src}${sp ? `:${sp}` : ""} → ${p.dst}${dp ? `:${dp}` : ""}`, (p.ts - t0).toFixed(6) + " s"], ["Info", p.info || ""]]));
    g.addEventListener("mouseleave", hideTip);
    g.addEventListener("click", () => { hideTip(); window.goToFrame(p.n); });
    root.append(g);
  });

  const headBox = el("div", { class: "flow-head-box" });
  headBox.append(head);
  const scroll = el("div", { class: "flow-scroll", tabindex: "0", "aria-label": "Flow graph" });
  scroll.append(root);
  scroll.addEventListener("scroll", () => { headBox.scrollLeft = scroll.scrollLeft; });
  box.replaceChildren(headBox, scroll);
  const total = st.flowTotal;
  note.textContent = `${fmtNum(rows.length)} packet${rows.length === 1 ? "" : "s"}` +
    (total != null && total > rows.length ? ` (the first ${fmtNum(rows.length)} of ${fmtNum(total)}: narrow the filter to see the rest)` : "") +
    ` between ${fmtNum(order.length)} host${order.length === 1 ? "" : "s"}${st.flowFilter ? ` · ${st.flowFilter}` : ""}.`;
}

// ------------------------------------------------------------ TCP stream graphs

const TCP_KINDS = [["stevens", "Sequence (Stevens)"], ["throughput", "Throughput"], ["rtt", "Round-trip time"], ["window", "Window scaling"]];
const F_SYN = 1, F_FIN = 2, F_RST = 4, F_RETRANS = 8;

function selectedTcpStream() {
  const f = (pkt.detail && pkt.detail.fields) || [];
  const hit = f.find(([name]) => name === "tcp.stream");
  return hit ? Number(hit[1]) : null;
}

TOOLS.tcpgraph = (body) => {
  if (graphs.tcpStream == null) graphs.tcpStream = selectedTcpStream();
  const form = el("form", { class: "graph-form" });
  const stream = el("input", { type: "number", min: "0", step: "1", class: "mono", "aria-label": "TCP stream number",
    placeholder: "TCP stream" });
  if (graphs.tcpStream != null) stream.value = String(graphs.tcpStream);
  const dir = el("select", { class: "tb small", "aria-label": "Direction" });
  const kinds = el("div", { class: "seg", role: "group", "aria-label": "Graph" });
  for (const [k, label] of TCP_KINDS) {
    const b = el("button", { type: "button", class: `chip${graphs.tcpKind === k ? " active" : ""}`, "aria-pressed": String(graphs.tcpKind === k) }, label);
    b.addEventListener("click", () => {
      graphs.tcpKind = k;
      kinds.querySelectorAll(".chip").forEach((c) => { c.classList.toggle("active", c === b); c.setAttribute("aria-pressed", String(c === b)); });
      tcpRender(out, summary, dir);
    });
    kinds.append(b);
  }
  form.append(el("label", { class: "inline" }, "Stream"), stream, el("button", { type: "submit", class: "tb small tb-primary" }, "Show"),
    el("label", { class: "inline" }, "Direction"), dir, kinds);
  const summary = el("p", { class: "muted small", role: "status" });
  const out = el("div", { class: "io-chart tcp-chart" });
  body.append(el("p", { class: "muted small" }, "One direction of one TCP connection, as Wireshark's TCP Stream Graphs draw it: " +
    "how the data went out (sequence numbers), how fast, how long acknowledgements took, and the receiver's window against the data " +
    "in flight. Right-click a TCP packet → TCP stream graphs to open its connection here."), form, summary, out);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const n = Number(stream.value);
    if (!Number.isInteger(n) || n < 0) { summary.textContent = "Give a TCP stream number (the packet details show it as Stream index)."; return; }
    graphs.tcpStream = n;
    graphs.tcpDir = 0;
    tcpLoad(out, summary, dir, true);
  });
  dir.addEventListener("change", () => { graphs.tcpDir = Number(dir.value); tcpRender(out, summary, dir); });
  if (graphs.tcpStream != null) tcpLoad(out, summary, dir, false);
  else summary.textContent = "Select a TCP packet in the packet list, or type a stream number.";
};

// Opened from a packet's menu: its stream, in the direction the packet went.
window.openTcpGraph = (stream, fromSrc) => {
  graphs.tcpStream = stream;
  graphs.tcpPreferSrc = fromSrc || null;
  graphs.tcpKey = "";
  stats.tool = "tcpgraph";
  setView("stats");
  statsRender();
};
window.openFlowGraph = (filter) => {
  graphs.flowFilter = filter;
  graphs.flowKey = "";
  stats.tool = "flow";
  setView("stats");
  statsRender();
};

async function tcpLoad(out, summary, dir, force) {
  const scope = MAIN_RX.scope();
  const key = `${sessionKey()}|${scope}|${graphs.tcpStream}`;
  if (!force && graphs.tcpData && graphs.tcpKey === key) { tcpRender(out, summary, dir); return; }
  const seq = ++graphs.seq;
  summary.textContent = "Reading the connection…";
  out.replaceChildren();
  try {
    const d = await api(`/api/tcpgraph?stream=${graphs.tcpStream}${scope ? `&scope=${encodeURIComponent(scope)}` : ""}`);
    if (seq !== graphs.seq) return;
    graphs.tcpData = d;
    graphs.tcpKey = key;
    if (graphs.tcpPreferSrc) {  // (the direction of the packet it was opened from)
      graphs.tcpDir = d.b.startsWith(`${graphs.tcpPreferSrc}:`) || d.b.startsWith(`[${graphs.tcpPreferSrc}]`) ? 1 : 0;
      graphs.tcpPreferSrc = null;
    } else {
      // Wireshark graphs the direction that carries the data.
      const bytes = [0, 0];
      for (const p of d.points) bytes[p[2]] += p[4];
      graphs.tcpDir = bytes[1] > bytes[0] ? 1 : 0;
    }
    tcpRender(out, summary, dir);
  } catch (err) {
    if (seq === graphs.seq) summary.textContent = err.message;
  }
}

function tcpRender(out, summary, dir) {
  const d = graphs.tcpData;
  if (!d) return;
  const k = graphs.tcpDir;
  const [from, to] = k === 0 ? [d.a, d.b] : [d.b, d.a];
  dir.replaceChildren(el("option", { value: "0" }, `${d.a} → ${d.b}`), el("option", { value: "1" }, `${d.b} → ${d.a}`));
  dir.value = String(k);
  const mine = d.points.filter((p) => p[2] === k), theirs = d.points.filter((p) => p[2] !== k);
  const data = mine.filter((p) => p[4] > 0);
  const bytes = data.reduce((s, p) => s + p[4], 0);
  const retrans = data.filter((p) => p[8] & F_RETRANS).length;
  const rtts = theirs.map((p) => p[7]).filter((v) => v != null);
  const dur = d.points.length ? d.points[d.points.length - 1][1] - d.points[0][1] : 0;
  summary.textContent = `TCP stream ${d.stream}: ${from} → ${to} · ${fmtNum(data.length)} data segment${data.length === 1 ? "" : "s"}, ` +
    `${fmtBytes(bytes)} in ${dur.toFixed(3)} s` + (retrans ? ` · ${fmtNum(retrans)} retransmitted` : "") +
    (rtts.length ? ` · round trip ${fmtTick(Math.min(...rtts), "s")}–${fmtTick(Math.max(...rtts), "s")}` : "") +
    (d.truncated ? " · (only the first 100,000 packets)" : "");
  const kind = graphs.tcpKind;
  if (kind === "stevens") {
    if (!data.length) return tcpEmpty(out, "No data went this way: switch the direction.");
    const normal = data.filter((p) => !(p[8] & F_RETRANS)), re = data.filter((p) => p[8] & F_RETRANS);
    const seg = (p) => ({ x: p[1], y0: p[3], y1: p[3] + p[4], n: p[0], tip: [[`Packet ${p[0]}`], ["Time", `${p[1].toFixed(6)} s`],
      ["Bytes", `${fmtNum(p[3])}–${fmtNum(p[3] + p[4])} (${fmtNum(p[4])})`], ...(p[8] & F_RETRANS ? [["Retransmission", "yes"]] : [])] });
    xyChart(out, { label: "Sequence numbers over time", yFmt: (v) => fmtBytes(v), series: [
      { name: "Data segments", color: "--viz-1", kind: "segments", points: normal.map(seg) },
      ...(re.length ? [{ name: "Retransmissions", color: "--critical", kind: "segments", marker: true, points: re.map(seg) }] : []),
    ] });
  } else if (kind === "throughput") {
    if (!data.length) return tcpEmpty(out, "No data went this way: switch the direction.");
    const t0 = d.points[0][1], t1 = d.points[d.points.length - 1][1];
    const span = Math.max(t1 - t0, 0.001);
    const bin = Math.max(span / 120, 0.001);
    const n = Math.ceil(span / bin) + 1;
    const sums = new Array(n).fill(0);
    for (const p of data) sums[Math.min(n - 1, Math.floor((p[1] - t0) / bin))] += p[4];
    const pts = sums.map((b, i) => ({ x: t0 + i * bin, y: (b * 8) / bin, tip: [[`${(t0 + i * bin).toFixed(3)}–${(t0 + (i + 1) * bin).toFixed(3)} s`],
      ["Throughput", fmtRate((b * 8) / bin)], ["Bytes", fmtBytes(b)]] }));
    xyChart(out, { label: "Throughput", yFmt: fmtRate, series: [{ name: "Throughput", color: "--viz-1", kind: "line", points: pts }] });
  } else if (kind === "rtt") {
    if (!rtts.length) return tcpEmpty(out, "No acknowledgement of this direction's data was timed.");
    const pts = theirs.filter((p) => p[7] != null).map((p) => ({ x: p[1], y: p[7], n: p[0],
      tip: [[`Packet ${p[0]} (the acknowledgement)`], ["Time", `${p[1].toFixed(6)} s`], ["Round trip", fmtTick(p[7], "s")]] }));
    xyChart(out, { label: "Round-trip time of acknowledged data", yFmt: (v) => fmtTick(v, "s"),
      series: [{ name: "Round-trip time", color: "--viz-1", kind: "dots", points: pts }] });
  } else {
    // The receiver's window (from its own packets) against the bytes sent but not yet acknowledged.
    const events = d.points.slice().sort((a, b) => a[1] - b[1]);
    let acked = 0, highest = 0;
    const win = [], flight = [];
    for (const p of events) {
      if (p[2] !== k) {
        acked = Math.max(acked, p[5]);
        if (p[6] != null) win.push({ x: p[1], y: p[6], n: p[0], tip: [[`Packet ${p[0]}`], ["Receive window", fmtBytes(p[6])]] });
      } else if (p[4] > 0) {
        highest = Math.max(highest, p[3] + p[4]);
        const inflight = Math.max(0, highest - acked);
        flight.push({ x: p[1], y: inflight, n: p[0], tip: [[`Packet ${p[0]}`], ["Bytes in flight", fmtBytes(inflight)]] });
      }
    }
    if (!win.length && !flight.length) return tcpEmpty(out, "Nothing to draw for this direction.");
    xyChart(out, { label: "Receive window and bytes in flight", yFmt: (v) => fmtBytes(v), series: [
      { name: "Bytes in flight", color: "--viz-1", kind: "line", points: flight },
      { name: "Receive window", color: "--viz-2", kind: "step", points: win },
    ] });
  }
}

function tcpEmpty(out, text) { out.replaceChildren(el("p", { class: "empty" }, text)); }

// An x/y chart over time: lines, steps, dots or vertical segments (Stevens), one y axis,
// a legend when there are two series (and their names at the line ends), a crosshair with
// the nearest point's tooltip, and a click on a point opening its packet.
function xyChart(container, { label, yFmt, series }) {
  const W = chartWidth(container), H = 300;
  const labelled = series.length > 1 && series.some((s) => s.kind === "line" || s.kind === "step");
  const m = { l: 92, r: labelled ? 112 : 16, t: 12, b: 34 };
  const all = series.flatMap((s) => s.points);
  const xs = all.map((p) => p.x);
  const ys = all.flatMap((p) => (p.y1 != null ? [p.y0, p.y1] : [p.y]));
  const xmin = Math.min(...xs), xmax = Math.max(...xs, xmin + 1e-6);
  const ymax = Math.max(1e-9, ...ys);
  const yticks = niceTicks(0, ymax, 5);
  if (yticks.length > 1 && yticks[yticks.length - 1] < ymax) yticks.push(yticks[yticks.length - 1] + (yticks[1] - yticks[0]));
  const ytop = yticks[yticks.length - 1] || ymax;  // (the axis reaches past the largest value)
  const x = (v) => m.l + ((W - m.l - m.r) * (v - xmin)) / (xmax - xmin);
  const y = (v) => H - m.b - ((H - m.t - m.b) * v) / ytop;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", height: String(H), role: "img", "aria-label": label });
  for (const t of yticks) {
    root.append(svg("line", { x1: m.l, x2: W - m.r, y1: y(t), y2: y(t), class: "grid" }));
    root.append(svg("text", { x: m.l - 6, y: y(t) + 4, class: "tick", "text-anchor": "end" }, yFmt(t)));
  }
  for (const t of niceTicks(xmin, xmax, 6)) {
    if (t < xmin || t > xmax) continue;
    root.append(svg("text", { x: x(t), y: H - 12, class: "tick", "text-anchor": "middle" }, `${+t.toFixed(3)}s`));
  }
  root.append(svg("line", { x1: m.l, x2: W - m.r, y1: H - m.b, y2: H - m.b, class: "axis" }));
  for (const s of series) {
    const color = cssVar(s.color);
    const pts = s.points.slice().sort((a, b) => a.x - b.x);
    if (s.kind === "line" || s.kind === "step") {
      let dpath = "";
      pts.forEach((p, i) => {
        if (!i) dpath += `M${x(p.x).toFixed(1)},${y(p.y).toFixed(1)}`;
        else if (s.kind === "step") dpath += `H${x(p.x).toFixed(1)}V${y(p.y).toFixed(1)}`;
        else dpath += `L${x(p.x).toFixed(1)},${y(p.y).toFixed(1)}`;
      });
      if (pts.length === 1) dpath += `h4`;
      const path = svg("path", { d: dpath, class: "io-line" });
      path.style.stroke = color;
      root.append(path);
      if (series.length > 1 && pts.length) {  // its name at the line's end, so identity isn't color alone
        const last = pts[pts.length - 1];
        root.append(svg("text", { x: Math.min(x(last.x) + 6, W - m.r + 6), y: y(last.y) + 4, class: "line-label" }, s.name));
      }
    } else if (s.kind === "dots") {
      for (const p of pts) {
        const c = svg("circle", { cx: x(p.x), cy: y(p.y), r: 4, class: "dot" });
        c.style.fill = color;
        root.append(c);
      }
    } else {  // segments: each one's byte range at its time (at least 2px tall)
      for (const p of pts) {
        const y0 = y(p.y0), y1 = Math.min(y(p.y1), y0 - 2);
        const ln = svg("line", { x1: x(p.x), x2: x(p.x), y1: y0, y2: y1, class: "seg-mark" });
        ln.style.stroke = color;
        root.append(ln);
        if (s.marker) {
          const dm = svg("path", { d: `M${x(p.x)},${y1 - 6}l4,4l-4,4l-4,-4z`, class: "seg-marker" });
          dm.style.fill = color;
          root.append(dm);
        }
      }
    }
  }
  // The crosshair and the nearest point's tooltip.
  const hover = all.filter((p) => p.tip).sort((a, b) => a.x - b.x);
  const cross = svg("line", { y1: m.t, y2: H - m.b, class: "crosshair", visibility: "hidden" });
  root.append(cross);
  const hit = svg("rect", { x: m.l, y: m.t, width: W - m.l - m.r, height: H - m.t - m.b, class: "hit" });
  const nearest = (evt) => {
    const r = root.getBoundingClientRect();
    const px = ((evt.clientX - r.left) / r.width) * W;
    const v = xmin + ((px - m.l) / (W - m.l - m.r)) * (xmax - xmin);
    let lo = 0, hi = hover.length - 1;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (hover[mid].x < v) lo = mid + 1; else hi = mid; }
    const cand = [hover[lo - 1], hover[lo]].filter(Boolean);
    return cand.sort((a, b) => Math.abs(a.x - v) - Math.abs(b.x - v))[0];
  };
  hit.addEventListener("mousemove", (evt) => {
    const p = nearest(evt);
    if (!p) return;
    cross.setAttribute("x1", x(p.x));
    cross.setAttribute("x2", x(p.x));
    cross.setAttribute("visibility", "visible");
    showTip(evt, p.tip);
  });
  hit.addEventListener("mouseleave", () => { cross.setAttribute("visibility", "hidden"); hideTip(); });
  hit.addEventListener("click", (evt) => {
    const p = nearest(evt);
    if (p && p.n) { hideTip(); window.goToFrame(p.n); }
  });
  root.append(hit);
  const parts = [];
  if (series.length > 1) {
    const legend = el("div", { class: "legend" });
    for (const s of series) {
      const item = el("span", {});
      const sw = el("span", { class: `swatch${s.marker ? " sw-marker" : ""}` });
      sw.style.background = cssVar(s.color);
      item.append(sw, document.createTextNode(` ${s.name}`));
      legend.append(item);
    }
    parts.push(legend);
  }
  parts.push(root);
  container.replaceChildren(...parts);
}
