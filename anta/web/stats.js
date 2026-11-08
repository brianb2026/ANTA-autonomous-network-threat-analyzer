// Statistics view, after Wireshark's Statistics menu: capture properties,
// protocol hierarchy, conversations, endpoints, I/O graph, packet lengths,
// expert information, and DNS / HTTP / TLS summaries. Rows open filter actions.
"use strict";

const stats = {
  tool: "properties", data: null, map: null, key: null, loading: false, error: "",
  filter: "", interval: 0, series: [], showErrors: true, ioUnit: "packets",
  convTab: "ipv4", epTab: "ipv4", sort: {}, search: {}, topBy: "bytes", expertSev: "all",
};

const OWN_DATA_TOOLS = new Set(["flow", "tcpgraph", "logins", "rhythm"]);

// Where a tool is being drawn: the Statistics view (MAIN_RX), or a quick-tool window over a
// selection (quicktool.js). Tools read it once when they draw, and their buttons use that copy.
const MAIN_RX = {
  main: true,
  rerender: () => statsRender(),
  reload: () => statsLoad(true),
  scope: () => (window.focusScope ? window.focusScope() : ""),
  filter: () => stats.filter,
  geo: () => stats.geo,
  showPackets: (expr) => showPacketsFor(expr),
};
let RX = MAIN_RX;
function withRx(rx, fn) {
  const prev = RX;
  RX = rx;
  try { return fn(); } finally { RX = prev; }
}
const CAT = ["--cat-1", "--cat-2", "--cat-3", "--cat-4", "--cat-5", "--cat-6", "--cat-7", "--cat-8"];
// I/O graph: "All packets" is slot 1 and TCP errors is red; these two slots
// pass the palette checks against both (more lines would not stay distinct).
const IO_SLOTS = ["--text", "--dim"];  // after the accent-colored "all packets" line
const MAX_IO_SERIES = IO_SLOTS.length;
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

function statsKey() {
  return `${sessionKey()}|${MAIN_RX.scope()}|${stats.filter}|${stats.interval}|${stats.series.join("\u0001")}`;
}

function sessionActive() {
  return state.session && !["idle", "error"].includes(state.session.state);
}

async function statsLoad(force = false) {
  if (!sessionActive()) { stats.data = null; statsRender(); return; }
  const key = statsKey();
  if (!force && stats.key === key && stats.data) { statsRender(); return; }
  if (stats.loading) { stats.again = true; return; }  // (asked again while one runs: after it, for what is wanted then)
  stats.loading = true;
  $("stats-status").textContent = "Computing statistics…";
  stats.error = "";
  const scope = MAIN_RX.scope();
  const params = new URLSearchParams();
  if (stats.filter) params.set("dfilter", stats.filter);
  if (scope) params.set("scope", scope);
  if (stats.interval) params.set("interval", String(stats.interval));
  for (const s of stats.series) params.append("series", s);
  try {
    const res = await api(`/api/stats?${params}`);
    stats.data = res.stats;
    stats.map = res.map;
    stats.geo = res.geo || null;
    stats.key = key;
    const p = res.stats.properties;
    $("stats-status").textContent = `${fmtNum(p.frames)} of ${fmtNum(p.frames_total)} packets` +
      (scope ? (stats.filter ? " in the focus match the filter" : " (the focus)") : stats.filter ? " match the filter" : "");
  } catch (err) {
    stats.error = err.message;
    $("stats-status").textContent = "";
  } finally {
    stats.loading = false;
  }
  if (stats.again || statsKey() !== key) {  // (the focus, filter or capture changed meanwhile)
    stats.again = false;
    statsLoad(true);
    return;
  }
  $("stats-msg").textContent = stats.error;
  statsRender();
  if (window.mapStatsUpdated) window.mapStatsUpdated();
}
window.statsLoad = statsLoad;
window.statsData = () => stats;

// ---------------------------------------------------------- data table

// columns: [{label, get(row), type: "num"|"bytes"|"text"|"pct"|"sec", title}]
function dataTable(container, id, columns, rows, { onRow, limit = 1000, searchable = true, defaultSort } = {}) {
  const wrap = el("div", { class: "dt" });
  const sort = stats.sort[id] || defaultSort || { col: columns.findIndex((c) => c.type === "bytes"), dir: -1 };
  let query = stats.search[id] || "";
  let shown = limit;
  const tools = el("div", { class: "dt-tools" });
  const search = el("input", { type: "search", class: "pkt-filter dt-search", placeholder: "Search", "aria-label": "Search this table" });
  search.value = query;
  const count = el("span", { class: "muted small" });
  const csv = el("button", { type: "button", class: "tb small" }, "Export CSV");
  if (searchable) tools.append(search);
  tools.append(count, el("span", { class: "spacer" }), csv);
  let current = rows;  // what the table shows, filtered and sorted: what the CSV holds
  csv.addEventListener("click", async () => {
    const value = (c, r) => { const v = c.get(r); return c.type === "pct" && typeof v === "number" ? +(v * 100).toFixed(4) : v; };
    try {
      const saved = await saveTextFile(`${captureStem()}_${id}.csv`, "csv",
        csvText(columns.map((c) => c.label + (c.type === "pct" ? " %" : "")), current.map((r) => columns.map((c) => value(c, r)))));
      notice(`Saving ${fmtNum(current.length)} rows as ${saved.name}.`);
    } catch (err) { notice(err.message, true); }
  });
  const scroller = el("div", { class: "dt-scroll" });
  const table = el("table", { class: "dt-table" });
  scroller.append(table);
  wrap.append(tools, scroller);
  container.append(wrap);

  function draw() {
    let list = rows;
    if (query) {
      const q = query.toLowerCase();
      list = rows.filter((r) => columns.some((c) => String(c.get(r) ?? "").toLowerCase().includes(q)));
    }
    if (sort.col >= 0) {
      const c = columns[sort.col];
      const numeric = c.type !== "text";
      list = [...list].sort((a, b) => {
        const x = c.get(a), y = c.get(b);
        if (numeric) return ((x ?? -Infinity) - (y ?? -Infinity)) * sort.dir;
        return String(x ?? "").localeCompare(String(y ?? ""), undefined, { numeric: true }) * sort.dir;
      });
    }
    current = list;
    count.textContent = `${fmtNum(list.length)} of ${fmtNum(rows.length)}`;
    const thead = el("thead");
    const htr = el("tr");
    columns.forEach((c, i) => {
      const th = el("th", { class: c.type === "text" ? "" : "num", scope: "col", title: c.title || "" });
      const b = el("button", { type: "button", class: "dt-sort" }, c.label);
      if (sort.col === i) {
        b.append(el("span", { "aria-hidden": "true" }, sort.dir > 0 ? " ▲" : " ▼"));
        th.setAttribute("aria-sort", sort.dir > 0 ? "ascending" : "descending");
      }
      b.addEventListener("click", () => {
        if (sort.col === i) sort.dir = -sort.dir;
        else { sort.col = i; sort.dir = c.type === "text" ? 1 : -1; }
        stats.sort[id] = sort;
        draw();
      });
      th.append(b);
      htr.append(th);
    });
    thead.append(htr);
    const tbody = el("tbody");
    for (const r of list.slice(0, shown)) {
      const tr = el("tr");
      for (const c of columns) {
        const v = c.get(r);
        const td = el("td", { class: c.type === "text" ? "" : "num" });
        if (c.render) td.append(c.render(r));
        else td.textContent = fmtCell(v, c.type);
        tr.append(td);
      }
      if (onRow) {
        tr.tabIndex = 0;
        tr.classList.add("clickable");
        tr.addEventListener("click", (e) => onRow(e, r));
        tr.addEventListener("contextmenu", (e) => { e.preventDefault(); onRow(e, r); });
        tr.addEventListener("keydown", (e) => {
          if (e.key === "Enter") {
            const box = tr.getBoundingClientRect();
            onRow({ clientX: box.left + 40, clientY: box.bottom }, r);
          }
        });
      }
      tbody.append(tr);
    }
    table.replaceChildren(thead, tbody);
    if (list.length > shown) {
      const more = el("button", { type: "button", class: "link" }, `Show ${fmtNum(Math.min(list.length - shown, 2000))} more`);
      more.addEventListener("click", () => { shown += 2000; draw(); });
      const tr = el("tr");
      const td = el("td", { colspan: String(columns.length) });
      td.append(more);
      tr.append(td);
      tbody.append(tr);
    }
  }
  search.addEventListener("input", () => { query = search.value; stats.search[id] = query; shown = limit; draw(); });
  draw();
}

function fmtCell(v, type) {
  if (v === null || v === undefined) return "";
  switch (type) {
    case "bytes": return fmtBytes(v);
    case "num": return fmtNum(v);
    case "frame": return String(v);  // a frame number, written as Wireshark writes it
    case "pct": return `${(v * 100).toFixed(2)}%`;
    case "sec": return Number(v).toFixed(6);
    case "rate": return v ? fmtRate(v) : "";
    default: return String(v);
  }
}

function fmtRate(bitsPerSec) {
  const units = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"];
  let i = 0;
  while (bitsPerSec >= 1000 && i < units.length - 1) { bitsPerSec /= 1000; i++; }
  return `${bitsPerSec.toFixed(bitsPerSec < 10 && i ? 2 : 0)} ${units[i]}`;
}

function tiles(container, items) {
  const row = el("div", { class: "tiles" });
  for (const [label, value, sub] of items) {
    const t = el("div", { class: "tile" });
    t.append(el("div", { class: "tile-label" }, label), el("div", { class: "tile-value" }, value));
    if (sub) t.append(el("div", { class: "tile-sub muted" }, sub));
    row.append(t);
  }
  container.append(row);
}

function section(container, title, sub) {
  const h = el("div", { class: "st-head" });
  h.append(el("h3", {}, title));
  if (sub) h.append(el("span", { class: "muted small" }, sub));
  container.append(h);
}

function subTabs(container, current, tabs, onPick) {
  const bar = el("div", { class: "subtabs", role: "tablist" });
  for (const [key, label] of tabs) {
    const b = el("button", { type: "button", role: "tab", "aria-selected": String(key === current), class: "subtab" }, label);
    b.addEventListener("click", () => onPick(key));
    bar.append(b);
  }
  container.append(bar);
}

function hostName(addr) {
  const n = stats.map && stats.map.nodes.find((x) => x.addr === addr);
  return n ? n.name : null;
}
function hostRole(addr) {
  const n = stats.map && stats.map.nodes.find((x) => x.addr === addr);
  return n ? n.role : null;
}

// Horizontal bars for "top talkers" style rankings; values only, labels as text.
function barList(container, items, { unit = "bytes", onPick } = {}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  const list = el("div", { class: "barlist", role: "list" });
  for (const it of items) {
    const row = el("div", { class: "bl-row", role: "listitem" });
    const label = el("div", { class: "bl-label" });
    label.append(el("span", { class: "mono" }, it.label));
    if (it.sub) label.append(el("span", { class: "muted small" }, ` ${it.sub}`));
    const track = el("div", { class: "bl-track" });
    const bar = el("div", { class: "bl-bar" });
    bar.style.width = `${Math.max(0.5, (it.value / max) * 100)}%`;
    track.append(bar);
    const val = el("div", { class: "bl-value" }, unit === "bytes" ? fmtBytes(it.value) : fmtNum(it.value));
    row.append(label, track, val);
    if (onPick) {
      row.classList.add("clickable");
      row.tabIndex = 0;
      row.addEventListener("click", (e) => onPick(e, it));
      row.addEventListener("keydown", (e) => { if (e.key === "Enter") onPick({ clientX: 200, clientY: row.getBoundingClientRect().bottom }, it); });
    }
    list.append(row);
  }
  container.append(list);
}

// ---------------------------------------------------------------- tools

const TOOLS = {
  properties(box, d) {
    const p = d.properties;
    const dur = p.duration || 0;
    const rx = RX;
    tiles(box, [
      ["Packets", fmtNum(p.frames), rx.filter() || rx.scope() ? `of ${fmtNum(p.frames_total)} in the capture` : null],
      ["Bytes", fmtBytes(p.bytes)],
      ["Duration", fmtDuration(dur)],
      ["Average rate", dur ? fmtRate((p.bytes * 8) / dur) : "–", dur ? `${(p.frames / dur).toFixed(1)} packets/s` : null],
    ]);
    const dl = el("dl", { class: "kv props" });
    const rows = [
      ["File", (p.files || []).join(", ")],
      ["First packet", p.frames ? fmtDateTime(p.first) : "–"],
      ["Last packet", p.frames ? fmtDateTime(p.last) : "–"],
      ["Elapsed", dur ? `${dur.toFixed(6)} s` : "–"],
      ["Packets", fmtNum(p.frames)],
      ["Total packets in capture", fmtNum(p.frames_total)],
      ["Bytes", `${fmtNum(p.bytes)} (${fmtBytes(p.bytes)})`],
      ["Average packet size", p.frames ? `${Math.round(p.bytes / p.frames)} bytes` : "–"],
      ["Average packets/s", dur ? (p.frames / dur).toFixed(1) : "–"],
      ["Average bytes/s", dur ? fmtBytes(p.bytes / dur) : "–"],
      ["Average bits/s", dur ? fmtRate((p.bytes * 8) / dur) : "–"],
      ["Display filter", rx.scope() ? (rx.filter() ? `${rx.filter()}, within the selection` : "the selection") : p.filter || "none"],
      ["Hosts on the network map", stats.map ? fmtNum(stats.map.total_hosts) : "–"],
    ];
    for (const [k, v] of rows) dl.append(el("dt", {}, k), el("dd", {}, v));
    box.append(dl);
  },

  hierarchy(box, d) {
    section(box, "Protocol hierarchy", "frames and bytes of every packet that contains each protocol");
    const total = d.properties.frames || 1, totalBytes = d.properties.bytes || 1;
    const dur = d.properties.duration || 0;
    const rows = d.protocols.map((p) => ({ ...p, depth: p.path.split("/").length - 1 }));
    rows.sort((a, b) => a.path.localeCompare(b.path));
    // Order children by frames under their parent, keeping the tree shape.
    const children = new Map();
    for (const r of rows) {
      const parent = r.path.includes("/") ? r.path.slice(0, r.path.lastIndexOf("/")) : "";
      if (!children.has(parent)) children.set(parent, []);
      children.get(parent).push(r);
    }
    const ordered = [];
    const walk = (parent) => {
      for (const r of (children.get(parent) || []).sort((a, b) => b.frames - a.frames)) {
        ordered.push(r);
        walk(r.path);
      }
    };
    walk("");
    const table = el("table", { class: "dt-table phs" });
    const thead = el("thead");
    const htr = el("tr");
    for (const [h, cls] of [["Protocol", ""], ["Percent packets", "num"], ["Packets", "num"], ["Percent bytes", "num"],
      ["Bytes", "num"], ["Bits/s", "num"], ["End packets", "num"], ["End bytes", "num"]]) htr.append(el("th", { class: cls, scope: "col" }, h));
    thead.append(htr);
    const tbody = el("tbody");
    for (const r of ordered) {
      const tr = el("tr", { class: "clickable", tabindex: "0" });
      const name = el("td");
      name.style.paddingLeft = `${8 + r.depth * 16}px`;
      name.append(el("span", {}, r.name), el("span", { class: "muted small" }, `  ${r.abbr}`));
      const pct = el("td", { class: "num" });
      const bar = el("span", { class: "pct-bar" });
      bar.style.setProperty("--w", `${(r.frames / total) * 100}%`);
      pct.append(bar, document.createTextNode(`${((r.frames / total) * 100).toFixed(1)}%`));
      tr.append(name, pct, el("td", { class: "num" }, fmtNum(r.frames)),
        el("td", { class: "num" }, `${((r.bytes / totalBytes) * 100).toFixed(1)}%`), el("td", { class: "num" }, fmtNum(r.bytes)),
        el("td", { class: "num" }, dur ? fmtRate((r.bytes * 8) / dur) : ""), el("td", { class: "num" }, fmtNum(r.end_frames)),
        el("td", { class: "num" }, fmtNum(r.end_bytes)));
      const act = (e) => window.filterMenu(e, r.abbr);
      tr.addEventListener("click", act);
      tr.addEventListener("contextmenu", (e) => { e.preventDefault(); act(e); });
      tbody.append(tr);
    }
    table.append(thead, tbody);
    const wrap = el("div", { class: "dt-scroll" });
    wrap.append(table);
    box.append(wrap);
  },

  conversations(box, d) {
    const kinds = [["eth", "Ethernet"], ["ipv4", "IPv4"], ["ipv6", "IPv6"], ["tcp", "TCP"], ["udp", "UDP"]];
    const rx = RX;
    subTabs(box, stats.convTab, kinds.map(([k, l]) => [k, `${l} · ${fmtNum(d.conversations[k].total)}`]),
      (k) => { stats.convTab = k; rx.rerender(); });
    const kind = stats.convTab;
    const t = d.conversations[kind];
    const ports = kind === "tcp" || kind === "udp";
    const addrField = { eth: "eth.addr", ipv4: "ip.addr", ipv6: "ipv6.addr", tcp: "ip.addr", udp: "ip.addr" }[kind];
    const cols = [
      { label: "Address A", type: "text", get: (r) => r[0], render: (r) => addrCell(r[0]) },
      ...(ports ? [{ label: "Port A", type: "num", get: (r) => r[1] }] : []),
      { label: "Address B", type: "text", get: (r) => r[2], render: (r) => addrCell(r[2]) },
      ...(ports ? [{ label: "Port B", type: "num", get: (r) => r[3] }] : []),
      { label: "Packets", type: "num", get: (r) => r[4] + r[6] },
      { label: "Bytes", type: "bytes", get: (r) => r[5] + r[7] },
      { label: "Packets A→B", type: "num", get: (r) => r[4] },
      { label: "Bytes A→B", type: "bytes", get: (r) => r[5] },
      { label: "Packets B→A", type: "num", get: (r) => r[6] },
      { label: "Bytes B→A", type: "bytes", get: (r) => r[7] },
      { label: "Rel start", type: "sec", get: (r) => r[8] },
      { label: "Duration", type: "sec", get: (r) => r[9] },
      { label: "Bits/s A→B", type: "rate", get: (r) => (r[9] > 0 ? (r[5] * 8) / r[9] : null) },
      { label: "Bits/s B→A", type: "rate", get: (r) => (r[9] > 0 ? (r[7] * 8) / r[9] : null) },
    ];
    if (kind === "ipv4" || kind === "ipv6") {
      cols.push({ label: "Protocols", type: "text", get: (r) => Object.keys(r[11] || {}).join(", ") });
    }
    if (t.total > t.rows.length) box.append(el("p", { class: "muted small" }, `Showing the ${fmtNum(t.rows.length)} largest of ${fmtNum(t.total)}.`));
    dataTable(box, `conv-${kind}`, cols, t.rows, {
      onRow: (e, r) => {
        const items = [];
        const filter = ports
          ? (r[10] !== null && r[10] !== undefined ? `${kind}.stream eq ${r[10]}`
            : `${addrField} == ${r[0]} && ${kind}.port == ${r[1]} && ${addrField} == ${r[2]} && ${kind}.port == ${r[3]}`)
          : `${addrField} == ${r[0]} && ${addrField} == ${r[2]}`;
        items.push({ header: `${r[0]}${ports ? `:${r[1]}` : ""} ↔ ${r[2]}${ports ? `:${r[3]}` : ""}` });
        items.push({ label: "Show these packets", hint: filter, action: () => rx.showPackets(filter) });
        if (ports && r[10] !== null && r[10] !== undefined) {
          items.push({ label: "Explain this conversation…", hint: "in plain words",
            action: () => window.openExplain({ stream: `${kind}:${r[10]}` }, `${kind.toUpperCase()} stream ${r[10]}`) });
          items.push({ label: `Follow ${kind.toUpperCase()} stream`, action: () => { setView("packets"); window.openFollow(kind, r[10]); } });
        } else if (kind === "ipv4" || kind === "ipv6") {
          items.push({ label: "Explain these conversations…", hint: "in plain words",
            action: () => window.openExplain({ dfilter: filter }, `${r[0]} ↔ ${r[2]}`) });
        }
        items.push({ label: "More filter actions…", action: () => window.filterMenu(e, filter) });
        if (kind !== "eth") items.push({ label: "Host details", action: () => window.openHost(r[0]) });
        showMenu(e.clientX, e.clientY, items);
      },
    });
  },

  endpoints(box, d) {
    const kinds = [["eth", "Ethernet"], ["ipv4", "IPv4"], ["ipv6", "IPv6"], ["tcp", "TCP"], ["udp", "UDP"]];
    const rx = RX;
    subTabs(box, stats.epTab, kinds.map(([k, l]) => [k, `${l} · ${fmtNum(d.endpoints[k].total)}`]),
      (k) => { stats.epTab = k; rx.rerender(); });
    const kind = stats.epTab;
    const t = d.endpoints[kind];
    const ports = kind === "tcp" || kind === "udp";
    const field = { eth: "eth.addr", ipv4: "ip.addr", ipv6: "ipv6.addr", tcp: "ip.addr", udp: "ip.addr" }[kind];
    // Top talkers
    const head = el("div", { class: "st-head" });
    head.append(el("h3", {}, "Top talkers"));
    const by = el("select", { class: "tb small", "aria-label": "Rank by" });
    for (const [v, l] of [["bytes", "by bytes"], ["packets", "by packets"], ["tx", "by packets sent"]]) {
      const o = el("option", { value: v }, l);
      if (v === stats.topBy) o.selected = true;
      by.append(o);
    }
    by.addEventListener("change", () => { stats.topBy = by.value; rx.rerender(); });
    head.append(by);
    box.append(head);
    const val = (r) => (stats.topBy === "bytes" ? r[3] + r[5] : stats.topBy === "packets" ? r[2] + r[4] : r[2]);
    const top = [...t.rows].sort((a, b) => val(b) - val(a)).slice(0, 10);
    barList(box, top.map((r) => ({
      label: ports ? `${r[0]}:${r[1]}` : r[0], sub: [hostName(r[0]), kind === "ipv4" || kind === "ipv6" ? hostRole(r[0]) : null].filter(Boolean).join(" · "),
      value: val(r), row: r,
    })), {
      unit: stats.topBy === "bytes" ? "bytes" : "num",
      onPick: (e, it) => window.filterMenu(e, ports ? `${field} == ${it.row[0]} && ${kind}.port == ${it.row[1]}` : `${field} == ${it.row[0]}`),
    });
    section(box, "All endpoints", "packets sent (Tx) and received (Rx) by each address");
    const cols = [
      { label: "Address", type: "text", get: (r) => r[0], render: (r) => addrCell(r[0]) },
      ...(ports ? [{ label: "Port", type: "num", get: (r) => r[1] }] : []),
      ...(kind === "ipv4" || kind === "ipv6" ? [{ label: "Role", type: "text", get: (r) => hostRole(r[0]) || "" }] : []),
      { label: "Packets", type: "num", get: (r) => r[2] + r[4] },
      { label: "Bytes", type: "bytes", get: (r) => r[3] + r[5] },
      { label: "Tx packets", type: "num", get: (r) => r[2] },
      { label: "Tx bytes", type: "bytes", get: (r) => r[3] },
      { label: "Rx packets", type: "num", get: (r) => r[4] },
      { label: "Rx bytes", type: "bytes", get: (r) => r[5] },
    ];
    if (t.total > t.rows.length) box.append(el("p", { class: "muted small" }, `Showing the ${fmtNum(t.rows.length)} busiest of ${fmtNum(t.total)}.`));
    dataTable(box, `ep-${kind}`, cols, t.rows, {
      onRow: (e, r) => {
        const filter = ports ? `${field} == ${r[0]} && ${kind}.port == ${r[1]}` : `${field} == ${r[0]}`;
        const items = [{ header: ports ? `${r[0]}:${r[1]}` : r[0] },
          { label: "Show this endpoint's packets", hint: filter, action: () => rx.showPackets(filter) },
          { label: "Packets it sent", action: () => rx.showPackets(kind === "eth" ? `eth.src == ${r[0]}` : `${kind === "ipv6" ? "ipv6" : "ip"}.src == ${r[0]}${ports ? ` && ${kind}.srcport == ${r[1]}` : ""}`) },
          { label: "More filter actions…", action: () => window.filterMenu(e, filter) }];
        if (kind !== "eth") items.push({ label: "Host details", action: () => window.openHost(r[0]) });
        showMenu(e.clientX, e.clientY, items);
      },
    });
  },

  io(box, d) {
    const io = d.io;
    const rx = RX;
    const bar = el("div", { class: "io-bar" });
    const interval = el("select", { class: "tb small", "aria-label": "Interval" });
    for (const [v, l] of [[0, `Auto (${fmtInterval(io.interval)})`], [0.001, "1 ms"], [0.01, "10 ms"], [0.1, "100 ms"], [1, "1 s"],
      [10, "10 s"], [60, "1 min"], [600, "10 min"], [3600, "1 h"]]) {
      const o = el("option", { value: String(v) }, l);
      if (Number(v) === stats.interval) o.selected = true;
      interval.append(o);
    }
    interval.addEventListener("change", () => { stats.interval = Number(interval.value); rx.reload(); });
    const unit = el("select", { class: "tb small", "aria-label": "Y axis" });
    for (const [v, l] of [["packets", "Packets per interval"], ["bytes", "Bytes per interval"], ["bits", "Bits per second"]]) {
      const o = el("option", { value: v }, l);
      if (v === stats.ioUnit) o.selected = true;
      unit.append(o);
    }
    unit.addEventListener("change", () => { stats.ioUnit = unit.value; rx.rerender(); });
    const errs = el("label", { class: "check" });
    const cb = el("input", { type: "checkbox" });
    cb.checked = stats.showErrors;
    cb.addEventListener("change", () => { stats.showErrors = cb.checked; rx.rerender(); });
    errs.append(cb, document.createTextNode(" TCP errors"));
    const addForm = el("form", { class: "io-add" });
    const addInput = el("input", { type: "text", class: "pkt-filter", placeholder: "Add a graph: display filter, e.g. dns", "aria-label": "Add an I/O graph for a display filter", spellcheck: "false" });
    addInput.addEventListener("input", () => addInput.setCustomValidity(""));
    const addBtn = el("button", { type: "submit", class: "tb small" }, "Add graph");
    addForm.append(addInput, addBtn);
    addForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const f = addInput.value.trim();
      if (!f || stats.series.includes(f)) return;
      if (stats.series.length >= MAX_IO_SERIES) {
        addInput.setCustomValidity(`Up to ${MAX_IO_SERIES} extra graphs; remove one first.`);
        addInput.reportValidity();
        return;
      }
      stats.series = [...stats.series, f];
      statsLoad();
    });
    bar.append(el("label", { class: "inline" }, "Interval"), interval, unit, errs);
    if (rx.main) bar.append(addForm);  // (extra graphs: in the Statistics view)
    box.append(bar);

    const series = [{ name: rx.filter() ? "Packets matching the filter" : rx.scope() ? "Packets in the selection" : "All packets",
      idx: -1, color: cssVar(CAT[0]) }];
    // Errors are red as in Wireshark and dashed, so they don't rely on hue alone;
    // added graphs take the next categorical slots that stay distinct from both.
    if (stats.showErrors) series.push({ name: "TCP errors", idx: 2, color: cssVar("--critical"), dash: "6 4" });
    (rx.main ? io.series || [] : []).slice(0, MAX_IO_SERIES).forEach((f, i) =>
      series.push({ name: f, idx: 3 + i, color: cssVar(IO_SLOTS[i]), removable: f }));
    const legend = el("div", { class: "legend" });
    for (const s of series) {
      const key = el("span", { class: "key" });
      const sw = svg("svg", { width: "18", height: "10", "aria-hidden": "true" });
      const ln = svg("line", { x1: "1", x2: "17", y1: "5", y2: "5", "stroke-width": "2.5", "stroke-linecap": "round" });
      ln.style.stroke = s.color;
      if (s.dash) ln.setAttribute("stroke-dasharray", "4 3");
      sw.append(ln);
      key.append(sw, document.createTextNode(s.name));
      if (s.removable) {
        const x = el("button", { type: "button", class: "scope-x", "aria-label": `Remove graph ${s.name}` }, "✕");
        x.addEventListener("click", () => { stats.series = stats.series.filter((f) => f !== s.removable); rx.reload(); });
        key.append(x);
      }
      legend.append(key);
    }
    box.append(legend);
    const chartBox = el("div", { class: "chart io-chart" });
    box.append(chartBox);
    const value = (bin, s) => {
      const count = s.idx === -1 ? (stats.ioUnit === "packets" ? bin[0] : bin[1]) : bin[s.idx] || 0;
      if (stats.ioUnit === "bits") return s.idx === -1 ? (bin[1] * 8) / io.interval : count / io.interval;
      return count;
    };
    ioChart(chartBox, io, series, value, rx);
    box.append(el("p", { class: "muted small" }, "Click the graph to show the packets in that interval. " +
      "TCP errors and filter graphs count packets." + (stats.ioUnit === "bits" ? " Filter graphs are shown per second." : "")));
    if (io.truncated) box.append(el("p", { class: "muted small" }, "The interval is too fine for this capture's length; only the start is shown."));
    const asTable = el("details", { class: "io-table" });
    asTable.append(el("summary", { class: "small" }, "View as table"));
    asTable.addEventListener("toggle", () => {
      if (!asTable.open || asTable.querySelector(".dt")) return;
      const rows = io.bins.map((b, i) => ({ i, b })).filter((r) => series.some((s) => value(r.b, s)));
      dataTable(asTable, "io-table", [
        { label: "Interval start (s)", type: "num", get: (r) => +(r.i * io.interval).toFixed(6) },
        ...series.map((s) => ({ label: s.name, type: stats.ioUnit === "bytes" && s.idx === -1 ? "bytes" : "num",
          get: (r) => Math.round(value(r.b, s) * 100) / 100 })),
      ], rows, { searchable: false, defaultSort: { col: 0, dir: 1 },
        onRow: (e, r) => {
          const a = (r.i * io.interval).toFixed(6), b2 = ((r.i + 1) * io.interval).toFixed(6);
          const range = `frame.time_relative >= ${a} && frame.time_relative < ${b2}`;
          window.filterMenu(e, rx.filter() ? `(${rx.filter()}) && ${range}` : range);
        } });
    });
    box.append(asTable);
  },

  lengths(box, d) {
    section(box, "Packet lengths");
    const total = d.lengths.reduce((a, b) => a + b.count, 0) || 1;
    barList(box, d.lengths.map((b) => ({ label: b.range, value: b.count, sub: b.count ? `${((b.count / total) * 100).toFixed(1)}%` : "" })), { unit: "num" });
    dataTable(box, "lengths", [
      { label: "Packet length", type: "text", get: (r) => r.range },
      { label: "Count", type: "num", get: (r) => r.count },
      { label: "Average", type: "num", get: (r) => (r.avg ? Math.round(r.avg) : null) },
      { label: "Min", type: "num", get: (r) => r.min },
      { label: "Max", type: "num", get: (r) => r.max },
      { label: "Percent", type: "pct", get: (r) => r.count / total },
    ], d.lengths, { searchable: false, defaultSort: { col: -1, dir: 1 },
      onRow: (e, r) => {
        const [lo, hi] = r.range.split(/-| and /);
        window.filterMenu(e, r.range.includes("greater") ? `frame.len >= ${lo}` : `frame.len >= ${lo} && frame.len <= ${hi}`);
      } });
  },

  expert(box, d) {
    const sev = ["Error", "Warning", "Note", "Chat"];
    const rx = RX;
    const counts = Object.fromEntries(sev.map((s) => [s, d.expert.filter((e) => e.severity === s).reduce((a, e) => a + e.count, 0)]));
    const chips = el("div", { class: "filters", role: "group", "aria-label": "Severity" });
    for (const s of ["all", ...sev]) {
      const b = el("button", { type: "button", class: `chip${stats.expertSev === s ? " active" : ""}` });
      if (s !== "all") b.append(el("span", { class: `sev-dot x-${s.toLowerCase()}` }));
      b.append(document.createTextNode(s === "all" ? "All" : `${s} · ${fmtNum(counts[s])}`));
      b.addEventListener("click", () => { stats.expertSev = s; rx.rerender(); });
      chips.append(b);
    }
    box.append(chips);
    const rows = d.expert.filter((e) => stats.expertSev === "all" || e.severity === stats.expertSev);
    const list = el("div", { class: "expert-list" });
    for (const e of rows) {
      const det = el("details", { class: "expert" });
      const sum = el("summary");
      sum.append(el("span", { class: `xbadge x-${e.severity.toLowerCase()}` }, e.severity),
        el("span", { class: "x-summary" }, e.summary), el("span", { class: "muted small" }, `${e.group} · ${e.protocol}`),
        el("span", { class: "x-count" }, fmtNum(e.count)));
      det.append(sum);
      const frames = el("div", { class: "x-frames" });
      for (const n of e.frames.slice(0, 300)) {
        const b = el("button", { type: "button", class: "link mono" }, String(n));
        b.addEventListener("click", () => goToFrame(n));
        frames.append(b);
      }
      if (e.count > e.frames.length || e.frames.length > 300) frames.append(el("span", { class: "muted small" }, ` … ${fmtNum(e.count)} in all`));
      det.append(frames);
      list.append(det);
    }
    if (!rows.length) list.append(el("p", { class: "muted" }, "Nothing at this severity."));
    box.append(list);
  },

  dns(box, d) {
    const x = d.dns;
    const rt = x.response_time;
    const ms = (sec) => (sec < 1 ? `${(sec * 1000).toFixed(sec < 0.01 ? 2 : 1)} ms` : `${sec.toFixed(2)} s`);
    tiles(box, [["Queries", fmtNum(x.queries)], ["Responses", fmtNum(x.responses)], ["Names queried", fmtNum(x.names.length)],
      ["Median response time", rt ? ms(rt.median) : "–", rt ? `95th percentile ${ms(rt.p95)} · slowest ${ms(rt.max)}` : "No answered queries"],
      ["Retransmissions", fmtNum(x.retransmissions || 0), "queries or responses sent again"]]);
    if (x.slowest && x.slowest.length) {
      section(box, "Slowest responses", "time from each query to its response");
      dataTable(box, "dns-slowest", [
        { label: "Name", type: "text", get: (r) => r.name || "<Root>" },
        { label: "Server", type: "text", get: (r) => r.server },
        { label: "Client", type: "text", get: (r) => r.client },
        { label: "Response time (ms)", type: "num", get: (r) => Math.round(r.seconds * 10000) / 10 },
        { label: "Frame", type: "frame", get: (r) => r.frame },
      ], x.slowest, { defaultSort: { col: 3, dir: -1 }, onRow: (e, r) => goToFrame(r.frame) });
    }
    countSection(box, "Names queried", "dns-names", x.names, "Name", (v) => `dns.qry.name == "${v}"`);
    countSection(box, "Query types", "dns-types", x.types, "Type", null);
    countSection(box, "Response codes", "dns-rcodes", x.rcodes, "Response", null);
  },

  http(box, d) {
    const x = d.http;
    tiles(box, [["Requests", fmtNum(x.requests)], ["Responses", fmtNum(x.responses)], ["Hosts", fmtNum(x.hosts.length)]]);
    countSection(box, "Requests by host", "http-hosts", x.hosts, "Host", (v) => `http.host == "${v}"`);
    countSection(box, "Requests by URL", "http-uris", x.uris, "URL", null);
    countSection(box, "Methods", "http-methods", x.methods, "Method", (v) => `http.request.method == "${v}"`);
    countSection(box, "Status codes", "http-status", x.status, "Status", (v) => `http.response.code == ${v}`);
    countSection(box, "User agents", "http-ua", x.user_agents, "User-Agent", (v) => `http.user_agent == "${v.replace(/"/g, '\\"')}"`);
    countSection(box, "Content types", "http-ctype", x.content_types, "Content-Type", (v) => `http.content_type == "${v}"`);
  },

  tls(box, d) {
    const x = d.tls;
    tiles(box, [["Client Hellos", fmtNum(x.client_hellos)], ["Server names", fmtNum(x.server_names.length)],
      ["JA3 fingerprints", fmtNum(x.ja3.length)]]);
    countSection(box, "Server names (SNI)", "tls-sni", x.server_names, "Server name", (v) => `tls.handshake.extensions_server_name == "${v}"`);
    countSection(box, "JA3 fingerprints", "tls-ja3", x.ja3, "JA3 hash", (v) => `tls.handshake.ja3 == "${v}"`);
    countSection(box, "JA4 fingerprints", "tls-ja4", x.ja4, "JA4", (v) => `tls.handshake.ja4 == "${v}"`);
  },
};

function countSection(box, title, id, pairs, label, toFilter) {
  section(box, title, pairs.length ? `${fmtNum(pairs.length)} distinct` : "none seen");
  if (!pairs.length) return;
  const total = pairs.reduce((a, p) => a + p[1], 0) || 1;
  dataTable(box, id, [
    { label, type: "text", get: (r) => r[0], render: (r) => el("span", { class: "mono" }, r[0]) },
    { label: "Count", type: "num", get: (r) => r[1] },
    { label: "Percent", type: "pct", get: (r) => r[1] / total },
  ], pairs, { limit: 200, defaultSort: { col: 1, dir: -1 }, onRow: toFilter ? (e, r) => window.filterMenu(e, toFilter(r[0])) : null });
}

function addrCell(addr) {
  const span = el("span", { class: "addr" });
  span.append(el("span", { class: "mono" }, addr));
  const name = hostName(addr);
  if (name) span.append(el("span", { class: "muted small" }, ` ${name}`));
  return span;
}

function fmtInterval(s) {
  if (s >= 3600) return `${s / 3600} h`;
  if (s >= 60) return `${s / 60} min`;
  if (s >= 1) return `${s} s`;
  return `${Math.round(s * 1000)} ms`;
}

async function goToFrame(n) {
  if (pkt.follow) pktSetFollow(false);
  pkt.alert = null;
  pkt.filter = "";
  $("pkt-filter").value = "";
  pkt.total = null;
  pkt.starts = [];
  setView("packets");
  await pktLoad(n);
  pktSelect(n);
  document.querySelector(`#pkt-rows tr[data-n="${n}"]`)?.scrollIntoView({ block: "center" });
}
window.goToFrame = goToFrame;

// Multi-series line chart with a crosshair; click a bin to show its packets.
function ioChart(container, io, series, value, rx = MAIN_RX) {
  const W = chartWidth(container), H = 280;
  const m = { l: 64, r: 16, t: 12, b: 34 };
  const bins = io.bins;
  const n = Math.max(1, bins.length);
  const ymax = Math.max(1, ...series.flatMap((s) => bins.map((b) => value(b, s))));
  const ticks = niceTicks(0, ymax, 5);
  const top = ticks[ticks.length - 1] || ymax;
  const x = (i) => m.l + ((W - m.l - m.r) * i) / Math.max(1, n - 1);
  const y = (v) => H - m.b - ((H - m.t - m.b) * v) / top;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", height: String(H), role: "img",
    "aria-label": `I/O graph: ${series.map((s) => s.name).join(", ")}` });
  const unit = stats.ioUnit === "bytes" ? "bytes" : "";
  for (const t of ticks) {
    root.append(svg("line", { x1: m.l, x2: W - m.r, y1: y(t), y2: y(t), class: "grid" }));
    root.append(svg("text", { x: m.l - 6, y: y(t) + 4, class: "tick", "text-anchor": "end" },
      stats.ioUnit === "bits" ? fmtRate(t) : fmtTick(t, unit)));
  }
  const xt = niceTicks(0, (n - 1) * io.interval, 6);
  for (const t of xt) {
    const xi = m.l + ((W - m.l - m.r) * t) / Math.max(io.interval, (n - 1) * io.interval);
    root.append(svg("text", { x: xi, y: H - 12, class: "tick", "text-anchor": "middle" }, `${+t.toFixed(3)}s`));
  }
  root.append(svg("line", { x1: m.l, x2: W - m.r, y1: H - m.b, y2: H - m.b, class: "axis" }));
  for (const s of series) {
    let d = "";
    bins.forEach((b, i) => { d += `${i ? "L" : "M"}${x(i).toFixed(1)},${y(value(b, s)).toFixed(1)}`; });
    if (n === 1) d += `L${(W - m.r).toFixed(1)},${y(value(bins[0] || [0, 0, 0], s)).toFixed(1)}`;
    const path = svg("path", { d, class: "io-line" });
    path.style.stroke = s.color;
    if (s.dash) path.setAttribute("stroke-dasharray", s.dash);
    root.append(path);
  }
  const cross = svg("line", { y1: m.t, y2: H - m.b, class: "crosshair", visibility: "hidden" });
  root.append(cross);
  const hit = svg("rect", { x: m.l, y: m.t, width: W - m.l - m.r, height: H - m.t - m.b, class: "hit" });
  const idxAt = (evt) => {
    const r = root.getBoundingClientRect();
    const px = ((evt.clientX - r.left) / r.width) * W;
    return Math.max(0, Math.min(n - 1, Math.round(((px - m.l) / (W - m.l - m.r)) * (n - 1))));
  };
  hit.addEventListener("mousemove", (evt) => {
    const i = idxAt(evt);
    cross.setAttribute("x1", x(i));
    cross.setAttribute("x2", x(i));
    cross.setAttribute("visibility", "visible");
    const b = bins[i] || [];
    showTip(evt, [[`${(i * io.interval).toFixed(3)}–${((i + 1) * io.interval).toFixed(3)} s`],
      ...series.map((s) => [s.name, stats.ioUnit === "bits" && s.idx === -1 ? fmtRate(value(b, s))
        : stats.ioUnit === "bytes" && s.idx === -1 ? fmtBytes(value(b, s)) : fmtNum(Math.round(value(b, s) * 100) / 100)])]);
  });
  hit.addEventListener("mouseleave", () => { cross.setAttribute("visibility", "hidden"); hideTip(); });
  hit.addEventListener("click", (evt) => {
    const i = idxAt(evt);
    const a = (i * io.interval).toFixed(6), b2 = ((i + 1) * io.interval).toFixed(6);
    const range = `frame.time_relative >= ${a} && frame.time_relative < ${b2}`;
    rx.showPackets(rx.filter() ? `(${rx.filter()}) && ${range}` : range);
  });
  root.append(hit);
  container.replaceChildren(root);
}

// ----------------------------------------------------------------- shell

function statsRender() {
  for (const b of document.querySelectorAll(".stats-nav button")) {
    if (b.dataset.tool === stats.tool) {
      b.setAttribute("aria-current", "page");
      $("stats-title").textContent = b.textContent;
    } else b.removeAttribute("aria-current");
  }
  const body = $("stats-body");
  body.replaceChildren();
  $("stats-form").hidden = OWN_DATA_TOOLS.has(stats.tool);  // (those tools take their own filter)
  if (!sessionActive()) {
    body.append(el("p", { class: "empty" }, "Open a capture to see its statistics."));
    return;
  }
  if (OWN_DATA_TOOLS.has(stats.tool)) {  // (the flow graph, TCP stream graphs, rhythm and logins read their own data)
    withRx(MAIN_RX, () => TOOLS[stats.tool](body));
    return;
  }
  if (!stats.data) {
    body.append(el("p", { class: "empty" }, stats.loading ? "Computing statistics…" : stats.error || "No statistics yet."));
    return;
  }
  withRx(MAIN_RX, () => TOOLS[stats.tool](body, stats.data));
}

for (const b of document.querySelectorAll(".stats-nav button")) {
  b.addEventListener("click", () => { stats.tool = b.dataset.tool; statsRender(); });
}
$("stats-form").addEventListener("submit", (e) => {
  e.preventDefault();
  stats.filter = $("stats-filter").value.trim();
  if (window.invForgetAll) invForgetAll();  // (Refresh reads every tool's data again, not only the statistics)
  statsLoad(true);
});
$("stats-use-packets").addEventListener("click", () => {
  $("stats-filter").value = pkt.filterKind === "display" ? pkt.filter : "";
  stats.filter = $("stats-filter").value.trim();
  statsLoad(true);
});
viewHooks.stats = () => {
  if (stats.key !== statsKey() || !stats.data) statsLoad();
  else statsRender();
};
let statsResize;
window.addEventListener("resize", () => {
  clearTimeout(statsResize);
  statsResize = setTimeout(() => { if (state.view === "stats" && stats.tool === "io") statsRender(); }, 150);
});
