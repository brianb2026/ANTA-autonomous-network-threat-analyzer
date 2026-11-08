// Selecting packets in the list, and the focus: the whole analysis limited to a selection.
//   Select: click a packet; Ctrl/⌘-click to add or remove one; Shift-click (or Shift+↑/↓)
//   for everything from the last click; drag across rows (with Ctrl/⌘ to add); Ctrl/⌘+A for
//   every packet the list shows; double-click an address for every packet involving it, or
//   elsewhere in a row for the conversation between its two ends.
//   Right-click the selection (or use the bar above the list) to focus the analysis on it,
//   open an analysis tool on it in a small window, explain it, or save it.
//   Focus: the packet list, Statistics, the map, Assets, Files, the alerts and the storyline
//   all limited to the selection, with a bar across the window that says so and leads back
//   (Back retraces each step, Whole capture returns at once; Esc does Back). A focus can be
//   narrowed again by selecting within it.
// Everything from the network is rendered with textContent, never innerHTML.
"use strict";

const sel = {
  view: "",          // the list view the selection belongs to (its filters, and the focus)
  viewState: null,   // that view: {kind, filter, alert}
  parts: [],         // [{ranges: [[a, b]], extra: display filter, test(p), label}]; b may be Infinity
  anchor: null,      // where Shift ranges start (a frame number)
  scope: null,       // the selection made on the server: {id, label, count, filter, …}
  scopeKey: "", makingKey: "", making: null, timer: null, error: "",
  drag: null,
};
const focus = { stack: [] };  // [{id, label, count, filter, filter_length, saved: the list as it was}]

// ------------------------------------------------------------------ frame ranges

function rangesAdd(ranges, a, b) {
  const all = [...ranges, [Math.min(a, b), Math.max(a, b)]].sort((x, y) => x[0] - y[0]);
  const out = [];
  for (const [lo, hi] of all) {
    const last = out[out.length - 1];
    if (last && lo <= last[1] + 1) last[1] = Math.max(last[1], hi);
    else out.push([lo, hi]);
  }
  return out;
}

function rangesCut(ranges, n) {
  const out = [];
  for (const [a, b] of ranges) {
    if (n < a || n > b) { out.push([a, b]); continue; }
    if (a <= n - 1) out.push([a, n - 1]);
    if (n + 1 <= b) out.push([n + 1, b]);
  }
  return out;
}

function rangesHas(ranges, n) {
  let lo = 0, hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (n < ranges[mid][0]) hi = mid - 1;
    else if (n > ranges[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}

function rangesText(ranges) {
  return ranges.map(([a, b]) => (a === b ? `${a}` : b === Infinity ? `${a}-` : `${a}-${b}`)).join(",");
}

const ALL = () => [[1, Infinity]];

// ------------------------------------------------------------------ the selection

function listView() {
  return { kind: pkt.filterKind, filter: pkt.filter || "", alert: pkt.alert || null };
}
function listViewKey() {
  return JSON.stringify([listView(), focusScope()]);
}

function selIsSelected(p) {
  return sel.parts.some((part) => rangesHas(part.ranges, p.n) && (!part.test || part.test(p)));
}

function explicitFrames() {
  let n = 0;
  for (const part of sel.parts) {
    if (part.extra) return Infinity;
    for (const [a, b] of part.ranges) n += b - a + 1;
  }
  return n;
}

function selIsMulti() {
  return explicitFrames() > 1;
}

// The count the bar shows before the server has answered: exact only when the list is the
// whole capture (then a range of frames is that many packets).
function quickCount() {
  const v = sel.viewState || listView();
  if (sel.parts.some((p) => p.extra) || v.filter || v.alert || focusScope()) return null;
  const n = explicitFrames();
  return Number.isFinite(n) ? n : null;
}

function selLabel() {
  if (sel.parts.length === 1 && sel.parts[0].label) return sel.parts[0].label;
  const v = sel.viewState || listView();
  if (sel.parts.length === 1 && !sel.parts[0].extra && sel.parts[0].ranges.length === 1 &&
      sel.parts[0].ranges[0][0] === 1 && sel.parts[0].ranges[0][1] === Infinity) {
    return v.filter ? `packets matching ${v.filter}` : v.alert ? pkt.alertLabel || "packets of the alert" : "packets in the list";
  }
  return "selected packets";
}

// The selection as the server takes it: the view's filter (or alert), and the frames.
function serverParts() {
  const v = sel.viewState || listView();
  const display = v.kind === "display" ? v.filter : "";
  const bpf = v.kind === "bpf" && v.filter;
  return sel.parts.map((part) => {
    let frames = rangesText(part.ranges);
    if (frames === "1-") frames = "";
    if (bpf) {  // (a capture filter can't join a display filter: name the rows themselves)
      frames = rangesText(pkt.rows.filter((p) => rangesHas(part.ranges, p.n) && (!part.test || part.test(p)))
        .reduce((r, p) => rangesAdd(r, p.n, p.n), [])) || "0";
    }
    const filter = [display, part.extra].filter(Boolean).map((f) => `(${f})`).join(" && ");
    return { filter, frames, ...(v.alert ? { alert: v.alert } : {}) };
  });
}

function selSet(parts, { anchor = sel.anchor } = {}) {
  if (sel.view !== listViewKey()) { sel.view = listViewKey(); sel.viewState = listView(); }
  sel.parts = parts;
  sel.anchor = anchor;
  selApply();
  scheduleScope();
}

function selClear() {
  const current = pkt.selected;
  sel.parts = current != null ? [{ ranges: [[current, current]] }] : [];
  sel.view = listViewKey();
  sel.viewState = listView();
  sel.scope = null;
  sel.error = "";
  clearTimeout(sel.timer);
  selApply();
  renderBar();
}

// One packet: what a plain click, the arrow keys, Go to and Find leave selected.
window.selSingle = (n) => {
  sel.view = listViewKey();
  sel.viewState = listView();
  sel.parts = [{ ranges: [[n, n]] }];
  sel.anchor = n;
  sel.scope = null;
  sel.error = "";
  clearTimeout(sel.timer);
  selApply();
  renderBar();
};

// Called by the packet list after it draws: forget a selection made in another view, mark rows.
window.selListChanged = () => {
  if (sel.view && sel.view !== listViewKey()) {
    sel.parts = [];
    sel.anchor = null;
    sel.scope = null;
    sel.view = listViewKey();
    sel.viewState = listView();
    renderBar();
  }
  selApply();
};

function rowData() {
  if (rowData.rows !== pkt.rows) {
    rowData.rows = pkt.rows;
    rowData.map = new Map(pkt.rows.map((p, i) => [p.n, [p, i]]));
  }
  return rowData.map;
}

function selApply() {
  const map = rowData();
  for (const tr of document.querySelectorAll("#pkt-rows tr")) {
    const hit = map.get(Number(tr.dataset.n));
    tr.classList.toggle("in-sel", Boolean(hit && selIsMulti() && selIsSelected(hit[0])));
  }
}

function scheduleScope() {
  clearTimeout(sel.timer);
  sel.scope = null;
  sel.error = "";
  renderBar();
  if (!selIsMulti()) return;
  sel.timer = setTimeout(() => { makeScope().catch(() => {}); }, 250);
}

function makeScope() {
  const body = { parts: serverParts(), label: selLabel() };
  if (focusScope()) body.within = focusScope();
  const key = JSON.stringify(body);
  if (sel.scope && sel.scopeKey === key) return Promise.resolve(sel.scope);
  if (sel.making && sel.makingKey === key) return sel.making;
  sel.makingKey = key;
  sel.making = api("/api/scope", "POST", body).then((s) => {
    if (sel.makingKey === key) { sel.scope = s; sel.scopeKey = key; sel.error = ""; renderBar(); }
    return s;
  }).catch((err) => {
    if (sel.makingKey === key) { sel.error = err.message; renderBar(); }
    throw err;
  }).finally(() => { if (sel.makingKey === key) sel.making = null; });
  return sel.making;
}
// The selection on the server (made when needed), for the tools to use.
window.selectionScope = () => (selIsMulti() ? makeScope() : Promise.resolve(null));

// A scope for any display filter (a conversation, from a single packet's menu).
async function scopeFor(filter, label) {
  const body = { parts: [{ filter }], label };
  if (focusScope()) body.within = focusScope();
  return api("/api/scope", "POST", body);
}

// ------------------------------------------------------------------ mouse and keys

const rowsBody = $("pkt-rows");
const list = $("pkt-list");

function rowOf(target) {
  const tr = target && target.closest ? target.closest("#pkt-rows tr") : null;
  if (!tr) return null;
  const hit = rowData().get(Number(tr.dataset.n));
  return hit ? { tr, p: hit[0], i: hit[1] } : null;
}

function rangeParts(a, b, add) {
  const base = add ? sel.drag ? sel.drag.base : sel.parts : [];
  const explicit = base.filter((p) => !p.extra);
  const others = base.filter((p) => p.extra);
  const ranges = rangesAdd(explicit.length ? explicit.flatMap((p) => p.ranges) : [], a, b);
  return [...others, { ranges }];
}

function toggleFrame(n) {
  if (sel.parts.some((part) => rangesHas(part.ranges, n) && (!part.test || part.test(rowData().get(n)?.[0] || { n })))) {
    const parts = sel.parts.map((part) => ({ ...part, ranges: rangesCut(part.ranges, n) })).filter((part) => part.ranges.length);
    selSet(parts, { anchor: n });
    return false;
  }
  const explicit = sel.parts.find((p) => !p.extra);
  const parts = explicit ? sel.parts.map((p) => (p === explicit ? { ranges: rangesAdd(p.ranges, n, n) } : p))
    : [...sel.parts, { ranges: [[n, n]] }];
  selSet(parts, { anchor: n });
  return true;
}

const IS_MAC = /Mac|iPhone|iPad/.test(navigator.platform || "");
const addKey = (e) => (IS_MAC ? e.metaKey : e.ctrlKey || e.metaKey);  // (Ctrl-click is a right-click on a Mac)

rowsBody.addEventListener("mousedown", (e) => {
  if (e.button !== 0 || (IS_MAC && e.ctrlKey)) return;
  const hit = rowOf(e.target);
  if (!hit) return;
  e.preventDefault();  // (no text selection while dragging)
  list.focus({ preventScroll: true });
  const add = addKey(e);
  if (e.shiftKey && sel.anchor != null) {
    selSet(rangeParts(sel.anchor, hit.p.n, add), { anchor: sel.anchor });
    pktSelect(hit.p.n, { keep: true });
    return;
  }
  sel.drag = { start: hit.p.n, add, base: sel.parts, moved: false, last: hit.p.n, y: e.clientY };
  document.body.classList.add("pkt-dragging");
});

function dragTo(n) {
  const d = sel.drag;
  if (!d || n === d.last) return;
  d.last = n;
  d.moved = d.moved || n !== d.start;
  if (!d.moved) return;
  sel.view = listViewKey();
  sel.viewState = listView();
  sel.parts = rangeParts(d.start, n, d.add);
  selApply();
  renderBar(true);
}

rowsBody.addEventListener("mouseover", (e) => {
  if (!sel.drag) return;
  const hit = rowOf(e.target);
  if (hit) dragTo(hit.p.n);
});

// Past the list's top or bottom edge while dragging: scroll, and keep extending.
let dragScroll = null;
document.addEventListener("mousemove", (e) => {
  if (!sel.drag) return;
  sel.drag.y = e.clientY;
  if (dragScroll) return;
  const step = () => {
    if (!sel.drag) { dragScroll = null; return; }
    const r = list.getBoundingClientRect();
    const y = sel.drag.y;
    const dy = y < r.top + 24 ? -Math.min(40, (r.top + 24 - y) / 2 + 4) : y > r.bottom - 24 ? Math.min(40, (y - r.bottom + 24) / 2 + 4) : 0;
    if (!dy) { dragScroll = null; return; }
    list.scrollTop += dy;
    const at = document.elementFromPoint(r.left + 40, Math.max(r.top + 30, Math.min(r.bottom - 6, y)));
    const hit = rowOf(at);
    if (hit) dragTo(hit.p.n);
    dragScroll = requestAnimationFrame(step);
  };
  dragScroll = requestAnimationFrame(step);
});

document.addEventListener("mouseup", (e) => {
  const d = sel.drag;
  if (!d) return;
  sel.drag = null;
  document.body.classList.remove("pkt-dragging");
  if (d.moved) {
    sel.anchor = d.start;
    scheduleScope();
    pktSelect(d.last, { keep: true });
    return;
  }
  if (d.add) {
    sel.parts = d.base;
    if (toggleFrame(d.start)) pktSelect(d.start, { keep: true });
    return;
  }
  if (e.button === 0) pktSelect(d.start);  // (a plain click: just this packet)
});

// Double-click: every packet involving the address clicked, else the row's conversation.
function addressField(a) {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(a)) return "ip";
  if (/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i.test(a)) return "eth";
  if (a.includes(":")) return "ipv6";
  return null;
}

rowsBody.addEventListener("dblclick", (e) => {
  const hit = rowOf(e.target);
  if (!hit) return;
  const add = addKey(e);
  const cell = e.target.closest("td");
  const p = hit.p;
  let part;
  if (cell && cell.classList.contains("c-addr") && cell.dataset.q && addressField(cell.dataset.q)) {
    const a = cell.dataset.q, f = addressField(a);
    part = { ranges: ALL(), extra: `${f}.addr == ${a}`, test: (q) => q.src === a || q.dst === a,
      label: `packets involving ${a}` };
  } else {
    const fa = addressField(p.src || ""), fb = addressField(p.dst || "");
    if (!fa || fa !== fb) return;
    const [a, b] = [p.src, p.dst];
    part = { ranges: ALL(), extra: `${fa}.addr == ${a} && ${fa}.addr == ${b}`,
      test: (q) => (q.src === a && q.dst === b) || (q.src === b && q.dst === a), label: `packets between ${a} and ${b}` };
  }
  window.getSelection()?.removeAllRanges();
  selSet(add ? [...sel.parts, part] : [part], { anchor: p.n });
  pktSelect(p.n, { keep: true });
  makeScope().then((s) => notice(`Selected ${fmtNum(s.count)} ${s.label}. Right-click for what to do with them; Esc to clear.`))
    .catch((err) => notice(err.message, true));
});

rowsBody.addEventListener("contextmenu", (e) => {
  const hit = rowOf(e.target);
  if (!hit) return;
  e.preventDefault();
  if (selIsMulti() && selIsSelected(hit.p)) {
    openSelectionMenu(e);
    return;
  }
  window.selSingle(hit.p.n);
  if (pkt.selected !== hit.p.n) pktSelect(hit.p.n, { keep: true });
  if (window.pktContextMenu) window.pktContextMenu(e, hit.p);
});

// Keys (before the list's own: Shift extends, Esc clears, Ctrl/⌘+A selects all).
list.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "a") {
    e.preventDefault();
    e.stopImmediatePropagation();
    selSet([{ ranges: ALL() }], { anchor: pkt.rows[0] ? pkt.rows[0].n : null });
    return;
  }
  if (e.shiftKey && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
    e.preventDefault();
    e.stopImmediatePropagation();
    const map = rowData();
    const at = map.get(pkt.selected);
    const i = at ? at[1] : -1;
    const j = Math.max(0, Math.min(pkt.rows.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)));
    const next = pkt.rows[j];
    if (!next) return;
    if (sel.anchor == null) sel.anchor = pkt.selected ?? next.n;
    selSet(rangeParts(sel.anchor, next.n, false), { anchor: sel.anchor });
    pktSelect(next.n, { keep: true });
    document.querySelector(`#pkt-rows tr[data-n="${next.n}"]`)?.scrollIntoView({ block: "nearest" });
    return;
  }
  if (!selIsMulti()) return;
  if (e.key === "Escape") {
    e.preventDefault();
    e.stopImmediatePropagation();
    selClear();
  } else if (e.key === "Enter" || e.key === "ContextMenu" || (e.shiftKey && e.key === "F10")) {
    e.preventDefault();
    e.stopImmediatePropagation();
    const tr = document.querySelector(`#pkt-rows tr[data-n="${pkt.selected}"]`) || rowsBody.firstElementChild;
    const r = tr ? tr.getBoundingClientRect() : list.getBoundingClientRect();
    openSelectionMenu({ clientX: r.left + 80, clientY: r.bottom });
  } else if (!mod && !e.altKey && e.key.toLowerCase() === "f") {
    e.preventDefault();
    focusSelection();
  } else if (mod && e.key.toLowerCase() === "m") {  // mark the selected packets in view
    e.preventDefault();
    e.stopImmediatePropagation();
    markSelected();
  }
}, true);

function markSelected() {
  const rows = pkt.rows.filter(selIsSelected);
  const allMarked = rows.every((p) => pkt.marks.has(p.n));
  for (const p of rows) { if (allMarked) pkt.marks.delete(p.n); else pkt.marks.add(p.n); }
  pktRender();
  notice(`${allMarked ? "Unmarked" : "Marked"} ${fmtNum(rows.length)} packet${rows.length === 1 ? "" : "s"} on this page.`);
}

// ------------------------------------------------------------------ the selection bar and menu

const QUICK_TOOLS = [
  ["conversations", "Conversations"], ["endpoints", "Endpoints"], ["hierarchy", "Protocol hierarchy"],
  ["io", "I/O graph"], ["flow", "Flow graph"], ["expert", "Expert information"], ["lengths", "Packet lengths"],
  ["dns", "DNS"], ["http", "HTTP"], ["tls", "TLS"], ["fingerprints", "TLS fingerprints"], ["logins", "Cleartext logins"],
  ["rhythm", "Rhythm"], ["encrypted", "Encrypted traffic"], ["geo", "Countries & networks"], ["properties", "Capture properties"],
];
window.QUICK_TOOLS = QUICK_TOOLS;

function countText(s) {
  if (s) return `${fmtNum(s.count)} ${s.label}`;
  const n = quickCount();
  return n != null ? `${fmtNum(n)} selected packets` : "Selecting…";
}

function renderBar(dragging = false) {
  const bar = $("sel-bar");
  const on = selIsMulti();
  bar.hidden = !on;
  if (!on) return;
  $("sel-bar-text").textContent = sel.error ? sel.error : dragging ? countText(null).replace("Selecting…", "Selecting") : countText(sel.scope);
  bar.classList.toggle("bad", Boolean(sel.error));
  for (const b of bar.querySelectorAll("button[data-needs-scope]")) b.disabled = Boolean(sel.error);
}

async function withSelection(fn) {
  try {
    const s = await makeScope();
    return fn(s);
  } catch (err) {
    notice(err.message, true);
    return null;
  }
}

function toolItems(getScope) {
  return QUICK_TOOLS.map(([tool, label]) => ({ label, action: async () => {
    try {
      const s = await getScope();
      if (s) window.openQuickTool(tool, s, menuAt);
    } catch (err) { notice(err.message, true); }
  } }));
}
let menuAt = { x: 200, y: 200 };

function openSelectionMenu(e) {
  menuAt = { x: e.clientX, y: e.clientY };
  const label = countText(sel.scope);
  const ai = window.aiReady && window.aiReady();
  showMenu(e.clientX, e.clientY, [
    { caption: label, kind: "Selection" },
    { label: "Focus the analysis on these packets", hint: "F", action: focusSelection },
    { label: "Analysis tools", hint: "in a small window", submenu: [{ header: "Open on the selection" }, ...toolItems(makeScope)] },
    { separator: true },
    { label: "Explain these packets…", hint: "in plain words", action: () => withSelection((s) =>
      window.openExplain({ scope: s.id }, `${fmtNum(s.count)} ${s.label}`, s)) },
    { label: "Explain with AI…", hint: ai ? ai : "set up a model first", action: () => withSelection((s) =>
      window.openExplainAI({ scope: s.id }, `${fmtNum(s.count)} ${s.label}`)) },
    { separator: true },
    { label: "Show only these packets", hint: "the same as Focus", action: focusSelection },
    { label: "Mark the selected packets on this page", hint: "Ctrl+M", action: markSelected },
    { label: "Save these packets…", action: () => withSelection((s) => window.openSaveDialog(false, false, s)) },
    { label: "Copy as a display filter", action: () => withSelection((s) => copyText(s.filter_full || s.filter)) },
    { separator: true },
    { label: "Clear the selection", hint: "Esc", action: selClear },
  ]);
}

$("sel-focus").addEventListener("click", focusSelection);
$("sel-tools").addEventListener("click", (e) => {
  const r = e.currentTarget.getBoundingClientRect();
  menuAt = { x: r.left, y: r.bottom + 4 };
  showMenu(r.left, r.bottom, [{ header: "Open on the selection" }, ...toolItems(makeScope)]);
});
$("sel-explain").addEventListener("click", () => withSelection((s) =>
  window.openExplain({ scope: s.id }, `${fmtNum(s.count)} ${s.label}`, s)));
$("sel-ai").addEventListener("click", () => withSelection((s) =>
  window.openExplainAI({ scope: s.id }, `${fmtNum(s.count)} ${s.label}`)));
$("sel-clear").addEventListener("click", selClear);

// ------------------------------------------------------------------ focus

function focusTop() { return focus.stack[focus.stack.length - 1] || null; }
function focusScope() { return focusTop() ? focusTop().id : ""; }
window.focusInfo = () => focusTop();

function saveList() {
  return { filterKind: pkt.filterKind, filter: pkt.filter, alert: pkt.alert, alertLabel: pkt.alertLabel,
    from: pkt.from, starts: [...pkt.starts], before: pkt.before, selected: pkt.selected };
}

function setListFilter(kind, filter, alert, alertLabel) {
  pkt.filterKind = kind;
  $("pkt-filter-kind").value = kind;
  pkt.filter = filter;
  $("pkt-filter").value = filter;
  pkt.alert = alert;
  pkt.alertLabel = alertLabel || "";
}

async function focusSelection() {
  await withSelection((s) => focusOn(s));
}

function focusOn(scope) {
  if (!scope) return;
  if (pkt.follow) pktSetFollow(false);
  focus.stack.push({ ...scope, saved: saveList() });
  setListFilter("display", "", null, "");  // (the selection holds the list's filters)
  sel.parts = [];
  sel.anchor = null;
  focusChanged({ from: 1 });
  notice(`Focused on ${fmtNum(scope.count)} ${scope.label}. Back or Esc returns.`);
}

function focusBack(level = focus.stack.length - 1) {
  if (!focus.stack.length || level < 0 || level >= focus.stack.length) return;
  const removed = focus.stack.splice(level);
  const saved = removed[0].saved;
  setListFilter(saved.filterKind, saved.filter, saved.alert, saved.alertLabel);
  sel.parts = [];
  sel.anchor = null;
  focusChanged(saved);
}

function focusChanged(where) {
  renderFocusBar();
  sel.view = listViewKey();
  sel.viewState = listView();
  sel.scope = null;
  renderBar();
  // Every view reads its data again for the new scope.
  pkt.total = null;
  pkt.starts = where.starts ? [...where.starts] : [];
  if (state.view === "packets" || pkt.loadedKey) {
    pktLoad(where.from || 1, { keepStack: true, before: where.before || 0 }).then(() => {
      if (where.selected != null && pkt.rows.some((p) => p.n === where.selected)) {
        pktSelect(where.selected);
        document.querySelector(`#pkt-rows tr[data-n="${where.selected}"]`)?.scrollIntoView({ block: "center" });
      }
    });
  }
  stats.key = null;
  if (state.view === "stats" || viewIs("map")) statsLoad(true);
  else if (state.view !== "packets") runViewHook();
  if (window.firstLookChanged) window.firstLookChanged();
  focusAlerts();
  window.dispatchEvent(new CustomEvent("anta:focus"));
}

// The alert table, within a focus: the alerts about its connections.
async function focusAlerts() {
  const top = focusTop();
  if (!top) { state.focusAlerts = null; renderFeed(); return; }
  try {
    const r = await api(`/api/scope/${encodeURIComponent(top.id)}/alerts`);
    if (focusTop() === top) { state.focusAlerts = new Set(r.alerts); renderFeed(); }
  } catch { state.focusAlerts = null; renderFeed(); }
}

// A pop-out window opened on the main window's focus: the same selection, from the server.
window.focusAdopt = async (sid) => {
  try {
    const info = await api(`/api/scope/${encodeURIComponent(sid)}`);
    focus.stack = [{ ...info, saved: saveList() }];
    focusChanged({ from: 1 });
  } catch (err) {
    notice(`This window shows the whole capture: ${err.message}`, true);
  }
};

function renderFocusBar() {
  const bar = $("focus-bar");
  const top = focusTop();
  bar.hidden = !top;
  document.body.classList.toggle("focused", Boolean(top));
  const pop = document.getElementById("pop-scope");  // (a pop-out window's bar)
  if (pop) {
    pop.textContent = top ? `Focus: ${fmtNum(top.count)} ${top.label}` : "";
    $("pop-leave").hidden = !top;
  }
  if (!top) return;
  const crumbs = $("focus-crumbs");
  crumbs.replaceChildren();
  const whole = el("button", { type: "button", class: "crumb" }, "Whole capture");
  whole.addEventListener("click", () => focusBack(0));
  crumbs.append(whole);
  focus.stack.forEach((f, i) => {
    crumbs.append(el("span", { class: "crumb-sep", "aria-hidden": "true" }, "›"));
    const last = i === focus.stack.length - 1;
    const b = el("button", { type: "button", class: `crumb${last ? " current" : ""}`, title: f.filter_length > 600 ? `${f.filter.slice(0, 600)}…` : f.filter },
      `${fmtNum(f.count)} ${f.label}`);
    if (last) b.setAttribute("aria-current", "location");
    else b.addEventListener("click", () => focusBack(i + 1));
    crumbs.append(b);
  });
  $("focus-back").textContent = focus.stack.length > 1 ? "‹ Back" : "‹ Back to the whole capture";
}

$("focus-back").addEventListener("click", () => focusBack());
$("focus-clear").addEventListener("click", () => focusBack(0));
$("focus-tools").addEventListener("click", (e) => {
  const r = e.currentTarget.getBoundingClientRect();
  menuAt = { x: r.left, y: r.bottom + 4 };
  showMenu(r.left, r.bottom, [{ header: "Open on the focus" }, ...toolItems(async () => focusTop())]);
});
$("focus-explain").addEventListener("click", () => {
  const top = focusTop();
  if (top) window.openExplain({ scope: top.id }, `${fmtNum(top.count)} ${top.label}`, top);
});
$("focus-ai").addEventListener("click", () => {
  const top = focusTop();
  if (top) window.openExplainAI({ scope: top.id }, `${fmtNum(top.count)} ${top.label}`);
});
$("focus-copy").addEventListener("click", () => {
  const top = focusTop();
  if (top) copyText(top.filter_full || top.filter).then(() => notice("Copied the focus as a display filter."));
});

// Esc, anywhere outside a text box, dialog or menu: clear the selection, else leave the focus.
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape" || e.defaultPrevented) return;
  const t = document.activeElement;
  if (t && /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) return;
  if (document.querySelector("dialog[open]") || !$("ctx-menu").hidden || (t && t.closest && t.closest(".qt"))) return;
  if (selIsMulti()) { selClear(); return; }
  if (focusTop()) { e.preventDefault(); focusBack(); }
});

// The server no longer has the selection the focus is (it restarted, or the capture changed):
// back to the list as it was before the first focus, once, with the reason.
window.focusLost = (why) => {
  if (!focus.stack.length && !sel.scope) return;
  const first = focus.stack[0];
  focus.stack = [];
  sel.parts = [];
  sel.scope = null;
  if (first) {
    setListFilter(first.saved.filterKind, first.saved.filter, first.saved.alert, first.saved.alertLabel);
    focusChanged(first.saved);
  } else {
    renderBar();
    selApply();
  }
  notice(why || "That selection has expired: select the packets again.", true);
};

// A new capture: no selection, no focus (the server forgot them too).
window.selSessionReset = () => {
  if (window.closeQuickTools) window.closeQuickTools();
  focus.stack = [];
  sel.parts = [];
  sel.anchor = null;
  sel.scope = null;
  state.focusAlerts = null;
  renderFocusBar();
  renderBar();
};

// A pop-out window opened while the main window had a focus: the same focus here.
if (POP_VIEW && POPOUT.get("scope")) window.focusAdopt(POPOUT.get("scope"));
