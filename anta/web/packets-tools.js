// Packet list tools: Wireshark-style display filter bar (validation, field
// suggestions, recent/saved filters), right-click menus, coloring rules,
// Go to packet, and Follow TCP/UDP Stream.
// Everything from the network is rendered with textContent, never innerHTML.
"use strict";

// --------------------------------------------------------- context menus

const ctx = $("ctx-menu");
let ctxReturnFocus = null;
let ctxSub = null;       // the open submenu, and the item that opened it
let ctxSubParent = null;
let ctxSubTimer = null;

// items: {label, action, disabled, hint, title} | {label, submenu: [items]} | {header} | {caption, kind} | {separator: true}
//      | {swatches: [{color, title, action}]} | {about: () => Promise<{lines}>} (facts that fill in when they arrive)
// Falsy entries are skipped, so menus can be built with conditions inline.
function menuFill(box, items, sub) {
  for (const it of items) {
    if (!it) continue;
    if (it.separator) { box.append(el("div", { class: "ctx-sep", role: "separator" })); continue; }
    if (it.header) { box.append(el("div", { class: "ctx-head" }, it.header)); continue; }
    if (it.caption) {  // what was clicked: its kind, then the value as written
      const c = el("div", { class: "ctx-caption" });
      if (it.kind) c.append(el("span", { class: "ctx-kind" }, it.kind));
      c.append(el("span", { class: "ctx-value" }, it.caption));
      box.append(c);
      continue;
    }
    if (it.about) {
      const div = el("div", { class: "ctx-about", role: "note", "aria-live": "polite" });
      div.append(el("div", { class: "ctx-about-line muted" }, "Looking it up…"));
      box.append(div);
      Promise.resolve().then(it.about).then((r) => {
        const lines = (r && r.lines) || [];
        div.replaceChildren(...lines.map((t, i) => el("div", { class: `ctx-about-line${i === 0 ? " first" : ""}` }, t)));
        if (!lines.length) div.remove();
        menuPlace(box, box.dataset.x, box.dataset.y);
      }).catch(() => div.remove());
      continue;
    }
    if (it.swatches) {
      const row = el("div", { class: "ctx-swatches", role: "group", "aria-label": it.label || "Colors" });
      for (const sw of it.swatches) {
        const b = el("button", { type: "button", role: "menuitem", class: "ctx-swatch", title: sw.title, "aria-label": sw.title });
        b.style.setProperty("--sw", sw.color);
        b.addEventListener("click", () => { hideMenu(); sw.action(); });
        row.append(b);
      }
      box.append(row);
      continue;
    }
    const b = el("button", { type: "button", role: "menuitem", class: "ctx-item" });
    b.append(el("span", { class: "ctx-label" }, it.label));
    if (it.hint) b.append(el("span", { class: "ctx-hint" }, it.hint));
    if (it.title) b.title = it.title;
    if (it.disabled) b.disabled = true;
    if (it.submenu) {
      b.classList.add("ctx-parent");
      b.setAttribute("aria-haspopup", "menu");
      b.append(el("span", { class: "ctx-arrow", "aria-hidden": "true" }));
      b.addEventListener("click", () => openSub(b, it.submenu, true));
      b.addEventListener("mouseenter", () => { clearTimeout(ctxSubTimer); ctxSubTimer = setTimeout(() => openSub(b, it.submenu, false), 120); });
      b.addEventListener("keydown", (e) => { if (e.key === "ArrowRight") { e.preventDefault(); openSub(b, it.submenu, true); } });
    } else {
      b.addEventListener("click", () => { hideMenu(); it.action(); });
      if (!sub) b.addEventListener("mouseenter", () => { clearTimeout(ctxSubTimer); ctxSubTimer = setTimeout(closeSub, 200); });
    }
    box.append(b);
  }
}

function menuPlace(box, x, y) {
  x = Number(x);
  y = Number(y);
  const r = box.getBoundingClientRect();
  box.style.left = `${Math.max(4, Math.min(x, window.innerWidth - r.width - 8))}px`;
  box.style.top = `${Math.max(4, Math.min(y, window.innerHeight - r.height - 8))}px`;
}

// A menu opened from a modal dialog lives inside it: the dialog is drawn above the rest of the
// page, so a menu outside it would open underneath.
function menuHost() {
  const open = [...document.querySelectorAll("dialog[open]")].filter((d) => d.matches(":modal"));
  return open.length ? open[open.length - 1] : document.body;
}

function showMenu(x, y, items) {
  closeSub();
  const host = menuHost();
  if (ctx.parentElement !== host) host.append(ctx);
  if (!x && !y && document.activeElement && document.activeElement !== document.body) {  // (opened from the keyboard)
    const r = document.activeElement.getBoundingClientRect();
    x = r.left + 16;
    y = r.bottom;
  }
  ctxReturnFocus = ctx.hidden ? document.activeElement : ctxReturnFocus;
  ctx.replaceChildren();
  ctx.dataset.x = x;
  ctx.dataset.y = y;
  menuFill(ctx, items, false);
  ctx.hidden = false;
  menuPlace(ctx, x, y);
  ctx.querySelector("button:not(:disabled)")?.focus();
}

function openSub(parent, items, focus) {
  if (ctxSub && ctxSubParent === parent) {
    if (focus) ctxSub.querySelector("button:not(:disabled)")?.focus();
    return;
  }
  closeSub();
  ctxSub = el("div", { class: "ctx ctx-sub", role: "menu" });
  ctxSubParent = parent;
  parent.classList.add("open");
  parent.setAttribute("aria-expanded", "true");
  menuFill(ctxSub, items, true);
  ctxSub.addEventListener("keydown", menuKeys);
  ctxSub.addEventListener("mouseenter", () => clearTimeout(ctxSubTimer));
  menuHost().append(ctxSub);
  const pr = parent.getBoundingClientRect(), r = ctxSub.getBoundingClientRect();
  const right = pr.right + r.width + 8 <= window.innerWidth;
  ctxSub.dataset.x = right ? pr.right - 2 : pr.left - r.width + 2;
  ctxSub.dataset.y = pr.top - 8;
  menuPlace(ctxSub, ctxSub.dataset.x, ctxSub.dataset.y);
  if (focus) ctxSub.querySelector("button:not(:disabled)")?.focus();
}

function closeSub() {
  clearTimeout(ctxSubTimer);
  if (!ctxSub) return;
  ctxSub.remove();
  ctxSub = null;
  if (ctxSubParent) {
    ctxSubParent.classList.remove("open");
    ctxSubParent.removeAttribute("aria-expanded");
  }
  ctxSubParent = null;
}

function hideMenu() {
  closeSub();
  if (ctx.hidden) return;
  ctx.hidden = true;
  ctxReturnFocus?.focus?.();
}

function menuKeys(e) {
  const box = e.currentTarget;
  const buttons = [...box.querySelectorAll("button:not(:disabled)")];
  const i = buttons.indexOf(document.activeElement);
  if (e.key === "Escape" || (e.key === "ArrowLeft" && box !== ctx)) {
    e.preventDefault();
    e.stopPropagation();
    if (box === ctx) hideMenu();
    else { const p = ctxSubParent; closeSub(); p?.focus(); }
  } else if (e.key === "ArrowDown") { e.preventDefault(); buttons[(i + 1) % buttons.length]?.focus(); }
  else if (e.key === "ArrowUp") { e.preventDefault(); buttons[(i - 1 + buttons.length) % buttons.length]?.focus(); }
}
ctx.addEventListener("keydown", menuKeys);
document.addEventListener("mousedown", (e) => {
  if (!ctx.hidden && !ctx.contains(e.target) && !(ctxSub && ctxSub.contains(e.target))) hideMenu();
});
window.addEventListener("blur", hideMenu);
window.addEventListener("resize", hideMenu);

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); } catch {
    const ta = el("textarea");
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
}

// ------------------------------------------------------------ filter bar

const filterInput = $("pkt-filter");
const filterKind = $("pkt-filter-kind");
const suggestBox = $("pkt-suggest");
let fieldCatalog = null;
let checkTimer = null;
let checkSeq = 0;

function setFilterKind(kind) {
  filterKind.value = kind;
  const display = kind === "display";
  filterInput.placeholder = display ? "Apply a display filter … e.g. ip.addr == 10.0.0.5 && tcp.port == 443"
    : "Capture filter (BPF) … e.g. host 10.0.0.23 and tcp port 443";
  filterInput.setAttribute("aria-label", display ? "Display filter" : "Capture filter (BPF syntax)");
  filterInput.dataset.valid = "";
  $("pkt-filter-msg").textContent = "";
  hideSuggest();
  if (display) scheduleCheck();
}
filterKind.addEventListener("change", () => setFilterKind(filterKind.value));

async function checkFilter(text) {
  const params = new URLSearchParams();
  params.append("f", text);
  const [res] = await api(`/api/filters/check?${params}`);
  return res;
}

function scheduleCheck() {
  clearTimeout(checkTimer);
  checkTimer = setTimeout(async () => {
    const text = filterInput.value.trim();
    const msg = $("pkt-filter-msg");
    if (filterKind.value !== "display" || !text) { filterInput.dataset.valid = ""; msg.textContent = ""; return; }
    const seq = ++checkSeq;
    try {
      const res = await checkFilter(text);
      if (seq !== checkSeq) return;
      filterInput.dataset.valid = res.ok ? "ok" : "bad";
      msg.textContent = res.ok ? "" : res.error;
    } catch { /* offline: leave as is */ }
  }, 250);
}

// Used by the filter form: a display filter that doesn't compile is reported
// in place and the current packet list is kept.
window.validateDisplayFilter = async (text) => {
  const msg = $("pkt-filter-msg");
  try {
    const res = await checkFilter(text);
    ++checkSeq;
    filterInput.dataset.valid = res.ok ? "ok" : "bad";
    msg.textContent = res.ok ? "" : res.error;
    return res.ok;
  } catch { return true; /* let the packet request report it */ }
};

async function loadFields() {
  if (fieldCatalog) return fieldCatalog;
  try { fieldCatalog = await api("/api/filters/fields"); } catch { fieldCatalog = []; }
  return fieldCatalog;
}

function currentToken() {
  const pos = filterInput.selectionStart ?? filterInput.value.length;
  const before = filterInput.value.slice(0, pos);
  const m = before.match(/[A-Za-z_][A-Za-z0-9_.-]*$/);
  return m ? { text: m[0], start: pos - m[0].length, end: pos } : null;
}

let suggestIndex = -1;
function hideSuggest() { suggestBox.hidden = true; suggestBox.replaceChildren(); suggestIndex = -1;
  filterInput.setAttribute("aria-expanded", "false"); }

async function updateSuggest() {
  if (filterKind.value !== "display") return hideSuggest();
  const tok = currentToken();
  if (!tok || tok.text.length < 1) return hideSuggest();
  const fields = await loadFields();
  const q = tok.text.toLowerCase();
  const starts = fields.filter((f) => f.name.startsWith(q));
  const contains = fields.filter((f) => !f.name.startsWith(q) && f.name.includes(q));
  const list = [...starts, ...contains].slice(0, 12);
  if (!list.length || (list.length === 1 && list[0].name === q)) return hideSuggest();
  suggestBox.replaceChildren();
  list.forEach((f, i) => {
    const li = el("li", { role: "option", id: `sg-${i}`, "aria-selected": "false" });
    li.append(el("span", { class: "sg-name" }, f.name), el("span", { class: "sg-desc" }, `${f.desc} · ${f.kind}`));
    li.addEventListener("mousedown", (e) => { e.preventDefault(); acceptSuggest(f.name); });
    suggestBox.append(li);
  });
  suggestIndex = -1;
  suggestBox.hidden = false;
  filterInput.setAttribute("aria-expanded", "true");
}

function acceptSuggest(name) {
  const tok = currentToken();
  if (!tok) return;
  const v = filterInput.value;
  filterInput.value = v.slice(0, tok.start) + name + v.slice(tok.end);
  const caret = tok.start + name.length;
  filterInput.setSelectionRange(caret, caret);
  hideSuggest();
  scheduleCheck();
}

filterInput.addEventListener("input", () => { scheduleCheck(); updateSuggest(); });
filterInput.addEventListener("blur", () => setTimeout(hideSuggest, 100));
filterInput.addEventListener("keydown", (e) => {
  if (suggestBox.hidden) return;
  const items = [...suggestBox.children];
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    suggestIndex = (suggestIndex + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length;
    items.forEach((li, i) => li.setAttribute("aria-selected", String(i === suggestIndex)));
    filterInput.setAttribute("aria-activedescendant", items[suggestIndex].id);
  } else if ((e.key === "Tab" && !e.shiftKey) || (e.key === "Enter" && suggestIndex >= 0)) {
    // Tab takes the highlighted suggestion, or the first one; Enter without a
    // highlight applies the filter as typed.
    e.preventDefault();
    acceptSuggest(items[Math.max(suggestIndex, 0)].querySelector(".sg-name").textContent);
  } else if (e.key === "Escape") {
    hideSuggest();
  }
});

// Recent and saved filters live in this browser only (a per-viewer convenience).
function storeGet(key) { try { return JSON.parse(localStorage.getItem(key) || "[]"); } catch { return []; } }
function storeSet(key, list) { try { localStorage.setItem(key, JSON.stringify(list)); } catch { /* private mode */ } }

window.rememberFilter = (kind, text) => {
  const key = `anta.recent.${kind}`;
  storeSet(key, [text, ...storeGet(key).filter((t) => t !== text)].slice(0, 15));
};

const EXAMPLES = [
  ["tcp.analysis.flags", "TCP problems (retransmissions, lost segments…)"],
  ["http.request", "HTTP requests"],
  ["dns", "DNS"],
  ["tls.handshake.type == 1", "TLS Client Hellos"],
  ["tcp.flags.syn == 1 && tcp.flags.ack == 0", "New TCP connections"],
  ["tcp.flags.reset == 1", "TCP resets"],
  ["icmp || icmpv6", "ICMP"],
  ["arp", "ARP"],
  ["!(arp || dns || icmp)", "Hide ARP, DNS and ICMP"],
  ["frame.len > 1000", "Large frames"],
];

function applyFilter(kind, text) {
  setFilterKind(kind);
  filterInput.value = text;
  $("pkt-filter-form").requestSubmit();
}

$("pkt-recent").addEventListener("click", (e) => {
  const kind = filterKind.value;
  const recent = storeGet(`anta.recent.${kind}`);
  const saved = storeGet(`anta.saved.${kind}`);
  const r = e.currentTarget.getBoundingClientRect();
  const items = [];
  const current = filterInput.value.trim();
  if (current && !saved.includes(current)) {
    items.push({ label: "Save this filter", action: () => storeSet(`anta.saved.${kind}`, [current, ...saved].slice(0, 30)) });
  }
  if (saved.length) {
    items.push({ header: "Saved" });
    for (const t of saved) items.push({ label: t, action: () => applyFilter(kind, t) });
    items.push({ label: "Remove all saved filters", action: () => storeSet(`anta.saved.${kind}`, []) });
  }
  if (recent.length) {
    items.push({ header: "Recent" });
    for (const t of recent) items.push({ label: t, action: () => applyFilter(kind, t) });
  }
  if (kind === "display") {
    items.push({ header: "Examples" });
    for (const [t, hint] of EXAMPLES) items.push({ label: t, hint, action: () => applyFilter(kind, t) });
  }
  if (!items.length) items.push({ label: "No recent filters yet", disabled: true, action: () => {} });
  showMenu(r.left, r.bottom + 4, items);
});

// ------------------------------------------------- packet context menu

function fieldsOf(d) {
  const m = new Map();
  for (const [name, value] of d.fields || []) {
    if (!m.has(name)) m.set(name, []);
    m.get(name).push(value);
  }
  return m;
}

function and(a, b) { return a && b ? `${a} && ${b}` : a || b; }

// Wireshark's "Colorize Conversation" palette (Edit ▸ Preferences ▸ colors 1–10).
const CONV_COLORS = [
  ["#ffc0c0", "#000000"], ["#ffc0ff", "#000000"], ["#e0c0e0", "#000000"], ["#c0c0ff", "#000000"],
  ["#c0e0e0", "#000000"], ["#c0ffff", "#000000"], ["#c0ffc0", "#000000"], ["#ffffc0", "#000000"],
  ["#e0e0c0", "#000000"], ["#e0e0e0", "#000000"],
];

function colorizeConversation(filter, idx) {
  const [bg, fg] = CONV_COLORS[idx % CONV_COLORS.length];
  pkt.tmpColors = [{ filter, bg, fg, name: `Colorized conversation: ${filter}` },
    ...pkt.tmpColors.filter((t) => t.filter !== filter)].slice(0, 16);
  if (!$("pkt-colorize").checked) { $("pkt-colorize").checked = true; pkt.colorize = true; }
  pktLoad(pkt.from, { keepStack: true, before: pkt.before });
}

async function packetDetailFor(n) {
  if (pkt.detail && pkt.detail.n === n) return pkt.detail;
  return api(`/api/packets/${n}`);
}

window.pktContextMenu = async (e, p) => {
  const x = e.clientX, y = e.clientY;
  const clicked = window.subjectAt ? window.subjectAt(e) : null;  // (read now: the row is re-rendered below)
  let d;
  try { d = await packetDetailFor(p.n); } catch { d = { fields: [] }; }
  const f = fieldsOf(d);
  const v4 = f.has("ip.src");
  const ipf = v4 ? "ip" : "ipv6";
  const src = (f.get(`${ipf}.src`) || [])[0], dst = (f.get(`${ipf}.dst`) || [])[0];
  const tcpStream = (f.get("tcp.stream") || [])[0], udpStream = (f.get("udp.stream") || [])[0];
  const proto = (d.protocols || "").split(":").filter((x) => x !== "ethertype").pop();
  const ethSrc = (f.get("eth.src") || [])[0], ethDst = (f.get("eth.dst") || [])[0];
  const choices = [];
  if (src) choices.push([`Source ${src}`, `${ipf}.src == ${src}`]);
  if (dst) choices.push([`Destination ${dst}`, `${ipf}.dst == ${dst}`]);
  if (src && dst) choices.push([`Conversation ${src} ↔ ${dst}`, `${ipf}.addr == ${src} && ${ipf}.addr == ${dst}`]);
  if (tcpStream !== undefined) choices.push([`TCP stream ${tcpStream}`, `tcp.stream eq ${tcpStream}`]);
  if (udpStream !== undefined) choices.push([`UDP stream ${udpStream}`, `udp.stream eq ${udpStream}`]);
  if (!src && ethSrc && ethDst) choices.push([`Ethernet ${ethSrc} ↔ ${ethDst}`, `eth.addr == ${ethSrc} && eth.addr == ${ethDst}`]);
  if (proto) choices.push([`Protocol ${proto}`, proto]);

  const stream = tcpStream !== undefined ? ["tcp", tcpStream] : udpStream !== undefined ? ["udp", udpStream] : null;
  const convExpr = stream ? `${stream[0]}.stream eq ${stream[1]}`
    : src && dst ? `${ipf}.addr == ${src} && ${ipf}.addr == ${dst}` : null;
  const prepare = (expr) => { setFilterKind("display"); filterInput.value = expr; filterInput.focus(); scheduleCheck(); };
  const items = [
    { caption: src && dst ? `${src} → ${dst}` : p.info || "", kind: `Packet ${p.n} · ${p.proto}` },
    window.guideMenuItem && window.guideMenuItem({ col: p.proto, chain: d.protocols }),
    stream && { label: "Explain this connection…", hint: "in plain words",
      action: () => window.openExplain({ stream: `${stream[0]}:${stream[1]}` }, `${stream[0].toUpperCase()} stream ${stream[1]}`) },
    stream && { label: `Follow ${stream[0].toUpperCase()} stream`, hint: `stream ${stream[1]}`, action: () => openFollow(stream[0], Number(stream[1])) },
    tcpStream !== undefined && /^(TLS|SSL|HTTP2)/.test(p.proto || "") && { label: "Follow TLS stream", hint: "decrypted, with your key log",
      action: () => openFollow("tls", Number(tcpStream)) },
    convExpr && { label: "Show only this conversation", hint: convExpr, action: () => showPacketsFor(convExpr) },
    convExpr && { label: "Flow graph of this conversation", hint: "who sent what, in order", action: () => window.openFlowGraph(convExpr) },
    tcpStream !== undefined && { label: "TCP stream graphs…", hint: "throughput, RTT, window",
      action: () => window.openTcpGraph(Number(tcpStream), src) },
    convExpr && window.QUICK_TOOLS && { label: "Analysis tools", hint: "on this conversation", submenu: [
      { header: `In a small window: ${stream ? `${stream[0].toUpperCase()} stream ${stream[1]}` : `${src} ↔ ${dst}`}` },
      ...window.QUICK_TOOLS.map(([tool, label]) => ({ label, action: async () => {
        try {
          const s = await window.scopeFor(convExpr, stream ? `packets of ${stream[0].toUpperCase()} stream ${stream[1]}` : `packets between ${src} and ${dst}`);
          window.openQuickTool(tool, s, { x, y });
        } catch (err) { notice(err.message, true); }
      } })),
    ] },
    stream && window.openExplainAI && { label: "Explain with AI…", hint: window.aiReady && window.aiReady() ? "this connection" : "set up a model first",
      action: () => window.openExplainAI({ stream: `${stream[0]}:${stream[1]}` }, `${stream[0].toUpperCase()} stream ${stream[1]}`) },
    { separator: true },
    src && window.subjectItems && { label: src, hint: "source", submenu: window.subjectItems({ kind: "ip", value: src }) },
    dst && window.subjectItems && { label: dst, hint: "destination", submenu: window.subjectItems({ kind: "ip", value: dst }) },
    clicked && !["text", "frame"].includes(clicked.kind) && clicked.value !== src && clicked.value !== dst &&
      { label: clicked.value.length > 36 ? `${clicked.value.slice(0, 35)}…` : clicked.value, hint: "clicked",
        submenu: window.subjectItems(clicked) },
    { label: "More filters", submenu: [
      { header: "Apply as filter" },
      ...choices.map(([label, expr]) => ({ label, hint: expr, action: () => showPacketsFor(expr) })),
      { header: "Prepare as filter (edit before applying)" },
      ...choices.slice(0, 3).map(([label, expr]) => ({ label, action: () => prepare(expr) })),
    ] },
    convExpr && { label: "Colorize this conversation", submenu: [{ label: "Colors", swatches: CONV_COLORS.map(([bg], i) => ({
      color: bg, title: `Color ${i + 1}`, action: () => colorizeConversation(convExpr, i) })) }] },
    { label: pkt.refs.has(p.n) ? "Unset time reference" : "Set as time reference", hint: "times count from here",
      action: () => toggleTimeRef(p) },
    { label: pkt.marks.has(p.n) ? "Unmark packet" : "Mark packet", hint: "Ctrl+M", action: () => {
      if (pkt.marks.has(p.n)) pkt.marks.delete(p.n); else pkt.marks.add(p.n);
      pktRender();
    } },
    { separator: true },
    { label: "Copy", submenu: [
      { label: "Summary", hint: "the row's columns", action: () => copyText([p.n, p.ts, p.src, p.dst, p.proto, p.len, p.info].join("\t")) },
      { label: "Info", action: () => copyText(p.info || "") },
      src && { label: "Source address", hint: src, action: () => copyText(src) },
      dst && { label: "Destination address", hint: dst, action: () => copyText(dst) },
      convExpr && { label: "Conversation as a filter", hint: convExpr, action: () => copyText(convExpr) },
    ] },
  ];
  showMenu(x, y, items);
};

// A field or expression from the detail pane or a statistics table.
window.filterMenu = (e, expr) => {
  const current = pkt.filterKind === "display" ? pkt.filter : "";
  const value = /==\s*"?([^"]+?)"?\s*$/.exec(expr);  // the field's value, if it is an address, a name, a hash …
  const thing = value && window.classifyText ? window.classifyText(value[1]) : null;
  const items = [
    { header: expr },
    /^[a-z][a-z0-9-]*$/.test(expr) && window.guideMenuItem && window.guideMenuItem({ abbr: expr }),  // (a protocol)
    thing && !["text", "frame"].includes(thing.kind) && { label: thing.value.length > 36 ? `${thing.value.slice(0, 35)}…` : thing.value,
      hint: "the value", submenu: window.subjectItems(thing) },
    { label: "Apply as filter", action: () => showPacketsFor(expr) },
    { label: "Apply as filter: not selected", action: () => showPacketsFor(`!(${expr})`) },
  ];
  if (current) {
    items.push({ label: "… and selected", action: () => showPacketsFor(and(`(${current})`, expr)) });
    items.push({ label: "… or selected", action: () => showPacketsFor(`(${current}) || ${expr}`) });
    items.push({ label: "… and not selected", action: () => showPacketsFor(and(`(${current})`, `!(${expr})`)) });
  }
  items.push({ label: "Prepare as filter", action: () => {
    setView("packets"); setFilterKind("display"); filterInput.value = expr; filterInput.focus(); scheduleCheck();
  } });
  items.push({ label: "Colorize with this filter", submenu: [{ label: "Colors", swatches: CONV_COLORS.map(([bg], i) => ({
    color: bg, title: `Color ${i + 1}`, action: () => { setView("packets"); colorizeConversation(expr, i); } })) }] });
  // One field, alone or compared with one value (not a whole expression).
  const field = /^([a-z0-9][a-z0-9_.-]*)(?:\s*==\s*(?:"[^"]*"|[^\s&|()!]+))?$/.exec(expr);
  if (field) items.push({ label: "Apply as column", hint: field[1], action: () => addColumn(field[1]) });
  items.push({ label: "Copy as filter", action: () => copyText(expr) });
  showMenu(e.clientX, e.clientY, items);
};

// ------------------------------------------------------- coloring rules

let colorDefaults = [];

function ruleRow(r) {
  const tr = el("tr");
  const on = el("input", { type: "checkbox", "aria-label": "Enabled" });
  on.checked = r.enabled !== false;
  const name = el("input", { type: "text", class: "r-name", maxlength: "80", "aria-label": "Name" });
  name.value = r.name;
  const flt = el("input", { type: "text", class: "r-filter mono", maxlength: "2048", spellcheck: "false", "aria-label": "Filter" });
  flt.value = r.filter;
  const bg = el("input", { type: "color", "aria-label": "Background color" });
  bg.value = r.bg;
  const fg = el("input", { type: "color", "aria-label": "Text color" });
  fg.value = r.fg;
  const preview = el("span", { class: "r-preview" }, "Sample packet");
  const paint = () => { preview.style.background = bg.value; preview.style.color = fg.value; };
  paint();
  bg.addEventListener("input", paint);
  fg.addEventListener("input", paint);
  let timer = null;
  let seq = 0;
  flt.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const mine = ++seq;
      try {
        const res = await checkFilter(flt.value.trim());
        if (mine !== seq) return;
        flt.dataset.valid = res.ok ? "ok" : "bad";
        flt.title = res.ok ? "" : res.error;
      } catch { /* offline: the save reports it */ }
    }, 250);
  });
  const ops = el("span", { class: "r-ops" });
  for (const [label, fn] of [["↑", "up"], ["↓", "down"], ["✕", "del"]]) {
    const b = el("button", { type: "button", class: "tb small", "aria-label": { up: "Move up", down: "Move down", del: "Delete" }[fn] }, label);
    b.addEventListener("click", () => {
      if (fn === "del") tr.remove();
      else if (fn === "up" && tr.previousElementSibling) tr.parentNode.insertBefore(tr, tr.previousElementSibling);
      else if (fn === "down" && tr.nextElementSibling) tr.parentNode.insertBefore(tr.nextElementSibling, tr);
    });
    ops.append(b);
  }
  for (const node of [on, name, flt, bg, fg, preview, ops]) {
    const td = el("td");
    td.append(node);
    tr.append(td);
  }
  tr.read = () => ({ enabled: on.checked, name: name.value.trim(), filter: flt.value.trim(), bg: bg.value, fg: fg.value });
  return tr;
}

function fillRules(rules) { $("color-rows").replaceChildren(...rules.map(ruleRow)); }

$("pkt-color-rules").addEventListener("click", async () => {
  $("color-error").textContent = "";
  try {
    const data = await api("/api/color-rules");
    colorDefaults = data.defaults;
    fillRules(data.rules);
    $("color-dialog").showModal();
  } catch (err) { $("pkt-filter-msg").textContent = err.message; }
});
$("color-add").addEventListener("click", () => {
  const tr = ruleRow({ name: "New rule", filter: filterInput.value.trim() || "tcp.port == 443", bg: "#fff2b3", fg: "#000000", enabled: true });
  $("color-rows").prepend(tr);
  tr.querySelector(".r-name").focus();
});
$("color-defaults").addEventListener("click", () => fillRules(colorDefaults));
$("color-cancel").addEventListener("click", () => $("color-dialog").close());
$("color-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const rules = [...$("color-rows").children].map((tr) => tr.read());
  $("color-save").disabled = true;
  try {
    await api("/api/color-rules", "PUT", { rules });
    $("color-error").textContent = "";
    $("color-dialog").close();
    if (!pkt.follow) pktLoad(pkt.from, { keepStack: true, before: pkt.before });
  } catch (err) {
    $("color-error").textContent = err.message;
  } finally {
    $("color-save").disabled = false;
  }
});

// ---------------------------------------------------------- go to packet

function openGoto() {
  $("goto-error").textContent = "";
  $("goto-n").value = "";
  $("goto-dialog").showModal();
  $("goto-n").focus();
}
$("pkt-goto").addEventListener("click", openGoto);
$("goto-cancel").addEventListener("click", () => $("goto-dialog").close());
$("goto-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const n = parseInt($("goto-n").value, 10);
  if (!(n >= 1)) { $("goto-error").textContent = "Enter a packet number."; return; }
  $("goto-dialog").close();
  if (pkt.follow) pktSetFollow(false);
  pkt.starts = [];
  await pktLoad(n, { keepStack: false, before: 0 });
  const row = pkt.rows.find((r) => r.n >= n);
  if (row) {
    pktSelect(row.n);
    document.querySelector(`#pkt-rows tr[data-n="${row.n}"]`)?.scrollIntoView({ block: "center" });
  }
});
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "g" && state.view === "packets") {
    e.preventDefault();
    openGoto();
  }
});

// --------------------------------------------------------- follow stream

let followData = null;

function printable(bytes) {
  let s = "";
  for (const b of bytes) s += b === 10 || b === 13 || b === 9 || (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".";
  return s;
}

function hexBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function renderFollow() {
  const d = followData;
  if (!d) return;
  const dir = $("follow-dir").value, as = $("follow-as").value;
  const body = $("follow-body");
  const pre = el("pre", { class: "follow-text" });
  let shown = 0;
  const limit = 3 * 1024 * 1024;
  for (const c of d.chunks) {
    if (dir !== "both" && String(c.dir) !== dir) continue;
    const bytes = hexBytes(c.hex);
    if (shown > limit) break;
    shown += bytes.length;
    let text;
    if (as === "hex") {
      const lines = [];
      for (let i = 0; i < bytes.length; i += 16) {
        const row = [...bytes.slice(i, i + 16)];
        lines.push(`${i.toString(16).padStart(8, "0")}  ${row.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(48)}  ${printable(row).replace(/[\r\n\t]/g, ".")}`);
      }
      text = lines.join("\n") + "\n";
    } else {
      text = printable(bytes);
    }
    const span = el("span", { class: `fdir${c.dir}`, title: `frame ${c.frame}` }, text);
    pre.append(span);
  }
  if (shown > limit) pre.append(el("span", { class: "muted" }, "\n… (display limited to 3 MB)"));
  body.replaceChildren(pre);
}

// What the View picker offers for a TCP stream: its bytes; with a key log, the TLS
// application data decrypted; and each HTTP/2 stream carried inside it.
const followViews = { tls: false, h2: [] };

function followViewOptions(stream, current) {
  const sel = $("follow-view");
  const opts = [["tcp", `TCP bytes`]];
  if (followViews.tls) opts.push(["tls", "TLS, decrypted"]);
  for (const id of followViews.h2) opts.push([`http2:${id}`, `HTTP/2 stream ${id}`]);
  sel.replaceChildren(...opts.map(([v, label]) => el("option", { value: v }, label)));
  sel.value = current;
  $("follow-view-wrap").hidden = opts.length < 2;
  sel.onchange = () => {
    const [p, h2] = sel.value.split(":");
    openFollow(p, stream, h2 ? Number(h2) : undefined);
  };
}

async function openFollow(proto, stream, h2) {
  const dialog = $("follow-dialog");
  followData = null;
  if (proto === "tcp" || proto === "udp") { followViews.tls = false; followViews.h2 = []; }
  const label = proto === "http2" ? `Follow HTTP/2 stream ${h2} (TCP stream ${stream})`
    : proto === "tls" ? `Follow TLS stream ${stream} (decrypted)` : `Follow ${proto.toUpperCase()} stream ${stream}`;
  $("follow-title").textContent = label;
  $("follow-sub").textContent = "Loading…";
  $("follow-body").replaceChildren();
  const filter = proto === "udp" ? `udp.stream eq ${stream}`
    : proto === "http2" ? `tcp.stream eq ${stream} && http2.streamid eq ${h2}` : `tcp.stream eq ${stream}`;
  $("follow-filter").onclick = () => { dialog.close(); showPacketsFor(filter); };
  if (!dialog.open) dialog.showModal();
  try {
    followData = await api(`/api/follow?proto=${proto}&stream=${stream}${proto === "http2" ? `&h2=${h2}` : ""}`);
    const d = followData;
    if (d.tls && d.decrypt_available) followViews.tls = true;
    if (d.h2_streams) followViews.h2 = d.h2_streams;
    if (proto !== "udp") followViewOptions(stream, proto === "http2" ? `http2:${h2}` : proto);
    else $("follow-view-wrap").hidden = true;
    const sub = $("follow-sub");
    sub.replaceChildren();
    const a = el("span", { class: "fdir0" }, `${d.a}:${d.a_port} → ${d.b}:${d.b_port}: ${fmtBytes(d.a_bytes)}`);
    const b = el("span", { class: "fdir1" }, `${d.b}:${d.b_port} → ${d.a}:${d.a_port}: ${fmtBytes(d.b_bytes)}`);
    sub.append(a, document.createTextNode("   "), b,
      document.createTextNode(`   ·   ${fmtNum(d.frames)} packets${d.truncated ? " (truncated)" : ""}`));
    renderFollow();
  } catch (err) {
    $("follow-sub").textContent = err.message;
  }
}
window.openFollow = openFollow;
$("follow-dir").addEventListener("change", renderFollow);
$("follow-as").addEventListener("change", renderFollow);
$("follow-close").addEventListener("click", () => $("follow-dialog").close());

// ------------------------------------------------------------ Find Packet (Ctrl+F)
// Wireshark's find bar: text in the packet list or the detail tree, a display filter, hex
// bytes or a regular expression over the bytes. It searches the packets the list shows
// (its filter or alert), from the selected one, and wraps around the end.

const findBar = $("pkt-find");

function findModeChanged() {
  const mode = $("find-mode").value;
  $("find-where-label").hidden = mode !== "text";
  $("find-text").placeholder = { text: "Text to find, any case", filter: "A display filter, e.g. http.request.method == \"POST\"",
    hex: "Bytes in hex, e.g. 47 45 54 20", regex: "A regular expression over the bytes, e.g. pass(word)?=" }[mode];
}
$("find-mode").addEventListener("change", findModeChanged);

function openFind() {
  if (state.view !== "packets") setView("packets");
  findBar.hidden = false;
  findModeChanged();
  $("find-text").focus();
  $("find-text").select();
}

async function findPacket(backwards) {
  const text = $("find-text").value.trim();
  const msg = $("find-msg");
  if (!text) { msg.textContent = "Type what to find."; return; }
  const mode = $("find-mode").value;
  const params = new URLSearchParams({ mode, text, where: mode === "text" ? $("find-where").value : "bytes",
    from: String(pkt.selected ?? 0), dir: backwards ? "prev" : "next" });
  if (pkt.filter) params.set(pkt.filterKind === "display" ? "dfilter" : "filter", pkt.filter);
  if (pkt.alert) params.set("alert", pkt.alert);
  msg.textContent = "Searching…";
  for (const b of findBar.querySelectorAll("button")) b.disabled = true;
  try {
    const r = await api(withFocus(`/api/packets/find?${params}`));
    if (r.frame == null) {
      msg.textContent = pkt.filter || pkt.alert ? "Not found in the packets the list shows." : "Not found.";
    } else {
      msg.textContent = r.wrapped ? (backwards ? "Reached the start: continued from the end." : "Reached the end: continued from the start.")
        : `Packet ${fmtNum(r.frame)}.`;
      await pktReveal(r.frame);
    }
  } catch (err) {
    msg.textContent = err.message;
  } finally {
    for (const b of findBar.querySelectorAll("button")) b.disabled = false;
    $("find-text").focus();
  }
}

findBar.addEventListener("submit", (e) => { e.preventDefault(); findPacket(false); });
$("find-prev").addEventListener("click", () => findPacket(true));
$("find-text").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.shiftKey) { e.preventDefault(); findPacket(true); }
  if (e.key === "Escape") { e.preventDefault(); findBar.hidden = true; $("pkt-list").focus(); }
});
$("find-close").addEventListener("click", () => { findBar.hidden = true; });
$("pkt-find-open").addEventListener("click", openFind);
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "f" && ["packets", "alerts"].includes(state.view) &&
      !e.target.closest("dialog")) {
    e.preventDefault();
    openFind();
  }
});

// ------------------------------------------------------------ custom columns

function addColumn(field) {
  if (pkt.columns.some((c) => c.field === field)) { notice(`${field} is already a column.`); return; }
  if (pkt.columns.length >= 12) { notice("There are already 12 custom columns: remove one first.", true); return; }
  const known = (fieldCatalog || []).find((f) => f.name === field);
  pkt.columns.push({ field, title: known && known.desc ? known.desc : field });
  saveColumns();
  setView("packets");
  pktLoad(pkt.from, { keepStack: true, before: pkt.before });
}
window.addColumn = addColumn;

window.columnMenu = (e, i) => {
  const c = pkt.columns[i];
  if (!c) return;
  const move = (d) => {
    const j = i + d;
    [pkt.columns[i], pkt.columns[j]] = [pkt.columns[j], pkt.columns[i]];
    saveColumns();
    pktRender();
  };
  showMenu(e.clientX, e.clientY, [
    { caption: c.field, kind: `Column: ${c.title}` },
    { label: "Remove this column", action: () => { pkt.columns.splice(i, 1); saveColumns(); pktRender(); } },
    i > 0 && { label: "Move left", action: () => move(-1) },
    i < pkt.columns.length - 1 && { label: "Move right", action: () => move(1) },
    { label: "Show packets that have it", hint: c.field, action: () => showPacketsFor(c.field) },
    { separator: true },
    { label: "Remove every custom column", action: () => { pkt.columns = []; saveColumns(); pktRender(); } },
  ]);
};
loadFields();  // (the catalog names new columns by their description)

// ------------------------------------------------------------ time reference and time shift

function toggleTimeRef(p) {
  pktTimeState();
  if (pkt.refs.has(p.n)) pkt.refs.delete(p.n);
  else pkt.refs.set(p.n, p.ts);
  pktRender();
}
window.toggleTimeRef = toggleTimeRef;

function parseShift(text) {  // "+2.5", "-01:30:00", "1:02:03.5"
  const m = /^([+-])?\s*(?:(\d+):)?(?:(\d+):)?(\d+(?:\.\d+)?)$/.exec(text.trim());
  if (!m) return null;
  const parts = [m[2], m[3], m[4]].filter((x) => x !== undefined).map(Number);
  let secs = 0;
  for (const x of parts) secs = secs * 60 + x;
  return (m[1] === "-" ? -1 : 1) * secs;
}

function shiftDescribe() {
  if (!pkt.shift) return "No shift is applied.";
  const a = Math.abs(pkt.shift), h = Math.floor(a / 3600), mnt = Math.floor((a % 3600) / 60), sec = (a % 60).toFixed(6);
  return `Times are shifted by ${pkt.shift < 0 ? "−" : "+"}${String(h).padStart(2, "0")}:${String(mnt).padStart(2, "0")}:${sec.padStart(9, "0")}` +
    " (absolute time formats).";
}

$("pkt-time-shift").addEventListener("click", () => {
  pktTimeState();
  $("shift-error").textContent = "";
  $("shift-now").textContent = shiftDescribe();
  if (pkt.selected != null) $("shift-frame").value = String(pkt.selected);
  $("shift-dialog").showModal();
});
$("shift-cancel").addEventListener("click", () => $("shift-dialog").close());
$("shift-undo").addEventListener("click", () => { pkt.shift = 0; $("shift-dialog").close(); pktRender(); notice("The time shift is undone."); });
$("shift-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const how = document.querySelector('input[name="shift-how"]:checked').value;
  $("shift-error").textContent = "";
  try {
    if (how === "by") {
      const by = parseShift($("shift-by").value);
      if (by == null) throw new Error("Write the shift as seconds (+2.5) or hours:minutes:seconds (-01:30:00).");
      pkt.shift += by;
    } else {
      const n = Number($("shift-frame").value);
      const when = Date.parse($("shift-to").value.trim().replace(" ", "T"));
      if (!Number.isInteger(n) || n < 1) throw new Error("Give the packet's number.");
      if (Number.isNaN(when)) throw new Error("Write the time as 2026-10-06 10:00:00 (your local time), or ISO with a Z for UTC.");
      const frac = /\.(\d+)/.exec($("shift-to").value);
      const target = Math.floor(when / 1000) + (frac ? Number(`0.${frac[1]}`) : 0);
      const d = await api(`/api/packets/${n}`);
      pkt.shift = target - d.ts;
    }
    $("shift-dialog").close();
    if (["relative", "delta"].includes(pkt.timeFormat)) {
      pkt.timeFormat = "datetime";
      $("pkt-time-format").value = "datetime";
    }
    pktRender();
    notice(shiftDescribe());
  } catch (err) {
    $("shift-error").textContent = err.message;
  }
});

// ------------------------------------------------------------ host names

let namesKey = "";
async function refreshNames(force = false) {
  const key = `${sessionKey()}|${state.alerts.size}`;
  if (!force && key === namesKey) return;
  namesKey = key;
  try { pkt.nameMap = (await api("/api/names")).names || {}; } catch (err) { notice(err.message, true); }
}
window.refreshNames = refreshNames;

$("pkt-names").addEventListener("change", async (e) => {
  pkt.names = e.target.checked;
  if (pkt.names) {
    await refreshNames(true);
    if (!Object.keys(pkt.nameMap).length) notice("The capture names no addresses yet (no DNS answers seen).");
  }
  pktRender();
});

// ------------------------------------------------------------ Tools ▾ (one menu for the list's options)

function toolToggle(id) {
  const box = $(id);
  box.checked = !box.checked;
  box.dispatchEvent(new Event("change"));
}

async function packetToolsItems() {
  const tf = $("pkt-time-format");
  const on = (id) => ($(id).checked ? "✓ on" : "off");
  const keys = !$("pkt-keylog-on").hidden;
  return [
    { label: "Filter templates", hint: "ready-made filters", submenu: await window.templateItems() },
    { separator: true },
    { label: "Colorize packets", hint: on("pkt-colorize"), action: () => toolToggle("pkt-colorize") },
    { label: "Coloring rules…", action: () => $("pkt-color-rules").click() },
    { label: "Show host names", hint: on("pkt-names"), title: "The names the capture gives addresses (DNS answers, names hosts announce)",
      action: () => toolToggle("pkt-names") },
    { label: "Time display", hint: tf.selectedOptions[0] ? tf.selectedOptions[0].text : "",
      submenu: [...tf.options].map((o) => ({ label: o.text, hint: o.value === tf.value ? "✓" : "",
        action: () => { tf.value = o.value; tf.dispatchEvent(new Event("change")); } })) },
    { label: "Time shift…", title: "Shift every packet's time, or set one packet's time (display only)", action: () => $("pkt-time-shift").click() },
    { separator: true },
    { label: "Find packet…", hint: "Ctrl+F", action: () => openFind() },
    { label: "Go to packet…", hint: "Ctrl+G", action: () => $("pkt-goto").click() },
    { label: "Save packets…", hint: "all, shown or marked", action: () => $("pkt-save").click() },
    { separator: true },
    keys ? { label: "Clear the TLS keys", action: () => $("pkt-keylog-clear").click() }
      : { label: "Decrypt TLS with a key log…", title: "Load a TLS key log (SSLKEYLOGFILE) to decrypt your own TLS, as in Wireshark",
        action: () => $("pkt-keylog").click() },
  ];
}

// Tools ▾ (or, from the Analyze menu, straight to its templates).
window.packetToolsMenu = async (which = "") => {
  const r = $("pkt-options").getBoundingClientRect();
  const items = which === "templates" ? await window.templateItems() : await packetToolsItems();
  showMenu(r.left, r.bottom + 4, items);
};
$("pkt-options").addEventListener("click", () => window.packetToolsMenu());
