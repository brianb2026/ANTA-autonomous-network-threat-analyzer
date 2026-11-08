// Right-click anywhere: ANTA's own menu in place of the system one (whose Look Up,
// Translate and Services have nothing to do with a capture). It recognises what was
// clicked: an alert, a file, a device, an address (with its port), a domain, a MAC address,
// a file hash, a TLS fingerprint, a URL, a packet number, or selected text. It offers what
// an analyst does next with it, with a quick look at what ANTA already knows about it
// filling in at the top. Text fields keep the system menu (paste, spelling). Everything from
// the network is rendered with textContent, never innerHTML.
"use strict";

const KIND_LABEL = {
  ip: "Address", mac: "MAC address", domain: "Domain", sha256: "SHA-256", sha1: "SHA-1", md5: "MD5 or JA3",
  ja4: "JA4 fingerprint", ja4s: "JA4S fingerprint", url: "URL", filename: "File name", frame: "Packet", text: "Text",
};
const LOOKUP_KINDS = new Set(["ip", "mac", "domain", "sha256", "sha1", "md5", "ja4", "ja4s", "url", "filename"]);
const SWEEP_KINDS = new Set(["ip", "domain", "url", "sha256", "md5", "ja4", "filename"]);
const quickCache = new Map();  // value -> Promise of the facts (kept while the capture is the same)
let quickCacheKey = "";

// ------------------------------------------------------------ what was clicked

function isIPv4(v) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
  return !!m && m.slice(1).every((x) => Number(x) <= 255);
}

function isIPv6(v) {
  if (!v.includes(":") || !/^[0-9a-f:.]+$/i.test(v) || (v.match(/::/g) || []).length > 1) return false;
  try { new URL(`http://[${v}]/`); return true; } catch { return false; }
}

function classifyText(raw) {
  let v = String(raw || "").trim();
  if (!v || v.length > 300) return null;
  v = v.replace(/^[(<"'`]+/, "").replace(/[)>"'`,;!?]+$/, "").replace(/\.$/, "");
  let port = null;
  let m = /^\[([0-9a-f:.]+)\]:(\d{1,5})$/i.exec(v) || /^((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})$/.exec(v);
  if (m) { v = m[1]; port = m[2]; }
  if (isIPv4(v) || isIPv6(v)) return { kind: "ip", value: v.toLowerCase(), port };
  if (/^[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}$/i.test(v)) return { kind: "mac", value: v.toLowerCase().replace(/-/g, ":") };
  if (/^[0-9a-f]+$/i.test(v) && [32, 40, 64].includes(v.length)) {
    return { kind: { 32: "md5", 40: "sha1", 64: "sha256" }[v.length], value: v.toLowerCase() };
  }
  if (/^[tqd][0-9a-z]{2}[di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/i.test(v)) return { kind: "ja4", value: v };
  if (/^[tqd][0-9a-z]{2}\d{2}[0-9a-z]{2}_[0-9a-f]{4}_[0-9a-f]{12}$/i.test(v)) return { kind: "ja4s", value: v };
  if (/^https?:\/\/\S+$/i.test(v)) return { kind: "url", value: v };
  m = /^#(\d{1,9})$/.exec(v);
  if (m) return { kind: "frame", value: m[1] };
  if (/^(?=.{3,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/i.test(v)) {
    const ext = v.split(".").pop().toLowerCase();
    return { kind: FILE_EXTENSIONS.has(ext) ? "filename" : "domain", value: FILE_EXTENSIONS.has(ext) ? v : v.toLowerCase() };
  }
  return { kind: "text", value: v };
}
const FILE_EXTENSIONS = new Set(("exe dll js vbs ps1 bat cmd msi scr jar zip rar 7z gz tar iso img pdf doc docx docm xls " +
  "xlsx xlsm ppt pptx rtf txt csv log html htm php asp aspx json xml png jpg jpeg gif svg bin dat tmp lnk hta pcap pcapng " +
  "py sh apk dmg pkg deb rpm").split(" "));

// The word under the pointer: the run of characters an address, name, hash or URL is made of.
function tokenAt(x, y) {
  let node = null, offset = 0;
  if (document.caretRangeFromPoint) {
    const r = document.caretRangeFromPoint(x, y);
    if (r) { node = r.startContainer; offset = r.startOffset; }
  } else if (document.caretPositionFromPoint) {
    const p = document.caretPositionFromPoint(x, y);
    if (p) { node = p.offsetNode; offset = p.offset; }
  }
  if (!node || node.nodeType !== Node.TEXT_NODE) return "";
  const text = node.textContent;
  const part = (c) => /[A-Za-z0-9.:_\-/%@#[\]?=&+~]/.test(c);
  let a = offset, b = offset;
  while (a > 0 && part(text[a - 1])) a--;
  while (b < text.length && part(text[b])) b++;
  if (a === b) return "";
  const range = document.createRange();  // (the caret can land on text nowhere near the pointer)
  range.setStart(node, a);
  range.setEnd(node, b);
  const hit = [...range.getClientRects()].some((r) => x >= r.left - 2 && x <= r.right + 2 && y >= r.top - 2 && y <= r.bottom + 2);
  return hit ? text.slice(a, b) : "";
}

function isInternalIp(v) {
  if (v.includes(":")) return /^(fe80|fc|fd)/i.test(v) || v === "::1";
  const [a, b] = v.split(".").map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127);
}

// ------------------------------------------------------------ what ANTA knows

function quickLook(value, full = false) {
  const key = `${sessionKey()}|${state.alerts.size}`;
  if (key !== quickCacheKey) { quickCache.clear(); quickCacheKey = key; }
  const ck = `${full ? "full" : "fast"}|${value}`;
  if (!quickCache.has(ck)) {
    const p = api(`/api/lookup?${new URLSearchParams({ q: value, ...(full ? { full: "1" } : {}) })}`);
    p.catch(() => quickCache.delete(ck));
    quickCache.set(ck, p);
  }
  return quickCache.get(ck);
}

function quoted(v) { return JSON.stringify(v); }

// The display filter that shows a thing's packets (null if none does).
function filterFor(s) {
  const v = s.value;
  switch (s.kind) {
    case "ip": return `${v.includes(":") ? "ipv6" : "ip"}.addr == ${v}`;
    case "mac": return `eth.addr == ${v}`;
    case "domain": return `dns.qry.name contains ${quoted(v)} || tls.handshake.extensions_server_name contains ${quoted(v)} || ` +
      `http.host contains ${quoted(v)}`;
    case "md5": return `tls.handshake.ja3 == ${quoted(v)}`;
    case "ja4": return `tls.handshake.ja4 == ${quoted(v)}`;
    case "url": return `http.request.full_uri == ${quoted(v)}`;
    case "filename": case "text": return v.length <= 200 ? `frame contains ${quoted(v)}` : null;
    default: return null;
  }
}

function short(v, n = 28) { return v.length > n ? `${v.slice(0, n - 1)}…` : v; }

// ------------------------------------------------------------ the menus

// Everything to do with one thing: an address, a domain, a hash …
function subjectItems(s) {
  const v = s.value, f = filterFor(s);
  const items = [{ caption: s.port ? `${v} port ${s.port}` : v, kind: KIND_LABEL[s.kind] }];
  if (LOOKUP_KINDS.has(s.kind)) items.push({ about: () => quickLook(v) });
  switch (s.kind) {
    case "ip":
      items.push(
        { label: "Host details", hint: "who it is, who it talked to", action: () => window.openHost(v) },
        { label: "Show its packets", hint: short(f), action: () => showPacketsFor(f) },
        s.port && { label: `Only port ${s.port}`, hint: "its packets on that port",
          action: () => showPacketsFor(`${f} && (tcp.port == ${s.port} || udp.port == ${s.port})`) },
        { label: "Show its alerts", action: () => window.showAlertsInvolving(v) },
        { label: "Explain its traffic…", hint: "in plain words", action: () => window.openExplain({ dfilter: f }, v) });
      break;
    case "domain":
      items.push(
        { label: "Show its traffic", hint: "DNS, TLS and HTTP", action: () => showPacketsFor(f) },
        { label: "Show its DNS lookups", action: () => showPacketsFor(`dns.qry.name contains ${quoted(v)}`) },
        { label: "Show its alerts", action: () => window.showAlertsInvolving(v) },
        { label: "Explain its traffic…", hint: "in plain words", action: () => window.openExplain({ dfilter: f }, v) });
      break;
    case "mac":
      items.push({ label: "Host details", hint: "the address that uses it", action: () => window.openHost(v) },
        { label: "Show its packets", hint: short(f), action: () => showPacketsFor(f) });
      break;
    case "sha256": case "sha1":
      items.push({ label: "Find the file", hint: "Files", action: () => window.showFiles(v) },
        { label: "Show its alerts", action: () => window.showAlertsInvolving(v) });
      break;
    case "md5":
      items.push({ label: "Show TLS hellos with this JA3", hint: "if it is one", action: () => showPacketsFor(f) });
      break;
    case "ja4":
      items.push({ label: "Show the TLS hellos with it", action: () => showPacketsFor(f) });
      break;
    case "url": {
      items.push({ label: "Show its requests", action: () => showPacketsFor(f) });
      let host = "";
      try { host = new URL(v).hostname; } catch { /* not a URL after all */ }
      const hs = host ? classifyText(host) : null;
      if (hs && hs.kind !== "text") items.push({ label: host, hint: "the server", submenu: subjectItems(hs) });
      break;
    }
    case "filename":
      items.push({ label: "Find the file", hint: "Files", action: () => window.showFiles(v) },
        f && { label: "Show packets that name it", action: () => showPacketsFor(f) });
      break;
    case "frame":
      items.push({ label: `Go to packet ${v}`, action: () => { setView("packets"); window.goToFrame(Number(v)); } });
      break;
    default:
      if (f) items.push({ label: "Find it in the packets", hint: "frame contains", action: () => showPacketsFor(f) });
  }
  if (SWEEP_KINDS.has(s.kind)) {
    items.push({ label: "Sweep the capture for it", hint: "Indicators", action: () => window.sweepFor([v]) });
  }
  if (LOOKUP_KINDS.has(s.kind) && s.kind !== "ip") items.push({ label: "Quick look…", hint: "all ANTA knows", action: () => quickLookCard(s) });
  items.push({ separator: true }, { label: "Copy", hint: short(v, 22), action: () => copyText(s.port ? `${v}:${s.port}` : v) });
  if (f) items.push({ label: "Copy as filter", action: () => copyText(f) });
  return items;
}

// An alert's row: open it, its packets, explain it, triage it — and the thing clicked in it.
function alertItems(id, subject) {
  const a = state.alerts.get(id);
  if (!a) return [];
  const full = () => api(`/api/alerts/${encodeURIComponent(id)}`);
  const device = (a.offender || a.src_ip || "").split(",")[0].trim();
  const ready = typeof detection !== "undefined" && !!(detection.data && detection.data.agent_ready);
  const items = [
    { caption: a.title, kind: `${SEV_LABEL[a.severity] || a.severity} alert · ${a.id}` },
    { label: "Open it", action: () => { setView("alerts"); select(id); } },
    { label: "Show its packets", action: async () => {
      setView("alerts"); select(id);
      state.detail = await full();
      showAlertPackets();
    } },
    { label: "Explain what happened…", hint: "in plain words", action: () => window.openExplain({ alert: id }, `${a.title} (${id})`) },
    device && { label: "Host details", hint: device, action: () => window.openHost(device) },
    { label: "Mark as", submenu: Object.entries(VERDICT_LABEL).map(([k, label]) => ({
      label: `${verdictOf(a) === k ? "✓ " : ""}${label}`, action: () => window.setTriage(id, k) })) },
    window.ignoreItems && { label: "Ignore its source", hint: "stop showing", submenu: window.ignoreItems(a) },
    ready && a.kind !== "agent" && { label: "Ask the detection agent", action: async () => {
      setView("alerts"); select(id);
      notice("Asking the detection agent…");
      try {
        const r = await api(`/api/alerts/${encodeURIComponent(id)}/review`, "POST", {});
        if (state.detail && state.detail.id === id) { state.detail.agent_review = r.verdict; window.renderAlertAgent(state.detail); }
        notice(`The agent says ${r.verdict.verdict}: ${r.verdict.headline}`);
      } catch (err) { notice(err.message, true); }
    } },
    { label: "Sweep the capture for its indicators", hint: "Indicators", action: async () => {
      const x = alertIndicators(await full());
      const values = [...x.ips.map((v) => v.replace(/:\d+$/, "")), ...x.domains, ...x.urls.filter((u) => /^https?:\/\//i.test(u)),
        ...x.files.map((f) => f.sha256), ...(a.addresses || [])];
      if (values.length) window.sweepFor([...new Set(values)]);
      else notice("This alert names no indicators to sweep for.", true);
    } },
    { label: "Save its packets (.pcap)", action: async () => {
      const d = await full();
      if (!d.exportable) { notice("No capture file is recorded for this alert's source.", true); return; }
      const link = el("a", { href: `/api/export/${encodeURIComponent(id)}`, download: "", hidden: "" });
      document.body.append(link);
      link.click();
      link.remove();
    } },
  ];
  if (subject && subject.kind !== "text") items.push({ separator: true }, { label: short(subject.value, 40), hint: KIND_LABEL[subject.kind], submenu: subjectItems(subject) });
  items.push({ separator: true },
    { label: "Copy summary", action: () => copyText(`${a.severity}\t${a.title}\t${alertSource(a)}\t${a.target || ""}\t${a.id}`) });
  return items;
}

// A transferred file's row (Files).
function fileItems(id, subject) {
  const o = window.fileById(id);
  if (!o) return [];
  const conv = `${o.client.includes(":") ? "ipv6" : "ip"}.addr == ${o.client} && ${o.server.includes(":") ? "ipv6" : "ip"}.addr == ${o.server}`;
  const items = [
    { caption: o.name, kind: `${o.program ? "Program · " : ""}${o.type || "File"} · ${fmtBytes(o.size)}` },
    { label: "Save the file…", action: () => window.saveFile(o) },
    { label: "Show the transfer's packets", action: () => showPacketsFor(conv) },
    { label: "Explain the transfer…", hint: "in plain words", action: () => window.openExplain({ dfilter: conv }, o.name) },
    o.sha256 && { label: "Show alerts about it", action: () => window.showAlertsInvolving(o.sha256) },
    o.sha256 && { label: "Sweep the capture for its hash", hint: "Indicators", action: () => window.sweepFor([o.sha256]) },
    { separator: true },
    { label: "The server", hint: o.server, submenu: subjectItems({ kind: "ip", value: o.server }) },
    { label: "The client", hint: o.client, submenu: subjectItems({ kind: "ip", value: o.client }) },
  ];
  if (subject && !["text", "ip"].includes(subject.kind)) items.push({ label: short(subject.value, 40), hint: KIND_LABEL[subject.kind], submenu: subjectItems(subject) });
  items.push({ separator: true }, o.sha256 && { label: "Copy SHA-256", action: () => copyText(o.sha256) },
    { label: "Copy location", action: () => copyText(o.location || o.name) });
  return items;
}

// A conversation between two hosts (a line on the network map, a row in a conversations table).
function conversationItems(a, b) {
  const v6 = a.includes(":") || b.includes(":");
  const f = `${v6 ? "ipv6" : "ip"}.addr == ${a} && ${v6 ? "ipv6" : "ip"}.addr == ${b}`;
  return [
    { caption: `${a} ↔ ${b}`, kind: "Conversation" },
    { label: "Show its packets", hint: short(f), action: () => showPacketsFor(f) },
    { label: "Explain it…", hint: "in plain words", action: () => window.openExplain({ dfilter: f }, `${a} ↔ ${b}`) },
    { separator: true },
    { label: a, submenu: subjectItems({ kind: "ip", value: a }) },
    { label: b, submenu: subjectItems({ kind: "ip", value: b }) },
    { separator: true },
    { label: "Copy as filter", action: () => copyText(f) },
  ];
}

// Selected text that isn't one recognisable thing.
function textItems(text) {
  const f = filterFor({ kind: "text", value: text });
  return [
    { caption: short(text, 60), kind: "Selected text" },
    f && { label: "Find it in the packets", hint: "frame contains", action: () => showPacketsFor(f) },
    { label: "Find it in the alerts", action: () => window.showAlertsInvolving(text) },
    { separator: true },
    { label: "Copy", action: () => copyText(text) },
  ];
}

// The pane's own help (its ? button), so nobody is left wondering what they're looking at.
function paneItems(target) {
  const bar = target.closest("section, main, aside, .pane")?.querySelector("[data-help]");
  const help = bar && bar.querySelector(".pane-help, button[aria-label^='Help'], button[title^='What']");
  const items = [];
  if (help) items.push({ label: "What is this pane?", hint: "help", action: () => help.click() });
  if (state.view === "packets") items.push({ label: "Go to packet…", hint: "Ctrl+G", action: () => $("pkt-goto")?.click() });
  return items;
}

// What a right-click points at: selected text, an element that names its value, or the word under the pointer.
function subjectAt(e) {
  const sel = window.getSelection();
  const selText = sel && !sel.isCollapsed ? sel.toString().trim() : "";
  const holder = e.target.closest("[data-q]");
  if (selText) return classifyText(selText);
  if (holder) return classifyText(holder.dataset.q);
  return classifyText(tokenAt(e.clientX, e.clientY));
}
window.subjectAt = subjectAt;

function contextItems(e) {
  const target = e.target;
  const sel = window.getSelection();
  const selText = sel && !sel.isCollapsed ? sel.toString().trim() : "";
  const subject = subjectAt(e);
  const alertRow = target.closest(".alert-row[data-id]");
  if (alertRow) return alertItems(alertRow.dataset.id, subject);
  const fileRow = target.closest("[data-file]");
  if (fileRow) return fileItems(fileRow.dataset.file, subject);
  const edge = target.closest("[data-a][data-b]");
  if (edge && !selText) return conversationItems(edge.dataset.a, edge.dataset.b);
  let items = [];
  if (subject && subject.kind !== "text") items = subjectItems(subject);
  else if (selText) items = textItems(selText);
  const pane = paneItems(target);
  if (pane.length) items.push(items.length ? { separator: true } : null, ...pane);
  return items.filter(Boolean);
}

document.addEventListener("contextmenu", (e) => {
  if (e.defaultPrevented) return;  // (a pane's own menu: the packet list, the detail tree, statistics)
  if (e.target.closest("input, textarea, select, [contenteditable='true'], [contenteditable='']")) return;
  e.preventDefault();
  const items = contextItems(e);
  if (items.length) showMenu(e.clientX, e.clientY, items);
});

// ------------------------------------------------------------ the Quick look card

async function quickLookCard(s) {
  let dlg = $("ql-dialog");
  if (!dlg) {
    dlg = el("dialog", { id: "ql-dialog", "aria-labelledby": "ql-title" });
    document.body.append(dlg);
  }
  const body = el("div", { class: "ql-body" });
  body.append(el("p", { class: "muted" }, "Reading what ANTA knows…"));
  const close = el("button", { type: "button", class: "tb tb-primary" }, "Close");
  close.addEventListener("click", () => dlg.close());
  const actions = el("div", { class: "ql-actions" });
  for (const it of subjectItems(s)) {
    if (!it || !it.label || it.submenu || it.separator || it.label === "Quick look…") continue;
    const b = el("button", { type: "button", class: "tb" }, it.label);
    b.addEventListener("click", () => { dlg.close(); it.action(); });
    actions.append(b);
  }
  const caption = el("p", { class: "ql-caption" });
  caption.append(el("span", { class: "ctx-kind" }, KIND_LABEL[s.kind] || ""), el("span", { class: "mono" }, s.value));
  const foot = el("div", { class: "dialog-actions" });
  foot.append(close);
  dlg.replaceChildren(el("h2", { id: "ql-title" }, "Quick look"), caption, body, actions, foot);
  dlg.showModal();
  try {
    const r = await quickLook(s.value, true);
    const list = el("ul", { class: "ql-facts" });
    for (const t of r.lines) list.append(el("li", {}, t));
    body.replaceChildren(list);
    if (r.alerts && r.alerts.length) {
      body.append(el("h3", { class: "det-sub" }, "Its alerts"));
      const ul = el("ul", { class: "ql-alerts" });
      for (const a of r.alerts) {
        const b = el("button", { type: "button", class: "link" });
        b.append(el("span", { class: `sev sev-${a.severity}` }, SEV_LABEL[a.severity] || a.severity), document.createTextNode(` ${a.title}`));
        b.addEventListener("click", () => { dlg.close(); setView("alerts"); select(a.id); });
        const li = el("li");
        li.append(b);
        ul.append(li);
      }
      body.append(ul);
    }
    body.append(el("p", { class: "muted small" }, "From this capture's analysis only: nothing was looked up outside this computer."));
  } catch (err) {
    body.replaceChildren(el("p", { class: "error" }, err.message));
  }
}
window.openQuickLook = (value) => { const s = classifyText(value); if (s) quickLookCard(s); };
window.subjectItems = subjectItems;
window.classifyText = classifyText;
