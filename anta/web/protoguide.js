// Help → Protocols: a short, plain explanation of every protocol ANTA reads, for people new
// to packet analysis: what it is, what it looks like in a capture, what to look out for, and
// filters to try on the open capture. It marks the protocols this capture holds (from the
// protocol hierarchy), and the rest of the app links into it: "What is …?" on a packet's
// menu, the ? beside each layer in the packet details, and protocol rows in Statistics.
// The guide is anta/web/protocol-guide.json (its filters are checked by tests/test_protocol_guide.py).
"use strict";

const guide = { data: null, sel: null, query: "", onlyHere: false, counts: null, countsKey: "" };

fetch("/static/protocol-guide.json", { credentials: "same-origin" })
  .then((r) => (r.ok ? r.json() : null))
  .then((d) => {
    if (!d) return;
    for (const p of d.protocols) p.colRe = p.col ? new RegExp(p.col) : null;
    guide.data = d;
  })
  .catch(() => {});

// The guide's entry for a packet (its Protocol column, then its protocol chain), a layer of
// the packet details, or a protocol name as a filter writes it; null when there is none.
function guideFor({ col, chain, layer, abbr } = {}) {
  const list = guide.data ? guide.data.protocols : null;
  if (!list) return null;
  if (col) {
    const hit = list.find((p) => p.colRe && p.colRe.test(col));
    if (hit) return hit;
  }
  if (abbr) {
    const a = String(abbr).trim().toLowerCase();
    const hit = list.find((p) => p.id === a || p.filter === a || p.abbrs.includes(a));
    if (hit) return hit;
  }
  if (chain) {
    for (const t of String(chain).split(":").reverse()) {
      const hit = list.find((p) => p.abbrs.includes(t));
      if (hit) return hit;
    }
  }
  if (layer) {
    let best = null, len = 0;
    for (const p of list) {
      for (const prefix of p.layers || []) {
        if (layer.startsWith(prefix) && prefix.length > len) { best = p; len = prefix.length; }
      }
    }
    return best;
  }
  return null;
}

// The ? beside a layer in the packet details.
window.layerHelp = (name) => {
  const p = guideFor({ layer: name });
  if (!p) return null;
  const b = el("button", { type: "button", class: "layer-help", title: `What is ${p.name}?`, "aria-label": `What is ${p.name}?` }, "?");
  b.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); helpDialog("protocols", p.id); });
  return b;
};

// "What is …?" for a menu: the entry and the item, or null.
window.guideMenuItem = (what) => {
  const p = guideFor(what);
  return p ? { label: `What is ${p.name}?`, hint: "in plain words", action: () => helpDialog("protocols", p.id) } : null;
};

// How many packets of each protocol the open capture has (Statistics' protocol hierarchy).
function guideCounts() {
  const d = window.statsData ? window.statsData() : null;
  const key = d && d.data ? d.key : "";
  if (!d || !d.data) return null;
  if (guide.countsKey === key && guide.counts) return guide.counts;
  const byAbbr = {};
  for (const r of d.data.protocols || []) {
    const parts = r.path.split("/");
    const abbr = parts[parts.length - 1];
    if (parts.slice(0, -1).includes(abbr)) continue;  // (TLS inside TLS: counted once)
    byAbbr[abbr] = (byAbbr[abbr] || 0) + r.frames;
  }
  const counts = {};
  for (const p of guide.data.protocols) counts[p.id] = Math.max(0, ...p.abbrs.map((a) => byAbbr[a] || 0));
  guide.counts = counts;
  guide.countsKey = key;
  return counts;
}

function guideMatches(p, q) {
  if (!q) return true;
  const cat = (guide.data.categories.find((c) => c[0] === p.cat) || [])[1] || "";
  return [p.name, p.full, p.id, p.filter, p.ports, p.what, cat, ...p.abbrs].join(" ").toLowerCase().includes(q);
}

// Help's Protocols tab, in `box`; `focusId` opens one protocol.
function renderProtocolGuide(box, focusId) {
  if (!guide.data) {
    box.replaceChildren(el("p", { class: "muted" }, "Loading the protocol guide…"));
    setTimeout(() => { if (box.isConnected) renderProtocolGuide(box, focusId); }, 300);
    return;
  }
  if (focusId) { guide.sel = focusId; guide.query = ""; guide.onlyHere = false; }
  const active = typeof sessionActive === "function" && sessionActive();
  if (active && !guideCounts() && window.statsLoad) {  // (the counts come with the statistics)
    window.statsLoad().then(() => { if (box.isConnected) drawList(); });
  }
  const search = el("input", { type: "search", class: "pkt-filter pg-search", placeholder: "Find a protocol: a name, a port (443) or a word (email, login)…",
    "aria-label": "Find a protocol" });
  search.value = guide.query;
  const only = el("input", { type: "checkbox" });
  only.checked = guide.onlyHere;
  only.disabled = !active;
  const onlyLabel = el("label", { class: "check", title: active ? "" : "Open a capture first" });
  onlyLabel.append(only, document.createTextNode(" Only those in this capture"));
  const tools = el("div", { class: "pg-tools" });
  tools.append(search, onlyLabel);
  const list = el("div", { class: "pg-list", role: "listbox", "aria-label": "Protocols" });
  const detail = el("article", { class: "pg-detail", tabindex: "-1" });
  const split = el("div", { class: "pg-split" });
  split.append(list, detail);
  box.replaceChildren(el("p", { class: "pg-intro" }, guide.data.intro), tools, split);

  function shown() {
    const counts = guideCounts();
    const q = guide.query.trim().toLowerCase();
    return guide.data.protocols.filter((p) => guideMatches(p, q) && (!guide.onlyHere || (counts && counts[p.id] > 0)));
  }

  function drawList() {
    const counts = guideCounts();
    const items = shown();
    list.replaceChildren();
    if (!items.length) {
      list.append(el("p", { class: "muted small pg-none" }, "No protocol matches."));
      detail.replaceChildren();
      return;
    }
    if (!items.some((p) => p.id === guide.sel)) guide.sel = items[0].id;
    for (const [cat, label] of guide.data.categories) {
      const mine = items.filter((p) => p.cat === cat);
      if (!mine.length) continue;
      list.append(el("div", { class: "pg-cat", role: "presentation" }, label));
      for (const p of mine) {
        const b = el("button", { type: "button", role: "option", class: "pg-item", "aria-selected": String(p.id === guide.sel), dataset: { id: p.id } });
        b.append(el("span", { class: "pg-name" }, p.name));
        const n = counts ? counts[p.id] : 0;
        if (n) b.append(el("span", { class: "pg-count", title: `${fmtNum(n)} packets in this capture` }, fmtNum(n)));
        b.addEventListener("click", () => pick(p.id));
        list.append(b);
      }
    }
    drawDetail();
  }

  function pick(id, focus = true) {
    guide.sel = id;
    for (const b of list.querySelectorAll(".pg-item")) b.setAttribute("aria-selected", String(b.dataset.id === id));
    const cur = list.querySelector(`.pg-item[data-id="${CSS.escape(id)}"]`);
    if (cur) { cur.scrollIntoView({ block: "nearest" }); if (focus) cur.focus(); }
    drawDetail();
  }

  function drawDetail() {
    const p = guide.data.protocols.find((x) => x.id === guide.sel);
    if (!p) { detail.replaceChildren(); return; }
    const counts = guideCounts();
    const cat = guide.data.categories.find((c) => c[0] === p.cat);
    const head = el("div", { class: "pg-head" });
    head.append(el("h3", {}, p.name), el("span", { class: "muted" }, p.full));
    const meta = el("div", { class: "pg-meta" });
    meta.append(el("span", { class: "pg-chip" }, cat ? cat[1] : p.cat), el("span", { class: "pg-chip" }, `Port: ${p.ports}`));
    const fchip = el("span", { class: "pg-chip" }, "Filter: ");
    fchip.append(el("code", {}, p.filter));
    meta.append(fchip);
    if (counts) meta.append(el("span", { class: `pg-chip${counts[p.id] ? " pg-here" : ""}` },
      counts[p.id] ? `${fmtNum(counts[p.id])} packets in this capture` : "not in this capture"));
    const parts = [head, meta];
    for (const [title, text] of [["What it is", p.what], ["What you'll see", p.see], ["Look out for", p.watch]]) {
      parts.push(el("h4", {}, title), el("p", {}, text));
    }
    parts.push(el("h4", {}, "Try it on this capture"));
    const go = (expr) => { $("help-dialog").close(); showPacketsFor(expr); };
    const tries = el("div", { class: "pg-try" });
    const all = el("button", { type: "button", class: "tb small tb-primary" }, `Show its packets${counts && counts[p.id] ? ` (${fmtNum(counts[p.id])})` : ""}`);
    all.addEventListener("click", () => go(p.filter));
    all.disabled = !active;
    tries.append(all);
    for (const [expr, meaning] of p.try) {
      const b = el("button", { type: "button", class: "pg-filter" });
      b.disabled = !active;
      b.append(el("code", {}, expr), el("span", { class: "muted" }, ` ${meaning}`));
      b.addEventListener("click", () => go(expr));
      tries.append(b);
    }
    parts.push(tries);
    if (!active) parts.push(el("p", { class: "muted small" }, "Open a capture (or run the demo) to try these filters."));
    else parts.push(el("p", { class: "muted small" }, "A filter shows only the packets it matches in the Packets tab; Clear there shows them all again."));
    detail.replaceChildren(...parts);
  }

  search.addEventListener("input", () => { guide.query = search.value; drawList(); });
  search.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); list.querySelector(".pg-item")?.focus(); }
    if (e.key === "Enter") { e.preventDefault(); const first = list.querySelector(".pg-item"); if (first) pick(first.dataset.id); }
  });
  only.addEventListener("change", () => { guide.onlyHere = only.checked; drawList(); });
  list.addEventListener("keydown", (e) => {
    const items = [...list.querySelectorAll(".pg-item")];
    const i = items.indexOf(document.activeElement);
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const next = items[Math.max(0, Math.min(items.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
      if (next) pick(next.dataset.id);
    } else if (e.key === "Home" || e.key === "End") {
      e.preventDefault();
      const next = items[e.key === "Home" ? 0 : items.length - 1];
      if (next) pick(next.dataset.id);
    }
  });
  drawList();
  if (focusId) pick(focusId, false);
  (focusId ? detail : search).focus();
}
