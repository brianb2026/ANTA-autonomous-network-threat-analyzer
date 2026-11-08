// Ask the capture: a question in plain words becomes a display filter and/or the view that
// answers it, read by rules on this computer. Nothing is applied until the user picks it,
// and each phrase is shown with the part of the filter it became. An AI model (the one set
// up under Detection…) is asked only on its button, with the question alone.
// Everything from the network or a model is rendered with textContent, never innerHTML.
"use strict";

const askState = { seq: 0, history: [] };
const ASK_VIEW_LABEL = { alerts: "Alerts", story: "Storyline", assets: "Assets", files: "Files", packets: "Packets" };

window.openAsk = (text = "") => {
  const dlg = $("ask-dialog");
  if (!dlg.open) dlg.showModal();
  const input = $("ask-q");
  if (text) input.value = text;
  input.focus();
  input.select();
};

function askActionLabel(action) {
  if (!action) return "";
  if (action.kind === "packets") return "Show these packets";
  if (action.kind === "stats") {
    const b = document.querySelector(`.stats-nav button[data-tool="${action.tool}"]`);
    return `Open Statistics → ${b ? b.textContent : action.tool}${action.filter ? " (these packets)" : ""}`;
  }
  if (action.view === "host" && action.addr) return `Host details: ${action.addr}`;
  return `Open ${ASK_VIEW_LABEL[action.view] || action.view}`;
}

function askAddress(plan) {
  const p = (plan.parts || []).find((x) => /^(?:from|to|involving) /.test(x.label) && !x.negate);
  return p ? p.label.replace(/^(?:from|to|involving) /, "") : "";
}

function askRun(action, plan, filter) {
  $("ask-dialog").close();
  if (action.kind === "packets") { showPacketsFor(filter); return; }
  // (the answer was counted over these packets, so the tool shows the same ones)
  if (action.kind === "stats") { statsTool(action.tool, action.filter || ""); return; }
  if (action.view === "host" && action.addr) { window.openHost(action.addr); return; }
  const addr = plan ? askAddress(plan) : "";
  if (action.view === "alerts" && addr && window.showAlertsInvolving) { window.showAlertsInvolving(addr); return; }
  setView(action.view);
  if (action.view === "story" && addr) setTimeout(() => document.getElementById(`story-${addr}`)?.scrollIntoView({ block: "start" }), 400);
  if (action.view === "alerts") setAlertsMode("list");
}

async function askCount(filter, out) {
  const seq = askState.seq;
  out.textContent = "Counting the packets…";
  try {
    const page = await api(withFocus(`/api/packets?${new URLSearchParams({ from: "1", limit: "1", count: "1", dfilter: filter })}`));
    if (seq !== askState.seq) return;
    const n = page.matched_total;
    out.textContent = n == null ? "" : n ? `${fmtNum(n)} packet${n === 1 ? "" : "s"} match.` : "No packets match.";
  } catch (err) {
    if (seq === askState.seq) out.textContent = err.message;
  }
}

const ASK_NUMERIC = /^(?:[<>]?[\d,.]+(?:\s?(?:B|KB|MB|GB|%|ms|s|min(?: \d+ s)?|h(?: \d+ min)?|days))?)$/;

// A list that answers the question (a host's peers, the busiest ports…): each row opens its
// packets (click, or Enter on a focused row). A host's profile is a list of facts.
function askTable(t) {
  const wrap = el("div", { class: "ask-table" });
  const table = el("table", { class: `data-table${t.facts ? " ask-facts" : ""}` });
  // (a column is right-aligned when its cells are numbers, sizes or times)
  const numeric = t.columns.map((_, i) => i > 0 && t.rows.every((r) => !r.cells[i] || ASK_NUMERIC.test(r.cells[i])));
  if (!t.facts) {
    const head = el("tr");
    t.columns.forEach((c, i) => head.append(el("th", { scope: "col", class: numeric[i] ? "num" : "" }, c)));
    const thead = el("thead");
    thead.append(head);
    table.append(thead);
  }
  const body = el("tbody");
  for (const r of t.rows) {
    const tr = el("tr");
    r.cells.forEach((c, i) => {
      const cell = el(t.facts && i === 0 ? "th" : "td", { class: !t.facts && numeric[i] ? "num" : "", title: c }, i === 0 && r.host ? undefined : c);
      if (i === 0 && r.host) {  // (the host: its panel; the rest of the row: its packets)
        const link = el("button", { type: "button", class: "addr-link", title: `${r.host}: host details` }, c);
        link.addEventListener("click", (e) => { e.stopPropagation(); $("ask-dialog").close(); window.openHost(r.host); });
        cell.append(link);
      }
      if (t.facts && i === 0) cell.setAttribute("scope", "row");
      tr.append(cell);
    });
    if (r.filter) {
      tr.className = "ask-go";
      tr.tabIndex = 0;
      tr.title = `Show its packets: ${r.filter}`;
      const go = () => askRun({ kind: "packets" }, null, r.filter);
      tr.addEventListener("click", go);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); go(); } });
    }
    body.append(tr);
  }
  table.append(body);
  const scroller = el("div", { class: "ask-scroll" });
  scroller.append(table);
  wrap.append(scroller);
  const notes = [t.note, t.rows.some((r) => r.filter) ? "Click a row to see its packets." : ""].filter(Boolean);
  if (notes.length) wrap.append(el("p", { class: "muted small" }, notes.join(" ")));
  return wrap;
}

function askRender(plan) {
  const box = $("ask-result");
  box.replaceChildren();
  const btn = (label, fn, primary = false) => {
    const b = el("button", { type: "button", class: `tb${primary ? " tb-primary" : ""}` }, label);
    b.addEventListener("click", fn);
    return b;
  };
  if (!plan.understood) {
    box.append(el("p", {}, plan.source === "model" ? "The model had no answer for that."
      : "I couldn't turn that into a filter or a view. Questions like these work:"));
    const ex = el("div", { class: "ask-examples" });
    for (const q of plan.examples || []) ex.append(btn(q, () => { $("ask-q").value = q; askSubmit(); }));
    box.append(ex);
  } else {
    if (plan.source === "model") {
      box.append(el("p", { class: "muted small" }, `Suggested by ${plan.model}. Only your question was sent to it (internal `
        + "addresses replaced, unless you allowed sharing them); check the filter before you rely on it."));
    }
    if (plan.read_as) box.append(el("p", { class: "muted small ask-read-as" }, `Read as: “${plan.read_as}”`));
    if (plan.summary) box.append(el("p", { class: "ask-summary" }, plan.summary));
    if (plan.answer && plan.answer.length) {
      const ul = el("ul", { class: "ask-answer" });
      for (const line of plan.answer) ul.append(el("li", {}, line));
      box.append(ul);
    }
    if (plan.table && plan.table.rows && plan.table.rows.length) box.append(askTable(plan.table));
    const actions = el("div", { class: "ask-actions" });
    let filterInput = null;
    if (plan.filter) {
      const row = el("div", { class: "ask-filter" });
      filterInput = el("input", { type: "text", class: "pkt-filter mono", spellcheck: "false", "aria-label": "The display filter" });
      filterInput.value = plan.filter;
      row.append(el("label", { class: "muted small" }, "Display filter"), filterInput);
      box.append(row);
      const check = plan.check || { ok: true };
      const status = el("p", { class: `small ${check.ok ? "muted" : "error"}`, role: "status" });
      box.append(status);
      if (!check.ok) status.textContent = `This filter doesn't work: ${check.error}`;
      else askCount(plan.filter, status);
      if (plan.parts && plan.parts.length) {
        const parts = el("div", { class: "ask-parts", "aria-label": "How the question became the filter" });
        for (const p of plan.parts) {
          const chip = el("span", { class: "ask-part" });
          chip.append(el("span", {}, `“${p.words}”`), el("span", { class: "muted" }, " → "),
            el("code", {}, (p.negate ? "!" : "") + p.filter));
          parts.append(chip);
        }
        box.append(parts);
      }
      if (check.ok) actions.append(btn("Show these packets", () => askRun({ kind: "packets" }, plan, filterInput.value.trim()), true));
      actions.append(btn("Copy filter", () => copyText(filterInput.value.trim())));
    }
    for (const a of [plan.action, plan.also]) {
      if (a && a.kind !== "packets") actions.append(btn(askActionLabel(a), () => askRun(a, plan, ""), !plan.filter));
    }
    if ((plan.answer && plan.answer.length) || plan.filter) {
      const pin = btn("📌 Pin to the investigation", () => {
        window.pinAnswer({ kind: "ask", question: plan.question, summary: plan.summary || "", lines: plan.answer || [],
          table: plan.table || null, filter: filterInput ? filterInput.value.trim() : plan.filter || "" });
        pin.disabled = true;
        pin.textContent = "📌 Pinned";
      });
      actions.append(pin);
    }
    box.append(actions);
  }
  if (plan.source !== "model" && plan.model) {
    const more = el("p", { class: "muted small ask-model" });
    more.append(document.createTextNode(plan.understood ? "Not what you meant? " : ""),
      btn(`Ask ${plan.model}`, () => askModel(plan.question)));
    more.append(document.createTextNode(" Sends only the question, never the capture."));
    box.append(more);
  } else if (!plan.understood && plan.source !== "model") {
    box.append(el("p", { class: "muted small" }, "An AI model set up under Detection… can also try questions like this one."));
  }
}

async function askSubmit() {
  const q = $("ask-q").value.trim();
  if (!q) return;
  const seq = ++askState.seq;
  $("ask-result").replaceChildren(el("p", { class: "muted" }, "Reading the question…"));
  try {
    const plan = await api(withFocus("/api/ask"), "POST", { q, tz: new Date().getTimezoneOffset() });
    if (seq !== askState.seq) return;
    askState.history = [q, ...askState.history.filter((x) => x !== q)].slice(0, 12);
    const list = $("ask-history");
    list.replaceChildren(...askState.history.map((x) => el("option", { value: x })));
    askRender(plan);
  } catch (err) {
    if (seq === askState.seq) $("ask-result").replaceChildren(el("p", { class: "error" }, err.message));
  }
}

async function askModel(q) {
  const seq = ++askState.seq;
  $("ask-result").replaceChildren(el("p", { class: "muted" }, "Asking the model…"));
  try {
    const plan = await api("/api/ask/model", "POST", { q, tz: new Date().getTimezoneOffset() });
    if (seq === askState.seq) askRender(plan);
  } catch (err) {
    if (seq === askState.seq) $("ask-result").replaceChildren(el("p", { class: "error" }, err.message));
  }
}

$("ask-form").addEventListener("submit", (e) => { e.preventDefault(); askSubmit(); });
$("ask-close").addEventListener("click", () => $("ask-dialog").close());
// An answer the command bar already has: shown in this window, its question in the box for a follow-up.
window.askShow = (q, plan) => {
  const dlg = $("ask-dialog");
  if (!dlg.open) dlg.showModal();
  $("ask-q").value = q;
  ++askState.seq;
  askState.history = [q, ...askState.history.filter((x) => x !== q)].slice(0, 12);
  $("ask-history").replaceChildren(...askState.history.map((x) => el("option", { value: x })));
  askRender(plan);
};
