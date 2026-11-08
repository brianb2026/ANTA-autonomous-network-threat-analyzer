// Network rules: the policy tests and the firewall dry run in one list (anta/rules.py). One rule
// per line, in plain words ("block 10.0.0.5", "no ubuntu hosts on the network", "don't let router
// configs be uploaded") or pasted from a firewall (iptables, ufw, pf, Cisco). Every rule is a test
// (does this capture break it? the connections that do, each opening its packets) and a firewall
// rule (enforced with the others: what would be blocked, what would break, which alerts would be
// stopped). Checked as typed; saved rules apply to every capture; the status bar shows how the open
// one does. "What can I write?" lists every form, and a line it can't read gets suggestions.
// Everything from the network is rendered with textContent only.
"use strict";

const policyState = { saved: [], placement: "border", savedPlacement: "border", results: null, timer: null, seq: 0, reference: null };

function policyLines() {
  return $("policy-rules").value.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
}

function policyTz() { return new Date().getTimezoneOffset(); }

function policyChip() {
  const chip = $("policy-chip");
  const r = policyState.results;
  if (!policyState.saved.length) { chip.textContent = "Rules"; chip.className = "case-chip"; return; }
  if (!r) { chip.textContent = `Rules · ${policyState.saved.length}`; chip.className = "case-chip"; return; }
  const failed = r.filter((x) => x.status === "fail").length;
  const read = r.filter((x) => x.understood).length;
  chip.textContent = failed ? `Rules ✗ ${failed} of ${r.length} broken` : `Rules ✓ ${read} passed`;
  chip.className = `case-chip ${failed ? "policy-fail" : "policy-pass"}`;
}

async function policyLoad() {
  try {
    const d = await api(`/api/policy?tz=${policyTz()}`);
    policyState.saved = d.rules;
    policyState.savedPlacement = d.placement;
    policyState.results = d.results;
    if ($("policy-dialog").open && $("policy-rules").value.trim() === policyState.saved.join("\n")) policyRender(d);
  } catch { /* the chip just stays as it was */ }
  policyChip();
}
window.policyChanged = policyLoad;

// Open the rules; `add` puts one more line in (unsaved), e.g. "block 10.0.0.5" from a host's Block it…
window.openPolicy = async (opts = {}) => {
  const dlg = $("policy-dialog");
  $("policy-error").textContent = "";
  try {
    const d = await api(`/api/policy?tz=${policyTz()}${policyState.reference ? "" : "&reference=1"}`);
    if (d.reference) policyState.reference = d.reference;
    policyState.saved = d.rules;
    policyState.savedPlacement = d.placement;
    policyState.results = d.results;
    if (!dlg.open) {
      $("policy-rules").value = d.rules.join("\n");
      $("policy-placement").value = d.placement;
    }
    policyRender(d);
  } catch (err) {
    $("policy-error").textContent = err.message;
  }
  policyChip();
  policyGuide();
  if (!dlg.open) dlg.showModal();
  if (opts.add) policyAdd(opts.add);
  $("policy-rules").focus();
};

function policyAdd(line) {
  const box = $("policy-rules");
  if (!box.value.split("\n").some((l) => l.trim() === line)) box.value = `${box.value.replace(/\s+$/, "")}${box.value.trim() ? "\n" : ""}${line}\n`;
  box.focus();
  box.dispatchEvent(new Event("input"));
}

function policyDirty() {
  const dirty = policyLines().join("\n") !== policyState.saved.join("\n") || $("policy-placement").value !== policyState.savedPlacement;
  $("policy-state").textContent = dirty ? "Not saved yet: checked as you type." : policyState.saved.length ? "Saved." : "";
  $("policy-save").disabled = !dirty;
  $("policy-revert").disabled = !dirty;
}

// ------------------------------------------------------------ results

function policyRender(d) {
  const box = $("policy-results");
  policyDirty();
  if (d.error && d.results == null) {
    box.replaceChildren(el("p", { class: "muted" }, sessionActive() ? `The capture can't be checked: ${d.error}` :
      "Open a capture (or run the demo) to check the rules against it."));
    return;
  }
  const results = d.results || [];
  if (!results.length) {
    box.replaceChildren(el("p", { class: "muted" }, "Write a rule on the left, add one (Add a rule ▾), or see What can I write?: "
      + "each is checked here at once, as a test and as a firewall rule."));
    return;
  }
  box.replaceChildren(policySummary(d, results), ...results.map(policyResult), ...policyEffects(d));
}

function policySummary(d, results) {
  const wrap = el("div", { class: "rules-summary" });
  const failed = results.filter((r) => r.status === "fail").length;
  const unread = results.filter((r) => !r.understood).length;
  const head = el("p", { class: "policy-sum" });
  const n = results.length;
  head.append(el("strong", {}, n === 1 ? (failed ? "The rule is broken" : unread ? "The rule couldn't be read" : "The rule passes")
    : failed ? `${failed} of ${n} rules broken` : `All ${n - unread} rules pass`),
    document.createTextNode(` in ${(state.session && state.session.source ? state.session.source.split(/[\\/]/).pop() : "this capture")}`
      + (unread ? `; ${unread} not understood.` : ".")));
  wrap.append(head);
  const e = d.enforce;
  if (!e) return wrap;
  const t = e.totals;
  const where = e.placement === "host" ? "on every device" : "at the border";
  const pct = t.connections ? ` (${((t.blocked / t.connections) * 100).toFixed(t.blocked && t.blocked / t.connections < 0.01 ? 2 : 0)}%)` : "";
  const enf = el("p", { class: "small" });
  enf.append(el("strong", {}, `Enforced ${where}: ${fmtNum(t.blocked)} of ${fmtNum(t.connections)} connections blocked${pct}`),
    document.createTextNode(`, ${fmtBytes(t.blocked_bytes)}.`));
  if (e.placement === "border" && t.unseen) {
    enf.append(document.createTextNode(` ${fmtNum(t.unseen)} more stay inside your network, where a border firewall can't reach them `
      + "(choose Enforce on every device to judge them too)."));
  }
  wrap.append(enf);
  if (e.semantics) {
    wrap.append(el("p", { class: "muted small" }, `Firewall lines: ${e.semantics}.` + Object.entries(e.defaults || {}).map(([dir, v]) =>
      ` When no line matches ${dir === "internal" ? "inside the network" : dir === "in" ? "coming in" : "going out"}: ${v.action} (${v.why}).`).join("")));
  }
  const al = e.alerts;
  const stopped = al.stopped.length, through = al.through.length;
  if (stopped || through) {
    wrap.append(el("p", { class: "small" }, `Alerts: ${fmtNum(stopped)} stopped, ${fmtNum(through)} still get through`
      + (al.inside.length ? `, ${fmtNum(al.inside.length)} inside your network` : "") + " (details below the rules)."));
  }
  return wrap;
}

// What enforcing every rule would do, after the rules themselves: the alerts, what would stop, the blocked connections.
function policyEffects(d) {
  const e = d.enforce;
  if (!e) return [];
  const wrap = el("div", { class: "rules-effects" });
  wrap.append(el("h4", { class: "fw-head" }, `If you enforced them all ${e.placement === "host" ? "on every device" : "at the border"}`));
  const al = e.alerts;
  if (al.stopped.length || al.through.length || al.inside.length) {
    wrap.append(el("p", { class: "small muted" }, "The capture's alerts:"));
    policyAlerts(wrap, al.stopped, "✓", "fw-stopped", (a) => `stopped (${fmtNum(a.connections)} connection${a.connections === 1 ? "" : "s"})`);
    policyAlerts(wrap, al.through, "✗", "fw-through", (a) => `still gets through (${fmtNum(a.connections - a.blocked)} of ${fmtNum(a.connections)})`);
    policyAlerts(wrap, al.inside, "–", "fw-inside", () => "inside your network: a border firewall never sees it");
  }
  if (e.breaks.length) {
    wrap.append(el("p", { class: "small muted" }, "What would stop working:"));
    const ul = el("ul", { class: "fw-breaks small" });
    for (const b of e.breaks.slice(0, 10)) {
      const li = el("li");
      li.append(el("strong", {}, b.service), document.createTextNode(`: ${fmtNum(b.sessions)} connection${b.sessions === 1 ? "" : "s"}, `
        + `${fmtNum(b.devices)} local device${b.devices === 1 ? "" : "s"}, ${fmtBytes(b.bytes)} (e.g. ${b.example})`));
      ul.append(li);
    }
    wrap.append(ul);
  }
  if (e.blocked.length) {
    const det = el("details", { class: "rules-blocked" });
    det.append(el("summary", { class: "small" }, `Blocked connections (${e.blocked_groups > e.blocked.length ? `the ${e.blocked.length} busiest of ` : ""}`
      + `${fmtNum(e.blocked_groups)})`));
    det.append(policyTable(e.blocked.map((g) => ({ ...g, extra: g.by })), true));
    wrap.append(det);
  }
  return wrap.childElementCount > 1 ? [wrap] : [];
}

function policyAlerts(box, list, mark, cls, why) {
  for (const a of list) {
    const b = el("button", { type: "button", class: `fw-alert ${cls}`, title: "Open this alert" });
    b.append(el("span", { "aria-hidden": "true" }, `${mark} `), el("span", { class: `sev sev-${a.severity}` }, SEV_LABEL[a.severity] || a.severity),
      document.createTextNode(` ${a.title} `), el("span", { class: "mono muted small" }, a.what), el("span", { class: "muted small" }, ` · ${why(a)}`));
    b.addEventListener("click", () => { $("policy-dialog").close(); setView("list"); select(a.id); });
    box.append(b);
  }
}

function policyTable(groups, withExtra) {
  const table = el("table", { class: "data-table policy-table" });
  const tb = el("tbody");
  for (const g of groups) {
    const tr = el("tr", { class: g.filter ? "ask-go" : "", tabindex: g.filter ? "0" : "-1", title: g.filter ? `Show the packets: ${g.filter}` : "" });
    tr.append(el("td", {}, g.what), el("td", { class: "num" }, `${fmtNum(g.sessions)} conn.`),
      el("td", { class: "num" }, g.bytes ? fmtBytes(g.bytes) : ""),
      el("td", { class: "mono muted" }, withExtra ? (g.extra || "") : g.first ? fmtTime(g.first) : ""));
    if (g.filter) {
      const go = () => { $("policy-dialog").close(); showPacketsFor(g.filter); };
      tr.addEventListener("click", go);
      tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter") { ev.preventDefault(); go(); } });
    }
    tb.append(tr);
  }
  table.append(tb);
  return table;
}

function policyResult(r) {
  const card = el("article", { class: `policy-item policy-${r.understood ? r.status : "unread"}` });
  const top = el("div", { class: "policy-top" });
  const mark = !r.understood ? "?" : r.status === "pass" ? "✓" : r.status === "fail" ? "✗" : "–";
  const word = !r.understood ? "Not understood" : r.status === "pass" ? "Passes" : r.status === "fail" ? "Broken" : "Can't tell";
  top.append(el("span", { class: "policy-mark", "aria-hidden": "true" }, mark), el("strong", {}, r.rule),
    el("span", { class: "policy-word" }, word));
  card.append(top);
  if (!r.understood) {
    card.append(el("p", { class: "small error" }, r.error));
    if (r.suggestions && r.suggestions.length) {
      const row = el("p", { class: "small rules-suggest" });
      row.append(el("span", { class: "muted" }, "Did you mean "));
      r.suggestions.forEach((s, i) => {
        const b = el("button", { type: "button", class: "link mono", title: "Use this instead" }, s);
        b.addEventListener("click", () => policyReplace(r.rule, s));
        row.append(...(i ? [document.createTextNode(" or ")] : []), b);
      });
      row.append(document.createTextNode("?"));
      card.append(row);
    }
    return card;
  }
  card.append(el("p", { class: "muted small" }, `Read as: ${r.reads}${r.syntax && r.syntax !== "words" ? ` (${r.syntax})` : ""}.`));
  if (r.status === "fail") {
    const unit = ["upload_limit", "peer_limit", "no_new_devices", "no_hosts"].includes(r.kind) ? "host" :
      r.kind === "no_transfer" ? "file" : "connection";
    card.append(el("p", { class: "small" }, `${fmtNum(r.violations)} ${unit}${r.violations === 1 ? "" : "s"} break${r.violations === 1 ? "s" : ""} it:`));
    card.append(policyTable(r.groups, false));
  }
  const e = r.enforce || {};
  const enf = el("p", { class: "small rules-enforce" });
  if (e.test_only) enf.append(el("strong", {}, "A test only. "), document.createTextNode(e.test_only));
  else if (e.allows !== undefined) enf.append(el("strong", {}, "Enforced: "), document.createTextNode(`lets ${fmtNum(e.allows)} connection${e.allows === 1 ? "" : "s"} through (an exception to the lines after it).`));
  else if (e.blocks || e.inside) {
    enf.append(el("strong", {}, "Enforced: "), document.createTextNode(`blocks ${fmtNum(e.blocks)} connection${e.blocks === 1 ? "" : "s"}`
      + (e.inside ? `; ${fmtNum(e.inside)} more stay inside your network, where a border firewall can't reach them.` : ".")));
    if (e.note && (e.blocks || e.inside)) enf.append(el("span", { class: "muted" }, ` ${e.note}`));
  }
  if (enf.childNodes.length) card.append(enf);
  if (r.status === "fail") {
    const acts = el("div", { class: "first-actions" });
    if (r.filter) {
      const all = el("button", { type: "button", class: "tb small" }, "Show all of them");
      all.addEventListener("click", () => { $("policy-dialog").close(); showPacketsFor(r.filter); });
      acts.append(all);
    }
    const pin = el("button", { type: "button", class: "tb small" }, "📌 Pin");
    pin.addEventListener("click", () => {
      window.pinAnswer({ kind: "note", question: `Rule broken: ${r.rule}`, summary: `Read as: ${r.reads}`,
        lines: [`${r.violations} breaking.`], filter: r.filter || "",
        table: { columns: ["What", "Count", "Data", "First"], rows: r.groups.map((g) => ({
          cells: [g.what, String(g.sessions), g.bytes ? fmtBytes(g.bytes) : "", g.first ? fmtTime(g.first) : ""], filter: g.filter })) } });
      pin.disabled = true;
      pin.textContent = "📌 Pinned";
    });
    acts.append(pin);
    card.append(acts);
  }
  if (r.note) card.append(el("p", { class: "muted small" }, r.note));
  return card;
}

function policyReplace(oldLine, newLine) {
  const box = $("policy-rules");
  const lines = box.value.split("\n");
  const i = lines.findIndex((l) => l.trim() === oldLine.trim());
  if (i >= 0) lines[i] = newLine;
  else lines.push(newLine);
  box.value = lines.join("\n");
  box.focus();
  box.dispatchEvent(new Event("input"));
}

// ------------------------------------------------------------ what can I write?

function policyGuide() {
  const list = $("policy-guide-list");
  const ref = policyState.reference;
  if (!ref) { list.replaceChildren(el("p", { class: "muted small" }, "Loading…")); return; }
  const q = $("policy-guide-search").value.trim().toLowerCase();
  const parts = [];
  for (const g of ref) {
    const items = g.examples.filter((x) => !q || `${g.group} ${g.about} ${x.text} ${x.means}`.toLowerCase().includes(q));
    if (!items.length) continue;
    const sec = el("section", { class: "rules-guide-group" });
    sec.append(el("h4", {}, g.group));
    if (g.about) sec.append(el("p", { class: "muted small" }, g.about));
    for (const x of items) {
      const b = el("button", { type: "button", class: "rules-guide-item", title: "Add this rule" });
      b.append(el("span", { class: "mono" }, x.text), el("span", { class: "muted small" }, ` ${x.means}`));
      b.addEventListener("click", () => policyAdd(x.text));
      sec.append(b);
    }
    parts.push(sec);
  }
  list.replaceChildren(...(parts.length ? parts : [el("p", { class: "muted small" }, "Nothing matches. Try block, hosts, upload, dns, port or iptables.")]));
}

// ------------------------------------------------------------ checking and saving

async function policyCheckDraft() {
  const seq = ++policyState.seq;
  try {
    const d = await api("/api/policy/check", "POST", { rules: policyLines(), tz: policyTz(), placement: $("policy-placement").value });
    if (seq !== policyState.seq) return;
    $("policy-error").textContent = "";
    policyRender(d);
  } catch (err) {
    if (seq === policyState.seq) $("policy-error").textContent = err.message;
  }
}

$("policy-rules").addEventListener("input", () => {
  policyDirty();
  clearTimeout(policyState.timer);
  policyState.timer = setTimeout(policyCheckDraft, 600);
});
$("policy-placement").addEventListener("change", () => { policyDirty(); policyCheckDraft(); });
$("policy-save").addEventListener("click", async () => {
  try {
    const d = await api("/api/policy", "PUT", { rules: policyLines(), tz: policyTz(), placement: $("policy-placement").value });
    policyState.saved = d.rules;
    policyState.savedPlacement = d.placement;
    policyState.results = d.results;
    $("policy-rules").value = d.rules.join("\n");
    policyRender(d);
    policyChip();
    notice(`Saved ${d.rules.length} rule${d.rules.length === 1 ? "" : "s"}.`);
    if (window.firstLook && !state.selected) window.firstLook(true);
  } catch (err) {
    $("policy-error").textContent = err.message;
  }
});
$("policy-revert").addEventListener("click", () => {
  $("policy-rules").value = policyState.saved.join("\n");
  $("policy-placement").value = policyState.savedPlacement;
  policyCheckDraft();
});
$("policy-close").addEventListener("click", () => $("policy-dialog").close());
$("policy-examples").addEventListener("click", (e) => {
  const r = e.currentTarget.getBoundingClientRect();
  const ref = policyState.reference || [];
  showMenu(r.left, r.bottom + 4, ref.map((g) => ({ label: g.group, submenu: g.examples.map((x) => ({ label: x.text, hint: x.means,
    action: () => policyAdd(x.text) })) })));
});
$("policy-guide-toggle").addEventListener("click", (e) => {
  const guide = $("policy-guide");
  guide.hidden = !guide.hidden;
  e.currentTarget.setAttribute("aria-expanded", String(!guide.hidden));
  if (!guide.hidden) { policyGuide(); $("policy-guide-search").focus(); }
});
$("policy-guide-search").addEventListener("input", policyGuide);
$("policy-chip").addEventListener("click", () => window.openPolicy());
policyLoad();
