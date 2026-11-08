// Ignored alert sources: alerts from an address, network or MAC the analyst chose to ignore (of
// every kind, or of one kind) are set aside by the server (anta/ignore.py). They leave the alert
// list, the stories and What to look at first everywhere at once, and come back when the rule
// goes. Ways in: an alert's "Ignore its source ▾" (detail pane and right-click), the host panel,
// the "N ignored" chip on the alert bar, Detection → Ignored alert sources…, or type `ignored`.
// Everything from the network is rendered with textContent only.
"use strict";

const ignoreState = { rules: [], kinds: [], ignored: 0 };

function ignoreKindTitle(kind) {
  return (ignoreState.kinds.find((k) => k.kind === kind) || {}).title || kind;
}

function ignoreRuleText(r) {
  return `${r.kind ? `${ignoreKindTitle(r.kind)} alerts` : "every alert"} from ${r.source}`;
}

function ignoreApply(d) {
  ignoreState.rules = d.rules;
  ignoreState.kinds = d.kinds;
  ignoreState.ignored = d.ignored;
  ignoreChip();
  if ($("ignore-dialog").open) ignoreRender();
}

async function ignoreLoad() {
  try { ignoreApply(await api("/api/ignored")); } catch { /* the chip just stays as it was */ }
}

function ignoreChip() {
  const chip = $("alerts-ignored");
  const r = ignoreState.rules.length, n = ignoreState.ignored;
  chip.hidden = !r;
  chip.textContent = `${fmtNum(n)} ignored`;
  chip.title = `${r} ignored source${r === 1 ? "" : "s"}, holding back ${fmtNum(n)} alert${n === 1 ? "" : "s"}: `
    + "see or change them";
}

// The live count, from the summary the server sends every second.
window.ignoredSummary = (s) => {
  if (typeof s.ignored === "number" && s.ignored !== ignoreState.ignored) {
    ignoreState.ignored = s.ignored;
    ignoreChip();
  }
};

async function ignoreSave(rules) {
  ignoreApply(await api("/api/ignored", "PUT", { rules: rules.map(({ source, kind, note }) => ({ source, kind, note })) }));
}

window.ignoreSource = async (source, kind = "", note = "") => {
  const before = ignoreState.ignored;
  try {
    await ignoreSave([...ignoreState.rules, { source, kind, note }]);
    const held = Math.max(0, ignoreState.ignored - before);
    notice(`Ignoring ${ignoreRuleText({ source, kind })}: ${fmtNum(held)} alert${held === 1 ? "" : "s"} set aside. ` +
      "The “ignored” chip on the alert bar brings them back.");
  } catch (err) {
    notice(err.message, true);
  }
};

// The sources an alert can be ignored by: its source address and the device it blames.
function ignoreActors(a) {
  const ok = (x) => typeof x === "string" && (ADDR_TOKEN.test(x) || /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(x));
  return [...new Set([a.src_ip, a.offender].filter(ok))];
}

// Menu items to ignore an alert's source, for this kind of alert or every kind.
window.ignoreItems = (a) => {
  const items = [];
  for (const x of ignoreActors(a)) {
    if (items.length) items.push({ separator: true });
    items.push({ label: `${a.title} alerts from ${x}`, hint: "this kind", action: () => window.ignoreSource(x, a.kind) },
      { label: `Every alert from ${x}`, hint: "every kind", action: () => window.ignoreSource(x, "") });
  }
  if (!items.length) items.push({ label: "This alert has no single source address to ignore", disabled: true });
  items.push({ separator: true }, { label: "Ignored alert sources…", action: () => window.openIgnored() });
  return items;
};

// ------------------------------------------------------------ the dialog

function ignoreRender() {
  const list = $("ignore-list");
  if (!ignoreState.rules.length) {
    list.replaceChildren(el("p", { class: "muted" },
      "Nothing is ignored. Ignore a source from an alert (Ignore its source ▾), or add one below."));
    return;
  }
  const table = el("table", { class: "data-table ignore-table" });
  const head = el("tr");
  for (const h of ["Source", "Alerts", "Note", "Held back", ""]) head.append(el("th", { scope: "col" }, h));
  const tb = el("tbody");
  ignoreState.rules.forEach((r, i) => {
    const tr = el("tr");
    const stop = el("button", { type: "button", class: "tb small", title: "Show this source's alerts again" }, "Stop ignoring");
    stop.addEventListener("click", async () => {
      try {
        await ignoreSave(ignoreState.rules.filter((_, j) => j !== i));
        notice(`Showing ${ignoreRuleText(r)} again.`);
      } catch (err) { $("ignore-error").textContent = err.message; }
    });
    const act = el("td");
    act.append(stop);
    tr.append(el("td", { class: "mono" }, r.source), el("td", {}, r.kind ? ignoreKindTitle(r.kind) : "Every kind"),
      el("td", { class: "muted" }, r.note || ""), el("td", { class: "num" }, fmtNum(r.count)), act);
    tb.append(tr);
  });
  const thead = el("thead");
  thead.append(head);
  table.append(thead, tb);
  list.replaceChildren(table, el("p", { class: "muted small" },
    `${fmtNum(ignoreState.ignored)} alert${ignoreState.ignored === 1 ? "" : "s"} set aside in this capture.`));
}

window.openIgnored = async (prefill = "") => {
  const dlg = $("ignore-dialog");
  $("ignore-error").textContent = "";
  await ignoreLoad();
  const kind = $("ignore-kind");
  if (kind.options.length <= 1) {
    for (const k of ignoreState.kinds) kind.append(el("option", { value: k.kind }, k.title));
  }
  ignoreRender();
  if (prefill) $("ignore-source").value = prefill;
  if (!dlg.open) dlg.showModal();
  $("ignore-source").focus();
};

$("ignore-add").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("ignore-error").textContent = "";
  try {
    const rule = { source: $("ignore-source").value, kind: $("ignore-kind").value, note: $("ignore-note").value };
    await ignoreSave([...ignoreState.rules, rule]);
    $("ignore-source").value = "";
    $("ignore-note").value = "";
  } catch (err) {
    $("ignore-error").textContent = err.message;
  }
});
$("ignore-close").addEventListener("click", () => $("ignore-dialog").close());
$("alerts-ignored").addEventListener("click", () => window.openIgnored());

// ------------------------------------------------------------ on the open alert

{
  const b = el("button", { type: "button", class: "link small", id: "d-ignore",
    title: "Stop showing alerts from this alert's source" }, "Ignore its source ▾");
  b.addEventListener("click", () => {
    const a = state.detail;
    if (!a) return;
    const r = b.getBoundingClientRect();
    showMenu(r.left, r.bottom + 4, window.ignoreItems(a));
  });
  document.querySelector("#detail .triage").append(b);
  const render = window.renderTriage;
  window.renderTriage = (a) => {
    render(a);
    b.hidden = !ignoreActors(a).length;
  };
}

ignoreLoad();
