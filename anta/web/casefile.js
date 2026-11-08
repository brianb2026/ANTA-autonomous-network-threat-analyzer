// The investigation: the analyst's notes and the answers they pinned (from Ask and the host
// panel), kept on the server for this capture, saved to a file with the verdicts on the alerts
// and the focus, and opened again later (anta/casefile.py). The incident report includes the
// notes and pins. Everything from the network or a file is rendered with textContent only.
"use strict";

const caseState = { data: null, notesTimer: null, pending: null };

function caseChip() {
  const d = caseState.data;
  const pins = d ? d.pins.length : 0;
  const chip = $("case-chip");
  chip.textContent = pins ? `📌 Investigation · ${pins}` : "Investigation";
  chip.classList.toggle("has-pins", pins > 0 || !!(d && d.notes));
}

async function caseLoad() {
  try {
    caseState.data = await api("/api/case");
  } catch {
    return;
  }
  caseChip();
  if ($("case-dialog").open) caseRender();
}
window.caseChanged = caseLoad;

window.pinAnswer = async (pin) => {
  try {
    caseState.data = await api("/api/case/pins", "POST", { pin });
    caseChip();
    notice("Pinned to the investigation (File → Investigation, or the button in the status bar).");
  } catch (err) {
    notice(err.message, true);
  }
};

window.openCase = async () => {
  const dlg = $("case-dialog");
  $("case-error").textContent = "";
  $("case-open").hidden = true;
  await caseLoad();
  caseRender();
  if (!dlg.open) dlg.showModal();
};

function caseRender() {
  const d = caseState.data;
  if (!d) return;
  const v = d.verdicts || {};
  const verdicts = Object.entries(v).filter(([k]) => k !== "new").map(([k, n]) => `${n} ${(VERDICT_LABEL[k] || k).toLowerCase()}`);
  $("case-sub").textContent = `${d.capture.name ? `About ${d.capture.name}. ` : ""}` +
    (verdicts.length ? `Your verdicts on the alerts: ${verdicts.join(", ")}. ` : "") +
    "Kept while this capture is open; Save investigation keeps it for later.";
  if (document.activeElement !== $("case-notes")) $("case-notes").value = d.notes;
  $("case-pin-count").textContent = d.pins.length ? String(d.pins.length) : "";
  const box = $("case-pins");
  if (!d.pins.length) {
    box.replaceChildren(el("p", { class: "muted small" }, "Nothing pinned yet. Pin an answer from Ask (📌 Pin to the investigation) or a host from its panel."));
    return;
  }
  box.replaceChildren(...[...d.pins].reverse().map((p) => {
    const card = el("article", { class: "case-pin" });
    const head = el("div", { class: "case-pin-head" });
    head.append(el("strong", {}, p.question || p.summary), el("span", { class: "muted small" }, new Date(p.pinned * 1000).toLocaleString()));
    card.append(head);
    if (p.summary && p.question) card.append(el("p", { class: "muted small" }, p.summary));
    if (p.lines.length) {
      const ul = el("ul", { class: "ask-answer" });
      for (const line of p.lines) ul.append(el("li", {}, line));
      card.append(ul);
    }
    if (p.table && p.table.rows.length) {
      const det = el("details");
      det.append(el("summary", {}, p.table.facts ? "Profile" : `Table (${p.table.rows.length} rows)`));
      det.append(askTable(p.table));
      card.append(det);
    }
    const acts = el("div", { class: "first-actions" });
    if (p.filter) {
      const b = el("button", { type: "button", class: "tb small" }, "Show its packets");
      b.addEventListener("click", () => { $("case-dialog").close(); showPacketsFor(p.filter); });
      acts.append(b);
    }
    if (p.kind === "ask" && p.question) {
      const b = el("button", { type: "button", class: "tb small" }, "Ask again");
      b.addEventListener("click", () => { $("case-dialog").close(); window.focusCommand(p.question); });
      acts.append(b);
    }
    const rm = el("button", { type: "button", class: "tb small" }, "Remove");
    rm.addEventListener("click", async () => {
      try { caseState.data = await api(`/api/case/pins/${encodeURIComponent(p.id)}`, "DELETE"); caseChip(); caseRender(); }
      catch (err) { $("case-error").textContent = err.message; }
    });
    acts.append(rm);
    card.append(acts);
    return card;
  }));
}

async function caseSaveNotes() {
  clearTimeout(caseState.notesTimer);
  caseState.notesTimer = null;
  try {
    caseState.data = await api("/api/case/notes", "PUT", { notes: $("case-notes").value });
    $("case-notes-saved").textContent = "Saved.";
    caseChip();
  } catch (err) {
    $("case-error").textContent = err.message;
  }
}
$("case-notes").addEventListener("input", () => {
  $("case-notes-saved").textContent = "";
  clearTimeout(caseState.notesTimer);
  caseState.notesTimer = setTimeout(caseSaveNotes, 800);
});
$("case-notes").addEventListener("blur", () => { if (caseState.notesTimer) caseSaveNotes(); });

// The focus stack, as filters a later session can make again.
function caseFocus() {
  const stack = (typeof focus !== "undefined" && focus.stack) || [];
  return stack.map((f) => ({ label: f.label, filter: f.filter_full || f.filter })).filter((f) => f.filter && !f.filter.endsWith(" …"));
}

window.saveCase = async () => {
  if (caseState.notesTimer) await caseSaveNotes();
  try {
    const r = await api("/api/case/save", "POST", { focus: caseFocus() });
    saveDownload(r);
    notice(`Saving the investigation as ${r.name}.`);
  } catch (err) {
    notice(err.message, true);
  }
};

window.openCaseFile = () => $("case-file").click();

$("case-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  if (file.size > 5 * 1024 * 1024) { notice("That file is larger than 5 MB.", true); return; }
  caseState.pending = await file.text();
  await caseOpen(false);
});

// Open a chosen investigation file: on its own capture it is applied at once; on another one,
// the dialog says so and offers to open its capture (or to use it here anyway).
async function caseOpen(apply) {
  const content = caseState.pending;
  if (!content) return;
  let r;
  try {
    r = await api("/api/case/open", "POST", { content, apply });
  } catch (err) {
    await window.openCase();
    $("case-error").textContent = err.message;
    return;
  }
  if (r.applied) {
    caseState.pending = null;
    caseState.data = r.case;
    caseChip();
    await caseRestoreFocus(r.focus);
    await window.openCase();
    notice(`Investigation opened: ${r.pins} pinned answer${r.pins === 1 ? "" : "s"}, ${r.matched} of ${r.verdicts} verdicts put back on the alerts.`);
    return;
  }
  await window.openCase();
  const box = $("case-open");
  box.hidden = false;
  box.replaceChildren(el("p", {}, `This investigation is about ${r.capture.name || "another capture"}` +
    `${r.current ? `, but ${r.current} is open` : ", and no capture is open"}.`));
  const acts = el("div", { class: "first-actions" });
  if (r.can_open) {
    const b = el("button", { type: "button", class: "tb small tb-primary" }, `Open ${r.capture.name}`);
    b.addEventListener("click", async () => {
      box.hidden = true;
      caseState.waitFor = r.capture.name;
      $("case-dialog").close();
      const error = await startSession({ mode: "file", path: r.path });
      if (error) { caseState.waitFor = null; notice(error, true); }
    });
    acts.append(b);
  }
  const here = el("button", { type: "button", class: "tb small" }, "Use it here anyway");
  here.addEventListener("click", () => { box.hidden = true; caseOpen(true); });
  const cancel = el("button", { type: "button", class: "tb small" }, "Cancel");
  cancel.addEventListener("click", () => { box.hidden = true; caseState.pending = null; });
  acts.append(here, cancel);
  box.append(acts);
}

async function caseRestoreFocus(levels) {
  if (!levels || !levels.length || typeof focusOn !== "function") return;
  while (window.focusInfo && window.focusInfo()) window.focusBack(0);
  for (const f of levels) {
    try {
      const within = window.focusScope ? window.focusScope() : "";
      const scope = await api("/api/scope", "POST", { parts: [{ filter: f.filter }], label: f.label || "", ...(within ? { within } : {}) });
      focusOn(scope);
    } catch (err) {
      notice(`The saved focus "${f.label}" couldn't be made again: ${err.message}`, true);
      return;
    }
  }
}

// After its capture was opened from the investigation, put it back once the capture is read.
const caseSessionWatch = setInterval(() => {
  if (!caseState.waitFor || !caseState.pending || !state.session) return;
  if (state.session.state === "finished") { caseState.waitFor = null; caseOpen(false); }
  else if (["error", "stopped"].includes(state.session.state)) caseState.waitFor = null;
}, 1000);
void caseSessionWatch;

$("case-chip").addEventListener("click", () => window.openCase());
$("case-close").addEventListener("click", () => $("case-dialog").close());
$("case-save").addEventListener("click", () => window.saveCase());
$("case-open-file").addEventListener("click", () => window.openCaseFile());
$("case-report").addEventListener("click", () => { $("case-dialog").close(); clickIf("report-open"); });
caseLoad();
