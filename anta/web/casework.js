// Casework: saving the capture (all, displayed or marked packets), an analyst's
// verdict and notes on each alert, the alert table as CSV, the Files view
// (Export Objects) and the indicator sweep. Network-derived text is rendered with
// textContent only, as everywhere else.
"use strict";

function captureStem() {
  const src = (state.session && state.session.source) || "capture";
  return (src.split(/[\\/]/).pop() || "capture").replace(/\.(pcapng|pcap|cap)$/i, "").replace(/[^A-Za-z0-9._-]+/g, "_") || "capture";
}

let noticeTimer = null;
function notice(text, bad = false) {
  const box = $("status-msg");
  box.textContent = text;
  box.classList.toggle("bad", bad);
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => { box.textContent = ""; }, 12000);
}

// ------------------------------------------------------------ save capture

// Marked frame numbers as compact ranges: 1-20,35,40-41.
function frameRanges(numbers) {
  const sorted = [...numbers].sort((a, b) => a - b);
  const out = [];
  for (let i = 0; i < sorted.length;) {
    let j = i;
    while (j + 1 < sorted.length && sorted[j + 1] === sorted[j] + 1) j++;
    out.push(i === j ? `${sorted[i]}` : `${sorted[i]}-${sorted[j]}`);
    i = j + 1;
  }
  return out.join(",");
}

let saveKey = null;  // the last share-safe copy's address key, offered once the copy is saved
let saveSelection = null;  // the selected packets, when the dialog was opened for them

window.openSaveDialog = function openSaveDialog(preferShown = false, safe = false, selection = null) {
  saveSelection = selection;
  const shown = pkt.alert ? pkt.alertLabel
    : pkt.filter ? `${pkt.filterKind === "bpf" ? "capture filter" : "display filter"} ${pkt.filter}` : "";
  $("save-displayed").disabled = !shown;
  $("save-displayed-note").textContent = shown
    ? `(${shown}${pkt.total != null ? `: ${fmtNum(pkt.total)} packets` : ""})` : "(no filter is applied in the Packets tab)";
  $("save-marked").disabled = !pkt.marks.size;
  $("save-marked-note").textContent = pkt.marks.size ? `(${fmtNum(pkt.marks.size)})` : "(none: mark packets with Ctrl+M)";
  const live = state.session && state.session.mode === "live";
  const total = state.summary && state.summary.engine ? state.summary.engine.packets : null;
  const focused = window.focusInfo && window.focusInfo();
  $("save-all-label").textContent = focused ? "All packets in the focus" : "All packets";
  $("save-all-note").textContent = focused ? `(${fmtNum(focused.count)} ${focused.label})`
    : live ? "(everything recorded so far)" : total ? `(${fmtNum(total)})` : "";
  $("save-selected-row").hidden = !selection;
  $("save-selected-note").textContent = selection ? `(${fmtNum(selection.count)} ${selection.label})` : "";
  const want = selection ? "selected" : preferShown && shown ? "displayed" : "all";
  document.querySelectorAll('input[name="save-scope"]').forEach((r) => { r.checked = r.value === want; });
  $("save-safe").checked = safe;
  $("save-safe-opts").hidden = !safe;
  $("save-safe-done").hidden = true;
  $("save-cancel").textContent = "Cancel";
  $("save-title").textContent = safe ? "Save a share-safe copy" : "Save packets";
  saveKey = null;
  $("save-error").textContent = "";
  $("save-dialog").showModal();
};

$("btn-save").addEventListener("click", () => openSaveDialog(state.view === "packets"));
$("pkt-save").addEventListener("click", () => openSaveDialog(true));
$("save-cancel").addEventListener("click", () => $("save-dialog").close());
$("save-safe").addEventListener("change", () => {
  $("save-safe-opts").hidden = !$("save-safe").checked;
  $("save-title").textContent = $("save-safe").checked ? "Save a share-safe copy" : "Save packets";
});
$("save-safe-key").addEventListener("click", () => { if (saveKey) saveDownload(saveKey); });
$("save-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const picked = document.querySelector('input[name="save-scope"]:checked').value;
  const scope = picked === "selected" ? "all" : picked;
  const body = { scope };
  const focused = window.focusInfo && window.focusInfo();
  if (picked === "selected" && saveSelection) body.selection = saveSelection.id;
  else if (focused) body.selection = focused.id;  // (within a focus, everything saved is within it)
  if (scope === "displayed") {
    if (pkt.alert) body.alert = pkt.alert;
    else if (pkt.filterKind === "bpf") body.bpf = pkt.filter;
    else body.dfilter = pkt.filter;
  }
  if (scope === "marked") body.frames = frameRanges(pkt.marks);
  const safe = $("save-safe").checked;
  if (safe) body.safe = { keep_payload: $("save-safe-keep").checked, shift_time: $("save-safe-time").checked };
  const note = $("save-note"), was = note.textContent;
  $("save-go").disabled = true;
  $("save-error").textContent = "";
  note.textContent = "Writing the packets…";
  try {
    const r = await api("/api/save/packets", "POST", body);
    saveDownload(r);
    const left = r.skipped_link_type ? `; ${fmtNum(r.skipped_link_type)} of another link type left out` : "";
    if (!r.sanitized) {
      $("save-dialog").close();
      notice(`Saving ${fmtNum(r.packets)} packets (${fmtBytes(r.size)}) as ${r.name}${left}.`);
      return;
    }
    // A share-safe copy: say what was done, and offer the key (kept out of the copy).
    const s = r.sanitized, parts = [];
    if (s.ipv4) parts.push(`${fmtNum(s.ipv4)} IPv4`);
    if (s.ipv6) parts.push(`${fmtNum(s.ipv6)} IPv6`);
    if (s.mac) parts.push(`${fmtNum(s.mac)} hardware`);
    const n = s.ipv4 + s.ipv6 + s.mac;
    const replaced = n ? `${parts.join(", ")} address${n === 1 ? "" : "es"} replaced` : "no addresses to replace";
    $("save-safe-summary").textContent = `Saving ${fmtNum(r.packets)} packets as ${r.name}: ${replaced}` +
      (s.keep_payload ? "; what the packets carried is kept" : `; ${fmtBytes(s.bytes_cut)} of packet contents cut`) +
      (s.shift_time ? "; the date hidden" : "") + (s.unsupported ? `; ${fmtNum(s.unsupported)} packets of a link type that can't be made share-safe (such as Wi-Fi) left out` : left) + ".";
    saveKey = r.key;
    $("save-safe-done").hidden = false;
    $("save-cancel").textContent = "Close";
  } catch (err) {
    $("save-error").textContent = err.message;
  } finally {
    $("save-go").disabled = false;
    note.textContent = was;
  }
});

// ------------------------------------------------------------ alerts as CSV

$("alerts-csv").addEventListener("click", async () => {
  const alerts = [...state.alerts.values()].sort(compareAlerts);
  if (!alerts.length) { notice("There are no alerts to export.", true); return; }
  const rows = alerts.map((a) => [a.severity, VERDICT_LABEL[verdictOf(a)], isoTime(a.first_seen), isoTime(a.last_seen),
    a.title, alertSource(a), a.target || "", Math.round(a.confidence * 100), a.updates, a.id, a.headline,
    (a.triage && a.triage.note) || ""]);
  try {
    const r = await saveTextFile(`${captureStem()}_alerts.csv`, "csv", csvText(["Severity", "Verdict", "First seen (UTC)",
      "Last seen (UTC)", "Type", "Source", "Target", "Confidence %", "Updates", "ID", "Summary", "Analyst notes"], rows));
    notice(`Saving ${alerts.length} alerts as ${r.name}.`);
  } catch (err) { notice(err.message, true); }
});

// ------------------------------------------------------------ triage

let triageTimer = null;
window.renderTriage = (a) => {
  const status = verdictOf(a);
  document.querySelectorAll("#triage-status .chip").forEach((c) => {
    const on = c.dataset.status === status;
    c.classList.toggle("active", on);
    c.setAttribute("aria-pressed", String(on));
  });
  const note = $("triage-note");
  if (document.activeElement !== note || note.dataset.alert !== a.id) {
    note.value = (a.triage && a.triage.note) || "";
    note.dataset.alert = a.id;
  }
  $("triage-saved").textContent = a.triage && a.triage.ts ? `Saved ${fmtTime(a.triage.ts)}` : "";
};

async function saveTriage(status) {
  const a = state.detail;
  if (!a) return;
  clearTimeout(triageTimer);
  triageTimer = null;
  try {
    const summary = await api(`/api/alerts/${encodeURIComponent(a.id)}/triage`, "PUT",
      { status: status || verdictOf(a), note: $("triage-note").value });
    a.triage = summary.triage;
    state.alerts.set(a.id, summary);
    renderFeed();
    if (state.detail === a) window.renderTriage(a);
  } catch (err) {
    $("triage-saved").textContent = `Not saved: ${err.message}`;
  }
}

document.querySelectorAll("#triage-status .chip").forEach((chip) => {
  chip.addEventListener("click", () => saveTriage(chip.dataset.status));
});
$("triage-note").addEventListener("input", () => {
  $("triage-saved").textContent = "Editing…";
  clearTimeout(triageTimer);
  triageTimer = setTimeout(() => saveTriage(), 900);
});
$("triage-note").addEventListener("blur", () => { if (triageTimer) saveTriage(); });

// ------------------------------------------------------------ files (Export Objects)

const filesView = { list: null, key: null, proto: "all", programs: false, query: "" };

function filesShown() {
  const q = filesView.query.trim().toLowerCase();
  return (filesView.list || []).filter((o) =>
    (filesView.proto === "all" || o.proto === filesView.proto) && (!filesView.programs || o.program) &&
    (!q || [o.name, o.location, o.sha256, o.client, o.server, o.type].some((v) => String(v || "").toLowerCase().includes(q))));
}

async function filesLoad(force = false) {
  const key = `${sessionKey()}|${state.session ? state.session.state : ""}|${window.focusScope ? window.focusScope() : ""}`;
  if (!force && filesView.list && filesView.key === key) { filesRender(); return; }
  if (!state.session || ["idle", "error"].includes(state.session.state)) {
    filesView.list = null;
    filesRender();
    return;
  }
  $("files-status").textContent = "Reading the capture…";
  const seq = filesView.seq = (filesView.seq || 0) + 1;
  try {
    const list = (await api(withFocus("/api/objects"))).objects;
    if (seq !== filesView.seq) return;  // (a newer load, for another focus or capture, is under way)
    filesView.list = list;
    filesView.key = key;
    $("files-status").textContent = "";
  } catch (err) {
    if (seq !== filesView.seq) return;
    filesView.list = null;
    $("files-status").textContent = err.message;
  }
  filesRender();
}
viewHooks.files = () => filesLoad();

async function saveObject(o, button) {
  if (button) {
    button.disabled = true;
    button.textContent = "Saving…";
  }
  try {
    const r = await api("/api/save/object", "POST", { id: o.id });
    saveDownload(r);
    notice(r.verified ? `Saving ${r.name} (${fmtBytes(r.size)}); its SHA-256 matches the capture's.`
      : `Saving ${r.name} (${fmtBytes(r.size)}). Part of it was not captured, so it is incomplete.`, !r.verified);
  } catch (err) {
    notice(`Could not save ${o.name}: ${err.message}`, true);
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = "Save…";
    }
  }
}

function filesRender() {
  const all = filesView.list;
  const list = filesShown();
  $("files-count").textContent = all ? (list.length === all.length ? String(all.length) : `${list.length} of ${all.length}`) : "";
  $("files-empty").hidden = !!list.length;
  $("files-empty").textContent = !all ? "Open a capture to list the files it carries."
    : all.length ? "No file matches." : "No files were transferred over HTTP, SMB or FTP in this capture.";
  $("files-rows").replaceChildren(...list.map((o) => {
    const tr = el("tr", { dataset: { file: o.id } });
    const type = el("td");
    if (o.program) type.append(el("span", { class: "tag tag-program" }, "Program"), " ");
    type.append(o.type || "–");
    const hash = el("td", { class: "mono hash", title: o.sha256 ? `${o.sha256} (click to copy)` : "", dataset: o.sha256 ? { q: o.sha256 } : {} },
      o.sha256 ? `${o.sha256.slice(0, 16)}…` : "–");
    if (o.sha256) hash.addEventListener("click", () => { copyText(o.sha256); notice("SHA-256 copied."); });
    const act = el("td", { class: "c-act" });
    const btn = el("button", { type: "button", class: "tb small" }, "Save…");
    btn.addEventListener("click", () => saveObject(o, btn));
    act.append(btn);
    tr.append(el("td", { class: "mono" }, fmtTime(o.ts)), el("td", {}, o.proto), el("td", {}, o.direction),
      el("td", { title: o.location }, o.name), type, el("td", { class: "num", title: `${fmtNum(o.size)} bytes` }, fmtBytes(o.size)),
      el("td", { class: "mono" }, o.client), el("td", { class: "mono" }, o.server), hash,
      el("td", { class: o.complete ? "" : "warn" }, o.complete ? "Complete" : "Partial"), act);
    return tr;
  }));
}

document.querySelectorAll("#files-proto .chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    filesView.proto = chip.dataset.proto;
    document.querySelectorAll("#files-proto .chip").forEach((c) => {
      c.classList.toggle("active", c === chip);
      c.setAttribute("aria-pressed", String(c === chip));
    });
    filesRender();
  });
});
$("files-programs").addEventListener("change", (e) => { filesView.programs = e.target.checked; filesRender(); });
$("files-search").addEventListener("input", (e) => { filesView.query = e.target.value; filesRender(); });
$("files-refresh").addEventListener("click", () => filesLoad(true));
$("files-csv").addEventListener("click", async () => {
  const list = filesShown();
  if (!list.length) { notice("There are no files to export.", true); return; }
  try {
    const r = await saveTextFile(`${captureStem()}_files.csv`, "csv", csvText(
      ["Time (UTC)", "Protocol", "Direction", "Name", "Location", "Type", "Size (bytes)", "Client", "Server", "SHA-256", "Complete"],
      list.map((o) => [isoTime(o.ts), o.proto, o.direction, o.name, o.location, o.type, o.size, o.client, o.server,
        o.sha256, o.complete ? "yes" : "no"])));
    notice(`Saving the list of ${list.length} files as ${r.name}.`);
  } catch (err) { notice(err.message, true); }
});

// The Files tab narrowed to a name or hash, and one file's own menu (from the right-click menus).
window.showFiles = (q) => {
  filesView.query = q || "";
  $("files-search").value = filesView.query;
  setView("files");
  filesRender();
};
window.fileById = (id) => (filesView.list || []).find((o) => o.id === id) || null;
window.saveFile = (o) => saveObject(o, null);

// ------------------------------------------------------------ indicator sweep

const huntView = { result: null };

function huntRender() {
  const r = huntView.result;
  const body = $("hunt-body");
  $("hunt-csv").disabled = !r || !r.results.length;
  $("hunt-count").textContent = r ? `${r.matched} of ${r.indicators} found` : "";
  const rejected = $("hunt-rejected");
  rejected.replaceChildren();
  if (r && r.rejected.length) {
    rejected.append(el("h4", {}, `Not understood (${r.rejected.length})`));
    const ul = el("ul", { class: "mono-list" });
    for (const x of r.rejected) ul.append(el("li", {}, `${x.raw}: ${x.reason}`));
    rejected.append(ul);
  }
  if (!r) { body.replaceChildren(el("p", { class: "empty" }, "Paste indicators and sweep the capture.")); return; }
  if (!r.results.length) { body.replaceChildren(el("p", { class: "empty" }, "No indicators were recognised.")); return; }
  body.replaceChildren(...r.results.map((x) => {
    const item = el("details", { class: `hunt-item${x.hits || x.alerts.length ? " hit" : ""}` });
    const sum = el("summary");
    sum.append(el("span", { class: `tag ${x.hits ? "tag-hit" : "tag-miss"}` }, x.hits ? "Found" : x.alerts.length ? "In alerts" : "Not seen"),
      el("span", { class: "mono hunt-ind", title: x.value }, x.indicator),
      el("span", { class: "muted" }, x.kind_text),
      el("span", { class: "num" }, x.hits ? `${fmtNum(x.hits)} session${x.hits === 1 ? "" : "s"}` : "–"),
      el("span", { class: "mono muted" }, x.first ? `${fmtTime(x.first)} – ${fmtTime(x.last)}` : ""));
    item.append(sum);
    const inner = el("div", { class: "hunt-detail" });
    const actions = el("div", { class: "side-actions" });
    if (x.filter && x.hits) {
      const b = el("button", { type: "button", class: "tb small" }, "Show packets");
      b.addEventListener("click", () => { $("hunt-dialog").close(); showPacketsFor(x.filter); });
      actions.append(b);
    }
    for (const a of x.alerts) {
      const b = el("button", { type: "button", class: "link" }, `${a.title} (${a.id})`);
      b.addEventListener("click", () => { $("hunt-dialog").close(); setView("list"); select(a.id); });
      actions.append(b);
    }
    if (actions.childElementCount) inner.append(actions);
    if (x.hosts.length) inner.append(el("p", { class: "small" }, `Hosts involved: ${x.hosts.join(", ")}`));
    if (x.rows.length) {
      const t = el("table", { class: "data-table" });
      const head = el("tr");
      ["Time", "Session", "Where it appears"].forEach((h) => head.append(el("th", {}, h)));
      const thead = el("thead");
      thead.append(head);
      const tb = el("tbody");
      for (const row of x.rows) {
        const tr = el("tr");
        tr.append(el("td", { class: "mono" }, fmtTime(row.ts)), el("td", { class: "mono" }, row.session), el("td", {}, row.where));
        tb.append(tr);
      }
      t.append(thead, tb);
      inner.append(t);
      if (x.hits > x.rows.length) inner.append(el("p", { class: "muted small" }, `First ${x.rows.length} of ${fmtNum(x.hits)} sessions shown.`));
    } else if (!x.alerts.length) {
      inner.append(el("p", { class: "muted small" }, "Not in any session of this capture."));
    }
    item.append(inner);
    return item;
  }));
}

$("hunt-run").addEventListener("click", async () => {
  const text = $("hunt-text").value;
  $("hunt-error").textContent = "";
  if (!text.trim()) { $("hunt-error").textContent = "Paste at least one indicator."; return; }
  $("hunt-run").disabled = true;
  $("hunt-count").textContent = "Sweeping…";
  try {
    huntView.result = await api("/api/hunt", "POST", { text });
  } catch (err) {
    $("hunt-error").textContent = err.message;
    huntView.result = null;
  } finally {
    $("hunt-run").disabled = false;
  }
  huntRender();
});
$("hunt-clear").addEventListener("click", () => { $("hunt-text").value = ""; huntView.result = null; huntRender(); });

// The sweep, as a dialog (Alerts → Sweep indicators…, Analyze → Sweep for indicators…).
window.openHunt = () => {
  const dlg = $("hunt-dialog");
  if (!dlg.open) dlg.showModal();
  $("hunt-text").focus();
};
$("hunt-close").addEventListener("click", () => $("hunt-dialog").close());
$("alerts-sweep").addEventListener("click", () => window.openHunt());

// Sweep the capture for these indicators at once (from the right-click menus).
window.sweepFor = (values) => {
  $("hunt-text").value = values.filter(Boolean).join("\n");
  window.openHunt();
  $("hunt-run").click();
};

// An alert's triage status set from its row's menu, without opening it.
window.setTriage = async (id, status) => {
  try {
    const a = state.alerts.get(id);
    const summary = await api(`/api/alerts/${encodeURIComponent(id)}/triage`, "PUT",
      { status, note: (a && a.triage && a.triage.note) || "" });
    state.alerts.set(id, summary);
    if (state.detail && state.detail.id === id) {
      state.detail.triage = summary.triage;
      window.renderTriage(state.detail);
    }
    renderFeed();
  } catch (err) {
    notice(err.message, true);
  }
};
$("hunt-from-alerts").addEventListener("click", async () => {
  const ids = [...state.alerts.values()].filter((a) => ["critical", "high"].includes(a.severity) && verdictOf(a) !== "false_positive")
    .map((a) => a.id);
  if (!ids.length) { $("hunt-error").textContent = "There are no high or critical alerts to take indicators from."; return; }
  const full = (await Promise.all(ids.map((id) => api(`/api/alerts/${encodeURIComponent(id)}`).catch(() => null)))).filter(Boolean);
  const have = new Set($("hunt-text").value.split(/\s+/).filter(Boolean));
  const add = [];
  const push = (v) => { if (v && !have.has(v)) { have.add(v); add.push(v); } };
  for (const a of full) {
    const x = alertIndicators(a);
    x.ips.forEach((v) => push(v.replace(/:\d+$/, "")));
    x.domains.forEach(push);
    x.urls.forEach((u) => { if (/^https?:\/\//i.test(u)) push(u); });
    x.files.forEach((f) => push(f.sha256));
    (a.addresses || []).forEach(push);
  }
  const box = $("hunt-text");
  box.value = (box.value.trim() ? `${box.value.trim()}\n` : "") + add.join("\n");
  $("hunt-error").textContent = add.length ? "" : "The alerts' indicators are already in the list.";
});
$("hunt-csv").addEventListener("click", async () => {
  const r = huntView.result;
  if (!r) return;
  const rows = [];
  for (const x of r.results) {
    if (!x.rows.length) rows.push([x.indicator, x.kind_text, x.hits, "", "", "", x.alerts.map((a) => a.id).join(" ")]);
    for (const row of x.rows) rows.push([x.indicator, x.kind_text, x.hits, isoTime(row.ts), row.session, row.where,
      x.alerts.map((a) => a.id).join(" ")]);
  }
  try {
    const saved = await saveTextFile(`${captureStem()}_indicator_sweep.csv`, "csv", csvText(
      ["Indicator", "Type", "Sessions", "Time (UTC)", "Session", "Where it appears", "Related alerts"], rows));
    notice(`Saving the sweep results as ${saved.name}.`);
  } catch (err) { notice(err.message, true); }
});
