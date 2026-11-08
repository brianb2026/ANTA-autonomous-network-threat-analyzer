// What to look at first: with no alert open, the detail pane lists up to five findings,
// worst first, each with why it matters and a button for the next step (anta/triage.py).
// Network-derived text is rendered with textContent only.
"use strict";

const firstState = { key: "", data: null, seq: 0, timer: null };

function firstKey() {
  return `${sessionKey()}|${window.focusScope ? window.focusScope() : ""}|${state.alerts.size}|` +
    [...state.alerts.values()].map((a) => `${a.id}:${verdictOf(a)}`).join(",");
}

window.firstLook = async (force = false) => {
  const key = firstKey();
  if (!force && firstState.key === key && firstState.data) { firstRender(); return; }
  const seq = ++firstState.seq;
  firstState.key = key;
  if (!firstState.data) $("first-list").replaceChildren(el("li", { class: "muted" }, "Looking through the capture…"));
  try {
    const d = await api(withFocus(`/api/triage?tz=${new Date().getTimezoneOffset()}`));
    if (seq !== firstState.seq) return;
    firstState.data = d;
  } catch (err) {
    if (seq === firstState.seq) $("first-list").replaceChildren(el("li", { class: "error" }, err.message));
    return;
  }
  firstRender();
};

// Alerts keep arriving during a capture: read the list again at most every 3 s while it shows.
window.firstLookChanged = () => {
  if (firstState.timer || state.selected || $("placeholder").hidden) return;
  firstState.timer = setTimeout(() => { firstState.timer = null; if (!state.selected) window.firstLook(); }, 3000);
};

window.showFirstLook = () => {
  setView("alerts");
  state.selected = null;
  state.detail = null;
  document.querySelectorAll(".alert-row.selected").forEach((tr) => { tr.classList.remove("selected"); tr.setAttribute("aria-selected", "false"); });
  renderDetail();
  window.firstLook(true);
  $("first-look-title").focus?.();
};

const FIRST_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Worth a glance" };

function firstAction(a) {
  switch (a.do) {
    case "alert": setView("list"); select(a.id); break;
    case "host": window.openHost(a.addr); break;
    case "stats": statsTool(a.tool, a.filter || ""); break;
    case "files":
      window.showFiles("");
      if (a.programs && !$("files-programs").checked) $("files-programs").click();
      break;
    case "packets": showPacketsFor(a.filter); break;
    case "ask": window.focusCommand(a.q || ""); break;
    case "policy": window.openPolicy(); break;
    case "personalities": window.openPersonalities(); break;
    default: break;
  }
}

function firstRender() {
  const list = $("first-list");
  const d = firstState.data;
  if (!d) return;
  if (!d.items.length) {
    list.replaceChildren(el("li", { class: "first-none" }, state.session && state.session.state === "running"
      ? "Nothing stands out so far; this list fills in as the capture is read."
      : "Nothing stands out: no serious alert, no password sent in clear text, no program downloaded, no large upload to the internet. The command bar answers questions such as \"who talked the most?\"."));
    return;
  }
  list.replaceChildren(...d.items.map((it) => {
    const li = el("li", { class: `first-item sev-border-${it.severity === "info" ? "low" : it.severity}` });
    const head = el("div", { class: "first-head" });
    head.append(el("span", { class: `sev sev-${it.severity === "info" ? "low" : it.severity}` }, FIRST_LABEL[it.severity] || it.severity),
      el("strong", { class: "first-title" }, it.title));
    li.append(head);
    if (it.why) li.append(el("p", { class: "first-why" }, it.why));
    const acts = el("div", { class: "first-actions" });
    it.actions.forEach((a, i) => {
      const b = el("button", { type: "button", class: `tb small${i === 0 ? " tb-primary" : ""}` }, a.label);
      b.addEventListener("click", () => firstAction(a));
      acts.append(b);
    });
    li.append(acts);
    return li;
  }));
}

// "What to look at first" from an open alert: a button in the detail pane's title bar.
{
  const head = document.querySelector('#view-alerts .detail-col .pane-head');
  const b = el("button", { type: "button", class: "tb small first-back", title: "Close the alert and list what to look at first" }, "What to look at first");
  b.addEventListener("click", () => window.showFirstLook());
  head.querySelector("h2").after(b);
}
$("first-look-title").tabIndex = -1;
// (the capture's first message can arrive before this script has loaded: show the list now if it is due)
if (!state.selected && !$("placeholder").hidden && !$("ph-select").hidden && sessionActive()) window.firstLook();
