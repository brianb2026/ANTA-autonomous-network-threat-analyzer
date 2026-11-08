// Device personalities and drift: each device in one sentence, and (once remembered as normal)
// what each does differently in this capture (anta/personality.py). The changes worth a look
// come first; each opens the packets that show it.
// Everything from the network is rendered with textContent only.
"use strict";

window.openPersonalities = async () => {
  const dlg = $("persona-dialog");
  $("persona-error").textContent = "";
  $("persona-list").replaceChildren(el("p", { class: "muted" }, sessionActive() ? "Reading the devices…" : "Open a capture first."));
  if (!dlg.open) dlg.showModal();
  if (!sessionActive()) return;
  try {
    personaRender(await api("/api/personalities"));
  } catch (err) {
    $("persona-error").textContent = err.message;
  }
};

function personaRender(d) {
  const r = d.remembered;
  $("persona-sub").textContent = r
    ? `Compared with what you remembered as normal from ${r.capture} (${new Date(r.saved).toLocaleString()}, ${fmtNum(r.devices)} devices). `
      + "Remember these as normal to make this capture the new normal."
    : "Each device on the network in one sentence. Remember them as normal, and later captures show what each device does differently.";
  $("persona-forget").disabled = !r;
  const list = $("persona-list");
  const devices = [...d.devices].sort((a, b) => (b.malicious - a.malicious) || b.notable - a.notable ||
    b.changes.length - a.changes.length);
  const changed = devices.filter((x) => x.changes.length).length;
  const bad = devices.filter((x) => x.malicious).length;
  const parts = [];
  if (bad) {
    parts.push(el("p", { class: "persona-sum persona-bad-sum" }, `⚠ ${bad} device${bad === 1 ? " is" : "s are"} in serious alerts ` +
      "(high or critical, not marked as false positives): shown in red at the top."));
  }
  if (r) {
    parts.push(el("p", { class: "persona-sum" }, changed ? `${changed} of ${devices.length} devices behave differently` +
      `${d.missing.length ? `; ${d.missing.length} remembered device${d.missing.length === 1 ? " wasn't" : "s weren't"} seen` : ""}.`
      : `Every device behaves as remembered${d.missing.length ? `; ${d.missing.length} remembered device(s) weren't seen` : ""}.`));
  }
  for (const x of devices) {
    const card = el("article", { class: `persona-card${x.notable ? " notable" : ""}${x.malicious ? " malicious" : ""}` });
    const head = el("div", { class: "persona-head" });
    if (x.malicious) head.append(el("span", { class: "persona-flag", title: "In serious alerts" }, "⚠ Malicious activity"));
    const who = el("button", { type: "button", class: "addr-link mono", title: `${x.ip}: host details` }, x.ip);
    who.addEventListener("click", () => { $("persona-dialog").close(); window.openHost(x.ip); });
    head.append(who);
    if (x.name) head.append(el("span", { class: "muted" }, ` ${x.name}`));
    if (x.changes.length) head.append(el("span", { class: `persona-badge${x.notable ? " notable" : ""}` },
      `${x.changes.length} change${x.changes.length === 1 ? "" : "s"}`));
    card.append(head, el("p", { class: "persona-sentence" }, x.sentence));
    if (x.alerts && x.alerts.length) {
      const row = el("div", { class: "persona-alerts" });
      for (const a of x.alerts) {
        const b = el("button", { type: "button", class: "persona-alert", title: "Open this alert" });
        b.append(el("span", { class: `sev sev-${a.severity}` }, SEV_LABEL[a.severity] || a.severity), document.createTextNode(` ${a.title}`));
        b.addEventListener("click", () => { $("persona-dialog").close(); setView("list"); select(a.id); });
        row.append(b);
      }
      card.append(row);
    }
    if (x.apps.length) card.append(el("p", { class: "muted small" }, `Applications: ${x.apps.join(", ")}`));
    for (const c of x.changes) {
      const line = el("p", { class: `small persona-change${c.notable ? " notable" : ""}` });
      line.append(el("span", { "aria-hidden": "true" }, c.notable ? "▲ " : "· "), document.createTextNode(c.what));
      if (c.filter) {
        const b = el("button", { type: "button", class: "link" }, "show");
        b.addEventListener("click", () => { $("persona-dialog").close(); showPacketsFor(c.filter); });
        line.append(" ", b);
      }
      card.append(line);
    }
    parts.push(card);
  }
  if (d.missing.length) {
    const miss = el("details", { class: "persona-missing" });
    miss.append(el("summary", {}, `Remembered but not seen this time (${d.missing.length})`));
    const ul = el("ul", { class: "small" });
    for (const m of d.missing.slice(0, 50)) ul.append(el("li", {}, [m.ip, m.name, m.device].filter(Boolean).join(" · ")));
    miss.append(ul);
    parts.push(miss);
  }
  if (!devices.length) parts.push(el("p", { class: "muted" }, "No local devices in this capture."));
  list.replaceChildren(...parts);
}

$("persona-remember").addEventListener("click", async () => {
  try {
    personaRender(await api("/api/personalities/remember", "POST", {}));
    notice("Remembered these devices as normal: later captures are compared with them.");
    if (window.firstLook && !state.selected) window.firstLook(true);
  } catch (err) {
    $("persona-error").textContent = err.message;
  }
});
$("persona-forget").addEventListener("click", async () => {
  if (!window.confirm("Forget the devices remembered as normal? Later captures won't be compared with them.")) return;
  try {
    personaRender(await api("/api/personalities", "DELETE"));
  } catch (err) {
    $("persona-error").textContent = err.message;
  }
});
$("persona-close").addEventListener("click", () => $("persona-dialog").close());

// The Hosts tab's way in: a button beside its search.
{
  const b = el("button", { type: "button", class: "tb", title: "Each device in one sentence, and what changed since you remembered them as normal" },
    "Personalities…");
  b.addEventListener("click", () => window.openPersonalities());
  $("assets-csv").before(b);
}
