// Statistics → Installed software: the programs and versions each device runs, read from what
// its own traffic says about itself (User-Agents, update checks, Server headers, SSH and mail
// greetings; anta/software.py), each judged against an end-of-support table. Nothing is sent
// to the devices. Everything from the network is rendered with textContent only.
"use strict";

const SW_SEV = { vulnerable: "sev-critical", unsupported: "sev-high", ending: "sev-medium", old: "sev-medium", check: "sev-low" };
const SW_BAD = new Set(["vulnerable", "unsupported", "ending", "old"]);
const swView = { internet: false };

function swBadge(r) {
  return el("span", { class: `sev ${SW_SEV[r.status] || "sev-low"}`, title: r.why || "" }, r.status_text);
}

function swMenu(e, host, r) {
  showMenu(e.clientX, e.clientY, [
    { caption: `${r.name}${r.version ? ` ${r.version}` : ""}`, kind: host.ip },
    { label: "Show the packets that say so", hint: r.filter, action: () => RX.showPackets(r.filter) },
    { label: "Host details", action: () => window.openHost(host.ip) },
    { separator: true },
    { label: "Copy as filter", action: () => copyText(r.filter) },
    { label: "Copy what it said", action: () => copyText(r.evidence) },
  ]);
}

TOOLS.software = (box) => {
  const slot = invGet("software", "/api/software");
  if (invPending(box, slot, "what each device's traffic says about its software")) return;
  const d = slot.data;
  box.append(el("p", { class: "tool-note" }, "The programs and versions each device runs, read from what its own traffic says "
    + "about itself: browsers' and tools' User-Agents, update checks, web servers' Server headers, and SSH, FTP and mail "
    + "greetings. Each is held against a table of end-of-support dates and well-known flawed versions. Nothing is installed "
    + "on the devices or sent to them."));
  const t = d.totals || {};
  const one = /^(?:ipv6|ip)\.addr == (\S+)$/.exec(stats.filter || "");  // (opened from one device's panel)
  const hosts = d.hosts.filter((h) => (one ? h.ip === one[1] : h.local || swView.internet));
  tiles(box, [
    ["Devices", fmtNum(d.local_hosts), "on this network, with software seen"],
    ["Known flaws", fmtNum(t.vulnerable || 0), t.vulnerable ? "fix these first" : "none seen"],
    ["No longer supported", fmtNum(t.unsupported || 0), "no more security fixes"],
    ["Out of date or ending", fmtNum((t.old || 0) + (t.ending || 0)), "update soon"],
    ["To check", fmtNum(t.check || 0), "the version alone can't tell"],
  ]);
  const opts = el("label", { class: "inline small" });
  const cb = el("input", { type: "checkbox" });
  cb.checked = swView.internet;
  cb.addEventListener("change", () => { swView.internet = cb.checked; RX.rerender(); });
  opts.append(cb, document.createTextNode(" Also show servers on the internet (what they run, not your devices)"));
  box.append(opts);
  if (one) box.append(el("p", { class: "muted small" }, `Only ${one[1]}; clear the filter above for every device.`));
  if (!hosts.length) {
    box.append(el("p", { class: "empty" }, d.hosts.length ? "No device on this network said what software it runs; "
      + "tick the box above for the internet servers." : "No traffic here says what software it comes from. Encrypted "
      + "connections hide their User-Agents unless you decrypt them with your own key log."));
  }

  const attention = hosts.filter((h) => h.software.some((r) => SW_BAD.has(r.status)));
  if (attention.length) section(box, "Needs attention", "the worst first; click a line for the packets that say so");
  for (const h of attention) {
    const card = el("article", { class: "sw-host" });
    const top = el("div", { class: "sw-top" });
    const ip = el("button", { type: "button", class: "link mono", title: "Host details" }, h.ip);
    ip.addEventListener("click", () => window.openHost(h.ip));
    top.append(ip, el("span", { class: "muted small" }, h.local ? "" : `(${h.scope})`));
    card.append(top);
    for (const r of h.software.filter((x) => SW_BAD.has(x.status) || x.status === "check")) {
      const row = el("div", { class: "sw-line", tabindex: "0", role: "button" });
      const what = el("div", { class: "sw-what" });
      what.append(swBadge(r), el("strong", {}, ` ${r.name}${r.version ? ` ${r.version}` : ""}`),
        el("span", { class: "muted small" }, ` · ${r.role === "serves" ? "a service it offers" : r.kind}`));
      row.append(what, el("p", { class: "small" }, r.why));
      if (r.advice) {
        const adv = el("p", { class: "small" });
        adv.append(el("span", { class: "lint-label" }, "What to do: "), document.createTextNode(r.advice));
        row.append(adv);
      }
      const seen = el("p", { class: "small muted" });
      seen.append(document.createTextNode("Seen as "), el("code", {}, r.evidence),
        document.createTextNode(` in ${fmtNum(r.count)} connection${r.count === 1 ? "" : "s"}`));
      row.append(seen);
      row.addEventListener("click", (e) => swMenu(e, h, r));
      row.addEventListener("keydown", (e) => { if (e.key === "Enter") { const b = row.getBoundingClientRect(); swMenu({ clientX: b.left + 16, clientY: b.bottom }, h, r); } });
      card.append(row);
    }
    box.append(card);
  }

  section(box, "Everything seen", "every program each device reported; click a row for its packets");
  const rows = [];
  for (const h of hosts) for (const r of h.software) rows.push({ ...r, host: h });
  dataTable(box, "software", [
    { label: "Device", type: "text", get: (r) => r.host.ip },
    { label: "Software", type: "text", get: (r) => r.name },
    { label: "Version", type: "text", get: (r) => r.version || "—" },
    { label: "Kind", type: "text", get: (r) => (r.role === "serves" ? "service" : r.kind) },
    { label: "Status", type: "text", get: (r) => r.status_text },
    { label: "Why", type: "text", get: (r) => r.why },
    { label: "Seen as", type: "text", get: (r) => r.evidence },
    { label: "Connections", type: "num", get: (r) => r.count },
  ], rows, { onRow: (e, r) => swMenu(e, r.host, r), defaultSort: { col: 0, dir: 1 } });

  const notes = el("details", { class: "lint-passed" });
  notes.append(el("summary", {}, "How sure is this?"));
  const ul = el("ul", { class: "small" });
  for (const n of d.notes) ul.append(el("li", {}, n));
  notes.append(ul);
  box.append(notes);
};

