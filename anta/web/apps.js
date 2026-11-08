// Statistics → Applications: the capture's connections grouped into the applications people
// recognise (anta/apps.py), by data, with which devices used each and how the traffic splits
// by kind (video calls, streaming, updates…); and one device's applications.
// Everything from the network is rendered with textContent only.
"use strict";

const appsView = { device: "" };

TOOLS.apps = (box) => {
  const rx = RX;
  const slot = invGet("apps", "/api/apps");
  if (invPending(box, slot, "the applications")) return;
  const d = slot.data;
  box.append(el("p", { class: "tool-note" }, "Each connection named after the application it belongs to, from what the capture "
    + "says about its server (the TLS server name, the HTTP Host, or a name a DNS answer gave its address), or else from its "
    + "protocol. Click an application for its packets or the devices that used it."));
  if (!d.apps.length) { box.append(el("p", { class: "empty" }, "No connections in these packets.")); return; }
  const top = d.apps[0];
  tiles(box, [["Applications", fmtNum(d.apps.length)], ["Data", fmtBytes(d.total), "sent and received"],
    ["Most data", top.app, `${fmtBytes(top.bytes)} · ${fmtNum(top.devices)} device${top.devices === 1 ? "" : "s"}`]]);

  section(box, "By kind", "share of all the data");
  const bars = el("div", { class: "app-bars" });
  for (const c of d.categories.slice(0, 12)) {
    const share = d.total ? c.bytes / d.total : 0;
    const row = el("div", { class: "app-bar-row", title: `${c.category}: ${fmtBytes(c.bytes)} in ${fmtNum(c.sessions)} connections` });
    const bar = el("div", { class: "app-bar" });
    const fill = el("div", { class: "app-bar-fill" });
    fill.style.width = `${Math.max(0.5, share * 100).toFixed(1)}%`;
    bar.append(fill);
    row.append(el("span", { class: "app-bar-label" }, c.category), bar,
      el("span", { class: "num app-bar-value" }, `${fmtBytes(c.bytes)} · ${(share * 100).toFixed(share < 0.01 ? 1 : 0)}%`));
    bars.append(row);
  }
  box.append(bars);

  section(box, "Applications", "click a row for its packets and devices");
  dataTable(box, "apps", [
    { label: "Application", type: "text", get: (r) => r.app },
    { label: "Kind", type: "text", get: (r) => r.category },
    { label: "Data", type: "bytes", get: (r) => r.bytes },
    { label: "Sent", type: "bytes", get: (r) => r.up },
    { label: "Received", type: "bytes", get: (r) => r.down },
    { label: "Devices", type: "num", get: (r) => r.devices },
    { label: "Connections", type: "num", get: (r) => r.sessions },
    { label: "Seen as", type: "text", get: (r) => r.names.join(", ") },
  ], d.apps, { onRow: (e, r) => showMenu(e.clientX, e.clientY, [
    { caption: r.app, kind: r.category },
    r.filter ? { label: "Show its packets", hint: "its servers' addresses", action: () => showPacketsFor(r.filter) } : null,
    { label: "Devices that used it", submenu: r.top_devices.map((ip) => ({ label: ip, hint: "host details", action: () => window.openHost(ip) })) },
    { label: "Ask who uses it", action: () => window.focusCommand(`who uses ${r.app}`) },
    r.filter ? { separator: true } : null,
    r.filter ? { label: "Copy as filter", action: () => copyText(r.filter) } : null,
  ]) });

  section(box, "One device", "the applications it used");
  const devices = Object.keys(d.devices).sort((a, b) =>
    d.devices[b].reduce((s, x) => s + x.up + x.down, 0) - d.devices[a].reduce((s, x) => s + x.up + x.down, 0));
  const m = /^(?:ipv6|ip)\.addr == (\S+)$/.exec(stats.filter || "");
  if (m && d.devices[m[1]]) appsView.device = m[1];  // (opened from a question about one device)
  if (!d.devices[appsView.device]) appsView.device = devices[0] || "";
  const pick = el("select", { class: "tb small", "aria-label": "Device" });
  for (const ip of devices) {
    const o = el("option", { value: ip }, ip);
    if (ip === appsView.device) o.selected = true;
    pick.append(o);
  }
  pick.addEventListener("change", () => { appsView.device = pick.value; rx.rerender(); });
  const details = el("button", { type: "button", class: "tb small" }, "Host details");
  details.addEventListener("click", () => window.openHost(appsView.device));
  const bar = el("div", { class: "rhythm-bar" });
  bar.append(pick, details);
  box.append(bar);
  const rows = d.devices[appsView.device] || [];
  dataTable(box, "apps-device", [
    { label: "Application", type: "text", get: (r) => r.app },
    { label: "Kind", type: "text", get: (r) => r.category },
    { label: "Sent", type: "bytes", get: (r) => r.up },
    { label: "Received", type: "bytes", get: (r) => r.down },
    { label: "Connections", type: "num", get: (r) => r.sessions },
  ], rows, { searchable: false, defaultSort: { col: 3, dir: -1 } });
};
