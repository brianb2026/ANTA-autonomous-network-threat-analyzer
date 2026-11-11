// Statistics → Devices that changed address: one device followed across its IP addresses and
// network cards (MACs), from what it says about itself on this network (anta/moves.py): its MAC,
// the host name it gives DHCP, mDNS or Windows naming, and its DHCP request. Also the addresses
// that changed hands between different devices. Everything from the network is rendered with
// textContent only.
"use strict";

function mvTime(t) {
  return new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function mvMenu(e, dv) {
  const ips = [...new Set(dv.addresses.map((a) => a.ip))];
  showMenu(e.clientX, e.clientY, [
    { caption: dv.label, kind: dv.verdict },
    { label: "Show its packets", hint: "every network card it used", action: () => RX.showPackets(dv.filter) },
    ...ips.slice(0, 6).map((ip) => ({ label: `Host details: ${ip}`, action: () => window.openHost(ip) })),
    { separator: true },
    { label: "Copy as filter", action: () => copyText(dv.filter) },
    { label: "Copy its addresses", action: () => copyText([...dv.macs.map((m) => m.mac), ...ips, ...dv.v6].join("\n")) },
  ]);
}

// One row per address, a bar for when it was used, shaded by network card (MAC).
function mvTimeline(box, rows, start, end) {
  if (!rows.length || !(end > start)) return;
  const W = 640, L = 128, R = 12, ROW = 18, H = rows.length * ROW + 22;
  const x = (t) => L + (W - L - R) * Math.min(1, Math.max(0, (t - start) / (end - start)));
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("class", "mv-strip");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "When each address was used, over the capture");
  const mk = (tag, attrs, text) => {
    const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (text != null) n.textContent = text;
    svg.append(n);
    return n;
  };
  const macs = [...new Set(rows.map((r) => r.mac))];
  rows.forEach((r, i) => {
    const y = 4 + i * ROW;
    mk("text", { x: L - 8, y: y + 11, class: "mv-ip", "text-anchor": "end" }, r.ip);
    mk("rect", { x: L, y: y + 2, width: W - L - R, height: ROW - 6, class: "mv-lane" });
    const bar = mk("rect", { x: x(r.first), y: y + 2, width: Math.max(3, x(r.last) - x(r.first)), height: ROW - 6, rx: 2,
      class: `mv-bar mv-mac${macs.indexOf(r.mac) % 4}` });
    bar.append(Object.assign(document.createElementNS("http://www.w3.org/2000/svg", "title"),
      { textContent: `${r.ip}${r.mac ? ` from ${r.mac}` : ""}: ${mvTime(r.first)} to ${mvTime(r.last)}` }));
  });
  const yb = rows.length * ROW + 14;
  mk("text", { x: L, y: yb, class: "mv-tick" }, mvTime(start));
  mk("text", { x: W - R, y: yb, class: "mv-tick", "text-anchor": "end" }, mvTime(end));
  box.append(svg);
}

function mvCard(box, d, dv) {
  const card = el("article", { class: "lint-item mv-item" });
  const top = el("div", { class: "lint-top" });
  const name = el("button", { type: "button", class: "link", title: "What to do with this device" }, dv.label);
  name.addEventListener("click", (e) => mvMenu(e, dv));
  top.append(name, el("span", { class: `sev ${dv.verdict === "Same device" ? "sev-low" : "sev-medium"}` }, dv.verdict),
    el("span", { class: "lint-count muted small" }, `${mvTime(dv.first)} to ${mvTime(dv.last)}`));
  card.append(top);
  const cards = el("p", { class: "small" });
  cards.append(document.createTextNode(dv.macs.length > 1 ? "Network cards: " : "Network card: "));
  dv.macs.forEach((m, i) => {
    if (i) cards.append(document.createTextNode(", "));
    cards.append(el("code", {}, m.mac), document.createTextNode(m.randomised ? " (private address)" : m.vendor ? ` (${m.vendor})` : ""));
  });
  card.append(cards);
  mvTimeline(card, dv.addresses, d.start ?? dv.first, d.end ?? dv.last);
  if (dv.changes.length) {
    const ul = el("ul", { class: "small mv-changes" });
    for (const c of dv.changes) {
      const li = el("li");
      li.append(el("span", { class: "mono" }, mvTime(c.at)), document.createTextNode(": "),
        el("code", {}, c.from_ip), document.createTextNode(" → "), el("code", {}, c.to_ip),
        document.createTextNode(`, ${c.how}`));
      ul.append(li);
    }
    card.append(ul);
  }
  if (dv.v6.length) card.append(el("p", { class: "small muted" }, `Also IPv6: ${dv.v6.join(", ")}`));
  const why = el("p", { class: "small" });
  why.append(el("span", { class: "lint-label" }, "Why it's one device: "), document.createTextNode(dv.why.join("; ")));
  card.append(why);
  const acts = el("div", { class: "lint-acts" });
  const b = el("button", { type: "button", class: "tb small" }, "Show its packets");
  b.addEventListener("click", () => RX.showPackets(dv.filter));
  acts.append(b);
  card.append(acts);
  box.append(card);
}

TOOLS.moves = (box) => {
  const slot = invGet("moves", "/api/moves");
  if (invPending(box, slot, "how each device's addresses changed")) return;
  const d = slot.data;
  const t = d.totals;
  box.append(el("p", { class: "tool-note" }, "One device followed when its address changes: DHCP giving it a new IP address, or "
    + "a phone or laptop switching to a new private Wi-Fi address (MAC). It goes by what each device says about itself on this "
    + "network: its network card, the name it gives DHCP, mDNS or Windows naming, and the shape of its DHCP request. It also "
    + "shows addresses that passed from one device to another, so what happened on them isn't blamed on the wrong machine."));
  tiles(box, [["Devices", fmtNum(t.devices), `${d.names.join(", ")}${d.scoped ? " · within the focused packets" : ""}`],
    ["Changed address", fmtNum(t.moved), `${fmtNum(t.new_ip)} new IP · ${fmtNum(t.new_mac)} new MAC`],
    ["Addresses that changed hands", fmtNum(t.handovers), "one address, different devices"],
    ["Private Wi-Fi addresses", fmtNum(t.randomised), "MACs a device made up"]]);
  const moved = d.devices.filter((x) => x.kind === "moved");
  const two = d.devices.filter((x) => x.kind === "two-connections");
  const several = d.devices.filter((x) => x.kind === "several");
  if (!moved.length && !d.handovers.length && !two.length) {
    box.append(el("p", { class: "empty" }, "No device changed address here, and no address passed between devices. "
      + "Devices are only followed on the network segment the capture was taken on."));
  }
  if (moved.length) {
    section(box, `Changed address (${fmtNum(moved.length)})`, "each device's addresses over the capture; click its name for more");
    for (const dv of moved.slice(0, 60)) mvCard(box, d, dv);
  }
  if (d.handovers.length) {
    section(box, `Addresses that changed hands (${fmtNum(d.handovers.length)})`, "one address used by different devices");
    for (const h of d.handovers.slice(0, 60)) {
      const card = el("article", { class: "lint-item mv-item" });
      const top = el("div", { class: "lint-top" });
      const ip = el("button", { type: "button", class: "link mono", title: "Host details" }, h.ip);
      ip.addEventListener("click", () => window.openHost(h.ip));
      top.append(ip, el("span", { class: `sev ${h.at_once ? "sev-high" : "sev-low"}` }, h.at_once ? "at the same time" : "one after another"));
      card.append(top);
      const ul = el("ul", { class: "small mv-changes" });
      for (const x of h.holders) {
        const li = el("li");
        li.append(el("strong", {}, x.label), document.createTextNode(" ("), el("code", {}, x.macs.join(", ")),
          document.createTextNode(`) from ${mvTime(x.first)} to ${mvTime(x.last)}`));
        ul.append(li);
      }
      card.append(ul, el("p", { class: "small" }, h.why));
      const acts = el("div", { class: "lint-acts" });
      const b = el("button", { type: "button", class: "tb small" }, "Show its packets");
      b.addEventListener("click", () => RX.showPackets(h.filter));
      acts.append(b);
      for (const x of h.holders) {
        const one = el("button", { type: "button", class: "tb small" }, `Only ${x.label}`);
        one.addEventListener("click", () => RX.showPackets(`(${h.filter}) && (${x.macs.map((m) => `eth.addr == ${m}`).join(" || ")})`));
        acts.append(one);
      }
      card.append(acts);
      box.append(card);
    }
  }
  if (two.length) {
    section(box, `One machine, two connections (${fmtNum(two.length)})`, "one name on two network cards at the same time");
    for (const dv of two.slice(0, 40)) mvCard(box, d, dv);
  }
  if (d.conflicts.length) {
    section(box, "Kept apart", "the same name, but not the same device");
    const ul = el("ul", { class: "small" });
    for (const c of d.conflicts) {
      const li = el("li");
      li.append(el("code", {}, c.macs.join(" and ")), document.createTextNode(`: ${c.why}`));
      ul.append(li);
    }
    box.append(ul);
  }
  if (several.length) {
    section(box, "Several addresses at once", "one network card with IPv4 and IPv6, or more than one IPv4 address");
    dataTable(box, "moves-several", [
      { label: "Device", type: "text", get: (r) => r.label },
      { label: "Network card", type: "text", get: (r) => r.macs.map((m) => m.mac).join(", ") },
      { label: "IPv4", type: "text", get: (r) => [...new Set(r.addresses.map((a) => a.ip))].join(", ") || "—" },
      { label: "IPv6", type: "text", get: (r) => r.v6.join(", ") || "—" },
    ], several, { onRow: (e, r) => mvMenu(e, r), defaultSort: { col: 0, dir: 1 } });
  }
  const notes = el("details", { class: "lint-passed" });
  notes.append(el("summary", {}, "How sure is this?"));
  const ul = el("ul", { class: "small" });
  for (const n of d.notes) ul.append(el("li", {}, n));
  if (d.routers.length) ul.append(el("li", {}, `Not followed: ${d.routers.join(", ")}, which carr${d.routers.length === 1 ? "ies" : "y"} other machines' traffic (a router).`));
  notes.append(ul);
  box.append(notes);
};
