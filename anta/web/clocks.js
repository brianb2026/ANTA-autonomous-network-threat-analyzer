// Statistics → Machines behind addresses: several machines answering from one address (devices
// hidden behind a router), and one machine answering from several (anta/clocks.py), from the
// clocks their TCP timestamps read. Everything from the network is rendered with textContent only.
"use strict";

const clockView = { all: false };

function clockMenu(e, a) {
  showMenu(e.clientX, e.clientY, [
    { caption: a.ip, kind: a.verdict },
    a.filter ? { label: "Show its timestamped packets", hint: a.filter, action: () => RX.showPackets(a.filter) } : null,
    { label: "Host details", action: () => window.openHost(a.ip) },
    { separator: true },
    { label: "Copy", action: () => copyText(`${a.ip}: ${a.verdict}. ${a.why}`) },
  ]);
}

TOOLS.clocks = (box) => {
  const slot = invGet("clocks", "/api/clocks");
  if (invPending(box, slot, "each address's clock")) return;
  const d = slot.data;
  box.append(el("p", { class: "tool-note" }, "Every machine keeps its own clock, and TCP timestamps are readings of it: the rate it "
    + "ticks at and the moment it started are its own. One address showing several clocks has several machines behind it (a "
    + "router or travel router with devices behind it); several addresses showing one clock are one machine. Systems that hide "
    + "their clock's starting point are recognised and said so."));
  if (d.capture_note) box.append(el("p", { class: "seal-verdict seal-edited small" }, d.capture_note));
  const local = d.addresses.filter((a) => a.local);
  tiles(box, [["Addresses timed", fmtNum(d.addresses.length), `${fmtNum(local.length)} on this network`],
    ["Several machines behind one", fmtNum(d.behind.length), d.behind.length ? "see below" : "none found"],
    ["One machine, several addresses", fmtNum(d.shared.length), d.shared.length ? "see below" : "none found"],
    ["Can't be counted", fmtNum(d.hidden + (d.unsteady || 0)), "clocks hidden or unsteady"]]);
  if (!d.addresses.length) {
    box.append(el("p", { class: "empty" }, "No connection here carries TCP timestamps (Windows usually sends none), so there are no "
      + "clocks to read."));
    return;
  }

  if (d.behind.length) {
    section(box, "Several machines behind one address", "a router, travel router or shared connection with devices behind it");
    for (const a of d.behind) {
      const card = el("article", { class: "lint-item seal-fail" });
      const top = el("div", { class: "lint-top" });
      const b = el("button", { type: "button", class: "link mono" }, a.ip);
      b.addEventListener("click", (e) => clockMenu(e, a));
      top.append(b, el("strong", {}, a.verdict), el("span", { class: "muted small" }, a.local ? "on this network" : a.scope));
      card.append(top, el("p", { class: "small" }, a.why));
      const ul = el("ul", { class: "small" });
      for (const c of a.clocks) {
        ul.append(el("li", {}, `A clock ticking ${c.rate}/s on ${fmtNum(c.connections)} connection${c.connections === 1 ? "" : "s"}`
          + (c.peers.length ? ` (with ${c.peers.slice(0, 4).join(", ")}${c.peers.length > 4 ? "…" : ""})` : "")));
      }
      card.append(ul);
      box.append(card);
    }
  }
  if (d.shared.length) {
    section(box, "One machine, several addresses", "addresses whose clocks are the same clock");
    for (const g of d.shared) {
      const card = el("article", { class: "lint-item" });
      const top = el("div", { class: "lint-top" });
      top.append(el("strong", {}, `${g.addresses.length} addresses, one machine`));
      for (const ip of g.addresses) {
        const b = el("button", { type: "button", class: "link mono" }, ip);
        b.addEventListener("click", () => window.openHost(ip));
        top.append(b);
      }
      const show = el("button", { type: "button", class: "tb small" }, "Show their packets");
      show.addEventListener("click", () => RX.showPackets(g.filter));
      card.append(top, el("p", { class: "small" }, `${g.why} Seen on ${fmtNum(g.connections)} connections.`), show);
      box.append(card);
    }
  }

  section(box, "Each address", "click a row for its packets");
  const opts = el("label", { class: "inline small" });
  const cb = el("input", { type: "checkbox" });
  cb.checked = clockView.all;
  cb.addEventListener("change", () => { clockView.all = cb.checked; RX.rerender(); });
  opts.append(cb, document.createTextNode(" Also addresses on the internet"));
  box.append(opts);
  const rows = d.addresses.filter((a) => a.local || clockView.all);
  dataTable(box, "clocks", [
    { label: "Address", type: "text", get: (a) => a.ip },
    { label: "Verdict", type: "text", get: (a) => a.verdict },
    { label: "Machines", type: "num", get: (a) => a.machines ?? -1,
      render: (a) => document.createTextNode(a.machines == null ? "?" : String(a.machines)) },
    { label: "Clock rate", type: "text", get: (a) => (a.rates.length ? a.rates.map((r) => `${r}/s`).join(", ")
      : a.odd ? `${a.odd[0]}–${a.odd[1]}/s (uneven)` : "—") },
    { label: "Connections", type: "num", get: (a) => a.connections },
    { label: "Why", type: "text", get: (a) => a.why },
  ], rows, { onRow: (e, a) => clockMenu(e, a), defaultSort: { col: 2, dir: -1 } });

  const notes = el("details", { class: "lint-passed" });
  notes.append(el("summary", {}, "How sure is this?"));
  const ul = el("ul", { class: "small" });
  for (const t of d.notes) ul.append(el("li", {}, t));
  notes.append(ul);
  box.append(notes);
};
