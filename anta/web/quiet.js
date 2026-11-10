// Statistics → Certificate of quiet: for each device, everything it sent to the internet
// accounted for (anta/quiet.py), the most it could have hidden in headers and timing besides,
// and the stretches when it sent nothing at all. Everything from the network is rendered with
// textContent only.
"use strict";

function quietWhen(t) {
  return new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function quietDur(s) {
  if (s < 120) return `${Math.round(s)} s`;
  if (s < 7200) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${(s / 3600).toFixed(s < 36000 ? 1 : 0)} h`;
  return `${Math.round(s / 86400)} days`;
}

function quietMenu(e, r) {
  showMenu(e.clientX, e.clientY, [
    { caption: r.ip, kind: r.silent ? "sent nothing to the internet" : `${fmtBytes(r.open)} sent openly` },
    r.silent ? null : { label: "Show what it sent to the internet", hint: "its packets leaving the network", action: () => RX.showPackets(r.filter) },
    { label: "Host details", action: () => window.openHost(r.ip) },
    { separator: true },
    { label: "Copy its line of the certificate", action: () => copyText(quietLine(r)) },
  ]);
}

function quietLine(r) {
  if (r.silent) return `${r.ip} sent nothing to the internet while this was recorded.`;
  return `${r.ip}: sent ${fmtBytes(r.open)} openly in ${fmtNum(r.connections)} connection${r.connections === 1 ? "" : "s"}`
    + `${r.dns_names ? ` and looked up ${fmtNum(r.dns_names)} name${r.dns_names === 1 ? "" : "s"}` : ""}; `
    + `besides that, at most ${fmtBytes(r.room)} could have been hidden in its headers and timing.`;
}

TOOLS.quiet = (box) => {
  const slot = invGet("quiet", "/api/quiet");
  if (invPending(box, slot, "everything each device sent out")) return;
  const d = slot.data;
  const t = d.totals;
  box.append(el("p", { class: "tool-note" }, "Everything each device sent to the internet, accounted for. What it sent openly is "
    + "in the capture (readable, or encrypted and only countable). Anything else would have to hide inside normal-looking "
    + "traffic, in header values a sender may choose and in timing, and that room is finite: the certificate gives its upper "
    + "limit. Where a device sent nothing out at all, it says when."));

  const cert = el("section", { class: "quiet-cert", "aria-label": "The certificate" });
  cert.append(el("h3", {}, "Certificate of quiet"));
  cert.append(el("p", { class: "small muted" }, `${d.names.join(", ")} · ${quietWhen(d.first)} to ${quietWhen(d.last)} `
    + `(${quietDur(d.seconds)})${d.scoped ? " · within the focused packets" : ""}`));
  const main = el("p", { class: "quiet-claim" });
  if (!t.talkers) {
    main.textContent = `None of the ${fmtNum(t.devices)} devices on this network sent anything to the internet while this was recorded.`;
  } else {
    main.textContent = `Across ${fmtNum(t.devices)} device${t.devices === 1 ? "" : "s"}, besides the ${fmtBytes(t.open)} sent openly `
      + `in ${fmtNum(t.connections)} connection${t.connections === 1 ? "" : "s"}, no device could have hidden more than `
      + `${fmtBytes(t.most_room)} in its traffic's headers and timing (${fmtBytes(t.room)} for all of them together).`;
  }
  cert.append(main);
  if (t.silent) cert.append(el("p", { class: "small" }, `${fmtNum(t.silent)} device${t.silent === 1 ? "" : "s"} sent nothing to the internet at all.`));
  if (d.recording) cert.append(el("p", { class: "small muted" }, "Still recording: the certificate covers what has been captured so far."));
  if (d.used.reserved) {
    cert.append(el("p", { class: "small quiet-warn" }, `${fmtNum(d.used.reserved)} packet${d.used.reserved === 1 ? "" : "s"} set reserved `
      + "header bits, which nothing should: see Protocol spell-check."));
  }
  const copy = el("button", { type: "button", class: "tb small" }, "Copy the certificate");
  copy.addEventListener("click", () => copyText([main.textContent, ...d.devices.map(quietLine)].join("\n")));
  cert.append(copy);
  box.append(cert);

  tiles(box, [["Devices", fmtNum(t.devices), `${fmtNum(t.talkers)} sent to the internet`],
    ["Sent openly", fmtBytes(t.open), `${fmtBytes(t.encrypted)} of it encrypted`],
    ["In DNS names", fmtBytes(t.dns_bytes), "the parts of looked-up names a sender chooses"],
    ["Room to hide", fmtBytes(t.room), "headers and timing, all devices"]]);

  section(box, "Each device", "click a row for what it sent");
  dataTable(box, "quiet", [
    { label: "Device", type: "text", get: (r) => r.ip },
    { label: "Sent openly", type: "bytes", get: (r) => r.open },
    { label: "Encrypted", type: "bytes", get: (r) => r.encrypted },
    { label: "Connections", type: "num", get: (r) => r.connections },
    { label: "Names looked up", type: "num", get: (r) => r.dns_names },
    { label: "In DNS names", type: "bytes", get: (r) => r.dns_bytes },
    { label: "Room to hide (at most)", type: "bytes", get: (r) => r.room },
    { label: "Longest quiet", type: "text", get: (r) => (r.silent ? "the whole time"
      : r.quiet.length ? `${quietDur(r.quiet[0].seconds)} from ${quietWhen(r.quiet[0].from)}` : "—") },
  ], d.devices, { onRow: (e, r) => quietMenu(e, r), defaultSort: { col: 6, dir: -1 } });

  const quietOnes = d.devices.filter((r) => !r.silent && r.quiet.length);
  if (quietOnes.length) {
    section(box, "Stretches of quiet", "when a device sent nothing to the internet: a fact, not an estimate");
    const ul = el("ul", { class: "quiet-list small" });
    for (const r of quietOnes.slice(0, 40)) {
      const li = el("li");
      const b = el("button", { type: "button", class: "link mono" }, r.ip);
      b.addEventListener("click", () => window.openHost(r.ip));
      li.append(b, document.createTextNode(` was silent ${r.quiet.map((q) => `${quietWhen(q.from)} to ${quietWhen(q.to)} (${quietDur(q.seconds)})`).join("; ")}`));
      ul.append(li);
    }
    box.append(ul);
  }

  const how = el("details", { class: "lint-passed" });
  how.append(el("summary", {}, "How the room to hide is counted"));
  const table = el("table", { class: "data-table quiet-fields" });
  const hr = el("tr");
  for (const c of ["Where data could hide", "Room", "Counted"]) hr.append(el("th", {}, c));
  table.append(el("thead"));
  table.firstChild.append(hr);
  const tb = el("tbody");
  for (const f of d.fields) {
    const tr = el("tr", { class: f.removed ? "muted" : "" });
    tr.append(el("td", {}, f.label), el("td", {}, `${f.bits} bit${f.bits === 1 ? "" : "s"} ${f.unit}`),
      el("td", {}, f.removed ? `No: ${f.why}` : "Yes"));
    tb.append(tr);
  }
  table.append(tb);
  how.append(table);
  const ul = el("ul", { class: "small" });
  for (const n of d.notes) ul.append(el("li", {}, n));
  how.append(ul);
  box.append(how);
};
