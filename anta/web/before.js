// Statistics → Before the capture: what the recorded traffic shows happened before recording
// began (anta/before.py), from leftovers only: connections already open, addresses already
// known, the resolver's cache counting down, DHCP leases partway through, TLS sessions resumed.
// A strip shows how far back each dated finding reaches. Everything from the network is
// rendered with textContent only.
"use strict";

const BEFORE_KINDS = [
  ["lease", "Addresses already held", "DHCP renewals partway through a lease, and devices asking to keep an address"],
  ["cache", "In the resolver's memory", "DNS answers from your network's resolver with part of their time to live used up"],
  ["resumed", "Encrypted sessions resumed", "TLS 1.3 sessions continued from an earlier conversation"],
  ["open", "Connections already open", "data flowing in connections whose start isn't in the capture"],
  ["known", "Addresses already known", "servers reached by name with no lookup in the capture"],
];

function beforeAgo(start, t) {
  const s = Math.max(0, start - t);
  if (s < 90) return `${Math.round(s)} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${(s / 3600).toFixed(s < 36000 ? 1 : 0)} h`;
  return `${(s / 86400).toFixed(1)} days`;
}

function beforeWhen(e, start) {
  if (e.when != null) {
    const at = new Date(e.when * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    return `${e.sure ? "" : "about "}${beforeAgo(start, e.when)} before recording (${at})${e.sure ? "" : " · estimate"}`;
  }
  if (e.earliest != null) return `within the ${beforeAgo(start, e.earliest)} before recording`;
  return "before recording began";
}

// The strip: seconds before the start on a log scale, so minutes and days both show.
function beforeStrip(box, d) {
  const dated = d.events.filter((e) => e.when != null || e.earliest != null);
  if (!dated.length) return;
  const W = 760, H = 74, L = 16, R = 120, y = 34;
  const ago = (e) => Math.max(1, d.start - (e.when != null ? e.when : e.earliest));
  const maxAgo = Math.max(60, ...dated.map(ago)) * 1.4;
  const x = (s) => L + (W - L - R) * (1 - Math.log(Math.max(1, s)) / Math.log(maxAgo));
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("class", "before-strip");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "How far back each finding reaches, before recording began");
  const mk = (tag, attrs, text) => {
    const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (text != null) n.textContent = text;
    svg.append(n);
    return n;
  };
  mk("rect", { x: L, y: y - 10, width: W - L - R, height: 20, class: "before-band" });
  mk("line", { x1: W - R, y1: 8, x2: W - R, y2: H - 8, class: "before-start" });
  mk("text", { x: W - R + 6, y: y + 4, class: "before-label" }, "Recording began");
  for (const [s, label] of [[60, "1 min"], [3600, "1 h"], [86400, "1 day"], [604800, "7 days"]]) {
    if (s > maxAgo) continue;
    mk("line", { x1: x(s), y1: y + 12, x2: x(s), y2: y + 16, class: "before-tick" });
    mk("text", { x: x(s), y: y + 28, class: "before-tick-label", "text-anchor": "middle" }, `${label} before`);
  }
  for (const e of dated) {
    if (e.when == null) {  // (a window: within the 7 days before)
      mk("line", { x1: x(ago(e)), y1: y, x2: W - R, y2: y, class: "before-window" }).append(
        Object.assign(document.createElementNS("http://www.w3.org/2000/svg", "title"), { textContent: `${e.who} ${e.what}: ${beforeWhen(e, d.start)}` }));
      continue;
    }
    const c = mk("circle", { cx: x(ago(e)), cy: y, r: 5, class: `before-dot${e.sure ? "" : " est"}`, tabindex: "0" });
    c.append(Object.assign(document.createElementNS("http://www.w3.org/2000/svg", "title"), { textContent: `${e.who} ${e.what}: ${beforeWhen(e, d.start)}` }));
  }
  box.append(svg);
  const key = el("p", { class: "small muted" });
  key.append(document.createTextNode("● a dated finding   ○ an estimate   ━ a window it falls within. Hover for which."));
  box.append(key);
}

TOOLS.before = (box) => {
  const slot = invGet("before", "/api/before");
  if (invPending(box, slot, "the capture for traces of what came before it")) return;
  const d = slot.data;
  box.append(el("p", { class: "tool-note" }, "What happened before recording began, read from leftovers in the traffic that was "
    + "recorded: each finding is something the capture can only show if an earlier event happened. Dated ones go back as far "
    + "as the evidence allows; the rest are certain to be earlier, just not when."));
  const n = d.events.length;
  tiles(box, [["Findings", fmtNum(n), n ? "before the first packet" : "nothing points earlier"],
    ["Reaches back", d.earliest != null ? beforeAgo(d.start, d.earliest) : d.earliest_bound != null ? `≤ ${beforeAgo(d.start, d.earliest_bound)}` : "—",
      d.earliest != null ? "the oldest dated finding" : ""],
    ["Recording began", new Date(d.start * 1000).toLocaleString(), d.names.join(", ")]]);
  if (!n) {
    box.append(el("p", { class: "empty" }, "Nothing in this capture points to earlier events: every connection starts in it, and "
      + "every address it uses was looked up in it."));
    return;
  }
  beforeStrip(box, d);
  for (const [kind, title, sub] of BEFORE_KINDS) {
    const items = d.events.filter((e) => e.kind === kind);
    if (!items.length) continue;
    section(box, `${title} (${fmtNum(items.length)})`, sub);
    for (const e of items.slice(0, 60)) {
      const card = el("article", { class: "lint-item before-item" });
      const top = el("div", { class: "lint-top" });
      const who = el("button", { type: "button", class: "link mono", title: "Host details" }, e.who);
      who.addEventListener("click", () => window.openHost(e.who));
      top.append(who, el("span", {}, e.what), el("span", { class: "lint-count muted small" }, beforeWhen(e, d.start)));
      card.append(top, el("p", { class: "small" }, e.why));
      if (e.filter || e.frames.length) {
        const acts = el("div", { class: "lint-acts" });
        if (e.filter) {
          const b = el("button", { type: "button", class: "tb small" }, "Show the packets");
          b.addEventListener("click", () => RX.showPackets(e.filter));
          acts.append(b);
        }
        for (const f of e.frames) {
          const b = el("button", { type: "button", class: "link mono" }, String(f));
          b.addEventListener("click", () => goToFrame(f));
          acts.append(b, document.createTextNode(" "));
        }
        card.append(acts);
      }
      box.append(card);
    }
    if (items.length > 60) box.append(el("p", { class: "small muted" }, `…and ${fmtNum(items.length - 60)} more.`));
  }
  const notes = el("details", { class: "lint-passed" });
  notes.append(el("summary", {}, "How sure is this?"));
  const ul = el("ul", { class: "small" });
  for (const t of d.notes) ul.append(el("li", {}, t));
  notes.append(ul);
  box.append(notes);
};
