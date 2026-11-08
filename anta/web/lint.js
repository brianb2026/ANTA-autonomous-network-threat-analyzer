// Statistics → Protocol spell-check: every packet held against the rules of its protocol's
// standard (anta/lint.py), like a spell-checker for networks. Each broken rule says what is
// wrong in plain words, which rule of which RFC it breaks, why it matters, and opens its packets.
// Everything from the network is rendered with textContent only.
"use strict";

const LINT_SEV = { error: "Breaks a MUST", warning: "Crafted or forbidden", note: "Odd" };

TOOLS.lint = (box) => {
  const rx = RX;
  const filter = rx.filter() || "";
  const slot = invGet(`lint:${filter}`, `/api/lint${filter ? `?dfilter=${encodeURIComponent(filter)}` : ""}`);
  if (invPending(box, slot, "the packets against the standards")) return;
  const d = slot.data;
  box.append(el("p", { class: "tool-note" }, "Every packet held against the rules its protocol's standard sets, like a spell-checker: "
    + "headers no operating system would build, combinations scanners use, messages that open doors (HTTP request smuggling, "
    + "spoofing from off the link), and versions the standards now forbid. Each finding names the RFC section it breaks."));
  tiles(box, [["Rules checked", fmtNum(d.checked)], ["Broken", fmtNum(d.broken.length), d.broken.length ? "see below" : "everything conforms"],
    ["Packets breaking them", fmtNum(d.packets)]]);
  if (!d.broken.length) box.append(el("p", { class: "empty" }, "No packet breaks any of these rules."));
  for (const r of d.broken) {
    const card = el("article", { class: `lint-item lint-${r.severity}` });
    const top = el("div", { class: "lint-top" });
    top.append(el("span", { class: `lint-sev lint-${r.severity}` }, LINT_SEV[r.severity] || r.severity),
      el("strong", {}, r.title), el("span", { class: "muted small" }, r.protocol), el("span", { class: "lint-count" },
        `${fmtNum(r.count)} packet${r.count === 1 ? "" : "s"}`));
    const rule = el("p", { class: "small" });
    rule.append(el("span", { class: "lint-label" }, "The rule: "), document.createTextNode(r.rule));
    const why = el("p", { class: "small" });
    why.append(el("span", { class: "lint-label" }, "Why it matters: "), document.createTextNode(r.why));
    const acts = el("div", { class: "lint-acts" });
    const show = el("button", { type: "button", class: "tb small" }, "Show the packets");
    show.addEventListener("click", () => rx.showPackets(r.filter));
    acts.append(show, el("span", { class: "muted small" }, "First: "));
    for (const n of r.frames.slice(0, 12)) {
      const b = el("button", { type: "button", class: "link mono" }, String(n));
      b.addEventListener("click", () => goToFrame(n));
      acts.append(b, document.createTextNode(" "));
    }
    acts.append(el("code", { class: "lint-filter muted small", title: "The display filter that finds it" }, r.filter));
    card.append(top, rule, why, acts);
    box.append(card);
  }
  const passed = el("details", { class: "lint-passed" });
  passed.append(el("summary", {}, `Rules no packet breaks (${fmtNum(d.passed.length)})`));
  const ul = el("ul", { class: "small" });
  for (const p of d.passed) {
    const li = el("li");
    li.append(el("strong", {}, `${p.protocol}: `), document.createTextNode(`${p.title}. `), el("span", { class: "muted" }, p.rule));
    ul.append(li);
  }
  passed.append(ul);
  box.append(passed);
};
