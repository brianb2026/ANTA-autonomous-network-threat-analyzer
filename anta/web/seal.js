// Statistics → Tamper seal: was this capture edited, spliced or cut, and has it changed since
// you sealed it (anta/seal.py)? The seal is the file's SHA-256, recorded on request; the checks
// look for the contradictions editing leaves (record lengths, time running backwards, wrong
// checksums from other computers, many connections missing data at once after a silence).
// Everything from the file is rendered with textContent only.
"use strict";

const SEAL_LABEL = { fail: "Problem", note: "Note", pass: "OK" };
const sealView = { compare: "" };

TOOLS.seal = (box) => {
  const slot = invGet("seal", "/api/seal");
  if (invPending(box, slot, "the file and checking it")) return;
  const d = slot.data;
  box.append(el("p", { class: "tool-note" }, "Was this capture edited, spliced or cut? A capture tool writes files that "
    + "can't contradict themselves; editing tends to leave contradictions behind, and these checks look for them. "
    + "Record the seal (the file's fingerprint) to find out later whether a single byte changed."));
  const v = el("div", { class: `seal-verdict seal-${d.verdict}` });
  v.append(el("strong", {}, d.headline));
  const sub = d.verdict === "changed" ? "The file isn't the one you sealed."
    : d.verdict === "edited" ? "See the problems below; each says what it means."
      : d.verdict === "sealed" ? "Not one byte changed since you sealed it, and nothing in it contradicts itself."
        : "Nothing in it contradicts itself. That isn't proof (a careful forger recomputes checksums), but ordinary editing leaves traces these find.";
  v.append(el("span", { class: "small" }, sub));
  box.append(v);
  tiles(box, [["Packets", fmtNum(d.packets)], ["Format", d.format || "—", d.writer ? `written by ${d.writer}` : ""],
    ["Size", fmtBytes(d.fingerprint.size), d.names.join(", ")],
    ["Seal", d.sealed ? (d.matches ? "Matches" : "Doesn't match") : "Not sealed",
      d.sealed ? `recorded ${new Date(d.sealed.sealed * 1000).toLocaleString()}` : "record it below"]]);

  // The fingerprint, recording it, and comparing with one someone gave you.
  const fp = el("div", { class: "seal-fp" });
  fp.append(el("span", { class: "lint-label" }, "SHA-256: "), el("code", { class: "mono" }, d.fingerprint.sha256));
  const copy = el("button", { type: "button", class: "tb small" }, "Copy");
  copy.addEventListener("click", () => copyText(d.fingerprint.sha256));
  const rec = el("button", { type: "button", class: "tb small tb-primary",
    title: d.recording ? "Stop the capture first" : "Remember this fingerprint so later changes show" },
  d.sealed ? (d.matches ? "Seal again" : "Seal it as it is now") : "Record the seal");
  rec.disabled = !!d.recording;
  rec.addEventListener("click", async () => {
    rec.disabled = true;
    try {
      slot.data = await api("/api/seal", "POST", {});
      RX.rerender();
    } catch (err) {
      rec.disabled = false;
      box.append(el("p", { class: "error" }, err.message));
    }
  });
  fp.append(copy, rec);
  box.append(fp);
  const cmp = el("form", { class: "seal-compare" });
  const input = el("input", { type: "text", class: "pkt-filter mono", placeholder: "Paste a SHA-256 you were given to compare",
    spellcheck: "false", autocomplete: "off", maxlength: "200", "aria-label": "A SHA-256 to compare with" });
  input.value = sealView.compare;
  const out = el("span", { class: "small", role: "status" });
  const show = () => {
    const want = input.value.trim().toLowerCase();
    sealView.compare = input.value;
    if (!want) { out.textContent = ""; out.className = "small"; return; }
    const same = want === d.fingerprint.sha256;
    out.textContent = same ? "✓ Same file: every byte matches." : /^[0-9a-f]{64}$/.test(want)
      ? "✗ Different: this isn't the file that fingerprint came from." : "That doesn't look like a SHA-256 (64 hexadecimal characters).";
    out.className = `small ${same ? "seal-same" : "seal-diff"}`;
  };
  input.addEventListener("input", show);
  cmp.addEventListener("submit", (e) => { e.preventDefault(); show(); });
  cmp.append(input, out);
  box.append(cmp);
  show();
  if (d.fingerprint.files.length > 1) {
    const ul = el("ul", { class: "small muted" });
    for (const f of d.fingerprint.files) ul.append(el("li", {}, `${f.name}: ${f.sha256} (${fmtBytes(f.size)})`));
    box.append(ul);
  }

  section(box, "Checks", "problems first");
  for (const c of d.checks) {
    const card = el("article", { class: `lint-item seal-${c.status}` });
    const top = el("div", { class: "lint-top" });
    top.append(el("span", { class: `lint-sev seal-sev-${c.status}` }, SEAL_LABEL[c.status]), el("strong", {}, c.title));
    card.append(top, el("p", { class: "small" }, c.what));
    if (c.why) {
      const why = el("p", { class: "small" });
      why.append(el("span", { class: "lint-label" }, "What it means: "), document.createTextNode(c.why));
      card.append(why);
    }
    if (c.filter || c.frames.length) {
      const acts = el("div", { class: "lint-acts" });
      if (c.filter) {
        const b = el("button", { type: "button", class: "tb small" }, "Show the packets");
        b.addEventListener("click", () => RX.showPackets(c.filter));
        acts.append(b);
      }
      if (c.frames.length) {
        acts.append(el("span", { class: "muted small" }, "Frames: "));
        for (const n of c.frames.slice(0, 12)) {
          const b = el("button", { type: "button", class: "link mono" }, String(n));
          b.addEventListener("click", () => goToFrame(n));
          acts.append(b, document.createTextNode(" "));
        }
      }
      card.append(acts);
    }
    box.append(card);
  }
};
