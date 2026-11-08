// Explain: a connection, an alert's connections or a single packet in plain words.
// The diagnosis is made on the server (anta/diagnose.py) from the decoded packets;
// this renders it. Network-derived text goes in with textContent only.
"use strict";

const EXPLAIN_STATUS = { ok: "OK", info: "Note", problem: "Problem", failed: "Failed", suspicious: "Suspicious" };
let explainResult = null;

function explainList(title, items) {
  if (!items || !items.length) return null;
  const box = el("div", { class: "explain-part" });
  box.append(el("h4", {}, title));
  const ul = el("ul");
  for (const x of items) ul.append(el("li", {}, x));
  box.append(ul);
  return box;
}

function frameLink(n) {
  const b = el("button", { type: "button", class: "link mono" }, String(n));
  b.title = `Go to frame ${n}`;
  b.addEventListener("click", () => { $("explain-dialog").close(); window.goToFrame(n); });
  return b;
}

function explainConversation(c, open) {
  const item = el("details", { class: `explain-conv s-${c.status}` });
  if (open) item.open = true;
  const sum = el("summary");
  sum.append(el("span", { class: `tag tag-${c.status}` }, EXPLAIN_STATUS[c.status] || c.status),
    el("span", { class: "explain-title" }, c.title),
    el("span", { class: "mono muted" }, `${c.proto} ${c.client} → ${c.server}`));
  item.append(sum);
  const body = el("div", { class: "explain-detail" });
  body.append(el("p", { class: "explain-summary" }, c.summary));
  for (const part of [explainList("Likely causes", c.causes), explainList("What to check next", c.checks),
    explainList("Also seen", c.notes)]) {
    if (part) body.append(part);
  }
  if (c.facts && c.facts.length) {
    const dl = el("dl", { class: "kv" });
    for (const [k, v] of c.facts) dl.append(el("dt", {}, k), el("dd", {}, v));
    body.append(dl);
  }
  if (c.payload && c.payload.length) {
    const box = el("div", { class: "explain-part" });
    box.append(el("h4", {}, "What the payload is"));
    for (const p of c.payload) {
      box.append(el("p", {}, `${p.direction}: ${fmtBytes(p.size)}, ${p.what}.`));
      const sample = (p.lines && p.lines.length ? p.lines : p.strings || []).slice(0, 4);
      if (sample.length) {
        const pre = el("pre", { class: "explain-sample" });
        pre.textContent = sample.join("\n");
        box.append(pre);
      }
    }
    body.append(box);
  }
  if (c.timeline && c.timeline.length) {
    const box = el("div", { class: "explain-part" });
    box.append(el("h4", {}, "What happened"));
    const t = el("table", { class: "data-table explain-timeline" });
    const head = el("tr");
    ["Frame", "Time", "Who", "What"].forEach((h) => head.append(el("th", {}, h)));
    const thead = el("thead");
    thead.append(head);
    const tb = el("tbody");
    for (const e of c.timeline) {
      const tr = el("tr");
      const fcell = el("td");
      fcell.append(frameLink(e.n));
      tr.append(fcell, el("td", { class: "mono" }, e.t), el("td", { class: "mono" }, e.who), el("td", { class: "wrap" }, e.text));
      tb.append(tr);
    }
    t.append(thead, tb);
    box.append(t);
    body.append(box);
  }
  const actions = el("div", { class: "side-actions" });
  if (c.filter) {
    const show = el("button", { type: "button", class: "tb small" }, "Show its packets");
    show.addEventListener("click", () => { $("explain-dialog").close(); showPacketsFor(c.filter); });
    actions.append(show);
    if (c.stream !== null && c.stream !== undefined) {
      const follow = el("button", { type: "button", class: "tb small" }, "Follow stream");
      follow.addEventListener("click", () => { $("explain-dialog").close(); setView("packets"); window.openFollow(c.proto.toLowerCase(), c.stream); });
      actions.append(follow);
    }
  }
  if (actions.childElementCount) body.append(actions);
  item.append(body);
  return item;
}

function explainRender() {
  const r = explainResult;
  const body = $("explain-body");
  if (!r) return;
  if (!r.conversations.length) {
    body.replaceChildren(el("p", { class: "empty" }, "No TCP or UDP conversation in the selected packets."));
    return;
  }
  const parts = [];
  if (r.total > 1) {
    parts.push(el("p", { class: "explain-overview" },
      `${fmtNum(r.total)} conversations${r.shown < r.total ? ` (the first ${r.shown} explained)` : ""}: ${r.summary}.`));
  }
  r.conversations.forEach((c, i) => parts.push(explainConversation(c, i === 0)));
  body.replaceChildren(...parts);
}

let explainQuery = null;  // what the Explain dialog is explaining (for Explain with AI)

async function openExplain(query, label) {
  explainResult = null;
  explainQuery = { query, label };
  $("explain-title").textContent = `Explain ${label}`;
  $("explain-body").replaceChildren(el("p", { class: "muted" }, "Reading the packets…"));
  $("explain-dialog").showModal();
  try {
    explainResult = await api(`/api/explain?${new URLSearchParams(query)}`);
    explainRender();
  } catch (err) {
    $("explain-body").replaceChildren(el("p", { class: "error" }, err.message));
  }
}
window.openExplain = openExplain;

function explainText() {
  const r = explainResult;
  if (!r) return "";
  const lines = [];
  for (const c of r.conversations) {
    lines.push(`[${(EXPLAIN_STATUS[c.status] || c.status).toUpperCase()}] ${c.title} — ${c.proto} ${c.client} → ${c.server}`);
    lines.push(c.summary);
    for (const [title, items] of [["Likely causes", c.causes], ["What to check next", c.checks], ["Also seen", c.notes]]) {
      if (items && items.length) lines.push(`${title}:`, ...items.map((x) => `  - ${x}`));
    }
    for (const p of c.payload || []) lines.push(`Payload ${p.direction}: ${p.size} bytes, ${p.what}.`);
    if (c.timeline && c.timeline.length) {
      lines.push("What happened:");
      for (const e of c.timeline) lines.push(`  frame ${e.n}  ${e.t.padEnd(10)} ${e.who}: ${e.text}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

$("explain-close").addEventListener("click", () => $("explain-dialog").close());
$("explain-copy").addEventListener("click", () => { copyText(explainText()); notice("Explanation copied."); });
$("explain-alert").addEventListener("click", () => {
  const a = state.detail;
  if (a) openExplain({ alert: a.id }, `${a.title} (${a.id})`);
});

// The packet detail pane: what this one packet means, before its layers.
window.packetExplainBox = (d) => {
  const box = el("div", { class: "pkt-explain" });
  const lines = d.explain || [];
  const head = el("div", { class: "pkt-explain-head" });
  head.append(el("strong", {}, "In plain words"));
  if (d.stream_ref) {
    const [proto, stream] = d.stream_ref;
    const b = el("button", { type: "button", class: "tb small" }, "Explain this connection…");
    b.addEventListener("click", () => openExplain({ stream: `${proto}:${stream}` }, `${proto.toUpperCase()} stream ${stream}`));
    head.append(b);
  }
  box.append(head);
  if (!lines.length) {
    box.append(el("p", { class: "muted small" }, d.stream_ref
      ? "Nothing unusual about this packet on its own. Explain the connection to see what happened around it."
      : "Nothing unusual about this packet on its own."));
  }
  for (const l of lines) {
    const p = el("p", { class: `pkt-explain-line l-${l.level}` });
    p.append(el("strong", {}, `${l.title}. `), document.createTextNode(l.text));
    box.append(p);
  }
  return box;
};

$("explain-ai").addEventListener("click", () => {
  if (!explainQuery) return;
  $("explain-dialog").close();
  window.openExplainAI(explainQuery.query, explainQuery.label);
});

// ------------------------------------------------------------ Explain with AI

const AI_ASSESS = { normal: "Normal", "worth a look": "Worth a look", suspicious: "Suspicious", malicious: "Malicious", unclear: "Unclear" };
const ai = { query: null, label: "", preview: null, answer: null, seq: 0 };

// The AI model set up under Detection… (its name), or "" when there is none to ask.
window.aiReady = () => {
  const d = window.detectionData ? window.detectionData() : null;
  if (!d || !d.agent_ready || !d.agent || d.agent.provider === "command") return "";
  return window.detAgentName ? window.detAgentName(d.agent) : "the AI model";
};

function aiFrameLink(n) {
  const b = el("button", { type: "button", class: "link mono" }, String(n));
  b.title = `Go to frame ${n}`;
  b.addEventListener("click", () => { $("ai-dialog").close(); window.goToFrame(n); });
  return b;
}

function aiText() {
  const a = ai.answer;
  if (!a) return "";
  const lines = [`Explained by ${a.model} — ${AI_ASSESS[a.assessment] || a.assessment} (confidence ${Math.round(a.confidence * 100)}%)`,
    "", a.summary, ""];
  if (a.observations.length) lines.push("What the packets show:", ...a.observations.map((o) => `  - ${o.text}${o.frames.length ? ` [frames ${o.frames.join(", ")}]` : ""}`), "");
  if (a.next_steps.length) lines.push("What to check next:", ...a.next_steps.map((x) => `  - ${x}`));
  return lines.join("\n");
}

function aiRender() {
  const body = $("ai-body");
  const send = $("ai-send");
  const p = ai.preview;
  send.hidden = true;
  $("ai-copy").hidden = !ai.answer;
  if (ai.answer) {
    const a = ai.answer;
    const head = el("div", { class: "ai-head" });
    head.append(el("span", { class: `ai-badge ai-${a.assessment.replace(/ /g, "-")}` }, AI_ASSESS[a.assessment] || a.assessment),
      el("span", { class: "muted small" }, `confidence ${Math.round(a.confidence * 100)}% · ${a.model}`));
    const parts = [head, el("p", { class: "ai-summary" }, a.summary)];
    if (a.observations.length) {
      parts.push(el("h4", {}, "What the packets show"));
      const ul = el("ul", { class: "ai-obs" });
      for (const o of a.observations) {
        const li = el("li");
        li.append(document.createTextNode(o.text));
        if (o.frames.length) {
          const f = el("span", { class: "ai-frames muted small" }, " frames ");
          o.frames.forEach((n, i) => { if (i) f.append(document.createTextNode(", ")); f.append(aiFrameLink(n)); });
          li.append(f);
        }
        ul.append(li);
      }
      parts.push(ul);
    }
    if (a.next_steps.length) {
      parts.push(el("h4", {}, "What to check next"));
      const ul = el("ul");
      for (const x of a.next_steps) ul.append(el("li", {}, x));
      parts.push(ul);
    }
    parts.push(el("p", { class: "muted small" }, "Written by an AI model from the evidence below: it can be wrong. " +
      "Check the frames it cites before you act on it."));
    parts.push(aiSentBox(false));
    body.replaceChildren(...parts);
    return;
  }
  if (!p) return;
  if (!p.ready) {
    const set = el("button", { type: "button", class: "tb" }, "Set up a model…");
    set.addEventListener("click", () => { $("ai-dialog").close(); window.openDetection(); });
    body.replaceChildren(el("p", {}, "No AI model is set up to explain with. Choose one under Detection… (Claude, OpenAI, " +
      "Gemini, or a model on this computer through Ollama or LM Studio) and agree to send it data."), set,
      el("p", { class: "muted small" }, "Meanwhile, Explain (without AI) works on this computer alone."), aiSentBox(true));
    return;
  }
  send.hidden = false;
  send.textContent = `Send to ${p.model}`;
  body.replaceChildren(
    el("p", {}, `${p.model} gets a summary of ${fmtNum(p.packets)} packet${p.packets === 1 ? "" : "s"}, never their contents: ` +
      "one line per packet (as the packet list shows it), the statistics of the selection, and ANTA's own findings. " +
      "Passwords, logins, query strings and cookies are taken out" +
      (p.share_internal ? "." : ", and addresses on your network go as internal-host-1, mac-1 … (put back in the answer).")),
    aiSentBox(true));
}

function aiSentBox(open) {
  const d = el("details", { class: "ai-sent" });
  if (open) d.open = true;
  d.append(el("summary", {}, `Exactly what ${ai.answer ? "was" : "will be"} sent (${fmtNum(ai.preview ? ai.preview.chars : 0)} characters)`));
  const pre = el("pre", { class: "ai-preview" });
  pre.textContent = ai.preview ? ai.preview.preview : "";
  d.append(pre);
  return d;
}

window.openExplainAI = async (query, label) => {
  const seq = ++ai.seq;
  ai.query = query;
  ai.label = label;
  ai.preview = null;
  ai.answer = null;
  $("ai-title").textContent = `Explain with AI: ${label}`;
  $("ai-body").replaceChildren(el("p", { class: "muted" }, "Gathering what would be sent…"));
  $("ai-send").hidden = true;
  $("ai-copy").hidden = true;
  if (!$("ai-dialog").open) $("ai-dialog").showModal();
  try {
    const p = await api("/api/explain/ai", "POST", { ...query, preview: true });
    if (seq !== ai.seq) return;
    ai.preview = p;
    aiRender();
  } catch (err) {
    if (seq === ai.seq) $("ai-body").replaceChildren(el("p", { class: "error" }, err.message));
  }
};

$("ai-send").addEventListener("click", async () => {
  const seq = ++ai.seq;
  const send = $("ai-send");
  send.disabled = true;
  const wait = el("p", { class: "muted ai-wait", role: "status" }, `Asking ${ai.preview.model}… (a minute or so for a large selection)`);
  $("ai-body").prepend(wait);
  try {
    const a = await api("/api/explain/ai", "POST", { ...ai.query });
    if (seq !== ai.seq) return;
    ai.answer = a;
    aiRender();
  } catch (err) {
    if (seq === ai.seq) { wait.className = "error"; wait.textContent = err.message; }
  } finally {
    send.disabled = false;
  }
});
$("ai-copy").addEventListener("click", () => { copyText(aiText()); notice("Explanation copied."); });
$("ai-close").addEventListener("click", () => $("ai-dialog").close());
