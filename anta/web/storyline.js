// Storyline: each device's alerts linked into one story, in the order things happened and
// the attack stage they belong to, with a plain-words account at the top. A story's steps
// open their alerts; a device that spread to another links to that device's story.
// Everything from the network is rendered with textContent, never innerHTML.
"use strict";

const story = { data: null, key: "", timer: null, loading: false };

async function storyLoad(force = false) {
  const key = `${sessionKey()}|${window.focusScope ? window.focusScope() : ""}|${state.alerts.size}|${[...state.alerts.values()].map((a) => `${a.id}:${a.updates}:${verdictOf(a)}`).join(",")}`;
  if (!force && story.data && story.key === key) { storyRender(); return; }
  const seq = story.seq = (story.seq || 0) + 1;
  try {
    const data = await api(withFocus("/api/storyline"));
    if (seq !== story.seq) return;  // (a newer load, for another focus or capture, is under way)
    story.data = data;
    story.key = key;
  } catch (err) {
    if (seq === story.seq) $("story-list").replaceChildren(el("p", { class: "error" }, err.message));
    return;
  }
  storyRender();
}
viewHooks.story = () => storyLoad();

// Alerts keep arriving while a capture runs: refresh the stories at most every 2 s.
window.storyChanged = () => {
  if (!viewIs("story") || story.timer) return;
  story.timer = setTimeout(() => { story.timer = null; storyLoad(); }, 2000);
};

function storyClock(ts) {
  return ts ? new Date(ts * 1000).toLocaleTimeString([], { hour12: false }) : "";
}

function storyRender() {
  const list = $("story-list");
  const d = story.data;
  const stories = (d && d.stories) || [];
  $("story-count").textContent = stories.length ? String(stories.length) : "";
  if (!stories.length) {
    list.replaceChildren(el("p", { class: "empty" }, state.alerts.size
      ? "None of the alerts so far tells a story about a device (only shared or dismissed traffic)."
      : "No alerts yet. Open a capture, start a live capture, or run the demo."));
    return;
  }
  list.replaceChildren(...stories.map((s) => storyCard(s, d.stages)));
}

function storyCard(s, stages) {
  const card = el("article", { class: `story-card sev-border-${s.severity}`, id: `story-${s.device}`, dataset: { q: s.device } });
  const head = el("header", { class: "story-head" });
  head.append(el("span", { class: `sev sev-${s.severity}` }, SEV_LABEL[s.severity] || s.severity));
  const who = el("h3", { class: "story-device" });
  who.append(el("span", { class: "mono" }, s.device));
  if (s.name) who.append(el("span", { class: "muted" }, ` ${s.name}`));
  head.append(who, el("span", { class: "muted small story-when" },
    `${storyClock(s.first_seen)} – ${storyClock(s.last_seen)} · ${s.steps.length} step${s.steps.length === 1 ? "" : "s"}`));
  const tools = el("span", { class: "story-tools" });
  const btn = (label, fn) => { const b = el("button", { type: "button", class: "tb small" }, label); b.addEventListener("click", fn); return b; };
  tools.append(btn("Host details", () => window.openHost(s.device)),
    btn("Packets", () => showPacketsFor(`${s.device.includes(":") ? "ipv6" : "ip"}.addr == ${s.device}`)),
    btn("Its alerts", () => { setAlertsMode("list"); window.showAlertsInvolving(s.device); }));
  head.append(tools);
  card.append(head);
  if (s.summary) card.append(el("p", { class: "story-summary" }, s.summary));

  // How far it got: each attack stage, reached or not (named, not only shaded).
  const rail = el("ol", { class: "story-rail", "aria-label": "Attack stages" });
  for (const st of stages) {
    const on = s.stages.includes(st.id);
    const li = el("li", { class: on ? "on" : "", title: on ? "Seen" : "Not seen" });
    li.append(el("span", { class: "rail-mark", "aria-hidden": "true" }, on ? "✓" : ""), document.createTextNode(st.label));
    li.setAttribute("aria-label", `${st.label}: ${on ? "seen" : "not seen"}`);
    rail.append(li);
  }
  card.append(rail);

  const steps = el("ol", { class: "story-steps" });
  for (const st of s.steps) {
    const li = el("li", { class: `story-step v-${st.verdict}` });
    const b = el("button", { type: "button", class: "story-step-btn", title: "Open this alert" });
    b.append(el("span", { class: "mono story-time" }, storyClock(st.first_seen)),
      el("span", { class: "story-stage" }, st.stage_label),
      el("span", { class: `sev sev-${st.severity}` }, SEV_LABEL[st.severity] || st.severity));
    const what = el("span", { class: "story-what" });
    what.append(el("strong", {}, st.received_from ? `Received from ${st.received_from}: ${st.title}` : st.title));
    if (st.headline) what.append(el("span", { class: "muted" }, ` ${st.headline}`));
    b.append(what);
    b.addEventListener("click", () => { setView("alerts"); select(st.id); });  // (the detail beside the story)
    li.append(b);
    steps.append(li);
  }
  card.append(steps);

  if (s.links.length) {  // where it spread, or came from
    const p = el("p", { class: "story-links small" });
    p.append(document.createTextNode("Linked to "));
    s.links.forEach((ip, i) => {
      const a = el("button", { type: "button", class: "link mono" }, ip);
      a.addEventListener("click", () => document.getElementById(`story-${ip}`)?.scrollIntoView({ behavior: "smooth", block: "start" }));
      if (i) p.append(document.createTextNode(", "));
      p.append(a);
    });
    p.append(document.createTextNode(": one device spread to the other."));
    card.append(p);
  }
  return card;
}
