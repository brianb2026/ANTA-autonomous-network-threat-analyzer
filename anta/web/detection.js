// Detection: what looks at every session besides the rule-based detectors (the
// built-in Isolation Forest, an ONNX model the user adds, or a detection agent in a
// model's place: Claude, OpenAI, Gemini, a model behind an OpenAI-compatible server, or the
// user's own program), the agent's settings, and its verdicts on alerts. API keys are
// write-only: the page sends them and never gets them back. Network-derived text is
// rendered with textContent only, as everywhere else.
"use strict";

const detection = { data: null, activateOnReady: false, picked: null };
const DET_MAX_MODEL = 64 * 1024 * 1024;
const DET_API = ["claude", "openai", "gemini", "compatible"];
// What each AI provider's part of the dialog says.
const DET_PROVIDERS = {
  claude: { key: "Anthropic API key", to: "Anthropic", env: "ANTHROPIC_API_KEY" },
  openai: { key: "OpenAI API key", to: "OpenAI", env: "OPENAI_API_KEY" },
  gemini: { key: "Gemini API key", to: "Google", env: "GEMINI_API_KEY" },
  compatible: { key: "API key (only if the server needs one)", to: "the server", env: "" },
};
const DET_SENT = "Each review sends one session's summary (addresses, ports, sizes, timing, TLS names, HTTP paths without " +
  "query strings) and the lookups the agent asks for.";

function detPct(v) {
  if (v === null || v === undefined) return "–";
  const p = v * 100;
  return `${p < 1 && p > 0 ? p.toFixed(2) : p.toFixed(1)}%`;
}

function detDate(iso) {
  const d = iso ? new Date(iso) : null;
  return d && !Number.isNaN(d.getTime()) ? d.toLocaleDateString([], { dateStyle: "medium" }) : "";
}

function detAgentName(a, p = a.provider) {
  const m = a.models[p] || "no model chosen";
  if (p === "command") return a.command_configured ? a.command_name : "your agent (none configured)";
  if (p === "claude") return `Claude (${m}, ${a.effort} effort)`;
  if (p === "compatible") return `${m} at ${a.server || "no server set"}`;
  return `${a.providers[p].label} (${m})`;
}

function detAgentAbout(d) {
  return `${detAgentName(d.agent)}; at most ${fmtNum(d.agent.reviews_per_hour)} reviews an hour; ${d.agent_ready ? "set up" : "not set up yet"}`;
}

// What a provider still needs before the agent can use it ("" when nothing).
function agentMissing(d, p = d.agent.provider) {
  const a = d.agent;
  if (p === "command") return a.command_configured ? "" : "it needs agent_command set in anta.toml";
  if (p === "claude" && !d.sdk_installed) return "the Anthropic SDK isn't installed";
  if (p === "compatible" && !a.base_url) return "it needs the server's address";
  if (p !== "compatible" && !a.keys_saved[p] && !a.keys_from_environment[p]) return `it needs your ${DET_PROVIDERS[p].key}`;
  if (!a.models[p]) return "it needs a model chosen";
  if (!a.consents[p]) {
    return `it needs your agreement to send the sessions it reviews to ${p === "compatible" ? "that server" : DET_PROVIDERS[p].to}`;
  }
  return "";
}

function detRenderModels(d) {
  const tbody = $("det-models").querySelector("tbody");
  tbody.replaceChildren();
  for (const m of d.models) {
    const tr = el("tr", { class: m.active ? "selected" : "" });
    const use = el("td", { class: "c-use" });
    const radio = el("input", { type: "radio", name: "det-active", value: m.id, "aria-label": `Use ${m.name}` });
    radio.checked = m.active;
    radio.disabled = !!m.missing;
    radio.addEventListener("change", () => detChoose(m.id));
    use.append(radio);
    const name = el("td");
    name.append(el("div", {}, m.name || m.id));
    if (m.file) name.append(el("div", { class: "muted small mono" }, m.file));
    let about = "";
    if (m.kind === "builtin") about = m.missing ? "not found in this copy of ANTA" : m.about || "";
    else if (m.kind === "onnx") {
      about = `${m.direction === "higher" ? "higher" : "lower"} scores are anomalous · ${fmtBytes(m.size)} · added ${detDate(m.created)}`;
    } else about = detAgentAbout(d);
    const act = el("td", { class: "c-act" });
    if (m.kind === "onnx") {
      const b = el("button", { type: "button", class: "link" }, "Remove");
      b.addEventListener("click", () => detRemove(m));
      act.append(b);
    }
    tr.append(use, name, el("td", { class: "num mono" }, m.kind === "agent" ? "–" : detPct(m.benign_alert_rate)),
      el("td", { class: "num mono" }, m.kind === "agent" ? "–" : detPct(m.attack_catch_rate)),
      el("td", { class: "muted small" }, about), act);
    tbody.append(tr);
  }
  const c = d.calibration;
  $("det-rates").textContent = c ? `Rates are measured by ANTA on ${fmtNum(c.benign)} held-out benign sessions and on the ` +
    `${fmtNum(c.attack)} sessions to and from the attackers planted in the demo capture. Most of those are command-and-control ` +
    "check-ins that look ordinary one at a time: the beaconing detector catches them from their timing, not any session " +
    "model. A model trained on the demo capture will score well here without being better on your network." : "";
  let problem = d.model_error || "";
  if (d.active === "agent" && !d.agent_ready) {
    problem = `The detection agent is chosen, but it isn't set up yet (${agentMissing(d) || "see below"}), so no sessions are being reviewed.`;
  }
  $("det-model-error").textContent = problem;
}

function detPicked() {
  const r = document.querySelector('input[name="det-provider"]:checked');
  return r ? r.value : detection.data ? detection.data.agent.provider : "claude";
}

function detServerHost(url) {
  try { return new URL(url).host; } catch { return ""; }
}

// Whom the agreement is to: the provider, or the server at the address typed.
function detConsentLine(p) {
  const host = p === "compatible" ? detServerHost($("det-base").value.trim()) : "";
  $("det-consent-text").textContent = `Send the sessions it reviews to ${p === "compatible" ? (host ? `the server at ${host}` : "that server") : DET_PROVIDERS[p].to}`;
  $("det-consent-note").textContent = p === "compatible"
    ? `${DET_SENT} A server on this computer keeps them here; a hosted one may charge for each request.`
    : `${DET_SENT} Each is a paid request on your account.`;
}

// The provider's own settings into the dialog: its consent, key, model and server.
function detFillProvider(p, keepEdits = false) {
  const d = detection.data;
  if (!d || !DET_API.includes(p)) return;
  const a = d.agent, t = DET_PROVIDERS[p];
  if (!keepEdits) {
    $("det-consent").checked = !!a.consents[p];
    $("det-base").value = a.base_url || "";
    if (p === "claude") {
      const model = $("det-model");
      if (![...model.options].some((o) => o.value === a.models.claude)) model.append(el("option", { value: a.models.claude }, a.models.claude));
      model.value = a.models.claude;
    } else {
      $("det-model-name").value = a.models[p] || "";
    }
  }
  detConsentLine(p);
  $("det-key-label").textContent = t.key;
  $("det-key").value = "";
  $("det-key-status").textContent = a.keys_saved[p] ? "A key is saved."
    : a.keys_from_environment[p] ? `No key saved here; the one in ${t.env} will be used.`
      : p === "compatible" ? "No key saved (a server on this computer usually needs none)." : "No key saved.";
  $("det-key-forget").hidden = !a.keys_saved[p];
  $("det-model-name").placeholder = p === "compatible" ? "The model's name on that server, e.g. llama3.1:8b" : "Press List models, or type the model's name";
}

function detRenderAgent(d, keepEdits = false) {
  const a = d.agent;
  const p = keepEdits && detection.picked ? detection.picked : a.provider;
  for (const r of document.querySelectorAll('input[name="det-provider"]')) r.checked = r.value === p;
  $("det-provider-command").disabled = !a.command_configured && a.provider !== "command";
  detProviderShown(p);
  detFillProvider(p, keepEdits);
  if (!keepEdits) {
    $("det-share").checked = a.share_internal;
    $("det-effort").value = a.effort;
    $("det-rate").value = a.reviews_per_hour;
  }
  $("det-sdk").hidden = d.sdk_installed;
  $("det-command-line").textContent = a.command_configured ? a.command.join(" ") : "None configured.";
  const s = d.agent_status;
  const rows = [
    ["Reviewed", fmtNum(s.reviewed)],
    ["Flagged", fmtNum(s.flagged)],
    ["Judged benign", fmtNum(s.benign)],
    ["Reviews this hour", `${fmtNum(s.reviews_last_hour)} of ${fmtNum(s.limit_per_hour)}`],
  ];
  if (s.skipped) rows.push(["Skipped (queue full)", fmtNum(s.skipped)]);
  if (s.input_tokens || s.output_tokens) rows.push(["Tokens", `${fmtNum(s.input_tokens)} in · ${fmtNum(s.output_tokens)} out`]);
  if (s.errors) rows.push(["Errors", fmtNum(s.errors)]);
  if (s.last_error) rows.push(["Last error", s.last_error]);
  kvList($("det-agent-stats"), rows);
}

function detProviderShown(provider) {
  $("det-api").hidden = !DET_API.includes(provider);
  $("det-claude").hidden = provider !== "claude";
  $("det-other").hidden = !["openai", "gemini", "compatible"].includes(provider);
  $("det-base-row").hidden = provider !== "compatible";
  $("det-command").hidden = provider !== "command";
}

function detRender(d, keepEdits = false) {
  detection.data = d;
  $("det-features").textContent = d.features.join(", ");
  detRenderModels(d);
  detRenderAgent(d, keepEdits);
  if (state.detail && window.renderAlertAgent) window.renderAlertAgent(state.detail);
  if (window.renderDetectorSwitch) window.renderDetectorSwitch(d);
}

// After choosing an agent in the detector switcher: once it is set up, switch to it.
async function detMaybeActivate(d) {
  if (!detection.activateOnReady || !d.agent_ready || d.active === "agent" || agentMissing(d)) return;
  detection.activateOnReady = false;
  await detChoose("agent");
}

// The Detection dialog opened on the agent's settings, to set one up (`provider`, or the current one).
async function openAgentSetup(message, provider) {
  $("detection-error").textContent = "";
  $("det-add-status").textContent = "";
  await detLoad();
  const d = detection.data;
  const p = provider || (d ? d.agent.provider : "claude");
  detection.picked = p;
  if (d) {
    detRenderAgent(d, false);
    for (const r of document.querySelectorAll('input[name="det-provider"]')) r.checked = r.value === p;
    detProviderShown(p);
    detFillProvider(p);
  }
  detection.activateOnReady = true;
  $("det-agent-status").textContent = message ||
    "Choose what the agent is, give it a key and a model, tick Send the sessions it reviews, and press Save agent settings.";
  $("detection-dialog").showModal();
  const fieldset = document.querySelector(".det-agent");
  fieldset.classList.add("det-focus");
  fieldset.scrollIntoView({ block: "start" });
  if (!d || !DET_API.includes(p)) return;
  const a = d.agent;
  const needKey = p !== "compatible" && !a.keys_saved[p] && !a.keys_from_environment[p];
  (p === "compatible" && !a.base_url ? $("det-base") : needKey ? $("det-key")
    : !a.models[p] ? (p === "claude" ? $("det-model") : $("det-model-name")) : $("det-consent")).focus();
}

async function detLoad() {
  try {
    detRender(await api("/api/models"));
  } catch (err) {
    $("detection-error").textContent = err.message;
  }
}

async function detChoose(id) {
  $("detection-error").textContent = "";
  try {
    const d = await api("/api/models/active", "POST", { id });
    detRender(d);
    const m = d.models.find((x) => x.id === d.active);
    notice(d.active === "agent" ? "From now on the detection agent reviews unusual new sessions."
      : `From now on new sessions are scored by ${m ? m.name : d.active}.`);
  } catch (err) {
    $("detection-error").textContent = err.message;
    detLoad();
  }
}

async function detRemove(m) {
  if (!window.confirm(`Remove the model ${m.name}? ${m.active ? "The built-in model will be used instead. " : ""}` +
                      "This deletes ANTA's copy of it.")) return;
  try {
    detRender(await api("/api/models/remove", "POST", { id: m.id }));
  } catch (err) {
    $("detection-error").textContent = err.message;
  }
}

// ------------------------------------------------------------ adding a model

function detReadBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",", 2)[1] || "");
    r.onerror = () => reject(new Error("could not read that file"));
    r.readAsDataURL(file);
  });
}

$("det-file-pick").addEventListener("click", () => $("det-file").click());
$("det-file").addEventListener("change", () => {
  const f = $("det-file").files[0];
  $("det-file-name").textContent = f ? `${f.name} (${fmtBytes(f.size)})` : "No file chosen";
  if (f && !$("det-name").value) $("det-name").value = f.name.replace(/\.onnx$/i, "");
  $("det-add-status").textContent = "";
});

$("det-add").addEventListener("click", async (e) => {
  const b = e.currentTarget, status = $("det-add-status");
  const file = $("det-file").files[0];
  if (!file) { status.textContent = "Choose an ONNX file first."; return; }
  if (file.size > DET_MAX_MODEL) { status.textContent = "That file is larger than 64 MB."; return; }
  const fp = Number($("det-fp").value);
  if (!Number.isFinite(fp) || fp < 0.01 || fp > 20) { status.textContent = "The benign alert rate must be between 0.01% and 20%."; return; }
  b.disabled = true;
  status.textContent = "Checking the model and calibrating it on ANTA's benign and attack sessions…";
  try {
    const r = await api("/api/models/upload", "POST", {
      name: $("det-name").value, filename: file.name, direction: $("det-direction").value, fp_rate: fp / 100,
      content: await detReadBase64(file),
    });
    detRender(r);
    const m = r.added;
    status.textContent = `Added ${m.name}: it alerts on ${detPct(m.benign_alert_rate)} of benign sessions and catches ` +
      `${detPct(m.attack_catch_rate)} of the attack sessions (${m.direction} scores are anomalous). Choose it in the list to use it.`;
    $("det-file").value = "";
    $("det-file-name").textContent = "No file chosen";
    $("det-name").value = "";
  } catch (err) {
    status.textContent = "";
    $("detection-error").textContent = `Not added: ${err.message}`;
  } finally {
    b.disabled = false;
  }
});

// ------------------------------------------------------------ the agent

document.querySelectorAll('input[name="det-provider"]').forEach((r) => {
  r.addEventListener("change", () => {
    detection.picked = r.value;
    $("det-model-list").replaceChildren();
    detProviderShown(r.value);
    detFillProvider(r.value);
  });
});
$("det-base").addEventListener("input", () => detConsentLine("compatible"));

function detAgentValues() {
  const rate = Number($("det-rate").value);
  if (!Number.isInteger(rate) || rate < 1 || rate > 1000) throw new Error("Reviews per hour must be a whole number from 1 to 1000.");
  const p = detPicked();
  const values = { provider: p, share_internal: $("det-share").checked, effort: $("det-effort").value, reviews_per_hour: rate };
  if (DET_API.includes(p)) {
    values.consent = $("det-consent").checked;
    values.model = p === "claude" ? $("det-model").value : $("det-model-name").value.trim();
    if (p === "compatible") values.base_url = $("det-base").value.trim();
    if ($("det-key").value.trim()) Object.assign(values, { key_provider: p, api_key: $("det-key").value.trim() });
  }
  return values;
}

async function detSaveAgent() {
  const d = await api("/api/agent/settings", "POST", detAgentValues());
  detection.picked = null;
  detRender(d);
  await detMaybeActivate(d);
  return d;
}

$("det-agent-save").addEventListener("click", async () => {
  $("detection-error").textContent = "";
  try {
    await detSaveAgent();
    $("det-agent-status").textContent = "Agent settings saved.";
  } catch (err) {
    $("detection-error").textContent = err.message;
  }
});

// Saving or forgetting a key keeps what else was typed in the dialog (and the provider picked).
$("det-key-save").addEventListener("click", async () => {
  $("detection-error").textContent = "";
  const key = $("det-key").value.trim();
  if (!key) { $("detection-error").textContent = "Paste the key into the box first."; return; }
  try {
    detection.picked = detPicked();
    const d = await api("/api/agent/settings", "POST", { key_provider: detection.picked, api_key: key });
    detRender(d, true);
    await detMaybeActivate(d);
  } catch (err) {
    $("detection-error").textContent = err.message;
  }
});

$("det-key-forget").addEventListener("click", async () => {
  try {
    detection.picked = detPicked();
    detRender(await api("/api/agent/settings", "POST", { key_provider: detection.picked, api_key: null }), true);
  } catch (err) {
    $("detection-error").textContent = err.message;
  }
});

// The models the provider offers this key (or the server has): saves the typed key and
// server address first, since the list comes from them.
$("det-model-fetch").addEventListener("click", async (e) => {
  const b = e.currentTarget, note = $("det-model-note"), p = detPicked();
  $("detection-error").textContent = "";
  b.disabled = true;
  note.textContent = "Asking for the models…";
  try {
    detection.picked = p;
    const first = {};
    if (p === "compatible") first.base_url = $("det-base").value.trim();
    if ($("det-key").value.trim()) Object.assign(first, { key_provider: p, api_key: $("det-key").value.trim() });
    if (Object.keys(first).length) detRender(await api("/api/agent/settings", "POST", first), true);
    const r = await api("/api/agent/models", "POST", { provider: p });
    const list = $("det-model-list");
    list.replaceChildren(...r.models.map((m) => el("option", { value: m.id }, m.name !== m.id ? m.name : "")));
    note.textContent = r.models.length
      ? `${fmtNum(r.models.length)} models available. Click the Model box (or start typing) to pick one, then press Save agent settings.`
      : "The provider listed no models for this key.";
    $("det-model-name").focus();
  } catch (err) {
    note.textContent = "";
    $("detection-error").textContent = `Couldn't list the models: ${err.message}`;
  } finally {
    b.disabled = false;
  }
});

function detVerdictLine(v) {
  return `${v.verdict} (${Math.round(v.confidence * 100)}% confident): ${v.headline}`;
}

$("det-agent-test").addEventListener("click", async (e) => {
  const b = e.currentTarget, status = $("det-agent-status");
  $("detection-error").textContent = "";
  b.disabled = true;
  status.textContent = "Saving, then asking the agent about a made-up session to 203.0.113.77…";
  try {
    await detSaveAgent();
    const r = await api("/api/agent/test", "POST", {});
    status.textContent = `It works: ${r.verdict.reviewer || "the agent"} judged the test session ${detVerdictLine(r.verdict)}`;
  } catch (err) {
    status.textContent = "";
    $("detection-error").textContent = `The test failed: ${err.message}`;
  } finally {
    b.disabled = false;
    detLoad();
  }
});

window.openDetection = async () => {
  detection.picked = null;
  $("detection-error").textContent = "";
  $("det-add-status").textContent = "";
  $("det-agent-status").textContent = "";
  await detLoad();
  $("detection-dialog").showModal();
};
$("detection-form").addEventListener("submit", (e) => { e.preventDefault(); $("detection-dialog").close(); });
$("detection-dialog").addEventListener("close", () => {
  detection.activateOnReady = false;
  document.querySelector(".det-agent").classList.remove("det-focus");
});

// ------------------------------------------------------------ on an alert

function detList(items, label) {
  const ul = el("ul", { class: "evidence", "aria-label": label });
  for (const t of items) ul.append(el("li", {}, t));
  return ul;
}

window.renderAlertAgent = (a) => {
  const v = a.agent || a.agent_review;
  const ready = !!(detection.data && detection.data.agent_ready);
  $("d-agent").hidden = !v && !ready;
  $("d-agent-ask").hidden = !ready || a.kind === "agent";
  $("d-agent-ask").textContent = v ? "Ask again" : "Ask the agent about this alert";
  if ($("d-agent").dataset.alert !== a.id) $("d-agent-note").textContent = "";
  $("d-agent").dataset.alert = a.id;
  const body = $("d-agent-body");
  body.replaceChildren();
  if (!v) {
    body.append(el("p", { class: "muted small" }, "The agent hasn't looked at this alert. Asking sends its session to the agent you set up under Detection…"));
    return;
  }
  const head = el("p", { class: "det-verdict" });
  head.append(el("span", { class: `verdict-tag v-${v.verdict}` }, v.verdict),
    document.createTextNode(` ${Math.round(v.confidence * 100)}% confident · ${v.headline}`));
  body.append(head);
  if (v.reasons && v.reasons.length) body.append(el("h4", { class: "det-sub" }, "Why"), detList(v.reasons, "Reasons"));
  if (v.next_steps && v.next_steps.length) body.append(el("h4", { class: "det-sub" }, "What to check next"), detList(v.next_steps, "Next steps"));
  const who = [v.reviewer || "the agent"];
  if (v.model && v.reviewer && !v.reviewer.includes(v.model)) who.push(`answered by ${v.model}`);
  if (v.reviewed_at) who.push(fmtDateTime(v.reviewed_at));
  if (v.usage && (v.usage.input_tokens || v.usage.output_tokens)) {
    who.push(`${fmtNum(v.usage.input_tokens)} + ${fmtNum(v.usage.output_tokens)} tokens`);
  }
  const line = who.join(" · ");
  body.append(el("p", { class: "muted small" }, `${line[0].toUpperCase()}${line.slice(1)}. The agent's verdict is an opinion: check its reasons against the session before acting on it.`));
};

$("d-agent-ask").addEventListener("click", async (e) => {
  const a = state.detail;
  if (!a) return;
  const b = e.currentTarget;
  b.disabled = true;
  $("d-agent-note").textContent = "Asking the agent…";
  try {
    const r = await api(`/api/alerts/${encodeURIComponent(a.id)}/review`, "POST", {});
    a.agent_review = r.verdict;
    $("d-agent-note").textContent = "";
    if (state.detail === a) window.renderAlertAgent(a);
  } catch (err) {
    $("d-agent-note").textContent = `No answer: ${err.message}`;
  } finally {
    b.disabled = false;
  }
});

detLoad();
window.detectionData = () => detection.data;  // (Explain with AI asks whether a model is set up)
