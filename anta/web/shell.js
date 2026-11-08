// The application shell, as desktop analysis tools lay it out (Wireshark, Ghidra): a
// menu bar, a toolbar with the detector switcher, panes with title bars that explain
// themselves (?) and open in a window of their own (⧉), so statistics, charts and the
// map can sit side by side. A pop-out window is this same page showing one view.
// Network-derived text is rendered with textContent only, as everywhere else.
"use strict";

const SVG_POP = '<path d="M9.5 2.5h4v4M13.5 2.5l-6 6M11.5 9.5v4h-9v-9h4"/>';

function shellIcon(paths) {
  const s = document.createElementNS(SVG_NS, "svg");
  s.setAttribute("viewBox", "0 0 16 16");
  s.setAttribute("aria-hidden", "true");
  s.setAttribute("focusable", "false");
  s.setAttribute("fill", "none");
  s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "1.4");
  s.setAttribute("class", "ico");
  // (static markup from this file, never from the network)
  s.innerHTML = paths;
  return s;
}

// ------------------------------------------------------------ what each pane is

const HELP = {
  alerts: ["Alerts", "Everything ANTA found, most severe first. List shows one row per finding: what kind, which hosts, and how sure ANTA is; click a row to see why. Story links each device's alerts into one account, in the order things happened and the stage of an attack they belong to. Click an address for everything about that host. Sweep indicators… looks for the addresses, domains and hashes of a threat report in the capture. A source that keeps raising alerts you don't need (a central router, say): open one of its alerts and use Ignore its source ▾; the N ignored chip shows them again. Critical and High are worth checking first; Low is context."],
  detail: ["Alert detail", "With no alert open, what to look at first: the worst findings, each with the next step. With one open: why it was raised, in plain words, with the evidence it rests on and the charts behind it. Set a verdict (Confirmed, False positive…) and keep notes; both go in the investigation and the incident report."],
  stream: ["Stream", "The connection the alert is about: its addresses, timing, DNS names and TLS fingerprint. Explain describes what happened on it; Show packets opens its packets; Download context saves them as a .pcap for Wireshark."],
  packets: ["Packet list", "Every packet of the capture, one per row, as Wireshark lists it. Type a display filter above (for example dns, or ip.addr == 10.0.0.5) to show only some. Click a packet to see inside it; right-click for filters and Follow Stream. Select several to analyse just those: drag across rows, Shift-click for a range, Ctrl/⌘-click to add or remove one, double-click an address for every packet involving it, Ctrl/⌘+A for all. Right-click the selection to focus every view on it, open an analysis tool on it in a small window, or explain it (plainly, or with an AI model). The bar that appears leads back to the whole capture (or press Esc)."],
  tree: ["Packet details", "The selected packet taken apart layer by layer, from the Ethernet frame up to the application. Click a field to highlight its bytes; right-click it to filter on its value."],
  bytes: ["Packet bytes", "The raw bytes of the selected packet in hexadecimal, with their printable characters. The field you click above is highlighted here."],
  stats: ["Statistics", "Tables and charts about the whole capture: who talked to whom (Conversations, Endpoints), which protocols (Protocol hierarchy), traffic over time (I/O graph) and problems Wireshark-style (Expert information). Pick one on the left; ⧉ opens it in its own window so you can keep several in view."],
  map: ["Network map", "The hosts in the capture and the conversations between them. Each shape is a kind of device (router, server, client, internet host); bigger means more traffic. Click a host for what ANTA thinks it is and why, its packets, and to focus the map on it: that host, or it and every host it talks to and that talks to it, lit up while the rest fades back. Shift-click hosts to add them to the focus or take them out; Clear the focus goes back. Table shows the same hosts as a list; the host you picked stays picked."],
  host: ["Host details", "What the selected host probably is, the evidence for it, and who it talked to."],
  assets: ["Hosts", "The devices seen in the traffic, with their operating system, vendor and services where the traffic gives them away. Found passively: nothing is sent to any device. Map shows the same hosts and who talks to whom; the host you picked stays picked."],
  device: ["Device details", "How the selected device was identified, piece by piece."],
  files: ["Files", "Files the capture carries (HTTP downloads, SMB copies, FTP transfers), like Wireshark's Export Objects, with their SHA-256 to look up. Save one to examine it; never run it."],
  story: ["Storyline", "The alerts about each device linked into one story: what happened first and what followed, through the stages of an attack (scouting, getting in the middle, delivery, calling home, spreading, data leaving). Read the account at the top of a story, then click its steps for the evidence. When one device spreads to another, their stories link."],
  hunt: ["Indicators", "Paste indicators from a threat report (addresses, domains, URLs, hashes) and sweep the capture for them. Everything is matched on this computer."],
  intel: ["Threat intelligence feeds", "Published lists of known-bad addresses, domains and files. A feed is downloaded only when you press Update; every session is then checked against it."],
  "hunt-results": ["Results", "Which indicators turned up in the capture, and where."],
};

let helpPop = null;
function closeHelp() {
  if (helpPop) helpPop.remove();
  helpPop = null;
}

function showHelp(btn, key) {
  closeHelp();
  const [title, text] = HELP[key] || ["Help", ""];
  helpPop = el("div", { class: "help-pop", role: "dialog", "aria-label": title });
  const close = el("button", { type: "button", class: "pane-btn", "aria-label": "Close" }, "✕");
  close.addEventListener("click", () => { closeHelp(); btn.focus(); });
  const head = el("div", { class: "help-pop-head" });
  head.append(el("strong", {}, title), close);
  helpPop.append(head, el("p", {}, text));
  document.body.append(helpPop);
  const r = btn.getBoundingClientRect();
  const w = helpPop.offsetWidth;
  helpPop.style.left = `${Math.max(8, Math.min(window.innerWidth - w - 8, r.right - w))}px`;
  helpPop.style.top = `${Math.min(window.innerHeight - helpPop.offsetHeight - 8, r.bottom + 4)}px`;
  close.focus();
}

document.addEventListener("mousedown", (e) => { if (helpPop && !helpPop.contains(e.target)) closeHelp(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && helpPop) closeHelp(); });

// ------------------------------------------------------------ pop-out windows

const POPOUT = new URLSearchParams(location.search);
const POP_VIEW = POPOUT.get("popout");
const POP_TITLES = { alerts: "Alerts", alert: "Alert detail", story: "Storyline", packets: "Packets", stats: "Statistics", hosts: "Hosts",
  map: "Network map", assets: "Hosts", files: "Files" };

function popOut(spec) {
  const q = new URLSearchParams({ popout: spec.view });
  for (const k of ["tool", "id", "card", "stream", "flow", "filter"]) if (spec[k] != null && spec[k] !== "") q.set(k, spec[k]);
  const scope = window.focusScope ? window.focusScope() : "";
  if (scope) q.set("scope", scope);  // (the window opens on the same focus)
  const title = spec.title || POP_TITLES[spec.view] || "ANTA";
  if (state.app && state.app.native) {  // the desktop app opens it as a window of its own
    api("/api/native/popout", "POST", { query: q.toString(), title })
      .then((r) => { if (!r.ok) notice("That window couldn't be opened.", true); })
      .catch((err) => notice(`That window couldn't be opened: ${err.message}`, true));
    return;
  }
  const w = window.open(`/?${q}`, "_blank", "popup=yes,width=1100,height=760");
  if (!w) notice("The browser blocked the new window: allow pop-ups for ANTA.", true);
}

// What a pane's ⧉ opens: the view it belongs to, with the statistics tool or alert shown.
function popSpec(view, card) {
  if (view === "stats") {  // (with what the tool is showing: its stream, its filter)
    const name = document.querySelector(`.stats-nav button[data-tool="${stats.tool}"]`);
    return { view, tool: stats.tool, title: `Statistics: ${name ? name.textContent : ""}`, filter: stats.filter,
      stream: stats.tool === "tcpgraph" ? graphs.tcpStream : null, flow: stats.tool === "flow" ? graphs.flowFilter : null };
  }
  if (view === "alert") {
    if (!state.selected) { notice("Select an alert first.", true); return null; }
    const a = state.alerts.get(state.selected);
    const what = card === "chart" ? ($("chart-title").textContent || "Chart") : card === "timeline" ? "Session timeline" : "Alert";
    return { view, id: state.selected, card, title: `${what}: ${a ? a.title : state.selected} (${state.selected})` };
  }
  if (view === "alerts" && state.alertsMode === "story") return { view: "story" };
  if (view === "hosts") return { view: state.hostsMode === "map" ? "map" : "assets" };
  return { view };
}

function paneTools() {
  for (const host of document.querySelectorAll("[data-help], [data-popout]")) {
    if (host.querySelector(":scope > .pane-tools")) continue;
    const tools = el("span", { class: "pane-tools" });
    const heading = host.querySelector("h2, h3");
    const name = (HELP[host.dataset.help] || [])[0] ||
      (heading && heading.firstChild ? heading.firstChild.textContent : "") || "this pane";
    if (host.dataset.help) {
      const b = el("button", { type: "button", class: "pane-btn pane-help", title: "What is this?",
        "aria-label": `What is ${name.trim()}?` }, "?");
      b.addEventListener("click", () => showHelp(b, host.dataset.help));
      tools.append(b);
    }
    if (host.dataset.popout) {
      const b = el("button", { type: "button", class: "pane-btn", title: "Open in a new window",
        "aria-label": `Open ${name.trim()} in a new window` });
      b.append(shellIcon(SVG_POP));
      b.addEventListener("click", () => {
        const spec = popSpec(host.dataset.popout, host.dataset.card);
        if (spec) popOut(spec);
      });
      tools.append(b);
    }
    host.append(tools);
  }
}

// Read the view's data again: the View menu's Refresh (F5, Ctrl/⌘+R), and a pop-out window's bar.
function refreshView(view = state.view) {
  if (!sessionActive()) return;
  switch (view) {
    case "packets":
      if (!pkt.follow) { pkt.total = null; pktLoad(pkt.from, { keepStack: true, before: pkt.before }); }
      break;
    case "stats":
      invForgetAll();
      graphs.flowKey = "";
      graphs.tcpKey = "";
      statsLoad(true);
      break;
    case "hosts":
      if (state.hostsMode === "map") statsLoad(true);
      else assetsLoad(true);
      break;
    case "files": filesLoad(true); break;
    case "alerts":
      if (state.alertsMode === "story") storyLoad(true);
      api("/api/alerts").then((list) => { upsert(list); if (state.selected) select(state.selected); }).catch((err) => notice(err.message, true));
      if (!state.selected && window.firstLook) window.firstLook(true);
      break;
    default: if (viewHooks[view]) viewHooks[view]();
  }
}

// This page as a pop-out window: only its view, kept live like the main window, with a bar
// that names it, refreshes it and (opened on a focus) says so and leads back to the whole capture.
function enterPopout() {
  if (!POP_VIEW || !POP_TITLES[POP_VIEW]) return;
  document.body.classList.add("popout");
  document.body.dataset.popout = POP_VIEW;
  const bar = el("div", { class: "pop-bar", role: "toolbar", "aria-label": "Window" });
  const refresh = el("button", { type: "button", class: "tb small", title: "Read this view's data again (F5)" }, "⟳ Refresh");
  refresh.addEventListener("click", () => refreshView());
  const leave = el("button", { type: "button", class: "tb small", id: "pop-leave", hidden: "" }, "✕ Whole capture");
  leave.addEventListener("click", () => window.focusBack(0));
  bar.append(el("strong", { id: "pop-title" }), el("span", { class: "pop-scope", id: "pop-scope" }), el("span", { class: "spacer" }),
    leave, refresh);
  document.body.prepend(bar);
  const card = POPOUT.get("card");
  if (card === "chart" || card === "timeline") document.body.dataset.card = card;
  setView(POP_VIEW === "alert" ? "alerts" : POP_VIEW);
  if (POP_VIEW === "alerts") setAlertsMode("list");
  let title = POP_TITLES[POP_VIEW];
  if (POP_VIEW === "stats") {
    const tool = POPOUT.get("tool");
    if (POPOUT.get("filter")) { stats.filter = POPOUT.get("filter"); $("stats-filter").value = stats.filter; }
    if (/^\d+$/.test(POPOUT.get("stream") || "")) graphs.tcpStream = Number(POPOUT.get("stream"));
    if (POPOUT.has("flow")) graphs.flowFilter = POPOUT.get("flow");
    if (tool && TOOLS[tool]) {
      stats.tool = tool;
      statsRender();
      title = `Statistics: ${$("stats-title").textContent}`;
    }
  }
  if (POP_VIEW === "alert") {
    const id = POPOUT.get("id");
    if (id) {
      select(id);
      title = `Alert ${id}`;
    }
  }
  document.title = `${title} — ANTA`;
  $("pop-title").textContent = title;  // (a focus it was opened on: selection.js, which loads after this)
}

// ------------------------------------------------------------ the detector switcher

const CLAUDE_MODELS = [["claude-opus-5-5", "Claude Opus 5.5"], ["claude-sonnet-5-5", "Claude Sonnet 5.5"],
  ["claude-haiku-5-5", "Claude Haiku 5.5"]];

function detectorChoices(d) {
  const out = [];
  for (const m of d.models) {
    if (m.kind === "builtin") out.push({ value: "model:builtin", label: "Built-in model (Isolation Forest)", disabled: m.missing });
    else if (m.kind === "onnx") out.push({ value: `model:${m.id}`, label: `Your model: ${m.name}` });
  }
  const a = d.agent;
  const models = [...CLAUDE_MODELS];
  if (a.models.claude && !models.some(([id]) => id === a.models.claude)) models.push([a.models.claude, a.models.claude]);
  for (const [id, name] of models) out.push({ value: `agent:claude:${id}`, label: `Agent: ${name}` });
  // The other providers, once a model is chosen for them in the Detection dialog.
  if (a.models.openai) out.push({ value: `agent:openai:${a.models.openai}`, label: `Agent: OpenAI ${a.models.openai}` });
  if (a.models.gemini) out.push({ value: `agent:gemini:${a.models.gemini}`, label: `Agent: Gemini ${a.models.gemini}` });
  if (a.models.compatible && a.base_url) {
    out.push({ value: `agent:compatible:${a.models.compatible}`, label: `Agent: ${a.models.compatible} at ${a.server}` });
  }
  if (a.command_configured) out.push({ value: "agent:command", label: `Agent: ${a.command_name}` });
  out.push({ value: "agent:setup", label: "Agent: another AI model (OpenAI, Gemini, local)…" });
  out.push({ value: "manage", label: "Add a model, agent settings…" });
  return out;
}

function detectorCurrent(d) {
  if (d.active !== "agent") return `model:${d.active}`;
  const p = d.agent.provider;
  return p === "command" ? "agent:command" : `agent:${p}:${d.agent.models[p]}`;
}

window.renderDetectorSwitch = (d) => {
  const sel = $("det-switch");
  const current = detectorCurrent(d);
  sel.replaceChildren();
  for (const c of detectorChoices(d)) {
    const o = el("option", { value: c.value }, c.label);
    if (c.disabled) o.disabled = true;
    sel.append(o);
  }
  sel.value = current;
  const problem = d.model_error || (d.active === "agent" && !d.agent_ready ? "the agent isn't set up yet" : "");
  sel.classList.toggle("warn-field", !!problem);
  sel.title = problem ? `Detector: ${problem}` : "What looks at every session besides the rule-based detectors: switch here";
  if (shellMenus) shellMenus.refresh();
};

async function switchDetector(value) {
  const d = detection.data;
  if (!d) return;
  try {
    if (value.startsWith("model:")) {
      await detChoose(value.slice(6));
      return;
    }
    if (value === "manage") {  // (the Detection dialog; the switch keeps what is in use)
      $("det-switch").value = detectorCurrent(d);
      window.openDetection();
      return;
    }
    if (value === "agent:setup") {  // (pick the provider in the dialog)
      $("det-switch").value = detectorCurrent(d);
      openAgentSetup("Choose OpenAI, Google Gemini or an OpenAI-compatible server (for a model on this computer), " +
        "give it what it asks for and press Save agent settings; ANTA switches to it then.",
        ["openai", "gemini", "compatible"].includes(d.agent.provider) ? d.agent.provider : "openai");
      return;
    }
    const m = /^agent:(claude|openai|gemini|compatible):(.*)$/.exec(value);
    const r = await api("/api/agent/settings", "POST", m ? { provider: m[1], model: m[2] } : { provider: "command" });
    detRender(r);
    const missing = agentMissing(r);
    if (missing) {
      openAgentSetup(`To use ${detAgentName(r.agent)}, ${missing}. Fill it in below and press Save agent settings; ANTA switches to it then.`,
        r.agent.provider);
      return;
    }
    await detChoose("agent");
  } catch (err) {
    notice(err.message, true);
    detLoad();
  }
}

$("det-switch").addEventListener("change", (e) => switchDetector(e.target.value));

// --------------------------------------------------------------- getting started

const HELP_TABS = [["start", "Getting started"], ["protocols", "Protocols"], ["keys", "Keyboard shortcuts"], ["about", "About ANTA"]];

// Help, as one window with tabs; `arg` opens a protocol on the Protocols tab.
function helpDialog(kind = "start", arg = null) {
  let dlg = $("help-dialog");
  if (!dlg) {
    dlg = el("dialog", { id: "help-dialog", class: "wide help-dialog", "aria-labelledby": "help-title" });
    document.body.append(dlg);
  }
  dlg.replaceChildren();
  const close = el("button", { type: "button", class: "tb tb-primary" }, "Close");
  close.addEventListener("click", () => dlg.close());
  const actions = el("div", { class: "dialog-actions" });
  actions.append(close);
  const tabs = el("div", { class: "subtabs help-tabs", role: "tablist", "aria-label": "Help" });
  for (const [k, label] of HELP_TABS) {
    const b = el("button", { type: "button", role: "tab", class: "subtab", "aria-selected": String(k === kind), id: `help-tab-${k}` }, label);
    b.addEventListener("click", () => helpDialog(k));
    tabs.append(b);
  }
  tabs.addEventListener("keydown", (e) => {  // (← → move between the tabs)
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    const i = HELP_TABS.findIndex(([k]) => k === kind);
    const next = HELP_TABS[(i + (e.key === "ArrowRight" ? 1 : HELP_TABS.length - 1)) % HELP_TABS.length][0];
    helpDialog(next);
    $(`help-tab-${next}`)?.focus();
  });
  const panel = el("div", { class: `help-panel help-${kind}`, role: "tabpanel", "aria-labelledby": `help-tab-${kind}` });
  dlg.append(el("h2", { id: "help-title" }, "Help"), tabs, panel, actions);
  if (kind === "keys") {
    const rows = [["Ctrl+O (⌘O)", "Open a capture"], ["Ctrl+S (⌘S)", "Save the capture"], ["Ctrl+1 … Ctrl+5", "Alerts, Packets, Statistics, Hosts, Files"],
      ["Ctrl+K (⌘K)", "The command bar: type a display filter, a question, a packet number, find …, or an address"],
      ["↑ ↓ in the command bar", "What you typed before"], ["F5, Ctrl+R (⌘R)", "Refresh the view (also in a pop-out window)"],
      ["Ctrl+F", "Find a packet (Packets)"], ["Ctrl+G", "Go to a packet (Packets)"], ["Ctrl+M", "Mark the packet, or the selected packets (Packets)"],
      ["Shift+click, Shift+↑ ↓", "Select a range of packets"], ["Ctrl+click (⌘-click)", "Add a packet to the selection, or take it out"],
      ["Ctrl+A (⌘A)", "Select every packet the list shows"], ["Double-click an address", "Select every packet involving it"],
      ["F (with a selection)", "Focus every view on the selected packets"], ["Esc", "Close a menu or dialog; clear the selection; leave the focus"],
      ["↑ ↓ Enter", "Move through and open alerts or packets"], ["Alt+F, Alt+V, …", "Open a menu; the arrow keys move through it"], ["F1", "Help"]];
    const table = el("table", { class: "data-table" });
    const tb = el("tbody");
    for (const [k, v] of rows) {
      const tr = el("tr");
      tr.append(el("td", { class: "mono" }, k), el("td", {}, v));
      tb.append(tr);
    }
    table.append(tb);
    panel.append(table);
  } else if (kind === "about") {
    panel.append(el("p", {}, "ANTA, the Autonomous Network Threat Analyzer, reads packet captures and live traffic, shows them packet by packet the way Wireshark does, and finds what looks like an attack: command-and-control beacons, DNS tunnels, data theft, malicious downloads, scans and spoofing."),
      el("p", { class: "muted" }, "It only observes: nothing is sent to the devices on your network, and nothing leaves this computer unless you turn on a detection agent that uses an online AI provider."));
  } else if (kind === "protocols") {
    renderProtocolGuide(panel, arg);
  } else {
    const steps = [
      ["1. Load some traffic", "Open a capture file (.pcap or .pcapng, from Wireshark or tcpdump), capture live from a network interface, or run the demo: ten minutes of office traffic with five planted attacks."],
      ["2. Start with what to look at first", "With no alert open, the Alerts tab lists the worst findings, each with why it matters and the next step. The alert table lists everything, most severe first (Story shows each device's alerts as one account). Click an alert: the detail says what happened in plain words and shows the evidence."],
      ["3. Ask, filter or jump", "The command bar at the top takes anything: a question (who did 10.0.0.5 talk to the most?), a display filter (dns, ip.addr == 10.0.0.5), a packet number, find password, or an address for everything about that host."],
      ["4. Look at the packets", "The Packets tab shows every packet, as in Wireshark. A display filter narrows it down; Tools ▾ has ready-made filters, the time display, colors, find and TLS decryption. New to a protocol? The Protocols tab here explains each one, and the ? beside a layer in the packet details opens its explanation."],
      ["5. Step back with Statistics and Hosts", "Statistics has tables and charts for the whole capture; Hosts lists the devices, or maps who talks to whom. Click any address for the host panel: what it is, who it talked to, its alerts and files. Every pane's ⧉ button opens it in its own window."],
      ["6. Keep your findings", "Pin answers to the investigation (📌 in Ask and the host panel), write notes, set verdicts on alerts; File → Save investigation keeps them for later and the incident report includes them."],
      ["Choose the detector", "Rule-based detectors always run. The Detector box in the toolbar switches what else looks at every session: the built-in model, a model you added, or a detection agent: Claude, OpenAI or Gemini with your API key, a model running on this computer (Ollama, LM Studio and the like), or your own program."],
      ["Right-click anything", "An address, a domain, a file hash, an alert, a packet, a host on the map: the menu says what ANTA knows about it at a glance and offers the next step (its packets, its alerts, Explain, the map, a sweep for it)."],
      ["Stuck?", "Every pane has a ? button that explains it. Explain… on an alert or a packet describes a connection in plain words."],
    ];
    for (const [h, t] of steps) {
      const sec = el("div", { class: "help-step" });
      sec.append(el("h3", {}, h), el("p", {}, t));
      panel.append(sec);
    }
  }
  if (!dlg.open) dlg.showModal();
  if (kind !== "protocols") $(`help-tab-${kind}`)?.focus();
}

// ------------------------------------------------------------ the menu bar

function clickIf(id) {
  const b = $(id);
  if (b && !b.hidden && !b.disabled) b.click();
}

function goFilter() {
  setView("packets");
  $("pkt-filter").focus();
}

// A statistics tool, optionally limited to a display filter (Ask's "Open Statistics → …").
function statsTool(tool, filter) {
  stats.tool = tool;
  if (typeof filter === "string" && filter !== stats.filter) {
    stats.filter = filter;
    $("stats-filter").value = filter;
  }
  setView("stats");  // (its hook shows the tool, reading the statistics again when the filter changed)
}

const VIEW_NAMES = [["alerts", "Alerts"], ["packets", "Packets"], ["stats", "Statistics"], ["hosts", "Hosts"], ["files", "Files"]];

function menuModel() {
  const d = detection.data;
  const saveShown = !$("btn-save").hidden;
  const focused = !!(window.focusInfo && window.focusInfo());
  return [
    { label: "File", key: "f", items: [
      { label: "Open capture…", hint: "Ctrl+O", run: () => clickIf("btn-open") },
      { label: "Run the demo", run: () => window.runDemo() },
      { label: "Save capture…", hint: "Ctrl+S", run: () => clickIf("btn-save"), disabled: !saveShown },
      { label: "Save share-safe copy…", run: () => window.openSaveDialog(state.view === "packets", true), disabled: !saveShown },
      "-",
      { label: "Investigation: notes and pinned answers…", run: () => window.openCase() },
      { label: "Open investigation…", run: () => window.openCaseFile() },
      { label: "Save investigation…", run: () => window.saveCase() },
      "-",
      { label: "Export alerts as CSV…", run: () => clickIf("alerts-csv") },
      { label: "Incident report…", run: () => clickIf("report-open") },
      "-",
      { label: "Settings…", hint: "flow logs, feeds, GeoIP", run: () => window.openSettings() },
      ...(state.app && state.app.can_quit ? [{ label: "Quit ANTA", run: () => window.quitApp() }] : []),
    ] },
    { label: "View", key: "v", items: [
      ...VIEW_NAMES.map(([v, name], i) => ({ label: name, hint: `Ctrl+${i + 1}`, radio: true, checked: state.view === v,
        run: () => setView(v) })),
      "-",
      { label: "Alerts as each device's story", radio: true, checked: viewIs("story"), run: () => setView("story") },
      { label: "Hosts on the network map", radio: true, checked: viewIs("map"), run: () => setView("map") },
      { label: "Replay the capture on the map (time machine)", run: () => window.openTimeMachine() },
      "-",
      { label: "Refresh this view", hint: "F5", run: () => refreshView() },
      { label: "Open this view in a new window", run: () => {
        const spec = popSpec(state.view);
        if (spec) popOut(spec);
      } },
      { label: "Open the selected alert in a new window", disabled: !state.selected, run: () => {
        const spec = popSpec("alert");
        if (spec) popOut(spec);
      } },
    ] },
    { label: "Capture", key: "c", items: [
      { label: "Live capture…", run: () => clickIf("btn-live") },
      { label: "Stop", run: () => clickIf("btn-stop"), disabled: $("btn-stop").hidden },
      "-",
      { label: "Recordings and the capture buffer…", run: () => window.openSettings() },
    ] },
    { label: "Analyze", key: "a", items: [
      { label: "What to look at first", run: () => window.showFirstLook() },
      { label: "Network rules (tests and firewall)…", hint: "block, allow, check", run: () => window.openPolicy() },
      { label: "Device personalities…", hint: "and what changed", run: () => window.openPersonalities() },
      { label: "Ask, filter or go to…", hint: "Ctrl+K", run: () => window.focusCommand() },
      { label: "Host details…", hint: "an address", run: () => window.focusCommand("") },
      "-",
      { label: "Focus on the selected packets", hint: "F", disabled: !(window.selIsMulti && selIsMulti()),
        run: () => document.getElementById("sel-focus").click() },
      { label: "Back one focus step", hint: "Esc", disabled: !focused, run: () => window.focusBack() },
      { label: "Back to the whole capture", disabled: !focused, run: () => window.focusBack(0) },
      "-",
      { label: "Apply a display filter…", run: goFilter },
      { label: "Filter templates…", run: () => { setView("packets"); window.packetToolsMenu("templates"); } },
      { label: "Coloring rules…", run: () => { setView("packets"); clickIf("pkt-color-rules"); } },
      { label: "Find packet…", hint: "Ctrl+F", run: () => { setView("packets"); clickIf("pkt-find-open"); } },
      { label: "Go to packet…", hint: "Ctrl+G", run: () => { setView("packets"); clickIf("pkt-goto"); } },
      "-",
      { label: "Decrypt TLS with a key log…", run: () => { setView("packets"); clickIf("pkt-keylog"); } },
      { label: "Explain the selected alert…", disabled: !state.detail, run: () => clickIf("explain-alert") },
      { label: "Sweep for indicators…", run: () => window.openHunt() },
    ] },
    { label: "Statistics", key: "s", items: [
      ...[...document.querySelectorAll(".stats-nav button")].map((b) => ({ label: b.textContent,
        radio: true, checked: state.view === "stats" && stats.tool === b.dataset.tool, run: () => statsTool(b.dataset.tool) })),
      "-",
      { label: "Open the current statistics in a new window", run: () => popOut(popSpec("stats")) },
    ] },
    { label: "Detection", key: "d", items: [
      ...(d ? detectorChoices(d).filter((c) => c.value !== "manage").map((c) => ({ label: c.label, radio: true,
        checked: c.value === detectorCurrent(d), disabled: c.disabled, run: () => switchDetector(c.value) })) : [{ label: "Loading…", disabled: true }]),
      "-",
      { label: "Ignored alert sources…", hint: "a router, say", run: () => window.openIgnored() },
      { label: "Detection settings (add a model)…", run: () => window.openDetection() },
      { label: "Set up the detection agent (Claude, OpenAI, Gemini, a local model)…", run: () => openAgentSetup("") },
    ] },
    { label: "Help", key: "h", items: [
      { label: "Getting started", hint: "F1", run: () => helpDialog("start") },
      { label: "Protocols explained", run: () => helpDialog("protocols") },
      { label: "Keyboard shortcuts", run: () => helpDialog("keys") },
      "-",
      { label: "About ANTA", run: () => helpDialog("about") },
    ] },
  ];
}

class MenuBar {
  constructor(bar) {
    this.bar = bar;
    this.open = -1;
    this.menu = null;
    this.buttons = [];
    this.build();
    document.addEventListener("mousedown", (e) => {
      if (this.open >= 0 && !this.bar.contains(e.target) && !(this.menu && this.menu.contains(e.target))) this.close();
    });
    document.addEventListener("keydown", (e) => {
      if (e.altKey && !e.ctrlKey && !e.metaKey) {
        const i = menuModel().findIndex((m) => e.code === `Key${m.key.toUpperCase()}`);
        if (i >= 0) { e.preventDefault(); this.show(i, true); }
      }
    });
    window.addEventListener("resize", () => this.close());
    window.addEventListener("blur", () => this.close());
  }

  build() {
    this.bar.replaceChildren();
    this.buttons = menuModel().map((m, i) => {
      const b = el("button", { type: "button", class: "menu-top", role: "menuitem", "aria-haspopup": "true",
        "aria-expanded": "false", "aria-label": m.label });
      b.append(el("span", { class: "mk" }, m.label[0]), document.createTextNode(m.label.slice(1)));
      b.tabIndex = i === 0 ? 0 : -1;
      b.addEventListener("click", () => (this.open === i ? this.close() : this.show(i, false)));
      b.addEventListener("mouseenter", () => { if (this.open >= 0 && this.open !== i) this.show(i, false); });
      b.addEventListener("keydown", (e) => this.topKey(e, i));
      this.bar.append(b);
      return b;
    });
  }

  refresh() { if (this.open >= 0) this.show(this.open, false); }

  topKey(e, i) {
    const n = this.buttons.length;
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      const j = (i + (e.key === "ArrowRight" ? 1 : n - 1)) % n;
      if (this.open >= 0) this.show(j, true);
      else this.focusTop(j);
    } else if (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      this.show(i, true);
    } else if (e.key === "Escape") this.close();
  }

  focusTop(i) {
    this.buttons.forEach((b, k) => { b.tabIndex = k === i ? 0 : -1; });
    this.buttons[i].focus();
  }

  show(i, focusFirst) {
    this.close(false);
    const model = menuModel()[i];
    const top = this.buttons[i];
    this.open = i;
    top.setAttribute("aria-expanded", "true");
    top.classList.add("open");
    const menu = el("div", { class: "menu", role: "menu", "aria-label": model.label });
    const items = [];
    for (const it of model.items) {
      if (it === "-") { menu.append(el("div", { class: "menu-sep", role: "separator" })); continue; }
      const b = el("button", { type: "button", class: "menu-item", role: it.radio ? "menuitemradio" : "menuitem" });
      if (it.radio) b.setAttribute("aria-checked", String(!!it.checked));
      b.append(el("span", { class: "menu-check", "aria-hidden": "true" }, it.checked ? "●" : ""),
        el("span", { class: "menu-label" }, it.label), el("span", { class: "menu-hint" }, it.hint || ""));
      if (it.disabled) b.disabled = true;
      b.addEventListener("click", () => { this.close(); it.run(); });
      b.addEventListener("keydown", (e) => this.itemKey(e, items, i));
      menu.append(b);
      if (!it.disabled) items.push(b);
    }
    document.body.append(menu);
    const r = top.getBoundingClientRect();
    menu.style.left = `${Math.min(r.left, window.innerWidth - menu.offsetWidth - 4)}px`;
    menu.style.top = `${r.bottom}px`;
    this.menu = menu;
    if (focusFirst && items.length) items[0].focus();
  }

  itemKey(e, items, i) {
    const k = items.indexOf(document.activeElement);
    const n = this.buttons.length;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      items[(k + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length].focus();
    } else if (e.key === "Home" || e.key === "End") {
      e.preventDefault();
      items[e.key === "Home" ? 0 : items.length - 1].focus();
    } else if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      this.show((i + (e.key === "ArrowRight" ? 1 : n - 1)) % n, true);
    } else if (e.key === "Escape") {
      e.preventDefault();
      this.close();
      this.focusTop(i);
    } else if (e.key === "Tab") this.close();
  }

  close(all = true) {
    if (this.menu) this.menu.remove();
    this.menu = null;
    for (const b of this.buttons) { b.setAttribute("aria-expanded", "false"); b.classList.remove("open"); }
    if (all) this.open = -1;
  }
}

const shellMenus = POP_VIEW ? null : new MenuBar($("menubar"));

// ------------------------------------------------------------ shortcuts

document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  // Refresh the view (in a pop-out window too: reloading the page would lose its sign-in ticket).
  if (e.key === "F5" || (mod && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "r")) { e.preventDefault(); refreshView(); return; }
  if (POP_VIEW) return;
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
  if (mod && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "o") { e.preventDefault(); clickIf("btn-open"); }
  else if (mod && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "s") { e.preventDefault(); clickIf("btn-save"); }
  else if (mod && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "k") { e.preventDefault(); window.focusCommand(); }
  else if (mod && !e.altKey && /^[1-5]$/.test(e.key) && !typing) { e.preventDefault(); setView(VIEW_NAMES[Number(e.key) - 1][0]); }
  else if (e.key === "F1") { e.preventDefault(); helpDialog("start"); }
});

paneTools();
enterPopout();
