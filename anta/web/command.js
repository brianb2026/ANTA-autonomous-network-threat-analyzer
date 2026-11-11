// The command bar: one box for everything you would otherwise type in three places. It
// reads what was typed and does it:
//   1234, #1234, go to 1234        go to that packet
//   find password                  find text in the packets (the find bar, filled in)
//   10.0.0.5, fe80::1, a MAC       the host panel for it
//   dns, ip.addr == 10.0.0.5       apply the display filter
//   anything else                  ask the capture (the answer opens in the Ask window)
// What it will do is shown at the right as you type. ↑ ↓ go through what was typed before.
"use strict";

const cmdState = { history: [], items: [], active: -1, busy: false, fields: null };
const CMD_KEY = "anta.command.history";
const CMD_EXAMPLES = ["who talked the most?", "what to look at first", "dns", "find password", "1"];
const CMD_FILTER = /==|!=|&&|\|\||>=|<=|\bcontains\b|\bmatches\b|\bin \{|^!|\[\d|^[a-z][a-z0-9_-]*(?:\.[a-z0-9_-]+)+$/i;
const CMD_MAC = /^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;

try { cmdState.history = JSON.parse(localStorage.getItem(CMD_KEY) || "[]").filter((x) => typeof x === "string").slice(0, 30); }
catch { cmdState.history = []; }

// What a line typed into the bar asks for.
function cmdRead(text) {
  const t = text.trim();
  if (!t) return null;
  let m = /^(?:#|(?:go\s*to|goto|packet|frame|pkt|no\.?)\s*#?)?\s*(\d{1,9})$/i.exec(t);
  if (m) return { kind: "frame", n: Number(m[1]), label: `↵ go to packet ${Number(m[1]).toLocaleString()}` };
  m = /^(?:find|search(?:\s+for)?)\s+(.+)$/i.exec(t);
  if (m) return { kind: "find", text: m[1], label: "↵ find in the packets" };
  m = /^(?:host\s+|whois\s+)?(\S+)$/i.exec(t);
  if (m && (ADDR_TOKEN.test(m[1]) && (m[1].includes(".") || m[1].includes(":")) || CMD_MAC.test(m[1]))) {
    return { kind: "host", addr: m[1], label: "↵ host details" };
  }
  if (/^what to look at( first)?\??$|^triage$|^first look$/i.test(t)) return { kind: "first", label: "↵ what to look at first" };
  if (/^(?:replay|time ?machine|play(?: it)? back)$/i.test(t)) return { kind: "replay", label: "↵ replay on the map" };
  if (/^(?:personalit(?:y|ies)|devices?|habits|drift|what changed\??)$/i.test(t)) return { kind: "persona", label: "↵ device personalities" };
  if (/^(?:policy|policies|rules|policy tests?|network rules|firewall|firewall (?:dry run|rules|test)|dry run)$/i.test(t)) {
    return { kind: "policy", label: "↵ network rules" };
  }
  // A rule typed straight in ("block 10.0.0.5", "no ubuntu hosts on the network"): the rules, with it added.
  if (/^(?:block|deny|ban|don'?t let|do not let|keep \S+ off|no \S+ (?:hosts|devices|machines)\b)/i.test(t)) {
    return { kind: "rule", line: t, label: "↵ add to the network rules" };
  }
  if (/^(?:ignored|ignore list|ignored (?:sources?|alerts?|hosts?|addresses))$/i.test(t)) return { kind: "ignored", label: "↵ ignored alert sources" };
  if (/^(?:speed of light|physics|light check|where are the servers\??)$/i.test(t)) return { kind: "tool", tool: "physics", label: "↵ speed of light" };
  if (/^(?:before(?: the)? capture|pre-?history|what happened before(?: (?:the capture|recording|it started))?\??|before recording)$/i.test(t)) return { kind: "tool", tool: "before", label: "↵ before the capture" };
  if (/^(?:devices? that (?:changed|moved) address(?:es)?|changed address(?:es)?|address changes?|same device|moved devices?|mac randomi[sz]ation|private (?:wi-?fi )?address(?:es)?|who had (?:this|that|an?) (?:ip|address)|addresses? that changed hands)$/i.test(t)) return { kind: "tool", tool: "moves", label: "↵ devices that changed address" };
  if (/^(?:(?:certificate of )?quiet|quiet certificate|what (?:could|might) have (?:left|leaked)\??|(?:could anything|did anything) (?:leak|leave)(?: unnoticed)?\??|hidden data|how much could hide\??)$/i.test(t)) return { kind: "tool", tool: "quiet", label: "↵ certificate of quiet" };
  if (/^(?:tamper(?: seal| check)?|seal(?: (?:it|the capture|this))?|was (?:this|it|the capture) (?:edited|changed|tampered(?: with)?)\??|integrity(?: check)?|verify (?:the )?(?:capture|file))$/i.test(t)) return { kind: "tool", tool: "seal", label: "↵ tamper seal" };
  if (/^(?:(?:installed )?software|(?:installed )?programs|outdated(?: software)?|out of date(?: software)?|what software(?: is installed| runs)?\??|versions)$/i.test(t)) return { kind: "tool", tool: "software", label: "↵ installed software" };
  if (/^(?:spell ?check|protocol spell ?check|lint|rfc check|conformance)$/i.test(t)) return { kind: "tool", tool: "lint", label: "↵ protocol spell-check" };
  // A display filter: its syntax, or a field or protocol name (from the filter catalog) on its own.
  const bare = /^!?\(?\s*([a-z][a-z0-9_.-]*)\s*\)?$/i.exec(t);
  if (bare && cmdState.fields) {
    if (cmdState.fields.has(bare[1].toLowerCase())) return { kind: "filter", label: "↵ apply the filter" };
    return { kind: "ask", label: "↵ ask" };  // (zoom.us: a name, not a field)
  }
  if (CMD_FILTER.test(t) && !/\?$/.test(t) && !/\s(?:the|did|does|who|what|how|which)\s/i.test(` ${t} `)) {
    return { kind: "filter", label: "↵ apply the filter" };
  }
  if (/^[a-z][a-z0-9_-]*$/i.test(t)) return { kind: "ask", label: "↵ filter, or ask" };  // ("dns" is a filter; the server knows)
  return { kind: "ask", label: "↵ ask" };
}

function cmdRemember(text) {
  cmdState.history = [text, ...cmdState.history.filter((x) => x !== text)].slice(0, 30);
  try { localStorage.setItem(CMD_KEY, JSON.stringify(cmdState.history)); } catch { /* private window: this session only */ }
}

async function cmdRun(text) {
  const t = text.trim();
  const what = cmdRead(t);
  if (!what || cmdState.busy) return;
  cmdHideList();
  cmdRemember(t);
  const input = $("cmd");
  if (what.kind === "frame") { setView("packets"); window.goToFrame(what.n); input.blur(); return; }
  if (what.kind === "host") { window.openHost(what.addr); return; }
  if (what.kind === "first") { window.showFirstLook(); input.blur(); return; }
  if (what.kind === "replay") { window.openTimeMachine(); input.blur(); return; }
  if (what.kind === "persona") { window.openPersonalities(); input.blur(); return; }
  if (what.kind === "policy") { window.openPolicy(); input.blur(); return; }
  if (what.kind === "ignored") { window.openIgnored(); input.blur(); return; }
  if (what.kind === "rule") { window.openPolicy({ add: what.line }); input.blur(); return; }
  if (what.kind === "tool") { statsTool(what.tool); input.blur(); return; }
  if (what.kind === "find") {
    setView("packets");
    $("find-mode").value = "text";
    $("find-text").value = what.text;
    openFind();
    findPacket(false);
    return;
  }
  if (!sessionActive()) { notice("Open a capture first (or run the demo).", true); return; }
  cmdState.busy = true;
  $("cmd-kind").textContent = what.kind === "filter" ? "checking…" : "reading…";
  try {
    const plan = await api(withFocus("/api/ask"), "POST", { q: t, tz: new Date().getTimezoneOffset() });
    if (plan.source === "filter") {  // a display filter: straight into the packet list
      showPacketsFor(t);
      input.blur();
    } else {
      window.askShow(t, plan);
    }
  } catch (err) {
    notice(err.message, true);
  } finally {
    cmdState.busy = false;
    cmdShowKind();
  }
}

function cmdShowKind() {
  if (!cmdState.fields && !cmdState.loading) {  // (the display-filter fields and protocols, to tell "dns" from "zoom.us")
    cmdState.loading = loadFields().then((list) => {
      if (list && list.length) cmdState.fields = new Set(list.map((f) => String(f.name || f).toLowerCase()));
      cmdState.loading = null;
      if (cmdState.fields) cmdShowKind();
    });
  }
  const what = cmdRead($("cmd").value);
  $("cmd-kind").textContent = what ? what.label : "";
  $("cmd-kind").dataset.kind = what ? what.kind : "";
}

// The list under the bar: what was typed before that matches, or (empty) examples.
function cmdShowList() {
  const input = $("cmd");
  const q = input.value.trim().toLowerCase();
  const past = cmdState.history.filter((x) => !q || (x.toLowerCase().includes(q) && x.toLowerCase() !== q)).slice(0, 8);
  const items = past.map((x) => ({ text: x, note: "" }));
  if (!q) for (const x of CMD_EXAMPLES) if (!items.some((i) => i.text === x)) items.push({ text: x, note: "try" });
  cmdState.items = items.slice(0, 10);
  cmdState.active = -1;
  const list = $("cmd-list");
  list.replaceChildren(...cmdState.items.map((it, i) => {
    const li = el("li", { role: "option", id: `cmd-opt-${i}`, "aria-selected": "false" });
    li.append(el("span", { class: "mono" }, it.text));
    const what = cmdRead(it.text);
    li.append(el("span", { class: "muted small" }, it.note ? `${it.note} · ${what.label.slice(2)}` : what.label.slice(2)));
    li.addEventListener("mousedown", (e) => { e.preventDefault(); input.value = it.text; cmdRun(it.text); });
    return li;
  }));
  list.hidden = !cmdState.items.length;
  input.setAttribute("aria-expanded", String(!list.hidden));
}

function cmdHideList() {
  $("cmd-list").hidden = true;
  $("cmd").setAttribute("aria-expanded", "false");
  $("cmd").removeAttribute("aria-activedescendant");
  cmdState.active = -1;
}

function cmdMove(step) {
  if ($("cmd-list").hidden) cmdShowList();
  const n = cmdState.items.length;
  if (!n) return;
  cmdState.active = (cmdState.active + step + n + 1) % (n + 1) - 1;  // (-1: back to what was typed)
  [...$("cmd-list").children].forEach((li, i) => li.setAttribute("aria-selected", String(i === cmdState.active)));
  if (cmdState.active >= 0) {
    $("cmd").setAttribute("aria-activedescendant", `cmd-opt-${cmdState.active}`);
    $("cmd").value = cmdState.items[cmdState.active].text;
  } else {
    $("cmd").removeAttribute("aria-activedescendant");
  }
  cmdShowKind();
}

window.focusCommand = (text) => {
  const input = $("cmd");
  if (typeof text === "string") input.value = text;
  input.focus();
  input.select();
  cmdShowKind();
};

$("cmd-form").addEventListener("submit", (e) => { e.preventDefault(); cmdRun($("cmd").value); });
$("cmd").addEventListener("input", () => { cmdShowKind(); cmdShowList(); });
$("cmd").addEventListener("focus", () => { cmdShowKind(); cmdShowList(); });
$("cmd").addEventListener("blur", () => setTimeout(cmdHideList, 120));
$("cmd").addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { e.preventDefault(); cmdMove(1); }
  else if (e.key === "ArrowUp") { e.preventDefault(); cmdMove(-1); }
  else if (e.key === "Escape") {
    e.preventDefault();
    if (!$("cmd-list").hidden) cmdHideList();
    else $("cmd").blur();
  }
});
