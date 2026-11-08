// The host panel: everything about one address in one place, opened from wherever the
// address was clicked (an alert, a packet, a story, a statistics row, an Ask answer): what
// it is, who it talked to, its alerts, files and clear-text logins, and the next steps
// (its packets, a focus on it, Explain, pin it to the investigation).
// Everything from the network is rendered with textContent, never innerHTML.
"use strict";

const hostPanel = { addr: null, seq: 0, data: null, back: null };

function hostBtn(label, fn, cls = "tb small") {
  const b = el("button", { type: "button", class: cls }, label);
  b.addEventListener("click", fn);
  return b;
}

window.openHost = async (addr) => {
  addr = String(addr || "").trim();
  if (!addr) return;
  const panel = $("host-panel");
  if (panel.hidden) hostPanel.back = document.activeElement;
  hostPanel.addr = addr;
  const seq = ++hostPanel.seq;
  panel.hidden = false;
  panel.replaceChildren(hostHead(addr, "", ""), el("p", { class: "muted host-loading" }, "Reading what the capture says about it…"));
  panel.querySelector(".host-close").focus();
  if (!sessionActive()) {
    panel.append(el("p", { class: "muted" }, "Open a capture first."));
    return;
  }
  try {
    const d = await api(withFocus(`/api/host?${new URLSearchParams({ addr, tz: String(new Date().getTimezoneOffset()) })}`));
    if (seq !== hostPanel.seq) return;
    hostPanel.data = d;
    hostRender(d);
  } catch (err) {
    if (seq !== hostPanel.seq) return;
    panel.replaceChildren(hostHead(addr, "", ""), el("p", { class: "error" }, err.message));
  }
};

function hostClose() {
  const panel = $("host-panel");
  if (panel.hidden) return;
  panel.hidden = true;
  hostPanel.addr = null;
  hostPanel.seq++;
  if (hostPanel.back && hostPanel.back.isConnected) hostPanel.back.focus();
}
window.closeHost = hostClose;

function hostHead(addr, name, sub) {
  const head = el("header", { class: "host-head" });
  const titles = el("div", { class: "host-titles" });
  titles.append(el("h2", { id: "host-panel-title", class: "mono" }, addr));
  if (name || sub) titles.append(el("p", { class: "muted small" }, [name, sub].filter(Boolean).join(" · ")));
  const close = el("button", { type: "button", class: "pane-btn host-close", title: "Close (Esc)", "aria-label": "Close the host panel" }, "✕");
  close.addEventListener("click", hostClose);
  head.append(titles, close);
  return head;
}

function hostSection(title, count) {
  const sec = el("section", { class: "host-sec" });
  const h = el("h3", {}, title);
  if (count != null) h.append(el("span", { class: "count" }, String(count)));
  sec.append(h);
  return sec;
}

function hostRender(d) {
  const panel = $("host-panel");
  const worst = d.alerts[0];
  const head = hostHead(d.addr, d.name, d.device || (d.kind === "public" ? "Internet host" : ""));
  if (worst) head.querySelector(".host-titles").prepend(el("span", { class: `sev sev-${worst.severity}` }, SEV_LABEL[worst.severity]));
  const actions = el("div", { class: "host-actions", role: "toolbar", "aria-label": "Next steps" });
  actions.append(
    hostBtn("Show its packets", () => { hostClose(); showPacketsFor(d.filter); }, "tb small tb-primary"),
    hostBtn("Focus on it", () => hostFocus(d)),
    hostBtn("Explain…", () => window.openExplain({ dfilter: d.filter }, d.addr)));
  if (d.ip) actions.append(hostBtn("In Hosts", () => { hostClose(); window.showAsset(d.ip); }),
    hostBtn("On the map", () => { hostClose(); window.mapFocus(d.ip); }),
    hostBtn("Map of who it talks with", () => { hostClose(); window.mapFocusOn(d.ip, true); }));
  actions.append(hostBtn("📌 Pin", () => hostPin(d)), hostBtn("Copy", () => copyText(d.addr)));
  actions.append(hostBtn("Block it…", () => { hostClose(); window.openPolicy({ add: `block ${d.addr}` }); }));
  if (d.alerts.length) actions.append(hostBtn("Ignore its alerts…", () => { hostClose(); window.openIgnored(d.addr); }));
  const body = el("div", { class: "host-body" });
  if (d.scoped) body.append(el("p", { class: "muted small" }, "Within the focused packets."));
  if (d.personality) {
    const pers = el("div", { class: `host-persona${d.alerts.some((a) => ["critical", "high"].includes(a.severity) && a.verdict !== "false_positive") ? " malicious" : ""}` });
    pers.append(el("p", {}, d.personality.sentence));
    for (const c of d.personality.changes || []) {
      const line = el("p", { class: `small persona-change${c.notable ? " notable" : ""}` });
      line.append(el("span", { "aria-hidden": "true" }, c.notable ? "▲ " : "· "), document.createTextNode(c.what));
      if (c.filter) {
        const b = el("button", { type: "button", class: "link" }, "show");
        b.addEventListener("click", () => { hostClose(); showPacketsFor(c.filter); });
        line.append(" ", b);
      }
      pers.append(line);
    }
    body.append(pers);
  }
  if (d.lines.length) {
    const p = el("div", { class: "host-lines" });
    for (const line of d.lines) p.append(el("p", {}, line));
    body.append(p);
  }
  if (d.facts.length) {
    const dl = el("dl", { class: "kv host-facts" });
    for (const [k, v] of d.facts) dl.append(el("dt", {}, k), el("dd", {}, v));
    body.append(dl);
  }

  const talk = d.peers && d.peers.rows && d.peers.rows.length ? d.peers : null;
  const sec = hostSection("Talked to", talk ? d.peer_count : null);
  if (talk) {
    const table = el("table", { class: "data-table host-peers" });
    const thead = el("thead");
    const hr = el("tr");
    for (const [i, c] of ["Host", "Sent", "Received", "Packets"].entries()) hr.append(el("th", { class: i ? "num" : "" }, c));
    thead.append(hr);
    const tb = el("tbody");
    for (const r of talk.rows) {
      const tr = el("tr", { class: "ask-go", tabindex: "0", title: `Their packets: ${r.filter}` });
      const host = el("td");
      const peer = r.host;
      const link = el("button", { type: "button", class: "addr-link", title: `${peer}: host details` }, r.cells[0]);
      link.addEventListener("click", (e) => { e.stopPropagation(); window.openHost(peer); });
      host.append(link);
      tr.append(host, el("td", { class: "num" }, r.cells[1]), el("td", { class: "num" }, r.cells[2]), el("td", { class: "num" }, r.cells[3]));
      const go = () => { hostClose(); showPacketsFor(r.filter); };
      tr.addEventListener("click", go);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); go(); } });
      tb.append(tr);
    }
    table.append(thead, tb);
    sec.append(table);
    if (talk.note) sec.append(el("p", { class: "muted small" }, talk.note));
    const more = hostBtn("All its conversations", () => { hostClose(); statsTool("conversations", d.filter); }, "link");
    sec.append(more);
  } else {
    sec.append(el("p", { class: "muted small" }, d.peer_lines[0] || "No conversations in these packets."));
  }
  body.append(sec);

  const al = hostSection("Alerts", d.alerts.length);
  if (d.alerts.length) {
    const ul = el("ul", { class: "host-list" });
    for (const a of d.alerts.slice(0, 10)) {
      const li = el("li");
      const b = el("button", { type: "button", class: "host-item", title: a.headline });
      b.append(el("span", { class: `sev sev-${a.severity}` }, SEV_LABEL[a.severity]), el("span", {}, ` ${a.title}`),
        el("span", { class: "muted small" }, ` ${a.id}${a.verdict !== "new" ? ` · ${VERDICT_LABEL[a.verdict] || a.verdict}` : ""}`));
      b.addEventListener("click", () => { hostClose(); setView("list"); select(a.id); });
      li.append(b);
      ul.append(li);
    }
    al.append(ul);
    if (d.alerts.length > 10) al.append(hostBtn(`All ${d.alerts.length}`, () => { hostClose(); window.showAlertsInvolving(d.ip); }, "link"));
  } else {
    al.append(el("p", { class: "muted small" }, "None."));
  }
  body.append(al);

  if (d.apps && d.apps.length) {
    const ap = hostSection("Applications", d.apps.length);
    const ul = el("ul", { class: "host-list" });
    for (const a of d.apps.slice(0, 8)) {
      const li = el("li", { class: "host-app" });
      li.append(el("span", {}, a.app), el("span", { class: "muted small" }, ` ${a.category} · ${fmtBytes(a.up + a.down)}`));
      ul.append(li);
    }
    ap.append(ul, hostBtn("All its applications", () => { hostClose(); statsTool("apps", d.filter); }, "link"));
    body.append(ap);
  }
  if (d.files.length || d.logins) {
    const fs = hostSection("Files and logins", d.files.length || null);
    if (d.files.length) {
      const ul = el("ul", { class: "host-list" });
      for (const f of d.files.slice(0, 8)) {
        const li = el("li");
        const b = el("button", { type: "button", class: "host-item" });
        if (f.program) b.append(el("span", { class: "tag tag-hit" }, "program"), " ");
        b.append(el("span", {}, f.name), el("span", { class: "muted small" },
          ` ${f.proto} ${f.direction === "upload" ? "to" : "from"} ${f.peer} · ${fmtBytes(f.size)}`));
        b.addEventListener("click", () => { hostClose(); window.showFiles(f.name); });
        li.append(b);
        ul.append(li);
      }
      fs.append(ul);
    }
    if (d.logins) {
      fs.append(hostBtn(`${fmtNum(d.logins)} clear-text login${d.logins === 1 ? "" : "s"} (no passwords shown)`,
        () => { hostClose(); statsTool("logins", d.filter); }, "link"));
    }
    body.append(fs);
  }
  panel.replaceChildren(head, actions, body);
}

async function hostFocus(d) {
  try {
    const within = window.focusScope ? window.focusScope() : "";
    const scope = await api("/api/scope", "POST", { parts: [{ filter: d.filter }], label: `host ${d.addr}`,
      ...(within ? { within } : {}) });
    hostClose();
    focusOn(scope);
  } catch (err) {
    notice(err.message, true);
  }
}

function hostPin(d) {
  window.pinAnswer({
    kind: "host", question: `Host ${d.addr}`, summary: [d.name, d.device].filter(Boolean).join(" · ") || d.addr,
    lines: [...d.lines, ...d.peer_lines.slice(0, 2)],
    table: { columns: ["", ""], rows: d.facts.map((cells) => ({ cells, filter: "" })), facts: true }, filter: d.filter,
  });
}

$("host-panel").addEventListener("keydown", (e) => {
  if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); hostClose(); }
});
window.addEventListener("anta:focus", () => { if (hostPanel.addr) window.openHost(hostPanel.addr); });
