// Quick-tool windows: one analysis tool on a selection, in a small window over the page
// (right-click a selection, or a packet, → Analysis tools). Each window keeps the selection
// it was opened on, whatever happens in the list behind it. Drag its title to move it, its
// corner to resize it; several can be open side by side to compare. "Focus" limits the whole
// analysis to its selection; "Open in Statistics" does that and opens the tool full size.
// Everything from the network is rendered with textContent, never innerHTML.
"use strict";

const QT_STATS = new Set(["properties", "hierarchy", "conversations", "endpoints", "io", "lengths", "expert", "dns", "http",
  "tls", "geo"]);
const QT_MAX = 6;
const qt = { z: 60, open: [] };

function qtTitle(tool) {
  const hit = (window.QUICK_TOOLS || []).find(([t]) => t === tool);
  return hit ? hit[1] : tool;
}

window.openQuickTool = (tool, scope, at = { x: 200, y: 160 }) => {
  if (!scope || !TOOLS[tool]) return;
  while (qt.open.length >= QT_MAX) qtClose(qt.open[0]);
  const box = el("section", { class: "qt", role: "dialog", "aria-label": `${qtTitle(tool)}: ${scope.label}`, tabindex: "-1" });
  const head = el("header", { class: "qt-head" });
  const title = el("div", { class: "qt-title" });
  title.append(el("strong", {}, qtTitle(tool)), el("span", { class: "qt-scope", title: scope.filter_length > 400 ? "" : scope.filter },
    `${fmtNum(scope.count)} ${scope.label}`));
  const focusBtn = el("button", { type: "button", class: "tb small", title: "Limit the whole analysis to these packets" }, "Focus");
  const openBtn = el("button", { type: "button", class: "tb small", title: "Focus on these packets and open this tool in Statistics" },
    "Open in Statistics");
  const close = el("button", { type: "button", class: "qt-x", "aria-label": "Close" }, "✕");
  const again = el("button", { type: "button", class: "tb small", title: "Read the data again" }, "⟳");
  head.append(title, el("span", { class: "spacer" }), again, focusBtn, openBtn, close);
  const body = el("div", { class: "qt-body" });
  box.append(head, body);
  document.body.append(box);

  const w = { tool, scope, box, body, data: null, geo: null, error: "", state: {}, seq: 0, width: 0 };
  qt.open.push(w);
  const n = qt.open.length - 1;
  const width = Math.min(680, window.innerWidth - 24), height = Math.min(460, window.innerHeight - 80);
  box.style.width = `${width}px`;
  box.style.height = `${height}px`;
  box.style.left = `${Math.max(8, Math.min(at.x + 16 + n * 24, window.innerWidth - width - 8))}px`;
  box.style.top = `${Math.max(8, Math.min(at.y - 40 + n * 24, window.innerHeight - height - 8))}px`;
  qtFront(w);

  box.addEventListener("mousedown", () => qtFront(w));
  close.addEventListener("click", () => qtClose(w));
  again.addEventListener("click", () => {
    invForgetAll(w.scope.id);
    w.state.flowKey = "";
    w.data = null;
    qtLoad(w, true);
  });
  focusBtn.addEventListener("click", () => { qtFocus(w); });
  openBtn.addEventListener("click", () => {
    qtFocus(w);
    stats.tool = tool;
    setView("stats");
    statsRender();
    qtClose(w);
  });
  box.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !e.target.closest("input, select, textarea")) { e.preventDefault(); e.stopPropagation(); qtClose(w); }
  });
  // Move: drag the title bar.
  head.addEventListener("mousedown", (e) => {
    if (e.button !== 0 || e.target.closest("button")) return;
    e.preventDefault();
    const r = box.getBoundingClientRect();
    const dx = e.clientX - r.left, dy = e.clientY - r.top;
    const move = (ev) => {
      box.style.left = `${Math.max(0, Math.min(ev.clientX - dx, window.innerWidth - 80))}px`;
      box.style.top = `${Math.max(0, Math.min(ev.clientY - dy, window.innerHeight - 32))}px`;
    };
    const up = () => { document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); };
    document.addEventListener("mousemove", move);
    document.addEventListener("mouseup", up);
  });
  // Charts are drawn to the window's width: draw again when it is resized.
  let timer = null;
  w.observer = new ResizeObserver(() => {
    const wd = Math.round(body.clientWidth);
    if (Math.abs(wd - w.width) < 24) return;
    w.width = wd;
    clearTimeout(timer);
    timer = setTimeout(() => { if (["io", "flow", "rhythm"].includes(tool)) qtRender(w); }, 120);
  });
  w.observer.observe(body);
  qtLoad(w);
  box.focus();
};

function qtFront(w) {
  w.box.style.zIndex = String(++qt.z);
  for (const o of qt.open) o.box.classList.toggle("qt-front", o === w);
}

function qtClose(w) {
  w.observer?.disconnect();
  w.box.remove();
  qt.open = qt.open.filter((o) => o !== w);
}
window.closeQuickTools = () => { for (const w of [...qt.open]) qtClose(w); };

function qtFocus(w) {
  if (window.focusScope() !== w.scope.id) window.focusOn(w.scope);
}

// Where the tools draw: this window, its selection, its own state (the flow graph's filter).
function qtRx(w) {
  return {
    main: false,
    rerender: () => qtRender(w),
    reload: () => qtLoad(w, true),
    scope: () => w.scope.id,
    filter: () => "",
    geo: () => w.geo,
    state: w.state,
    showPackets: (expr) => { qtFocus(w); showPacketsFor(expr); },
  };
}

async function qtLoad(w, force = false) {
  if (!QT_STATS.has(w.tool)) { qtRender(w); return; }
  if (w.data && !force) { qtRender(w); return; }
  const seq = ++w.seq;
  w.body.replaceChildren(el("p", { class: "muted" }, "Computing…"));
  const params = new URLSearchParams({ scope: w.scope.id });
  if (stats.interval) params.set("interval", String(stats.interval));
  try {
    const res = await api(`/api/stats?${params}`);
    if (seq !== w.seq) return;
    w.data = res.stats;
    w.geo = res.geo || null;
    w.error = "";
  } catch (err) {
    if (seq !== w.seq) return;
    w.error = err.message;
  }
  qtRender(w);
}

function qtRender(w) {
  if (!w.box.isConnected) return;
  const body = w.body;
  const top = body.scrollTop;
  body.replaceChildren();
  if (w.error) { body.append(el("p", { class: "error" }, w.error)); return; }
  const rx = qtRx(w);
  if (QT_STATS.has(w.tool)) {
    if (!w.data) { body.append(el("p", { class: "muted" }, "Computing…")); return; }
    withRx(rx, () => TOOLS[w.tool](body, w.data));
  } else {
    withRx(rx, () => TOOLS[w.tool](body));
  }
  body.scrollTop = top;
}
