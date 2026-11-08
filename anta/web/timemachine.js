// The network time machine: replay the capture on the network map. A bar under the map plays
// any stretch of the capture (the whole of it, or From/To times you type or Shift-drag on the
// scrubber) at a multiple of the speed it was captured at (1× is as it happened; any multiple can
// be typed), or jumps to any moment. The map lights up the hosts and
// conversations active around that moment, rings the hosts whose alerts have been raised by
// then, and draws each packet as an arrow flying from its sender to its receiver (red when the
// pair is in an alert; when too many fly at once, one arrow per conversation, sized by count).
// Traffic per moment is the engine's exact I/O count (/api/timeline); the packets come in
// stretches from /api/timeline/packets while it plays.
// Everything from the network is rendered with textContent only.
"use strict";

const tm = { data: null, key: "", t: 0, playing: false, timer: 0, last: 0, on: false, range: null, drawn: 0,
  pk: null, pkLoading: null, arrows: [], alertPairs: new Set(), note: "", speed: 1 };
const TM_WINDOWS = [["10", "the last 10 s"], ["60", "the last minute"], ["300", "the last 5 minutes"], ["all", "everything so far"]];
// Speeds as multiples of the speed the traffic was captured at (1 = as it happened).
const TM_SPEEDS = ["0.01", "0.05", "0.1", "0.25", "0.5", "1", "2", "5", "10", "50", "100"];
const TM_MAX_SPEED = 10000;
const TM_FLIGHT_MS = 650;      // how long an arrow takes to cross
const TM_MAX_SINGLE = 90;      // packets per moment drawn one by one; above that, one arrow per conversation
const TM_FETCH = 12000;        // packets per fetch

// The timeline read belongs to the capture as it was: a live capture that is still running (or
// has stopped since) is read again.
function tmKey() {
  return `${sessionKey()}|${state.session ? state.session.state : ""}|${window.focusScope ? window.focusScope() : ""}`;
}
function tmStale() { return tm.key !== tmKey() || (state.session && state.session.state === "running"); }

function tmRel(t) {
  const s = Math.max(0, t);
  if (s < 60) return `+${s.toFixed(s < 10 ? 2 : 1)} s`;
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
  return `+${h ? `${h}:${String(m).padStart(2, "0")}` : m}:${String(sec).padStart(2, "0")}`;
}

function tmClock(t) {
  const d = tm.data;
  if (!d) return "";
  const date = new Date((d.start + t) * 1000);
  const ms = String(date.getMilliseconds()).padStart(3, "0");
  return `${date.toLocaleTimeString([], { hour12: false })}.${ms} (${tmRel(t)})`;
}

// A time typed in: 10:03:40 (the clock, your time zone), +3:40 or +220 (from the start), 3m40s.
function tmParse(text) {
  const d = tm.data;
  const v = String(text || "").trim().toLowerCase();
  if (!v || !d) return null;
  let m = /^\+?(\d+(?:\.\d+)?)\s*s?$/.exec(v);
  if (m) return Number(m[1]);
  m = /^\+(\d+):(\d{2})(?::(\d{2}(?:\.\d+)?))?$/.exec(v);
  if (m) return m[3] !== undefined ? Number(m[1]) * 3600 + Number(m[2]) * 60 + Number(m[3]) : Number(m[1]) * 60 + Number(m[2]);
  m = /^(?:(\d+)\s*h\s*)?(?:(\d+)\s*m(?:in)?\s*)?(?:(\d+(?:\.\d+)?)\s*s)?$/.exec(v);
  if (m && (m[1] || m[2] || m[3])) return Number(m[1] || 0) * 3600 + Number(m[2] || 0) * 60 + Number(m[3] || 0);
  m = /^(\d{1,2}):(\d{2})(?::(\d{2}(?:\.\d+)?))?\s*(am|pm)?$/.exec(v);
  if (m) {
    let h = Number(m[1]);
    if (m[4] === "pm" && h < 12) h += 12;
    if (m[4] === "am" && h === 12) h = 0;
    const day = new Date(d.start * 1000);
    day.setHours(h, Number(m[2]), 0, 0);
    let rel = day.getTime() / 1000 + Number(m[3] || 0) - d.start;
    if (rel < -43200) rel += 86400;  // (a capture that runs past midnight)
    return rel;
  }
  return null;
}
window.tmParse = tmParse;

function tmRange() { return tm.range || [0, tm.data ? tm.data.duration : 0]; }

async function tmOpen() {
  if (!sessionActive()) { notice("Open a capture first (or run the demo).", true); return; }
  setView("map");
  tm.on = true;
  $("tm-bar").hidden = false;
  $("tm-row2").hidden = false;
  $("tm-events").hidden = false;
  $("tm-toggle").setAttribute("aria-pressed", "true");
  if (!tm.data || tmStale()) {
    tmPause();
    tmClearArrows();
    $("tm-clock").textContent = "Reading the timeline…";
    // The same capture read again (a live one that grew or stopped): keep the moment and the stretch.
    const same = tm.data && tm.key.split("|").slice(0, 2).join("|") === tmKey().split("|").slice(0, 2).join("|")
      ? { start: tm.data.start, t: tm.t, range: tm.range } : null;
    try {
      tm.data = await api(withFocus("/api/timeline"));
      tm.key = tmKey();
    } catch (err) {
      $("tm-clock").textContent = err.message;
      return;
    }
    tm.range = null;
    tm.pk = null;
    tm.pkLoading = null;
    tm.alertPairs = new Set();
    for (const a of tm.data.alerts) {
      for (const x of [a.src, a.offender].filter(Boolean)) {
        if (a.dst) { tm.alertPairs.add(`${x}|${a.dst}`); tm.alertPairs.add(`${a.dst}|${x}`); }
      }
    }
    const first = tm.data.alerts[0];  // (start a little before the first alert, where the story begins)
    tm.t = first ? Math.max(0, first.t - tm.data.interval * 4) : 0;
    if (same) {  // (times are from the capture's start, which a live capture's rotation can move)
      const shift = same.start - tm.data.start, dur = tm.data.duration;
      tm.t = Math.max(0, Math.min(dur, same.t + shift));
      if (same.range) {
        const r = same.range.map((x) => Math.max(0, Math.min(dur, x + shift)));
        tm.range = r[1] - r[0] > 0.001 ? r : null;
      }
    }
    tmFillRange();
  }
  $("map-svg").classList.add("tm-on");
  tmDrawTrack();
  tmApply(true);
  $("tm-track").focus();
}

function tmClose() {
  tmPause();
  tmClearArrows();
  tm.on = false;
  $("tm-bar").hidden = true;
  $("tm-row2").hidden = true;
  $("tm-events").hidden = true;
  $("tm-toggle").setAttribute("aria-pressed", "false");
  const svgEl = $("map-svg");
  svgEl.classList.remove("tm-on");
  for (const x of svgEl.querySelectorAll(".tm-live, .tm-alert")) x.classList.remove("tm-live", "tm-alert");
}
window.closeTimeMachine = tmClose;

// What is active around moment t: hosts and pairs with a connection open in the window.
function tmActive(t) {
  const d = tm.data;
  const w = $("tm-window").value;
  const from = w === "all" ? tmRange()[0] : t - Number(w);
  const hosts = new Set();
  const pairs = new Set();
  for (const s of d.sessions) {
    if (s[0] > t) break;  // (sorted by start)
    if (s[1] < from) continue;
    const a = d.hosts[s[2]], b = d.hosts[s[3]];
    hosts.add(a);
    hosts.add(b);
    pairs.add(a < b ? `${a}|${b}` : `${b}|${a}`);
  }
  return { hosts, pairs, fired: d.alerts.filter((x) => x.t <= t), from };
}

function tmApply(force = false) {
  const d = tm.data;
  if (!d || !tm.on) return;
  const now = performance.now();
  if (!force && now - tm.drawn < 120) return;  // (the map's highlight a few times a second; the arrows every frame)
  tm.drawn = now;
  const t = tm.t;
  const { hosts, pairs, fired, from } = tmActive(t);
  const alertHosts = new Set(fired.flatMap((x) => [x.src, x.offender].filter(Boolean)));
  const svgEl = $("map-svg");
  for (const g of svgEl.querySelectorAll(".node")) {
    const id = g.dataset.id;
    g.classList.toggle("tm-live", hosts.has(id));
    g.classList.toggle("tm-alert", alertHosts.has(id));
  }
  for (const p of svgEl.querySelectorAll(".edge")) {
    const a = p.dataset.a, b = p.dataset.b;
    p.classList.toggle("tm-live", pairs.has(a < b ? `${a}|${b}` : `${b}|${a}`));
  }
  $("tm-clock").textContent = tmClock(t);
  const track = $("tm-track");
  track.setAttribute("aria-valuenow", String(Math.round(t)));
  track.setAttribute("aria-valuetext", tmClock(t));
  const head = $("tm-head");
  if (head) {
    const x = (t / Math.max(1e-9, d.duration)) * 1000;
    head.setAttribute("x1", x.toFixed(1));
    head.setAttribute("x2", x.toFixed(1));
  }
  const box = $("tm-events");
  const recent = [...fired].reverse().slice(0, 3);
  box.replaceChildren(el("span", { class: "muted small" }, `${hosts.size} hosts active · ${fired.length} of ${d.alerts.length} alerts raised by now`
    + ` · ${tmSpeedNote()}` + (tm.note ? ` · ${tm.note}` : "")));
  for (const x of recent) {
    const b = el("button", { type: "button", class: `tm-event${x.t >= from ? " new" : ""}`, title: "Open this alert" });
    b.append(el("span", { class: `sev sev-${x.severity}` }, SEV_LABEL[x.severity] || x.severity),
      el("span", {}, ` ${x.title} `), el("span", { class: "mono muted small" }, `${x.src}${x.dst ? ` → ${x.dst}` : ""} · ${tmClock(x.t).split(" ")[0]}`));
    b.addEventListener("click", () => { tmPause(); setView("list"); select(x.id); });
    box.append(b);
  }
}

function tmDrawTrack() {
  const d = tm.data;
  const svgEl = $("tm-svg");
  const W = 1000, H = 40;
  const max = Math.max(1, ...d.bins.map((b) => b[1]));
  const n = Math.max(1, d.bins.length);
  let path = `M0,${H}`;
  d.bins.forEach((b, i) => {
    const x = (i / n) * W, x2 = ((i + 1) / n) * W, y = H - (b[1] / max) * (H - 4);
    path += `L${x.toFixed(1)},${y.toFixed(1)}L${x2.toFixed(1)},${y.toFixed(1)}`;
  });
  path += `L${W},${H}Z`;
  const span = Math.max(1e-9, d.duration);
  const [r0, r1] = tmRange();
  const parts = [svg("path", { d: path, class: "tm-area" })];
  if (tm.range) {  // (outside the chosen stretch: shaded)
    parts.push(svg("rect", { x: 0, y: 0, width: ((r0 / span) * W).toFixed(1), height: H, class: "tm-out" }),
      svg("rect", { x: ((r1 / span) * W).toFixed(1), y: 0, width: Math.max(0, W - (r1 / span) * W).toFixed(1), height: H, class: "tm-out" }));
  }
  for (const a of d.alerts) {
    const x = (a.t / span) * W;
    const m = svg("line", { x1: x.toFixed(1), x2: x.toFixed(1), y1: 0, y2: H, class: `tm-mark ${a.severity}` });
    m.append(svg("title", {}, `${a.title}: ${a.src}${a.dst ? ` → ${a.dst}` : ""} at ${tmClock(a.t)}`));
    parts.push(m);
  }
  parts.push(svg("line", { id: "tm-head", x1: 0, x2: 0, y1: 0, y2: H, class: "tm-head" }));
  svgEl.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svgEl.setAttribute("preserveAspectRatio", "none");
  svgEl.replaceChildren(...parts);
  const track = $("tm-track");
  track.setAttribute("aria-valuemin", "0");
  track.setAttribute("aria-valuemax", String(Math.round(d.duration)));
}

function tmFillRange() {
  const [r0, r1] = tmRange();
  const short = (t) => tmClock(t).split(" ")[0];
  $("tm-from").value = tm.range ? short(r0) : "";
  $("tm-to").value = tm.range ? short(r1) : "";
  $("tm-from").placeholder = tm.data ? short(0) : "start";
  $("tm-to").placeholder = tm.data ? short(tm.data.duration) : "end";
  $("tm-whole").hidden = !tm.range;
  tmSpeedTitle();
}

function tmSetRange(r0, r1) {
  const d = tm.data;
  r0 = Math.max(0, Math.min(d.duration, r0));
  r1 = Math.max(0, Math.min(d.duration, r1));
  tm.range = Math.abs(r1 - r0) < 0.001 ? null : [Math.min(r0, r1), Math.max(r0, r1)];
  const [a, b] = tmRange();
  if (tm.t < a || tm.t > b) tm.t = a;
  tm.pk = null;
  tmClearArrows();
  tmFillRange();
  tmDrawTrack();
  tmApply(true);
}
window.tmSetRange = tmSetRange;

function tmSeek(clientX) {
  const r = $("tm-track").getBoundingClientRect();
  tm.t = Math.max(0, Math.min(tm.data.duration, ((clientX - r.left) / r.width) * tm.data.duration));
  tmClearArrows();
  tmApply(true);
}

// ------------------------------------------------------------- packets as arrows

function tmArrowLayer() {
  const vp = $("map-svg").querySelector(".map-vp");
  if (!vp) return null;
  let layer = vp.querySelector(".tm-packets");
  if (!layer) { layer = svg("g", { class: "tm-packets" }); vp.append(layer); }
  return layer;
}

function tmClearArrows() {
  for (const a of tm.arrows) a.el.remove();
  tm.arrows = [];
}

// The packets of the stretch around t (fetched ahead while playing), or null until they arrive.
function tmPackets(t) {
  const pk = tm.pk;
  if (pk && t >= pk.from && t < pk.to) {
    if (!tm.pkLoading && t > pk.from + (pk.to - pk.from) * 0.5 && pk.to < tmRange()[1]) tmFetch(pk.to, true);
    return pk;
  }
  if (pk && pk.next && t >= pk.next.from && t < pk.next.to) {  // (the stretch fetched ahead)
    tm.pk = pk.next;
    return tm.pk;
  }
  if (!tm.pkLoading || tm.pkLoading.from > t || tm.pkLoading.to <= t) tmFetch(t, false);
  return null;
}

function tmFetch(from, ahead) {
  const d = tm.data;
  // As long a stretch as holds about TM_FETCH packets (the I/O counts say how busy each slice is).
  // Slice by slice by index: stepping by the slice edges themselves can stall on rounding
  // (0.1-second slices: 43 × 0.1 / 0.1 floors to 42) and loop for ever.
  const end = tmRange()[1];
  let to = from, count = 0;
  for (let i = Math.max(0, Math.floor(from / d.interval)); to < end && count < TM_FETCH && to - from < 600; i++) {
    const next = Math.min(end, (i + 1) * d.interval);
    if (next <= to) continue;
    count += (d.bins[i] ? d.bins[i][0] : 0) * (next - to) / d.interval;
    to = next;
  }
  to = Math.max(to, Math.min(end, from + 0.5));
  const req = { from, to };
  tm.pkLoading = req;
  api(withFocus(`/api/timeline/packets?${new URLSearchParams({ from: from.toFixed(6), to: to.toFixed(6), max: String(TM_FETCH * 2) })}`))
    .then((r) => {
      if (tm.pkLoading !== req) return;
      const last = r.packets.length ? r.packets[r.packets.length - 1][0] : r.to;  // (a full fetch: up to its last packet)
      const got = { from: r.from, to: r.complete ? r.to : Math.max(last, r.from + 1e-6), rows: r.packets, hosts: r.hosts };
      if (ahead && tm.pk) tm.pk.next = got;
      else tm.pk = got;
    })
    .catch(() => {})
    .finally(() => { if (tm.pkLoading === req) tm.pkLoading = null; });
}

// The arrows for the packets sent between t0 and t1 (capture seconds).
function tmLaunch(t0, t1, now) {
  if (!$("tm-arrows").checked || t1 <= t0) return;
  const pk = tmPackets(t1);
  if (!pk) { tm.note = "reading the packets…"; return; }
  const rows = pk.rows;
  let lo = 0, hi = rows.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (rows[mid][0] <= t0) lo = mid + 1; else hi = mid; }
  const batch = [];
  for (let i = lo; i < rows.length && rows[i][0] <= t1; i++) batch.push(rows[i]);
  if (!batch.length) return;
  const layer = tmArrowLayer();
  if (!layer) return;
  const pos = nmap.pos;
  const shown = [];
  if (batch.length <= TM_MAX_SINGLE) {
    for (const r of batch) shown.push({ a: pk.hosts[r[1]], b: pk.hosts[r[2]], n: 1, delay: ((r[0] - t0) / (t1 - t0)) * 33 });
    tm.note = "each packet is an arrow";
  } else {  // (too many at once: one arrow per conversation and direction, sized by its count)
    const by = new Map();
    for (const r of batch) {
      const k = `${r[1]}>${r[2]}`;
      by.set(k, (by.get(k) || 0) + 1);
    }
    for (const [k, n] of [...by.entries()].sort((x, y) => y[1] - x[1]).slice(0, TM_MAX_SINGLE)) {
      const [ai, bi] = k.split(">").map(Number);
      shown.push({ a: pk.hosts[ai], b: pk.hosts[bi], n, delay: 0 });
    }
    tm.note = `${fmtNum(batch.length)} packets this moment: one arrow per conversation (slow the replay down to see each packet)`;
  }
  for (const x of shown) {
    const pa = pos.get(x.a), pb = pos.get(x.b);
    if (!pa || !pb || x.a === x.b) continue;
    const bad = tm.alertPairs.has(`${x.a}|${x.b}`);
    const faint = nmap.lit && !(nmap.lit.has(x.a) && nmap.lit.has(x.b));  // (outside the map's focus)
    const scale = x.n > 1 ? Math.min(3, 1 + Math.log10(x.n)) : 1;
    const e = svg("path", { d: "M-6,-3.5L5,0L-6,3.5Z", class: `tm-pkt${bad ? " bad" : ""}${faint ? " faint" : ""}`, visibility: "hidden" });
    layer.append(e);
    const my = (pa.y + pb.y) / 2 - (nmap.layout === "grouped" ? Math.abs(pb.x - pa.x) * 0.08 : 0);
    tm.arrows.push({ el: e, a: pa, b: pb, c: { x: (pa.x + pb.x) / 2, y: my }, born: now + x.delay, scale });
  }
  if (tm.arrows.length > 600) {  // (a hard cap on what is on screen)
    for (const a of tm.arrows.splice(0, tm.arrows.length - 600)) a.el.remove();
  }
}

function tmMoveArrows(now) {
  const keep = [];
  for (const a of tm.arrows) {
    const p = (now - a.born) / TM_FLIGHT_MS;
    if (p >= 1) { a.el.remove(); continue; }
    keep.push(a);
    if (p < 0) continue;
    a.el.removeAttribute("visibility");
    const u = 1 - p;  // (along the same curve as the map's line between the two hosts)
    const x = u * u * a.a.x + 2 * u * p * a.c.x + p * p * a.b.x;
    const y = u * u * a.a.y + 2 * u * p * a.c.y + p * p * a.b.y;
    const dx = 2 * u * (a.c.x - a.a.x) + 2 * p * (a.b.x - a.c.x);
    const dy = 2 * u * (a.c.y - a.a.y) + 2 * p * (a.b.y - a.c.y);
    a.el.setAttribute("transform", `translate(${x.toFixed(1)},${y.toFixed(1)}) rotate(${(Math.atan2(dy, dx) * 180 / Math.PI).toFixed(0)}) scale(${a.scale.toFixed(2)})`);
  }
  tm.arrows = keep;
}

// ------------------------------------------------------------- speed

// A speed typed in: 0.3, 0.3x, ×2, 2x, 1/20 (a multiple of the speed it was captured at).
function tmParseSpeed(text) {
  const v = String(text || "").trim().toLowerCase().replace(/^[x×]\s*|\s*[x×]$/g, "");
  let n = null;
  const frac = /^(\d+(?:\.\d+)?)\s*\/\s*(\d+(?:\.\d+)?)$/.exec(v);
  if (frac) n = Number(frac[1]) / Number(frac[2]);
  else if (/^(\d+(?:\.\d*)?|\.\d+)(e-?\d+)?$/.test(v)) n = Number(v);
  return n !== null && Number.isFinite(n) && n > 0 && n <= TM_MAX_SPEED ? n : null;
}
window.tmParseSpeed = tmParseSpeed;

function tmSpeedLabel(n) {
  return `${Number(n.toPrecision(4))}×`;
}

// How long the chosen stretch takes at this speed, said plainly.
function tmSpeedNote() {
  const [r0, r1] = tmRange();
  const secs = (r1 - r0) / tm.speed;
  const long = secs < 60 ? `${secs.toFixed(secs < 10 ? 1 : 0)} s` : secs < 3600 ? `${(secs / 60).toFixed(1)} min`
    : secs < 86400 * 2 ? `${(secs / 3600).toFixed(1)} h` : `${(secs / 86400).toFixed(0)} days`;
  return `${tm.speed === 1 ? "as fast as it was captured" : `${tmSpeedLabel(tm.speed)} the speed it was captured at`}: `
    + `the ${tm.range ? "stretch" : "capture"} plays in ${long}`;
}

function tmSetSpeed(n) {
  tm.speed = n;
  tm.last = performance.now();  // (the new speed from now on)
  const sel = $("tm-speed"), custom = $("tm-speed-custom");
  const preset = TM_SPEEDS.find((v) => Math.abs(Number(v) - n) < 1e-12);
  sel.value = preset || "custom";
  custom.hidden = Boolean(preset);
  if (!preset) custom.value = tmSpeedLabel(n);
  custom.classList.remove("bad");
  tmSpeedTitle();
  if (tm.data) tmApply(true);
}

function tmSpeedTitle() {
  const note = tm.data ? tmSpeedNote() : "";
  $("tm-speed").title = note;
  $("tm-speed-custom").title = `Any multiple of the speed it was captured at: 0.3, 0.3x, 2x, 1/20 (up to ${fmtNum(TM_MAX_SPEED)}×)${note ? `. Now: ${note}` : ""}`;
}

// ------------------------------------------------------------- playing

// One frame (a timer, not animation frames: those stop in a window in the background).
function tmTick() {
  const now = performance.now();
  if (tm.playing) {
    const r1 = tmRange()[1];
    const before = tm.t;
    tm.t = Math.min(r1, tm.t + ((now - tm.last) / 1000) * tm.speed);  // (capture seconds per second: the multiplier)
    tm.last = now;
    tmLaunch(before, tm.t, now);
    tmApply();
    if (tm.t >= r1) { tmApply(true); tmPause(); }
  }
  tmMoveArrows(now);
  if (!tm.playing && !tm.arrows.length) { clearInterval(tm.timer); tm.timer = 0; }
}

async function tmPlay() {
  if (!tm.data) return;
  if (tmStale()) {  // (the capture has changed since the timeline was read: read it again first)
    await tmOpen();
    if (!tm.data) return;
  }
  const [r0, r1] = tmRange();
  if (tm.t >= r1 || tm.t < r0) tm.t = r0;
  tm.playing = true;
  tm.last = performance.now();
  $("tm-play").textContent = "❚❚ Pause";
  tmPackets(tm.t);
  if (!tm.timer) tm.timer = setInterval(tmTick, 33);
}

function tmPause() {
  tm.playing = false;
  $("tm-play").textContent = "▶ Play";
}

// ------------------------------------------------------------- the bar, under the map

{
  const bar = el("div", { class: "tm-bar", id: "tm-bar", role: "region", "aria-label": "Time machine: replay the capture", hidden: "" });
  const play = el("button", { type: "button", class: "tb small tb-primary", id: "tm-play" }, "▶ Play");
  const speed = el("select", { class: "tb small", id: "tm-speed", "aria-label": "Replay speed: a multiple of the speed it was captured at" });
  for (const v of TM_SPEEDS) speed.append(el("option", { value: v }, `${v}×${v === "1" ? " (as captured)" : ""}`));
  speed.append(el("option", { value: "custom" }, "Custom…"));
  speed.value = "1";
  const custom = el("input", { type: "text", class: "tb small mono tm-speed-custom", id: "tm-speed-custom", hidden: "", spellcheck: "false",
    autocomplete: "off", placeholder: "e.g. 0.3×", "aria-label": "Your own speed: a multiple of the speed it was captured at",
    title: "Any multiple of the speed it was captured at: 0.3, 0.3x, 2x, 1/20 (up to 10000×)" });
  const track = el("div", { class: "tm-track", id: "tm-track", role: "slider", tabindex: "0",
    "aria-label": "Moment in the capture (Shift-drag to choose a stretch)", title: "Click or drag to move; Shift-drag to choose a stretch to replay" });
  track.append(svg("svg", { id: "tm-svg", class: "tm-svg", "aria-hidden": "true" }));
  const clock = el("span", { class: "tm-clock mono", id: "tm-clock" });
  bar.append(play, speed, custom, track, clock);

  const row2 = el("div", { class: "tm-row2", id: "tm-row2", hidden: "" });
  const timeBox = (id, label, hint) => {
    const lab = el("label", { class: "inline small" }, label);
    const input = el("input", { type: "text", id, class: "tb small mono tm-time", spellcheck: "false", autocomplete: "off",
      title: hint || "A time: 10:03:40 (the clock, your time zone), +3:40 or +220 (from the start of the capture), 3m40s" });
    lab.append(input);
    return [lab, input];
  };
  const [fromLab, fromIn] = timeBox("tm-from", "From ");
  const [toLab, toIn] = timeBox("tm-to", "to ");
  const [goLab, goIn] = timeBox("tm-go", "Go to ");
  goIn.placeholder = "10:03:40 or +3:40";
  const whole = el("button", { type: "button", class: "tb small", id: "tm-whole", hidden: "" }, "Whole capture");
  const win = el("select", { class: "tb small", id: "tm-window", "aria-label": "What counts as active" });
  for (const [v, label] of TM_WINDOWS) win.append(el("option", { value: v }, `Active: ${label}`));
  win.value = "10";
  const arrowsLab = el("label", { class: "check small", title: "Draw each packet as an arrow flying from its sender to its receiver" });
  const arrows = el("input", { type: "checkbox", id: "tm-arrows" });
  arrows.checked = true;
  arrowsLab.append(arrows, document.createTextNode(" Packets as arrows"));
  const close = el("button", { type: "button", class: "tb small", title: "Show the whole capture on the map again" }, "✕ Leave the replay");
  row2.append(fromLab, toLab, whole, goLab, win, arrowsLab, el("span", { class: "spacer" }), close);
  const events = el("div", { class: "tm-events", id: "tm-events", "aria-live": "polite", hidden: "" });
  document.querySelector("#hosts-map .map-split").after(bar, row2, events);

  const typed = (input, apply) => {
    const go = () => {
      if (!tm.data) return;
      const v = input.value.trim();
      const t = v ? tmParse(v) : null;
      input.classList.toggle("bad", Boolean(v) && t === null);
      if (!v || t !== null) apply(t);
    };
    input.addEventListener("change", go);
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); go(); } });
  };
  typed(fromIn, (t) => { const [, r1] = tmRange(); tmSetRange(t === null ? 0 : t, r1); });
  typed(toIn, (t) => { const [r0] = tmRange(); tmSetRange(r0, t === null ? tm.data.duration : t); });
  typed(goIn, (t) => {
    if (t === null) return;
    tm.t = Math.max(0, Math.min(tm.data.duration, t));
    const [r0, r1] = tmRange();
    if (tm.t < r0 || tm.t > r1) tm.range = null;
    tmClearArrows();
    tmFillRange();
    tmDrawTrack();
    tmApply(true);
    goIn.value = "";
  });
  whole.addEventListener("click", () => tmSetRange(0, 0));

  play.addEventListener("click", () => (tm.playing ? tmPause() : tmPlay()));
  speed.addEventListener("change", () => {
    if (speed.value === "custom") {
      custom.hidden = false;
      if (!custom.value) custom.value = tmSpeedLabel(tm.speed);
      custom.focus();
      custom.select();
      return;
    }
    tmSetSpeed(Number(speed.value));
  });
  const typedSpeed = () => {
    const n = tmParseSpeed(custom.value);
    custom.classList.toggle("bad", n === null);
    if (n !== null) tmSetSpeed(n);
  };
  custom.addEventListener("change", typedSpeed);
  custom.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); typedSpeed(); } });
  close.addEventListener("click", tmClose);
  win.addEventListener("change", () => tmApply(true));
  arrows.addEventListener("change", () => { if (!arrows.checked) { tmClearArrows(); tm.note = ""; } });
  let dragging = false, selecting = null;
  const at = (clientX) => {
    const r = track.getBoundingClientRect();
    return Math.max(0, Math.min(tm.data.duration, ((clientX - r.left) / r.width) * tm.data.duration));
  };
  track.addEventListener("pointerdown", (e) => {
    if (!tm.data) return;
    track.setPointerCapture(e.pointerId);
    tmPause();
    if (e.shiftKey) selecting = at(e.clientX);  // (Shift-drag: the stretch to replay)
    else { dragging = true; tmSeek(e.clientX); }
  });
  track.addEventListener("pointermove", (e) => {
    if (dragging) tmSeek(e.clientX);
    else if (selecting !== null) {
      const t = at(e.clientX);
      tm.range = [Math.min(selecting, t), Math.max(selecting, t)];
      tmDrawTrack();
      tmFillRange();
    }
  });
  track.addEventListener("pointerup", (e) => {
    if (selecting !== null) tmSetRange(selecting, at(e.clientX));
    dragging = false;
    selecting = null;
  });
  track.addEventListener("keydown", (e) => {
    if (!tm.data) return;
    const step = tm.data.interval * (e.shiftKey ? 10 : 1);
    const [r0, r1] = tmRange();
    if (e.key === "ArrowRight") tm.t = Math.min(r1, tm.t + step);
    else if (e.key === "ArrowLeft") tm.t = Math.max(r0, tm.t - step);
    else if (e.key === "Home") tm.t = r0;
    else if (e.key === "End") tm.t = r1;
    else if (e.key === " ") { e.preventDefault(); if (tm.playing) tmPause(); else tmPlay(); return; }
    else return;
    e.preventDefault();
    tmPause();
    tmClearArrows();
    tmApply(true);
  });

  const toggle = el("button", { type: "button", class: "tb small", id: "tm-toggle", "aria-pressed": "false",
    title: "Replay the capture on the map: what was active at each moment, each packet as an arrow, when each alert was raised" }, "⏱ Replay");
  toggle.addEventListener("click", () => (tm.on ? tmClose() : tmOpen()));
  $("map-fit").before(toggle);

  // The map redraws itself (a new layout, more hosts): light the replay's moment again (the arrows restart).
  new MutationObserver(() => {
    if (!tm.on) return;
    $("map-svg").classList.add("tm-on");
    tm.arrows = [];
    tmApply(true);
  }).observe($("map-svg"), { childList: true });
  window.addEventListener("anta:focus", () => { if (tm.on) { tm.data = null; tmOpen(); } });
}
window.openTimeMachine = tmOpen;
