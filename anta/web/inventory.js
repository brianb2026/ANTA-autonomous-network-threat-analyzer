// Inventory and intelligence: the Assets view (passive device inventory), the TLS
// fingerprint, encrypted-traffic and country/network statistics, the threat
// intelligence feeds, one-click filter templates, the location card on alerts,
// and Settings (flow logs, the rolling capture buffer, recordings, GeoIP).
// Text from the network is rendered with textContent only, as everywhere else.
"use strict";

const APP_LABELS = {
  tls: "TLS", quic: "QUIC", http: "HTTP", dns: "DNS", ssh: "SSH", smb: "SMB", ldap: "LDAP", cldap: "CLDAP",
  kerberos: "Kerberos", dcerpc: "DCE/RPC", ntp: "NTP", dhcp: "DHCP", mdns: "mDNS", ssdp: "SSDP", llmnr: "LLMNR",
  "netbios-ns": "NetBIOS names", "netbios-dgm": "NetBIOS datagrams", rdp: "RDP", vnc: "VNC", telnet: "Telnet",
  ftp: "FTP", "ftp-data": "FTP data", smtp: "SMTP", pop3: "POP3", imap: "IMAP", mysql: "MySQL", postgresql: "PostgreSQL",
  mssql: "SQL Server", mongodb: "MongoDB", redis: "Redis", mqtt: "MQTT", sip: "SIP", rtsp: "RTSP", stun: "STUN",
  openvpn: "OpenVPN", wireguard: "WireGuard", dtls: "DTLS", snmp: "SNMP", syslog: "Syslog", tftp: "TFTP", irc: "IRC",
  bittorrent: "BitTorrent", socks: "SOCKS", xmpp: "XMPP", winrm: "WinRM",
};
const appLabel = (a) => APP_LABELS[a] || a;

function geoText(g) {
  if (!g) return "";
  const where = g.country_name || g.country || "";
  return `AS${g.asn} ${g.as_name || ""}${where ? ` · ${where}` : ""}`.replace(/\s+/g, " ").trim();
}
window.geoText = geoText;

function addrFilter(ip) { return `${ip.includes(":") ? "ipv6" : "ip"}.addr == ${ip}`; }

function listSection(box, title, items, mono = false) {
  if (!items || !items.length) return;
  box.append(el("h4", {}, title));
  const ul = el("ul", { class: mono ? "mono-list" : "reasons" });
  for (const it of items) ul.append(el("li", {}, it));
  box.append(ul);
}

// ------------------------------------------------------- filter templates

let filterTemplates = null;
async function loadTemplates() {
  if (!filterTemplates) {
    const r = await fetch("/static/filter-templates.json", { credentials: "same-origin", cache: "no-store" });
    if (!r.ok) throw new Error("templates unavailable");
    filterTemplates = (await r.json()).groups;
  }
  return filterTemplates;
}

// The templates as menu items: one submenu per group (the packet list's Tools ▾).
window.templateItems = async () => {
  let groups;
  try { groups = await loadTemplates(); } catch { notice("Could not load the filter templates.", true); return []; }
  return groups.map((g) => ({ label: g.name, submenu: g.templates.map((t) => ({ label: t.name, title: `${t.about}\n\n${t.filter}`,
    action: () => { setView("packets"); applyFilter("display", t.filter); } })) }));
};

// ------------------------------------------------------------ assets view

const assetsView = { list: null, key: null, scope: "local", query: "", selected: null };

function assetsShown() {
  const q = assetsView.query.trim().toLowerCase();
  return (assetsView.list || []).filter((a) => {
    if (assetsView.scope === "local" && a.scope === "public") return false;
    if (assetsView.scope === "public" && a.scope !== "public") return false;
    if (assetsView.scope === "iot" && !a.iot) return false;
    if (!q) return true;
    return [a.ip, a.name, a.device, a.os, a.vendor, a.as_name, a.country_name, ...(a.services || []), ...(a.names || []),
      ...(a.macs || []), ...(a.apps_used || []), ...(a.apps_served || []), ...(a.users || [])]
      .some((v) => String(v || "").toLowerCase().includes(q));
  });
}

async function assetsLoad(force = false) {
  const key = `${sessionKey()}|${state.session ? state.session.state : ""}|${state.alerts.size}|${window.focusScope ? window.focusScope() : ""}`;
  if (!force && assetsView.list && assetsView.key === key) { assetsRender(); return; }
  if (!state.session || ["idle", "error"].includes(state.session.state)) {
    assetsView.list = null;
    assetsRender();
    return;
  }
  $("assets-status").textContent = "Reading the capture…";
  const seq = assetsView.seq = (assetsView.seq || 0) + 1;
  try {
    const list = (await api(withFocus("/api/assets"))).assets;
    if (seq !== assetsView.seq) return;  // (a newer load, for another focus or capture, is under way)
    assetsView.list = list;
    assetsView.key = key;
    $("assets-status").textContent = "";
  } catch (err) {
    if (seq !== assetsView.seq) return;
    assetsView.list = null;
    $("assets-status").textContent = err.message;
  }
  assetsRender();
}
viewHooks.assets = () => assetsLoad();

function assetOwner(a) {
  if (a.scope !== "public") return "";
  if (!a.asn) return "";
  return `${a.as_name || `AS${a.asn}`}${a.country ? ` (${a.country})` : ""}`;
}

function assetsRender() {
  const all = assetsView.list;
  const list = assetsShown();
  $("assets-count").textContent = all ? (list.length === all.length ? String(all.length) : `${list.length} of ${all.length}`) : "";
  $("assets-empty").hidden = !!list.length;
  $("assets-empty").textContent = !all ? "Open a capture to list the devices in it." : all.length ? "No device matches." : "No devices were seen.";
  $("assets-rows").replaceChildren(...list.map((a) => {
    const tr = el("tr", { tabindex: "0", class: "clickable", dataset: { q: a.ip } });
    if (assetsView.selected === a.ip) tr.classList.add("selected");
    const device = el("td");
    if (a.iot) device.append(el("span", { class: "tag tag-hit" }, "IoT"), " ");
    device.append(a.device || "–");
    const apps = [...(a.apps_used || []).map(appLabel), ...(a.apps_served || []).map((x) => `${appLabel(x)} (server)`)];
    const alerts = el("td", { class: a.alerts ? "num warn" : "num" }, a.alerts ? String(a.alerts) : "");
    tr.append(el("td", { class: "mono" }, a.ip), el("td", { title: (a.names || []).join(", ") }, a.name || ""), device,
      el("td", { class: a.os ? "" : "muted", title: (a.os_evidence || []).join("\n") }, a.os || "unknown"),
      el("td", {}, a.vendor || ""), el("td", { title: (a.services || []).join("\n") }, (a.services || []).join(", ")),
      el("td", { title: apps.join(", ") }, apps.slice(0, 6).join(", ")), el("td", {}, assetOwner(a)),
      el("td", { class: "num", title: `sent ${fmtBytes(a.tx_bytes)}, received ${fmtBytes(a.rx_bytes)}` }, fmtBytes((a.tx_bytes || 0) + (a.rx_bytes || 0))),
      alerts);
    const pick = () => { assetsView.selected = a.ip; nmap.selected = a.ip; assetsRender(); };  // (the map picks it too)
    tr.addEventListener("click", pick);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") pick(); });
    return tr;
  }));
  assetSide((all || []).find((a) => a.ip === assetsView.selected) || null);
}

// A device's row and details in the Assets tab (from the right-click menus).
window.showAsset = (ip) => {
  assetsView.selected = ip;
  assetsView.query = "";
  $("assets-search").value = "";
  assetsView.scope = "all";
  document.querySelectorAll("#assets-scope .chip").forEach((c) => {
    c.classList.toggle("active", c.dataset.scope === "all");
    c.setAttribute("aria-pressed", String(c.dataset.scope === "all"));
  });
  setView("assets");
  setTimeout(() => document.querySelector("#assets-rows tr.selected")?.scrollIntoView({ block: "center" }), 300);
};

function assetSide(a) {
  const side = $("assets-side");
  side.replaceChildren();
  if (!a) { side.append(el("p", { class: "muted" }, "Select a device to see how it was identified.")); return; }
  side.append(el("h2", {}, a.name || a.ip));
  side.append(el("p", { class: "side-role" }, [a.device, a.os].filter(Boolean).join(" · ")));
  const actions = el("div", { class: "side-actions" });
  const packets = el("button", { type: "button", class: "tb small" }, "Show its packets");
  packets.addEventListener("click", () => showPacketsFor(addrFilter(a.ip)));
  const map = el("button", { type: "button", class: "tb small" }, "Show on map");
  map.addEventListener("click", () => window.mapFocus && window.mapFocus(a.ip));
  const copy = el("button", { type: "button", class: "tb small" }, "Copy address");
  copy.addEventListener("click", () => { copyText(a.ip); notice("Address copied."); });
  actions.append(packets, map, copy);
  side.append(actions);
  const dl = el("dl", { class: "kv" });
  const add = (k, v) => { if (v !== null && v !== undefined && v !== "") dl.append(el("dt", {}, k), el("dd", {}, String(v))); };
  add("Address", a.ip);
  add("MAC address", (a.macs || []).join(", ") + (a.vendor ? ` (${a.vendor})` : ""));
  add("Host names", (a.names || []).join(", "));
  add("User accounts", (a.users || []).join(", "));
  add("Domain", (a.domains || []).join(", "));
  if (a.asn) add("Network owner", `AS${a.asn} ${a.as_name || ""}`);
  add("Country", a.country_name || a.country);
  add("Sent", fmtBytes(a.tx_bytes));
  add("Received", fmtBytes(a.rx_bytes));
  add("Talks to", a.peers ? `${fmtNum(a.peers)} hosts` : "");
  add("Seen", a.first ? `${fmtDateTime(a.first)} – ${fmtTime(a.last)}` : "");
  add("Alerts", a.alerts || "");
  side.append(dl);
  listSection(side, a.os ? `Operating system: ${a.os}` : "Operating system: not enough evidence", a.os_evidence);
  if (a.iot) listSection(side, "Why it looks like an IoT device", a.iot_evidence);
  const prints = [];
  if (a.syn) {
    const s = a.syn;
    prints.push(`TCP SYN: initial TTL ${s.ttl}, window ${s.win}${s.mss !== undefined ? `, MSS ${s.mss}` : ""}` +
      `${s.ws !== undefined ? `, window scale ${s.ws}` : ""}${s.opts ? `, options ${s.opts}` : ""}`);
  }
  if (a.dhcp_prl) prints.push(`DHCP parameter request list: ${a.dhcp_prl}`);
  for (const v of a.dhcp_vendor || []) prints.push(`DHCP vendor class: ${v}`);
  for (const ua of a.user_agents || []) prints.push(`User-Agent: ${ua}`);
  listSection(side, "Fingerprints", prints, true);
  listSection(side, "mDNS services it announces", a.mdns_services, true);
  listSection(side, "Services it offers", a.services);
  listSection(side, "Applications it uses", (a.apps_used || []).map(appLabel));
  listSection(side, "Applications it serves", (a.apps_served || []).map(appLabel));
}

document.querySelectorAll("#assets-scope .chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    assetsView.scope = chip.dataset.scope;
    document.querySelectorAll("#assets-scope .chip").forEach((c) => {
      c.classList.toggle("active", c === chip);
      c.setAttribute("aria-pressed", String(c === chip));
    });
    assetsRender();
  });
});
$("assets-search").addEventListener("input", (e) => { assetsView.query = e.target.value; assetsRender(); });
$("assets-refresh").addEventListener("click", () => assetsLoad(true));
$("assets-csv").addEventListener("click", async () => {
  const list = assetsShown();
  if (!list.length) { notice("There are no devices to export.", true); return; }
  try {
    const r = await saveTextFile(`${captureStem()}_assets.csv`, "csv", csvText(
      ["Address", "Name", "MAC addresses", "Vendor", "Device", "IoT", "Operating system", "OS evidence", "Services",
        "Applications used", "Applications served", "Users", "AS number", "Network owner", "Country", "Bytes sent",
        "Bytes received", "Peers", "First seen (UTC)", "Last seen (UTC)", "Alerts"],
      list.map((a) => [a.ip, a.name, (a.macs || []).join(" "), a.vendor, a.device, a.iot ? "yes" : "no", a.os,
        (a.os_evidence || []).join("; "), (a.services || []).join("; "), (a.apps_used || []).join(" "),
        (a.apps_served || []).join(" "), (a.users || []).join(" "), a.asn, a.as_name, a.country, a.tx_bytes, a.rx_bytes,
        a.peers, isoTime(a.first), isoTime(a.last), a.alerts])));
    notice(`Saving the inventory of ${list.length} devices as ${r.name}.`);
  } catch (err) { notice(err.message, true); }
});

// --------------------------------------------- statistics: fingerprints, ETA, geo

const invData = {};  // "kind|selection" -> {key, data, error, loading}

// A tool's data, for the selection it is drawn for (the focus, or a quick-tool window's);
// when it arrives, the tool is drawn again where it was asked for.
function invGet(kind, path) {
  const rx = RX;
  const scope = rx.scope();
  const key = `${sessionKey()}|${state.session ? state.session.state : ""}`;
  const name = `${kind}|${scope}`;
  const slot = invData[name] || (invData[name] = {});
  if (slot.key === key && (slot.data || slot.loading || slot.error)) return slot;
  slot.key = key;
  slot.data = null;
  slot.error = "";
  slot.loading = true;
  const url = scope ? `${path}${path.includes("?") ? "&" : "?"}scope=${encodeURIComponent(scope)}` : path;
  api(url).then((d) => { slot.data = d; }).catch((err) => { slot.error = err.message; }).finally(() => {
    slot.loading = false;
    if (slot.key === key && (!rx.main || state.view === "stats")) rx.rerender();
  });
  return slot;
}

function invForget(kind) {  // (Refresh: read it again)
  for (const name of Object.keys(invData)) if (name.startsWith(`${kind}|`)) delete invData[name];
}

// Forget every tool's data (Refresh in Statistics), or one selection's (a quick-tool window's).
function invForgetAll(scope = null) {
  for (const name of Object.keys(invData)) if (scope === null || name.endsWith(`|${scope}`)) delete invData[name];
}

function invPending(box, slot, what) {
  if (slot.data) return false;
  box.append(el("p", { class: "empty" }, slot.error || `Reading ${what}…`));
  return true;
}

function flowExpr(r) {
  const ip = (a) => `${a.includes(":") ? "ipv6" : "ip"}.addr == ${a}`;
  return `${ip(r.src)} && ${ip(r.dst)} && ${r.proto}.port == ${r.sport} && ${r.proto}.port == ${r.dport}`;
}

TOOLS.fingerprints = (box) => {
  const slot = invGet("fingerprints", "/api/fingerprints");
  if (invPending(box, slot, "the TLS handshakes")) return;
  const { clients, servers } = slot.data;
  const listed = clients.filter((c) => c.listed.length);
  tiles(box, [["Client fingerprints", fmtNum(clients.length), "distinct JA4 (JA3 varies with Chrome's shuffled extensions)"],
    ["Server fingerprints", fmtNum(servers.length), "distinct JA4S / JA3S pairs"],
    ["Listed by a feed", fmtNum(listed.length), listed.length ? "see the top of the table" : "none of the enabled feeds"]]);
  section(box, "Clients (JA4, JA3)", "a TLS library's Client Hello; rare ones used by one host are worth a look");
  dataTable(box, "fp-clients", [
    { label: "JA4", type: "text", get: (r) => r.ja4, render: (r) => el("span", { class: "mono" }, r.ja4 || "–") },
    { label: "JA3 (most used)", type: "text", get: (r) => r.ja3_variants.join(" "), render: (r) => {
      const span = el("span", { class: "mono", title: r.ja3_variants.join("\n") }, r.ja3 || "–");
      if (r.ja3_count > 1) span.append(el("span", { class: "muted" }, ` +${r.ja3_count - 1} more`));
      return span;
    } },
    { label: "Sessions", type: "num", get: (r) => r.sessions },
    { label: "Clients", type: "num", get: (r) => r.client_count, title: "Hosts that sent this fingerprint" },
    { label: "Client addresses", type: "text", get: (r) => r.clients.join(", ") },
    { label: "Server names", type: "text", get: (r) => r.sni.join(", ") },
    { label: "Feed listing", type: "text", get: (r) => r.listed.join("; "),
      render: (r) => r.listed.length ? el("span", { class: "warn" }, r.listed.join("; ")) : el("span", { class: "muted" }, "") },
  ], clients, { defaultSort: { col: 3, dir: 1 },
    onRow: (e, r) => window.filterMenu(e, r.ja4 ? `tls.handshake.ja4 == "${r.ja4}"` : `tls.handshake.ja3 == "${r.ja3}"`) });
  section(box, "Servers (JA4S, JA3S)", "how each server answered; JA4S is computed by ANTA (Wireshark shows JA3S only)");
  dataTable(box, "fp-servers", [
    { label: "JA4S", type: "text", get: (r) => r.ja4s, render: (r) => el("span", { class: "mono" }, r.ja4s || "–") },
    { label: "JA3S", type: "text", get: (r) => r.ja3s, render: (r) => el("span", { class: "mono" }, r.ja3s || "–") },
    { label: "Sessions", type: "num", get: (r) => r.sessions },
    { label: "Servers", type: "num", get: (r) => r.server_count },
    { label: "Server addresses", type: "text", get: (r) => r.servers.join(", ") },
    { label: "Server names", type: "text", get: (r) => r.sni.join(", ") },
  ], servers, { defaultSort: { col: 2, dir: -1 },
    onRow: (e, r) => r.ja3s && window.filterMenu(e, `tls.handshake.ja3s == "${r.ja3s}"`) });
};

const LOGIN_STATUS = {  // whether the server took the password: "accepted" means it works and must be changed
  accepted: ["⚠", "Accepted", "warn"], refused: ["✕", "Refused", "muted"], unknown: ["?", "Not known", "muted"],
  mixed: ["⚠", "Some accepted", "warn"],
};

TOOLS.logins = (box) => {
  const rx = RX;
  const bar = el("div", { class: "rhythm-bar" });
  const refresh = el("button", { type: "button", class: "tb small" }, "Refresh");
  refresh.addEventListener("click", () => { invForget("logins"); rx.rerender(); });
  bar.append(el("span", { class: "spacer" }), refresh);
  box.append(bar);
  const slot = invGet("logins", "/api/logins");
  if (invPending(box, slot, "the logins")) return;
  const { logins, total, accounts, accepted } = slot.data;
  box.append(el("p", { class: "tool-note" }, "Logins whose password (or SNMP community string) crossed the network unencrypted, "
    + "so anyone on the path could read it. ANTA never shows or keeps the passwords: only the account and whether the "
    + "server accepted it. Change each password listed, and move the service to its encrypted form."));
  if (!logins.length) {
    box.append(el("p", { class: "empty" }, "No logins were sent in clear text in this capture."));
    return;
  }
  tiles(box, [["Logins in clear text", fmtNum(total)], ["Accounts exposed", fmtNum(accounts), "client, server and account"],
    ["Accepted by the server", fmtNum(accepted), accepted ? "these passwords work: change them first" : "none worked"]]);
  section(box, "Logins", "right-click a row for its packets");
  dataTable(box, "logins", [
    { label: "Last seen", type: "num", get: (r) => r.last, render: (r) => el("span", {}, fmtTime(r.last)) },
    { label: "Service", type: "text", get: (r) => r.service },
    { label: "How", type: "text", get: (r) => r.method },
    { label: "Account", type: "text", get: (r) => r.user, render: (r) => {
      if (r.service === "SNMP") return el("span", { class: r.default_secret ? "warn" : "muted" }, r.default_secret ? "factory-default community" : "community string");
      if (!r.user) return el("span", { class: "muted" }, "(none sent)");
      const s = el("span", { class: "mono" }, r.user);
      if (r.anonymous) s.append(el("span", { class: "muted" }, " (anonymous: no real password)"));
      return s;
    } },
    { label: "Server said", type: "text", get: (r) => LOGIN_STATUS[r.status][1], render: (r) => {
      const [icon, label, cls] = LOGIN_STATUS[r.status];
      return el("span", { class: r.anonymous ? "muted" : cls }, `${r.anonymous ? "✓" : icon} ${label}`);
    } },
    { label: "Logins", type: "num", get: (r) => r.logins },
    { label: "Client", type: "text", get: (r) => r.client, render: (r) => addrCell(r.client) },
    { label: "Server", type: "text", get: (r) => `${r.server}:${r.port}`, render: (r) => el("span", { class: "mono" }, `${r.server}:${r.port}`) },
    { label: "Use instead", type: "text", get: (r) => r.safer },
  ], logins, { limit: 1000, defaultSort: { col: 0, dir: -1 }, onRow: (e, r) => r.flow && window.filterMenu(e, flowExpr(r.flow)) });
};

TOOLS.encrypted = (box) => {
  const slot = invGet("eta", "/api/eta");
  if (invPending(box, slot, "the encrypted sessions")) return;
  const { sessions, total, classes } = slot.data;
  if (!total) {
    box.append(el("p", { class: "empty" }, "No encrypted sessions have been analysed yet. This analysis runs while ANTA analyses a capture: open a file or start a capture."));
    return;
  }
  const order = Object.entries(classes).sort((a, b) => b[1] - a[1]);
  tiles(box, [["Encrypted sessions", fmtNum(total)], ["Most common", order[0][0], `${fmtNum(order[0][1])} sessions`],
    ["Uploads", fmtNum(classes["Bulk upload"] || 0), "more sent than received: backups, or exfiltration"]]);
  section(box, "What the encrypted sessions are doing", "from packet sizes, direction and timing; nothing is decrypted");
  barList(box, order.map(([label, n]) => ({ label, value: n })), { unit: "count" });
  section(box, "Sessions", total > sessions.length ? `the latest ${fmtNum(sessions.length)} of ${fmtNum(total)}` : null);
  dataTable(box, "eta", [
    { label: "Start", type: "text", get: (r) => fmtTime(r.ts) },
    { label: "Client", type: "text", get: (r) => r.src, render: (r) => addrCell(r.src) },
    { label: "Server", type: "text", get: (r) => `${r.dst}:${r.dport}`, render: (r) => el("span", { class: "mono" }, `${r.dst}:${r.dport}`) },
    { label: "Server name", type: "text", get: (r) => r.sni },
    { label: "Protocol", type: "text", get: (r) => appLabel(r.app || r.proto) },
    { label: "Owner", type: "text", get: (r) => (r.geo ? `${r.geo.as_name} (${r.geo.country})` : "") },
    { label: "Looks like", type: "text", get: (r) => r.label, render: (r) => { const s = el("span", {}, r.label); s.title = r.why; return s; } },
    { label: "Conf.", type: "pct", get: (r) => r.confidence },
    { label: "Sent", type: "bytes", get: (r) => r.up },
    { label: "Received", type: "bytes", get: (r) => r.down },
    { label: "Duration (s)", type: "num", get: (r) => r.duration },
    { label: "Why", type: "text", get: (r) => r.why },
  ], sessions, { limit: 500, defaultSort: { col: 8, dir: -1 }, onRow: (e, r) => window.filterMenu(e, flowExpr(r)) });
};

TOOLS.geo = (box) => {
  const g = RX.geo();
  if (!g || !g.available) {
    box.append(el("p", { class: "empty" }, "The GeoIP table is not available. Settings… can download it."));
    return;
  }
  if (!g.countries.length) {
    box.append(el("p", { class: "empty" }, "No internet addresses in this capture (or the GeoIP table is still loading: Refresh in a moment)."));
    return;
  }
  const bytes = g.countries.reduce((s, c) => s + c.bytes, 0) || 1;
  tiles(box, [["Countries", fmtNum(g.countries.length)], ["Networks (AS)", fmtNum(g.ases.length)],
    ["Largest", g.countries[0].name || g.countries[0].country, `${((g.countries[0].bytes / bytes) * 100).toFixed(0)}% of internet traffic`]]);
  section(box, "Traffic by country", "where each network's owner is registered (cloud and CDN servers can stand elsewhere)");
  barList(box, g.countries.slice(0, 20).map((c) => ({ label: c.name || c.country || "?", sub: `${c.hosts} hosts · ${c.ases} networks`, value: c.bytes })));
  dataTable(box, "geo-countries", [
    { label: "Country", type: "text", get: (r) => r.name || r.country },
    { label: "Code", type: "text", get: (r) => r.country },
    { label: "Hosts", type: "num", get: (r) => r.hosts },
    { label: "Networks", type: "num", get: (r) => r.ases },
    { label: "Bytes", type: "bytes", get: (r) => r.bytes },
    { label: "Packets", type: "num", get: (r) => r.packets },
  ], g.countries, { limit: 300, defaultSort: { col: 4, dir: -1 } });
  section(box, "Traffic by network (autonomous system)", "a rare network moving a lot of data is worth a look");
  dataTable(box, "geo-ases", [
    { label: "AS", type: "frame", get: (r) => r.asn },  // an identifier: no thousands separators
    { label: "Owner", type: "text", get: (r) => r.name },
    { label: "Country", type: "text", get: (r) => r.country },
    { label: "Hosts", type: "num", get: (r) => r.hosts },
    { label: "Bytes", type: "bytes", get: (r) => r.bytes },
    { label: "Packets", type: "num", get: (r) => r.packets },
    { label: "Addresses", type: "text", get: (r) => r.addresses.join(", "), render: (r) => el("span", { class: "mono" }, r.addresses.join(", ")) },
  ], g.ases, { limit: 500, defaultSort: { col: 4, dir: -1 },
    onRow: (e, r) => window.filterMenu(e, r.addresses.length === 1 ? addrFilter(r.addresses[0])
      : `ip.addr in {${r.addresses.filter((a) => !a.includes(":")).join(", ")}}`) });
};

// ------------------------------------------------- alert: where the other end is

window.renderAlertGeo = (a) => {
  const geo = a.geo || {};
  const rows = Object.entries(geo);
  $("d-geo").hidden = !rows.length;
  if (!rows.length) return;
  kvList($("d-geo-kv"), rows.map(([ip, g]) => [ip, `${g.country_name || g.country || "unknown country"} · AS${g.asn} ${g.as_name || ""}`.trim()]));
};

// ------------------------------------------------- threat intelligence feeds

const intelView = { feeds: null, indicators: 0, busy: "" };

async function intelLoad() {
  try {
    const r = await api("/api/intel");
    intelView.feeds = r.feeds;
    intelView.indicators = r.indicators;
  } catch (err) {
    $("intel-error").textContent = err.message;
  }
  intelRender();
}

function intelRender() {
  const box = $("intel-rows");
  $("intel-count").textContent = intelView.feeds ? `${fmtNum(intelView.indicators)} indicators` : "";
  box.replaceChildren();
  for (const f of intelView.feeds || []) {
    const row = el("div", { class: "intel-feed" });
    const head = el("div", { class: "intel-head" });
    const on = el("input", { type: "checkbox", "aria-label": `Use ${f.name}` });
    on.checked = f.installed && f.enabled;
    on.disabled = !f.installed || !!intelView.busy;
    on.addEventListener("change", () => intelChange({ id: f.id, enabled: on.checked }));
    head.append(on, el("strong", {}, f.name));
    row.append(head, el("p", { class: "muted small" }, f.about));
    const status = f.installed
      ? `${fmtNum(f.entries || 0)} indicators · ${f.builtin ? "downloaded" : "imported"} ${fmtDateTime(f.updated)}`
      : "Not downloaded";
    const line = el("div", { class: "intel-status" });
    line.append(el("span", { class: "muted small" }, intelView.busy === f.id ? "Downloading…" : status));
    if (f.builtin) {
      const up = el("button", { type: "button", class: "link" }, f.installed ? "Update" : "Download");
      up.disabled = !!intelView.busy;
      up.title = f.url;
      up.addEventListener("click", () => intelUpdate(f.id));
      line.append(up);
    }
    if (f.installed) {
      const rm = el("button", { type: "button", class: "link" }, "Remove");
      rm.disabled = !!intelView.busy;
      rm.addEventListener("click", () => intelChange({ id: f.id, remove: true }));
      line.append(rm);
    }
    row.append(line);
    box.append(row);
  }
  $("intel-update-all").disabled = !!intelView.busy;
  $("intel-import").disabled = !!intelView.busy;
  $("intel-recheck").disabled = !!intelView.busy || !sessionActive();
}

async function intelRecheck(quiet = false) {
  if (!sessionActive()) return;
  try {
    const r = await api("/api/intel/recheck", "POST", {});
    notice(r.matches ? `Checked ${fmtNum(r.sessions)} sessions: ${fmtNum(r.matches)} touch a listed indicator (see Alerts).`
      : `Checked ${fmtNum(r.sessions)} sessions against the feeds: no matches.`, r.matches > 0);
  } catch (err) {
    if (!quiet) notice(err.message, true);
  }
}

async function intelUpdate(id) {
  intelView.busy = id;
  $("intel-error").textContent = "";
  intelRender();
  try {
    const r = await api("/api/intel/update", "POST", { id });
    intelView.feeds = r.feeds;
    intelView.indicators = r.indicators;
    const failed = Object.entries(r.results).filter(([, v]) => !v.ok);
    if (failed.length) $("intel-error").textContent = failed.map(([k, v]) => `${k}: ${v.error}`).join("; ");
    else notice("Feeds updated.");
  } catch (err) {
    $("intel-error").textContent = err.message;
  } finally {
    intelView.busy = "";
    intelRender();
  }
  await intelRecheck(true);
}

async function intelChange(body) {
  try {
    const r = await api("/api/intel/change", "POST", body);
    intelView.feeds = r.feeds;
    intelView.indicators = r.indicators;
  } catch (err) {
    $("intel-error").textContent = err.message;
  }
  intelRender();
}

$("intel-update-all").addEventListener("click", () => intelUpdate("all"));
$("intel-recheck").addEventListener("click", () => intelRecheck());
$("intel-import").addEventListener("click", () => $("intel-file").click());
$("intel-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  if (file.size > 15 * 1024 * 1024) { $("intel-error").textContent = "That file is larger than 15 MB."; return; }
  try {
    const r = await api("/api/intel/import", "POST", { name: file.name.replace(/\.[^.]+$/, ""), content: await file.text() });
    intelView.feeds = r.feeds;
    intelView.indicators = r.indicators;
    notice(`Imported ${fmtNum(r.imported.entries)} indicators from ${file.name}.`);
    intelRender();
    await intelRecheck(true);
  } catch (err) {
    $("intel-error").textContent = err.message;
  }
});


// ------------------------------------------------------------------ settings

const SETTING_INPUTS = { flowlog_days: "set-flowlog-days", flowlog_max_mb: "set-flowlog-mb", ring_segment_mb: "set-ring-mb",
  ring_segments: "set-ring-n" };

function fileList(box, files, actions) {
  box.replaceChildren();
  if (!files.length) { box.append(el("p", { class: "muted small" }, "None yet.")); return; }
  const table = el("table", { class: "data-table" });
  const tbody = el("tbody");
  for (const f of files) {
    const tr = el("tr");
    tr.append(el("td", { class: "mono", title: f.title || f.name }, f.name), el("td", { class: "num" }, fmtBytes(f.size)),
      el("td", { class: "muted" }, fmtDateTime(f.modified)));
    const act = el("td", { class: "c-act" });
    for (const [label, fn] of actions(f)) {
      const b = el("button", { type: "button", class: "link" }, label);
      b.addEventListener("click", () => fn(b));
      act.append(b);
    }
    tr.append(act);
    tbody.append(tr);
  }
  table.append(tbody);
  box.append(table);
}

function ringTotal() {
  const mb = Number($("set-ring-mb").value) || 0, n = Number($("set-ring-n").value) || 0;
  $("set-ring-total").textContent = mb && n ? `Up to ${fmtBytes(mb * (n + 1) * 1024 * 1024)} on disk per live capture.` : "";
}
$("set-ring-mb").addEventListener("input", ringTotal);
$("set-ring-n").addEventListener("input", ringTotal);

function settingsFill(r) {
  const s = r.settings;
  $("set-flowlog-live").checked = s.flowlog_live;
  $("set-flowlog-files").checked = s.flowlog_files;
  for (const [k, id] of Object.entries(SETTING_INPUTS)) $(id).value = s[k];
  ringTotal();
  $("set-flowlog-dir").textContent = r.flowlog_dir;
  fileList($("set-flowlog-files-list"), [...r.flowlogs].reverse().slice(0, 14), () => []);
  const g = r.geo;
  kvList($("set-geo"), [
    ["Status", g.loaded ? `${fmtNum(g.rows)} address ranges loaded` : g.error ? `unavailable: ${g.error}` : "loading…"],
    ["Copy", g.bundled ? "the one shipped with ANTA" : "downloaded"],
    ["File date", g.file_date ? fmtDateTime(g.file_date) : "–"],
    ["Source", g.source_url, true],
  ]);
}

async function recordingsLoad() {
  const box = $("set-recordings");
  try {
    const r = await api("/api/recordings");
    const files = [];
    for (const rec of r.recordings) {
      for (const seg of rec.segments) files.push({ ...seg, name: seg.file, title: seg.path, rec });
    }
    fileList(box, files, (f) => [
      ["Analyse", () => { $("settings-dialog").close(); startSession({ mode: "file", path: f.path }); }],
      ["Delete", async () => {
        const n = f.rec.segments.length;
        if (!window.confirm(`Delete the recording ${f.rec.name}${n > 1 ? ` and all ${n} of its segments` : ""} ` +
                            `(${fmtBytes(f.rec.size)})? This cannot be undone.`)) return;
        try {
          await api("/api/recordings/delete", "POST", { name: f.rec.name });
          recordingsLoad();
        } catch (err) { $("settings-error").textContent = err.message; }
      }],
    ]);
  } catch (err) {
    box.replaceChildren(el("p", { class: "error" }, err.message));
  }
}

window.openSettings = async () => {
  $("settings-error").textContent = "";
  $("set-geo-status").textContent = "";
  try {
    settingsFill(await api("/api/settings"));
  } catch (err) {
    notice(err.message, true);
    return;
  }
  recordingsLoad();
  intelLoad();  // (the threat-intelligence feeds live here)
  $("settings-dialog").showModal();
};
$("settings-cancel").addEventListener("click", () => $("settings-dialog").close());
$("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const values = { flowlog_live: $("set-flowlog-live").checked, flowlog_files: $("set-flowlog-files").checked };
  for (const [k, id] of Object.entries(SETTING_INPUTS)) {
    const v = Number($(id).value);
    if (!Number.isFinite(v)) { $("settings-error").textContent = "Each number must be a number."; return; }
    values[k] = v;
  }
  try {
    settingsFill(await api("/api/settings", "PUT", { settings: values }));
    $("settings-dialog").close();
    notice("Settings saved.");
  } catch (err) {
    $("settings-error").textContent = err.message;
  }
});
$("set-flowlog-save").addEventListener("click", async () => {
  if (!sessionActive()) { $("settings-error").textContent = "Open a capture first."; return; }
  try {
    const r = await api("/api/save/flows", "POST", {});
    saveDownload(r);
    notice(`Saving the flow log of ${fmtNum(r.flows)} connections as ${r.name}.`);
  } catch (err) {
    $("settings-error").textContent = err.message;
  }
});
$("set-geo-update").addEventListener("click", async (e) => {
  const b = e.currentTarget;
  b.disabled = true;
  $("set-geo-status").textContent = "Downloading the GeoIP table (about 8 MB)…";
  try {
    const r = await api("/api/intel/update", "POST", { id: "geoip" });
    const res = r.results.geoip;
    $("set-geo-status").textContent = res.ok ? "Downloaded; loading it now." : `Could not download it: ${res.error}`;
    setTimeout(async () => { try { settingsFill(await api("/api/settings")); } catch { /* dialog closed */ } }, 3000);
  } catch (err) {
    $("set-geo-status").textContent = err.message;
  } finally {
    b.disabled = false;
  }
});

// ------------------------------------------------- TLS decryption (key log)

// After a key log is loaded, the server re-reads the capture with it and checks the
// HTTPS it opens up (downloads, threat-feed URLs); this follows that until it is done.
let keylogPoll = null;

async function keylogStatus() {
  try {
    const s = await api("/api/keylog");
    const on = $("pkt-keylog-on");
    on.hidden = !s.loaded;
    $("pkt-keylog").hidden = s.loaded;
    if (!s.loaded) return;
    let text = `TLS keys loaded (${fmtNum(s.secrets)} secret${s.secrets === 1 ? "" : "s"})`;
    const scan = s.scan;
    if (scan && scan.state === "running") text += " · checking HTTPS…";
    else if (scan && scan.state === "done") {
      text += ` · ${fmtNum(scan.sessions)} HTTPS session${scan.sessions === 1 ? "" : "s"} decrypted, ` +
        `${fmtNum(scan.files)} file${scan.files === 1 ? "" : "s"}, ${fmtNum(scan.alerts)} alert${scan.alerts === 1 ? "" : "s"}`;
    } else if (scan && scan.state === "error") text += ` · could not check HTTPS: ${scan.message}`;
    $("pkt-keylog-text").textContent = text;
    clearTimeout(keylogPoll);
    if (scan && scan.state === "running") {
      keylogPoll = setTimeout(keylogStatus, 1500);
    } else if (scan && scan.state === "done" && keylogPoll !== null) {
      keylogPoll = null;
      if (state.view === "files") filesLoad(true);  // the decrypted downloads are in the list now
    }
  } catch { /* not fatal */ }
}

function reloadPacketsAfterKeys() {
  pkt.loadedKey = null;
  if (state.view === "packets" && state.session && state.session.state !== "idle") pktLoad(1);
}

$("pkt-keylog").addEventListener("click", () => $("pkt-keylog-file").click());
$("pkt-keylog-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  if (file.size > 16 * 1024 * 1024) { notice("That key log is larger than 16 MB.", true); return; }
  try {
    const r = await api("/api/keylog", "POST", { content: await file.text() });
    notice(`Loaded ${fmtNum(r.added)} TLS secrets from ${file.name}. Your own TLS sessions will now be decrypted.`);
    filesView.key = null;  // downloads inside the decrypted HTTPS join the Files list
    await keylogStatus();
    reloadPacketsAfterKeys();
  } catch (err) {
    notice(err.message, true);
  }
});
$("pkt-keylog-clear").addEventListener("click", async () => {
  try {
    await api("/api/keylog/clear", "POST", {});
    await keylogStatus();
    reloadPacketsAfterKeys();
    filesView.key = null;  // the Files list no longer includes decrypted HTTPS
    notice("TLS keys cleared.");
  } catch (err) { notice(err.message, true); }
});
keylogStatus();
