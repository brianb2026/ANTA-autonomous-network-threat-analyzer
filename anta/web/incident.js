// Incident context: the file an alert is about, who the affected host is (IP,
// MAC, host name, user account, domain, OS, from the capture's own evidence),
// and an incident report that gathers victims, alerts and indicators.
"use strict";

// ------------------------------------------------------- host evidence

// Host evidence comes from the capture's statistics (the unfiltered run, which
// the server caches), fetched once per capture.
const hostCtx = { key: null, nodes: null, loading: null };

async function hostNodes() {
  if (!sessionActive()) return null;
  const key = sessionKey();
  if (hostCtx.key === key && hostCtx.nodes) return hostCtx.nodes;
  if (hostCtx.loading && hostCtx.key === key) return hostCtx.loading;
  hostCtx.key = key;
  hostCtx.loading = api("/api/stats").then((res) => {
    hostCtx.nodes = new Map(((res.map || {}).nodes || []).map((n) => [n.addr, n]));
    return hostCtx.nodes;
  }).catch(() => null).finally(() => { hostCtx.loading = null; });
  return hostCtx.loading;
}

function isInternal(ip) {
  if (!ip) return false;
  if (ip.includes(":")) return /^(fe80|fc|fd)/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b < 128);
}

// The side of an alert that is on the local network: usually the victim. When an
// alert names an offender (a resolver lying about names), that device is the subject.
function affectedHost(a) {
  if (a.offender) return a.offender;
  if (isInternal(a.src_ip)) return a.src_ip;
  if (isInternal(a.dst_ip)) return a.dst_ip;
  return a.src_ip;
}

// Every address a device has, from its configuration: "192.168.5.1/28 (to_openwrt2)".
function deviceAddresses(d) {
  return (d.interfaces || []).map((i) => `${i.address}${i.prefix !== null && i.prefix !== undefined ? `/${i.prefix}` : ""} (${i.name})`);
}

function hostFacts(n) {
  const facts = [];
  const names = (n.names || []).map(([name, src]) => `${name} (${src})`);
  if (names.length) facts.push(["Host name", names.slice(0, 3).join(", ")]);
  if ((n.macs || []).length) facts.push(["MAC address", n.macs.join(", ") + (n.vendor ? ` (${n.vendor})` : "")]);
  if ((n.users || []).length) facts.push(["User account", n.users.join(", ")]);
  if ((n.domains || []).length) facts.push(["Domain", n.domains.join(", ")]);
  if (n.os) facts.push(["Operating system", `${n.os}${n.os_reason ? ` — from ${n.os_reason}` : ""}`]);
  if (n.role) facts.push(["Role on the network", n.role]);
  if (n.geo) facts.push(["Network owner", geoText(n.geo)]);
  return facts;
}

function kvList(dl, rows) {
  dl.replaceChildren();
  for (const [k, v, copy] of rows) {
    const dd = el("dd");
    dd.append(el("span", { class: copy ? "mono" : "" }, v));
    if (copy) {
      const b = el("button", { type: "button", class: "link small", "aria-label": `Copy ${k}` }, "Copy");
      b.addEventListener("click", () => copyText(v));
      dd.append(" ", b);
    }
    dl.append(el("dt", {}, k), dd);
  }
}

// ------------------------------------------------ alert detail cards

let contextSeq = 0;
window.renderAlertContext = async (a) => {
  const fileCard = $("d-file");
  fileCard.hidden = !a.file;
  if (a.file) {
    const f = a.file;
    $("d-file-sub").textContent = f.complete ? "complete file" : "partly captured";
    kvList($("d-file-kv"), [
      ["Name", f.name || "(none)"],
      [f.url.startsWith("\\\\") ? "Location" : "URL", f.url, true],
      ["Type", f.type + (f.content_type ? ` · sent as ${f.content_type}` : "")],
      ["Size", `${fmtBytes(f.size)} (${f.size.toLocaleString()} bytes)` + (f.decoded ? ", after decompression" : "")],
      ["SHA-256", f.sha256, true],
    ]);
  }
  const devCard = $("d-device");
  devCard.hidden = !a.device;
  if (a.device) {
    const d = a.device;
    $("d-device-title").textContent = `${a.offender ? "Suspected malicious device" : "Device"}: ${d.name}`;
    $("d-device-sub").textContent = d.kind;
    const rows = [["All its addresses", deviceAddresses(d).join("\n") || "(none listed)", true]];
    if ((d.dhcp_interfaces || []).length) rows.push(["Set by DHCP", d.dhcp_interfaces.join(", ")]);
    if ((d.dns_overrides || []).length) rows.push(["Names it answers itself", d.dns_overrides.map(([n, ip]) => `${n} → ${ip}`).join(", ")]);
    rows.push(["Described by", d.evidence || d.source]);
    kvList($("d-device-kv"), rows);
    $("d-device-note").textContent = (d.dhcp_interfaces || []).length
      ? "Interfaces set by DHCP have addresses the configuration doesn't record." : "";
  }
  const card = $("d-host");
  const ip = affectedHost(a);
  const seq = ++contextSeq;
  card.hidden = !ip;
  if (!ip) return;
  // With a device card above, this card only adds what the traffic shows about the address.
  $("d-host-title").textContent = a.device ? `In the capture: ${ip}` :
    `${a.offender ? "Suspected malicious device" : "Affected host"}: ${ip}`;
  $("d-host-note").textContent = "Looking up what the capture shows about this host…";
  $("d-host-kv").replaceChildren();
  const nodes = await hostNodes();
  if (seq !== contextSeq) return;  // another alert was opened meanwhile
  const n = nodes && nodes.get(ip);
  if (!n) {
    $("d-host-note").textContent = nodes ? "The capture has no more about this host." :
      "Host details need the capture file (or a recorded live capture).";
    return;
  }
  kvList($("d-host-kv"), [["IP address", ip], ...hostFacts(n)]);
  $("d-host-note").textContent = (n.users || []).length || a.device ? "" :
    "No user account was seen: Windows logons show up in Kerberos traffic to the domain controller.";
};

$("d-host-map").addEventListener("click", () => {
  const a = state.detail;
  if (a) window.openHost(affectedHost(a));
});

// ---------------------------------------------------------- the report

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

function alertIndicators(a) {
  const out = { ips: new Set(), urls: new Set(), files: [], domains: new Set() };
  const remote = a.src_ip === affectedHost(a) ? a.dst_ip : a.src_ip;
  if (remote && !isInternal(remote)) out.ips.add(a.dst_port ? `${remote}:${a.dst_port}` : remote);
  if (a.file) {
    out.urls.add(a.file.url);
    out.files.push(a.file);
  }
  const s = a.stream || {};
  for (const d of s.dns_context || []) out.domains.add(d);
  if (s.sni) out.domains.add(s.sni);
  if (s.http && s.http.host && !/^[\d.:[\]]+$/.test(s.http.host.split(":")[0])) out.domains.add(s.http.host.split(":")[0]);
  return out;
}

async function buildReport() {
  const ids = [...state.alerts.keys()];
  const full = await Promise.all(ids.map((id) => api(`/api/alerts/${encodeURIComponent(id)}`).catch(() => null)));
  const alerts = full.filter(Boolean).sort((x, y) =>
    SEV_RANK[x.severity] - SEV_RANK[y.severity] || x.first_seen - y.first_seen);
  const verdict = (a) => (a.triage && a.triage.status) || "new";
  // An alert the analyst dismissed stays in the list, but names no victim, device or indicator.
  const serious = alerts.filter((a) => SEV_RANK[a.severity] <= 1 && verdict(a) !== "false_positive");
  const dismissed = alerts.filter((a) => verdict(a) === "false_positive");
  const confirmed = alerts.filter((a) => verdict(a) === "confirmed");
  const nodes = await hostNodes();
  const kase = await api("/api/case").catch(() => null);
  const lines = [];
  const source = state.session && state.session.source ? state.session.source : "this session";
  lines.push(`ANTA incident report — ${source}`);
  lines.push(`Generated ${new Date().toLocaleString()} · ${alerts.length} alert${alerts.length === 1 ? "" : "s"}, ` +
    `${serious.length} high or critical` + (confirmed.length ? `, ${confirmed.length} confirmed by the analyst` : "") +
    (dismissed.length ? `, ${dismissed.length} dismissed as false positive${dismissed.length === 1 ? "" : "s"}` : ""));
  lines.push("");
  if (kase && kase.notes) {
    lines.push("ANALYST NOTES", ...kase.notes.split("\n").map((l) => `  ${l}`), "");
  }

  // Devices that are the attacker's (a resolver poisoning answers...): every address they have.
  const offenders = new Map();
  for (const a of serious) if (a.offender && !offenders.has(a.offender)) offenders.set(a.offender, a);
  if (offenders.size) {
    lines.push("MALICIOUS DEVICES");
    for (const [ip, a] of offenders) {
      const d = a.device;
      const n = nodes && nodes.get(ip);
      const why = [...new Set(serious.filter((x) => x.offender === ip && x.kind !== "compromised_device")
        .map((x) => x.title))].join(", ") || a.title;
      lines.push(`- ${ip}${d ? ` (${d.kind} ${d.name})` : n && n.name ? ` (${n.name})` : ""} — ${why}`);
      const withAll = serious.find((x) => x.offender === ip && (x.addresses || []).length);
      const all = withAll ? withAll.addresses.slice() : d ? d.addresses.slice() : [ip];
      if (!all.includes(ip)) all.unshift(ip);
      lines.push(`    All addresses of this device: ${all.join(", ")}`);
      if (d) {
        for (const x of deviceAddresses(d)) lines.push(`      ${x}`);
        if ((d.dhcp_interfaces || []).length) lines.push(`      plus DHCP-configured: ${d.dhcp_interfaces.join(", ")}`);
        lines.push(`    From: ${d.evidence || d.source}`);
      } else {
        lines.push("    (no configuration of this device was seen: other addresses it has are unknown)");
      }
      if (n) for (const [k, v] of hostFacts(n)) lines.push(`    ${k}: ${v}`);
    }
    lines.push("");
  }

  const victims = [...new Set(serious.flatMap((a) => a.offender ? (a.victims || []) : [affectedHost(a)]))];
  lines.push("AFFECTED HOSTS");
  if (!victims.length) lines.push("  None: no high or critical alerts.");
  for (const ip of victims) {
    const n = nodes && nodes.get(ip);
    lines.push(`- ${ip}${n && n.name ? ` (${n.name})` : ""}`);
    if (n) for (const [k, v] of hostFacts(n)) lines.push(`    ${k}: ${v}`);
    else lines.push("    (no host details: open the capture file to see them)");
  }
  lines.push("");

  lines.push("ALERTS");
  alerts.forEach((a, i) => {
    lines.push(`${i + 1}. [${a.severity.toUpperCase()}] ${a.title} — ${a.src_ip} → ${a.target || a.dst_ip || ""}`);
    lines.push(`   First seen ${fmtDateTime(a.first_seen)}`);
    if (a.triage) lines.push(`   Analyst verdict: ${VERDICT_LABEL[verdict(a)]}`);
    if (a.triage && a.triage.note) lines.push(...a.triage.note.split("\n").map((l, j) => `   ${j ? "  " : "Notes: "}${l}`));
    lines.push(`   ${a.headline}`);
    if (a.file) lines.push(`   File: ${a.file.name} · ${a.file.type} · ${a.file.size} bytes · SHA-256 ${a.file.sha256}`);
  });
  if (!alerts.length) lines.push("  None.");
  lines.push("");

  const ioc = { ips: new Set(), urls: new Set(), files: [], domains: new Set() };
  for (const a of serious) {
    const x = alertIndicators(a);
    x.ips.forEach((v) => ioc.ips.add(v));
    x.urls.forEach((v) => ioc.urls.add(v));
    x.domains.forEach((v) => ioc.domains.add(v));
    for (const f of x.files) if (!ioc.files.some((g) => g.sha256 === f.sha256)) ioc.files.push(f);
  }
  lines.push("INDICATORS (from high and critical alerts)");
  const list = (label, items) => { if (items.length) lines.push(`${label}:`, ...items.map((v) => `  ${v}`)); };
  list("Addresses", [...ioc.ips]);
  list("Domains", [...ioc.domains]);
  list("Locations (URLs, file shares)", [...ioc.urls]);
  list("Files (SHA-256)", ioc.files.map((f) => `${f.sha256}  ${f.name}`));
  if (!ioc.ips.size && !ioc.urls.size && !ioc.files.length && !ioc.domains.size) lines.push("  None.");
  if (kase && kase.pins.length) {
    lines.push("", "PINNED FINDINGS");
    kase.pins.forEach((p, i) => {
      lines.push(`${i + 1}. ${p.question || p.summary}`);
      if (p.summary && p.question) lines.push(`   ${p.summary}`);
      for (const l of p.lines) lines.push(`   ${l}`);
      if (p.table && p.table.rows.length) {
        for (const r of p.table.rows.slice(0, 10)) lines.push(`     ${r.cells.filter(Boolean).join(p.table.facts ? ": " : " | ")}`);
        if (p.table.rows.length > 10) lines.push(`     (${p.table.rows.length - 10} more rows)`);
      }
      if (p.filter) lines.push(`   Display filter: ${p.filter}`);
    });
  }
  return lines.join("\n");
}

$("report-open").addEventListener("click", async () => {
  const dialog = $("report-dialog");
  $("report-text").textContent = "Building the report…";
  dialog.showModal();
  try {
    $("report-text").textContent = await buildReport();
  } catch (err) {
    $("report-text").textContent = `Could not build the report: ${err.message}`;
  }
});
$("report-copy").addEventListener("click", () => copyText($("report-text").textContent));
$("report-save").addEventListener("click", async () => {
  try {
    await saveTextFile(`${captureStem()}_incident_report.txt`, "txt", $("report-text").textContent);
  } catch (err) {
    $("report-text").textContent += `\n\n(Could not save: ${err.message})`;
  }
});
$("report-close").addEventListener("click", () => $("report-dialog").close());
