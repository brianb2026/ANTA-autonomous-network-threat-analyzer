"""Turn detector metrics into analyst-readable sentences."""
from __future__ import annotations


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def fmt_period(s: float) -> str:
    if s < 1:
        return f"{s * 1000:.0f} ms"
    if s < 120:
        return f"{s:.1f} seconds"
    return f"{s / 60:.1f} minutes"


def fmt_duration(s: float) -> str:
    if s < 60:
        return f"{s:.1f} s"
    if s < 3600:
        return f"{s / 60:.1f} min"
    return f"{s / 3600:.1f} h"


def confidence_word(c: float) -> str:
    return "High-confidence" if c >= 0.85 else "Probable" if c >= 0.6 else "Possible"


def variance_phrase(cv: float) -> str:
    pct = cv * 100
    return "< 1% variance" if pct < 1 else f"{pct:.1f}% variance"


FEATURE_PHRASES = {
    "log_duration": "connection duration",
    "log_bytes_out": "bytes uploaded",
    "log_bytes_in": "bytes downloaded",
    "byte_asymmetry": "upload/download ratio",
    "size_entropy": "packet-size randomness",
    "iat_cv": "timing jitter",
    "log_iat_mean": "average gap between packets",
    "log_mean_payload": "average packet size",
    "log_packets": "packet count",
    "out_pkt_ratio": "share of packets sent by the client",
}


def beacon(m: dict) -> tuple[str, list[str]]:
    target = f"{m['dst_ip']}:{m['dst_port']}"
    mode = ("Connection occurs" if m["mode"] == "connections"
            else "The client checks in over a single persistent connection")
    if m["cv"] < 0.01:
        cadence = f"every exactly {fmt_period(m['period'])} with < 1% variance"
    elif m["jitter_pct"] < 8:
        cadence = f"every {fmt_period(m['period'])} with {variance_phrase(m['cv'])}"
    else:
        # Implants commonly randomise their sleep by a configured percentage.
        cadence = (f"every ~{fmt_period(m['period'])} with ±{m['jitter_pct']:.0f}% symmetric jitter "
                   f"(skew {m['skew']:+.2f})")
    cycle = "a C2 sleep cycle" if m["jitter_pct"] < 8 else "a C2 sleep cycle with configured jitter"
    head = (f"{confidence_word(m['confidence'])} automated beaconing detected to {target}. "
            f"{mode} {cadence}, characteristic of {cycle}.")
    details = [
        f"{m['count']} check-ins from {m['src_ip']} over {fmt_duration(m['span'])} "
        f"(interval median {m['period']:.3f} s, stdev {m['std'] * 1000:.1f} ms).",
        f"Check-in size is {'nearly constant' if m['size_cv'] < 0.15 else 'variable'} "
        f"(~{fmt_bytes(m['median_out'])} sent, ~{fmt_bytes(m['median_in'])} received per check-in).",
        f"Regularity score {m['score']:.2f} (timing {m['timing_score']:.2f}, size {m['size_score']:.2f}); "
        f"{m['presence']:.0%} of intervals fall on the dominant period.",
    ]
    if m.get("hosts") is not None:
        details.append(f"{m['hosts']} internal host{'s' if m['hosts'] != 1 else ''} contact this destination, "
                       f"so it is not a widely shared service.")
    if m.get("domain"):
        details.append(f"Destination was resolved from {m['domain']}.")
    if m.get("sni") and m["sni"] != m.get("domain"):
        details.append(f"TLS SNI: {m['sni']}.")
    if m.get("ja3"):
        details.append(f"Client TLS fingerprint JA3 {m['ja3']} is shared by every check-in.")
    if m.get("tasking"):
        details.append(f"{m['tasking']} check-ins received unusually large responses, consistent with tasking.")
    if m.get("user_agent"):
        details.append(f"HTTP User-Agent: {m['user_agent']}.")
    return head, details


def shared(m: dict) -> tuple[str, list[str]]:
    name = f"{m['domain']} ({m['dst_ip']}:{m['dst_port']})" if m.get("domain") else f"{m['dst_ip']}:{m['dst_port']}"
    head = (f"Periodic traffic to {name} from {m['hosts']} internal hosts, each checking in about every "
            f"{fmt_period(m['period'])}. A cadence shared this widely is typical of software heartbeats "
            f"or update checks rather than a targeted implant; verify the destination is expected.")
    details = [
        f"{m['prevalence']} of {m['clients']} active internal hosts talk to this destination.",
        f"Periodic hosts: {m['host_list']}.",
        "If this destination is unexpected, treat it as a possible fleet-wide compromise: "
        "malware on many hosts beaconing to the same server looks the same.",
    ]
    return head, details


def dns_tunnel(m: dict) -> tuple[str, list[str]]:
    head = (f"{confidence_word(m['confidence'])} DNS tunneling detected from {m['src_ip']} via {m['domain']}. "
            f"{m['queries']} queries carried {m['unique']} unique subdomains averaging "
            f"{m['mean_len']:.0f} characters with {m['mean_entropy']:.2f} bits/char of entropy, "
            f"consistent with data encoded into DNS labels.")
    details = [
        f"Encoded payload in query names: ~{fmt_bytes(m['qname_bytes'])} over {fmt_duration(m['span'])}.",
        f"Normal hostnames average roughly 2.5 to 3.2 bits/char; these average {m['mean_entropy']:.2f}.",
    ]
    if m["txt_ratio"] > 0.3:
        details.append(f"{m['txt_ratio']:.0%} of queries request TXT records "
                       f"({fmt_bytes(m['txt_bytes'])} of TXT answers), a common downstream channel.")
    if m.get("resolvers"):
        details.append(f"Resolver(s): {', '.join(m['resolvers'])}.")
    if m.get("sample"):
        details.append(f"Example query: {m['sample']}")
    return head, details


def exfil(m: dict) -> tuple[str, list[str]]:
    head = (f"{confidence_word(m['confidence'])} data exfiltration detected from {m['src_ip']} to "
            f"{m['dst_ip']}:{m['dst_port']}. {fmt_bytes(m['bytes_out'])} uploaded in "
            f"{fmt_duration(m['duration'])} while only {fmt_bytes(m['bytes_in'])} came back "
            f"({m['asymmetry']:.0%} outbound), an unusually one-sided transfer.")
    details = [f"Sustained upload rate: {fmt_bytes(m['rate'])}/s."]
    if m.get("hosts") is not None:
        details.append(f"Only {m['hosts']} internal host{'s' if m['hosts'] != 1 else ''} "
                       f"{'has' if m['hosts'] == 1 else 'have'} contacted this destination.")
    if m.get("entropy") is not None and m["entropy"] > 7.5:
        details.append(f"Upload stream entropy is {m['entropy']:.2f} bits/byte: encrypted or compressed data.")
    if m.get("domain"):
        details.append(f"Destination resolved from {m['domain']}.")
    if m.get("sni"):
        details.append(f"TLS SNI: {m['sni']}.")
    if m.get("ml_score") is not None:
        details.append(f"Isolation Forest also scores this session as anomalous (score {m['ml_score']:.3f}).")
    return head, details


def anomaly(m: dict) -> tuple[str, list[str]]:
    reasons = []
    for d in m["deviations"][:2]:
        word = "unusually high" if d["z"] > 0 else "unusually low"
        reasons.append(f"{word} {FEATURE_PHRASES.get(d['feature'], d['feature'])}")
    head = (f"{confidence_word(m['confidence'])} statistical anomaly in the session from "
            f"{m['src_ip']} to {m['dst_ip']}:{m['dst_port']}. The ML model scores it outside the "
            f"benign baseline, driven by {' and '.join(reasons)}.")
    details = [
        (f"{m.get('detector') or 'Isolation Forest'} score {m['score']:.3f} (alert threshold {m['threshold']:.3f}; "
         "lower is more anomalous)."),
        f"{fmt_bytes(m['bytes_out'])} sent, {fmt_bytes(m['bytes_in'])} received over {fmt_duration(m['duration'])}.",
    ]
    if m.get("hosts") is not None:
        n = m["hosts"]
        details.append(f"{n} internal host{'s' if n != 1 else ''} {'contacts' if n == 1 else 'contact'} this destination.")
    for d in m["deviations"]:
        details.append(f"{FEATURE_PHRASES.get(d['feature'], d['feature']).capitalize()}: "
                       f"{d['z']:+.1f} standard deviations from baseline.")
    return head, details


def agent(m: dict, verdict: dict) -> tuple[str, list[str]]:
    who = m.get("reviewer") or "the detection agent"
    head = (f"{who[0].upper() + who[1:]} judged the session from {m['src_ip']} to {m['dst_ip']}:{m['dst_port']} "
            f"{verdict['verdict']} ({round(verdict['confidence'] * 100)}% confident): "
            f"{verdict['headline'] or 'see the reasons below.'}")
    details = [f"Reason: {r}" for r in verdict.get("reasons") or []]
    details += [f"Next step: {s}" for s in verdict.get("next_steps") or []]
    details.append(f"{fmt_bytes(m['bytes_out'])} sent, {fmt_bytes(m['bytes_in'])} received over "
                   f"{fmt_duration(m['duration'])}.")
    if m.get("hosts") is not None:
        n = m["hosts"]
        details.append(f"{n} internal host{'s' if n != 1 else ''} {'contacts' if n == 1 else 'contact'} this destination.")
    details.append("This verdict comes from the detection agent, not from ANTA's own detectors: check its "
                   "reasons against the session before acting on it.")
    return head, details


def download(m: dict) -> tuple[str, list[str]]:
    how = ""
    if m["indicators"]:
        how = " " + " ".join(m["indicators"])
    head = (f"{m['src_ip']} downloaded {m['name'] or 'a file'} (a {m['file_type']}, "
            f"{fmt_bytes(m['size'])}) " + ("over HTTPS (decrypted with your TLS key log)" if m.get("decrypted")
                                           else "over unencrypted HTTP") + f" from {m['url']}.{how}")
    details = [f"SHA-256: {m['sha256']}" + ("" if m["complete"] else " (the capture missed part of the file, so "
                                                                     "this is the hash of what arrived)"),
               "Look the hash up in a threat-intelligence service (VirusTotal, a sandbox) to identify the file."]
    if m.get("content_type"):
        details.append(f"Content-Type: {m['content_type']}.")
    if m.get("user_agent"):
        details.append(f"User-Agent: {m['user_agent'][:200]}.")
    if m.get("hosts") is not None and m["hosts"] <= 1:
        details.append("No other internal host contacted this server.")
    if m.get("domain") and m["domain"] not in m["url"]:
        details.append(f"The server's address was resolved from {m['domain']}.")
    return head, details


def smb_file(m: dict) -> tuple[str, list[str]]:
    how = (" " + " ".join(m["indicators"])) if m["indicators"] else ""
    verb = f"copied {m['name']} (a {m['file_type']}, {fmt_bytes(m['size'])}) " + \
        ("to" if m["op"] == "write" else "from")
    head = f"{m['src_ip']} {verb} the Windows file share {m['share']} on {m['dst_ip']}.{how}"
    if m["sha256"]:
        details = [f"SHA-256: {m['sha256']}" + ("" if m["complete"] else " (part of the file was not copied in "
                                                                         "this capture: this is the hash of what was)"),
                   "Look the hash up in a threat-intelligence service (VirusTotal, a sandbox) to identify the file."]
    else:
        details = ["The capture missed part of the transfer, so the file could not be hashed."]
    details.append(f"Location: {m['location']}")
    if m["op"] == "write" and m["admin_share"]:
        details.append(f"On {m['dst_ip']}, look for a new service or scheduled task created around this time "
                       "(Windows events 7045 and 4698) that runs this file.")
    return head, details


def dns_poison(m: dict) -> tuple[str, list[str]]:
    from .devices import KIND_TEXT
    bad = ", ".join(m["bad"])
    why = "; ".join(f"{a} is {KIND_TEXT.get(k, k)}" for a, k in m["kinds"].items())
    if m.get("configured"):
        head = (f"{m['resolver']} is configured ({m['configured']}) to answer {m['name']} with {bad} itself, "
                f"instead of asking real DNS: {why}.")
    else:
        others = "; ".join(f"{res} answered {', '.join(a[:4])}{'…' if len(a) > 4 else ''}" for res, a in m["others"].items())
        head = (f"{m['resolver']} answered {m['name']} ({m['qtype']}) with {bad}: {why}."
                + (f" Other resolvers disagree ({others})." if others else "")
                + " A resolver that does this is redirecting its clients to an address of the attacker's choosing.")
    details = []
    if m["clients"]:
        details.append(f"Clients that received the false answer: {', '.join(m['clients'][:10])}.")
    if m.get("own_public"):
        details.append(f"The same resolver also gave the real address(es) {', '.join(m['own_public'][:4])}: "
                       "its answer for this name changed.")
    for c in m.get("contacts") or []:
        details.append(f"Connection to the false address: {c}.")
    details.append(f"Treat {m['resolver']} as compromised: check its DNS configuration (dnsmasq/hosts overrides) "
                   "and everything else it routes or serves.")
    return head, details


def compromised_device(m: dict) -> tuple[str, list[str]]:
    """The device behind an attacker's alert, with every address its configuration gives it."""
    from .devices import KIND_TEXT, address_kind
    dev = m["device"]
    head = (f"{dev['kind']} {dev['name']} is compromised. {m['reason']} "
            f"Addresses assigned to it ({len(m['addresses'])}): {', '.join(m['addresses'])}.")
    details = []
    for i in dev["interfaces"]:
        kind = address_kind(i["address"])
        line = f"{i['address']}" + (f"/{i['prefix']}" if i["prefix"] is not None else "") + f" on {i['name']}"
        if kind == "loopback":
            line += (": a loopback address, used only inside the device and never seen on the network; "
                     "only its configuration reveals it")
        elif i["address"] == m["ip"]:
            line += ": the address it did this from"
        else:
            line += f": {KIND_TEXT.get(kind, kind)}"
        details.append(line + ".")
    for name in dev.get("dhcp_interfaces") or []:
        details.append(f"{name} takes its address from DHCP, so that address isn't in the configuration: look for "
                       "DHCP leases given to this device.")
    details.append(f"Its configuration: {dev.get('evidence') or dev.get('source')}"
                   + (f", SHA-256 {dev['sha256']}" if dev.get("sha256") else "") + ".")
    for c in m["causes"]:
        details.append(f"Evidence: {c}")
    return head, details


def crafted_tcp(m: dict) -> tuple[str, list[str]]:
    what = (f"{m['segments']} TCP segment{'s' if m['segments'] != 1 else ''} with no flags set at all "
            "(not even ACK)")
    if m["payload"]:
        head = (f"{m['src_ip']} and {m['dst_ip']}:{m['dst_port']} exchanged {fmt_bytes(m['payload'])} in {what}. "
                "No operating system's TCP stack sends data that way: these packets were built by hand, as covert "
                "channels and raw-socket implants do.")
    else:
        head = (f"{m['src_ip']} sent {what} to {m['dst_ip']}:{m['dst_port']}: a NULL scan, probing which ports "
                "are open without completing a connection.")
    details = []
    if m.get("poisoned"):
        details.append(f"{m['dst_ip']} is the address a poisoned DNS answer pointed to.")
    if m.get("domain"):
        details.append(f"{m['dst_ip']} was resolved from {m['domain']}.")
    details.append("Wireshark shows these segments' flags as [<None>].")
    return head, details


def ftp_file(m: dict) -> tuple[str, list[str]]:
    verb = "uploaded" if m["upload"] else "downloaded"
    head = (f"{m['src_ip']} {verb} {m['name']} ({m['what']}, {fmt_bytes(m['size'])}) "
            f"{'to' if m['upload'] else 'from'} the FTP server {m['dst_ip']} as user {m['user']}, unencrypted: "
            "anyone on the path can read it.")
    details = []
    if m.get("tls_refused"):
        details.append("The client asked for TLS (AUTH TLS) and the server refused, so the login and file went in "
                       "clear text.")
    if m["user"] in ("anonymous", "ftp"):
        details.append("The server accepts anonymous logins: anyone can read what was stored there.")
    if m["sha256"]:
        details.append(f"SHA-256: {m['sha256']}" + ("" if m["complete"] else " (part of the transfer was missed)"))
    return head, details


def tls_port(m: dict) -> tuple[str, list[str]]:
    port = m["dst_port"]
    if m["protocol"]:
        head = (f"{m['src_ip']} spoke {m['protocol']}, not TLS, to {m['dst_ip']}:{port}. Tunnels and remote-access "
                f"tools use TLS ports this way to slip past firewalls that only allow web traffic.")
    else:
        what = ("an interactive, two-way session lasting " + fmt_duration(m["duration"])
                if m["remote_control"] else "a session")
        head = (f"{m['src_ip']} held {what} with {m['dst_ip']}:{port} in a custom binary protocol, not TLS. "
                f"Remote-access trojans and other command-and-control tools hide on port {port} this way.")
    details = [f"The {m['speaker']} spoke first, and its first bytes ({m['first_bytes']}) are not a TLS record.",
               f"{fmt_bytes(m['payload_out'])} sent and {fmt_bytes(m['payload_in'])} received over "
               f"{fmt_duration(m['duration'])}" + (" (still open at the end of the capture)." if m["open"] else ".")]
    if m["remote_control"] and m["payload_in"] > 4 * m["payload_out"]:
        details.append("Far more came back than was sent, as when a controller pushes tools or modules "
                       "to the client.")
    if not m.get("domain"):
        details.append("No DNS lookup for this address was seen: the client connected straight to an IP address.")
    else:
        details.append(f"Destination resolved from {m['domain']}.")
    if m.get("hosts") is not None and m["hosts"] <= 1:
        details.append("No other internal host contacted this destination.")
    if m.get("entropy") is not None and m["entropy"] > 7.5:
        details.append(f"Client stream entropy {m['entropy']:.2f} bits/byte: encrypted or compressed.")
    return head, details


def port_mismatch(m: dict) -> tuple[str, list[str]]:
    head = (f"Traffic from {m['src_ip']} to {m['target']} is {m['app']}, not the {m['expected']} that port is for: "
            "ANTA recognised it from its first bytes, not from the port number.")
    details = []
    if m.get("sample"):
        details.append(f"It starts with \"{m['sample'][:60]}\".")
    if m.get("remote"):
        details.append(f"{m['app']} on the {m['expected']} port is a classic way to get a remote shell, proxy or tunnel "
                       f"through a firewall that only lets {m['expected']} out.")
    else:
        details.append("A service on a non-standard port can be harmless (a developer's test server), but it also "
                       "slips past rules written for that port.")
    details.append(f"Check what runs on {m['dst_ip']} port {m['dst_port']} and who set it up.")
    return head, details


def intel_match(m: dict) -> tuple[str, list[str]]:
    what = {"ip": "an address", "ip_port": "an address and port", "domain": "a domain", "url": "a URL",
            "sha256": "a file", "ja3": "a TLS fingerprint (JA3)", "ja4": "a TLS fingerprint (JA4)"}.get(m["kind"], m["kind"])
    listed = ", ".join(m["feeds"]) or "a threat-intelligence feed"
    why = "; ".join(m["reasons"][:3])
    head = (f"{m['src_ip']} touched {what} on a threat-intelligence list: {m['indicator']} ({m['where']}). "
            f"Listed by {listed}" + (f" as {why}" if why else "") + ".")
    details = [f"Session: {m['session']}."]
    if m.get("first_seen"):
        details.append(f"First listed {m['first_seen']}.")
    if m["kind"] in ("ja3", "ja4"):
        details.append("TLS fingerprints identify the client software, and common libraries can share one: treat this "
                       "as a lead to confirm with the destination and the host's processes.")
    elif m["kind"] == "sha256":
        details.append("A file with exactly this content is known malware: treat the receiving host as infected.")
    else:
        details.append(f"Treat {m['src_ip']} as possibly compromised: find the process that made this connection.")
    return head, details


def baseline(m: dict) -> tuple[str, list[str]]:
    import datetime
    when = datetime.datetime.fromtimestamp(m["start"], tz=datetime.timezone.utc).strftime("%H:%M:%S UTC")
    head = f"{m['src_ip']} {m['text']} (from {when}), compared with its own last {m['history_min']} minutes."
    details = []
    meaning = {
        "bytes_out": "A host suddenly sending far more than usual: a large upload, a backup, or data being stolen.",
        "dst_hosts": "A host suddenly talking to many more machines than usual: scanning, a worm spreading, or a "
                     "misbehaving program.",
        "dst_ports": "A host suddenly trying many more ports than usual: a port scan.",
        "sessions": "A host suddenly opening far more connections than usual: scanning, a flood, or a stuck retry loop.",
        "bytes_in": "A host suddenly receiving far more than usual: a large download or update.",
        "new_app": "A protocol this host never used before: new software, an administrator at work, or an attacker "
                   "moving laterally.",
    }.get(m["metric"])
    if meaning:
        details.append(meaning)
    if m.get("examples"):
        details.append("For example: " + "; ".join(m["examples"][:3]) + ".")
    details.append("Each host is compared only with itself, so this is unusual for this host, not necessarily for "
                   "the network.")
    return head, details


def dga(m: dict) -> tuple[str, list[str]]:
    head = (f"{m['src_ip']} asked for {m['count']} different random-looking domains that do not exist "
            f"(average name randomness {m['entropy']} bits/character). This is how malware with a domain-generation "
            "algorithm finds its command-and-control server: it tries generated name after generated name until one "
            "resolves.")
    details = [
        "The names that do not exist are the misses; the one in the batch that does resolve is the likely C2. "
        "Check what this host connected to right after these lookups.",
        "A few failed lookups are normal (typos, a search domain that is gone). Many distinct random-looking ones "
        "from one host, in a short time, are not.",
    ]
    if m.get("examples"):
        details.append("For example: " + ", ".join(m["examples"][:8]) + ".")
    return head, details


def scan(m: dict) -> tuple[str, list[str]]:
    fail_pct = round(100 * m["failed"] / m["attempts"])
    if m["kind"] == "vertical":
        head = (f"{m['src_ip']} tried {m['count']} different ports on {m['dst_ip']} and {fail_pct}% of the attempts "
                "got no completed connection: a port scan, mapping which services the host is running.")
    else:
        where = ""
        if m.get("internal_targets"):
            where = f" ({m['internal_targets']} of them on the local network)"
        head = (f"{m['src_ip']} tried to reach port {m['dst_port']} on {m['count']} different hosts{where}, "
                f"and {fail_pct}% of the attempts got no completed connection: a host sweep, looking for every "
                "machine running one service.")
    details = []
    if m.get("internal_src"):
        details.append("The scanner is on the local network. An internal host scanning others is how an intruder "
                       "or a worm finds its next target (lateral movement), so treat it as a possibly compromised "
                       "device, not just noise.")
    else:
        details.append("The scanner is outside the local network. This is common background internet noise, but a "
                       "burst of it can be the reconnaissance before a targeted attack.")
    details.append("Most connection attempts never completed a TCP handshake, which is what a scan looks like: a "
                   "normal client finishes its handshakes and talks to only a few ports or hosts.")
    if m.get("examples"):
        details.append("For example: " + ", ".join(m["examples"][:6]) + ".")
    return head, details


def _mac_vendor(mac: str, vendor: str) -> str:
    return f"{mac} ({vendor})" if vendor else mac


def arp_spoof(m: dict) -> tuple[str, list[str]]:
    owners = m["owners"]
    listed = ", ".join(_mac_vendor(mc, v) for mc, v in sorted(owners.items()))
    head = (f"{m['ip']} is claimed over ARP by {len(owners)} different hardware addresses ({listed}). "
            "On a local network an IP belongs to one machine, so a second one answering for it is ARP cache "
            "poisoning: a device telling the LAN that this address is at its MAC, to intercept the traffic.")
    details = []
    if m.get("spoofer"):
        extra = m["also_claims"]
        line = f"{_mac_vendor(m['spoofer'], owners.get(m['spoofer'], ''))} is the likely spoofer"
        if extra:
            line += (f": it also answers ARP for {', '.join(extra[:8])}"
                     f"{'…' if len(extra) > 8 else ''}, which a real host never does")
        details.append(line + ".")
    details.append("If this address is your default gateway, the spoofer is positioned to read or alter all traffic "
                   "between this network and the internet (a man-in-the-middle).")
    details.append("Benign causes exist — a DHCP lease moving between machines, or a failover that is not VRRP/HSRP — "
                   "so confirm before acting: check which machine really owns the MAC, and whether both were active "
                   "at the same time.")
    details.append("The addresses are shown so you can find the offending device and remove it at your switch or "
                   "router (block its MAC or disable its port); ANTA only observes, it does not change the network.")
    return head, details


# The encrypted form of each service a login was seen in clear text on: where to move it.
SAFER_SERVICE = {
    "FTP": "SFTP (file transfer over SSH) or FTPS",
    "POP": "POP3 over TLS (port 995)",
    "IMAP": "IMAP over TLS (port 993)",
    "SMTP": "SMTP with STARTTLS, or mail submission over TLS (port 465)",
    "HTTP": "HTTPS",
    "LDAP": "LDAPS (port 636) or LDAP with StartTLS",
    "Telnet": "SSH",
    "SNMP": "SNMPv3 with authentication and encryption (authPriv)",
}


def cleartext_login(m: dict) -> tuple[str, list[str]]:
    where = f"{m['dst_ip']}:{m['dst_port']}"
    if m["service"] == "SNMP":
        head = (f"{m['src_ip']} sent an SNMP community string to {where} in clear text. A community string works "
                "as the device's password: anyone on the path can read it and use it to query the device"
                + (", and this one is a factory default anyone can guess." if m["default_secret"] else "."))
    else:
        who = f" as {m['users']}" if m["users"] else ""
        head = (f"{m['src_ip']} logged in to {m['service']} on {where}{who} with a password sent in clear text "
                f"({m['method']}): anyone on the path could read it.")
    details = []
    n = m["logins"]
    if m["service"] != "SNMP":
        if m["accepted"] == n:
            details.append("The server accepted the login, so the password works." if n == 1 else
                           f"The server accepted all {n} logins, so the password works.")
        elif m["refused"] == n:
            details.append("The server refused the login, but a mistyped or old password still went out readable."
                           if n == 1 else f"The server refused all {n} logins, but the passwords tried still went "
                           "out readable.")
        elif m["unknown"] == n:
            details.append("Whether the server accepted it isn't known from the capture.")
        else:
            details.append(f"{m['accepted']} of {n} logins were accepted, {m['refused']} refused.")
    details.append(f"Change {'this password' if m['accounts'] == 1 else 'these passwords'}, and move the service "
                   f"to {m['safer']} so logins are encrypted.")
    details.append("ANTA never shows or keeps the password itself: only the account and whether it worked.")
    return head, details
