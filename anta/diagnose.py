"""Plain-English diagnosis of connections and packets, for analysts who don't read
TCP flags for a living: what happened, why it most likely happened, and what to
check next.

It is rule-based and local. The facts come from the engine's decode, the same
fields Wireshark names (tcp.analysis.retransmission, tls.alert_message.desc,
icmp.code...), and every finding cites the frames it rests on, so an analyst can
check it in the packet list. Nothing is sent anywhere and nothing is guessed by a
language model: when the evidence doesn't say why, the explanation says so.
"""
from __future__ import annotations

import math
import re
from collections import Counter

# Fields the connection explainer reads for every frame (engine --fields).
FIELDS = ",".join([
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "ip.ttl", "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.len",
    "tcp.flags.*", "tcp.window_size_value", "tcp.analysis.*", "udp.srcport", "udp.dstport", "udp.stream",
    "icmp.type", "icmp.code", "icmpv6.type", "icmpv6.code", "tls.handshake.type", "tls.alert_message.level",
    "tls.alert_message.desc", "tls.handshake.extensions_server_name", "http.request.method", "http.request.uri",
    "http.host", "http.response.code", "dns.flags.response", "dns.flags.rcode", "dns.qry.name", "dns.id",
    "dns.flags.truncated", "ftp.response.code", "ftp.request.command", "smb2.nt_status", "kerberos.error_code",
    "kerberos.msg_type", "ldap.resultCode", "ntlmssp.auth.username",
])

MAX_FRAMES = 4000          # frames read per explanation
MAX_CONVERSATIONS = 25     # conversations explained at once
MAX_TIMELINE = 60          # events shown per conversation

SERVICES = {20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3", 123: "NTP", 135: "Microsoft RPC", 137: "NetBIOS name",
            138: "NetBIOS datagram", 139: "NetBIOS session (SMB)", 143: "IMAP", 161: "SNMP", 162: "SNMP trap",
            389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos password", 465: "SMTPS", 514: "syslog",
            587: "mail submission", 636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S", 1433: "Microsoft SQL",
            1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 3268: "AD global catalog", 3306: "MySQL", 3389: "RDP",
            5060: "SIP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM (TLS)", 6379: "Redis",
            8080: "HTTP alternate", 8443: "HTTPS alternate", 9200: "Elasticsearch", 27017: "MongoDB"}

# --------------------------------------------------------------- vocabularies

ICMP_UNREACHABLE = {
    0: ("network unreachable", "a router has no route to the destination network"),
    1: ("host unreachable", "the last router couldn't reach the host: it is off, or not answering ARP on its network"),
    2: ("protocol unreachable", "the host doesn't speak that IP protocol"),
    3: ("port unreachable", "the host is up, but nothing is listening on that port"),
    4: ("fragmentation needed", "the packet is too big for a link on the path and may not be fragmented: "
                                "an MTU problem (path MTU discovery, VPN or tunnel overhead)"),
    5: ("source route failed", "the source route in the packet couldn't be followed"),
    6: ("destination network unknown", "the network is unknown to the router"),
    7: ("destination host unknown", "the host is unknown to the router"),
    9: ("network administratively prohibited", "a firewall or router ACL forbids traffic to that network"),
    10: ("host administratively prohibited", "a firewall or router ACL forbids traffic to that host"),
    11: ("network unreachable for this type of service", "routing by type of service failed"),
    12: ("host unreachable for this type of service", "routing by type of service failed"),
    13: ("communication administratively prohibited", "a firewall rejected the traffic (a REJECT rule, not a silent drop)"),
    14: ("host precedence violation", "the requested precedence isn't allowed"),
    15: ("precedence cutoff", "the precedence is below the network's minimum"),
}
ICMPV6_UNREACHABLE = {
    0: ("no route to destination", "a router has no route to the destination"),
    1: ("communication administratively prohibited", "a firewall rejected the traffic"),
    2: ("beyond the scope of the source address", "the source address can't reach that destination"),
    3: ("address unreachable", "the last router couldn't reach the host: it is off, or not answering neighbour discovery"),
    4: ("port unreachable", "the host is up, but nothing is listening on that port"),
    5: ("source address failed ingress/egress policy", "a filter rejected the source address"),
    6: ("reject route to destination", "a router has a route that rejects that destination"),
}

TLS_ALERTS = {
    0: ("close_notify", "an orderly end of the encrypted session", None),
    10: ("unexpected_message", "a message arrived out of order", "a broken implementation or something tampering with the stream"),
    20: ("bad_record_mac", "a record failed its integrity check", "corruption in transit or a middlebox altering the stream"),
    22: ("record_overflow", "a record was too long", None),
    40: ("handshake_failure", "the two sides found no parameters in common",
         "no cipher suite, TLS version or curve both support: an old client or server, or one hardened to refuse it"),
    41: ("no_certificate", "no client certificate was sent", "the server wanted a client certificate"),
    42: ("bad_certificate", "a certificate was malformed or failed verification", "a corrupt or wrongly issued certificate"),
    43: ("unsupported_certificate", "the certificate type isn't supported", None),
    44: ("certificate_revoked", "the certificate was revoked by its issuer", "the server still uses a revoked certificate"),
    45: ("certificate_expired", "the certificate has expired or isn't valid yet", "an expired certificate, or a wrong clock on one side"),
    46: ("certificate_unknown", "the certificate couldn't be accepted", "an untrusted or mismatched certificate"),
    47: ("illegal_parameter", "a handshake field had an impossible value", None),
    48: ("unknown_ca", "the certificate was issued by an authority the side doesn't trust",
         "a self-signed or private-CA certificate, or a TLS-intercepting proxy whose CA isn't installed on the client"),
    49: ("access_denied", "a valid certificate was presented but access was refused", None),
    50: ("decode_error", "a message couldn't be decoded", "a non-TLS protocol on the port, or a broken implementation"),
    51: ("decrypt_error", "a handshake signature or key exchange check failed", None),
    70: ("protocol_version", "the TLS version offered isn't supported",
         "the client offers only old versions (TLS 1.0/1.1) the server refuses, or the reverse"),
    71: ("insufficient_security", "the offered ciphers are too weak for the server", None),
    80: ("internal_error", "the sender hit an internal error", "a fault on that side, not a protocol mismatch"),
    86: ("inappropriate_fallback", "a version downgrade was detected and refused", None),
    90: ("user_canceled", "the handshake was cancelled", None),
    109: ("missing_extension", "a required extension was missing", None),
    110: ("unsupported_extension", "an extension wasn't expected", None),
    112: ("unrecognized_name", "the server doesn't host the requested name (SNI)",
          "the name in the client's request isn't configured on that server"),
    116: ("certificate_required", "the server requires a client certificate", "mutual TLS without a client certificate"),
    120: ("no_application_protocol", "no application protocol (ALPN) in common", "e.g. the client insists on HTTP/2"),
}

HTTP_STATUS = {
    400: "the server couldn't parse the request (malformed, or too large)",
    401: "authentication is required, or the credentials were refused",
    403: "the server understood the request and refuses it (permissions, IP filter or WAF)",
    404: "the path doesn't exist on the server (a moved or deleted page, a typo, or someone probing for files)",
    405: "that method isn't allowed on this path",
    407: "the proxy requires authentication",
    408: "the server gave up waiting for the request",
    413: "the request body is too large",
    429: "too many requests: the client is being rate-limited",
    500: "the server application failed while handling the request",
    502: "a gateway or reverse proxy got a bad answer from the server behind it",
    503: "the service is unavailable: overloaded, down for maintenance, or no healthy back end",
    504: "a gateway or reverse proxy timed out waiting for the server behind it",
}

DNS_RCODES = {
    1: ("FORMERR", "the server couldn't parse the query"),
    2: ("SERVFAIL", "the resolver failed to get an answer: the domain's own name servers are down or broken, "
                    "or DNSSEC validation failed"),
    3: ("NXDOMAIN", "the name doesn't exist"),
    4: ("NOTIMP", "the server doesn't support that kind of query"),
    5: ("REFUSED", "the server refuses to answer this client (not its resolver, or a policy)"),
}

KERBEROS_ERRORS = {
    6: ("KDC_ERR_C_PRINCIPAL_UNKNOWN", "the user name doesn't exist in the domain",
        "a typo, a deleted account, or someone enumerating user names"),
    7: ("KDC_ERR_S_PRINCIPAL_UNKNOWN", "the service (SPN) asked for isn't registered", "a missing or duplicate SPN"),
    12: ("KDC_ERR_POLICY", "a logon restriction refused it", "logon hours or workstation restrictions"),
    14: ("KDC_ERR_ETYPE_NOSUPP", "no encryption type in common", "an old client or a hardened domain (RC4 disabled)"),
    18: ("KDC_ERR_CLIENT_REVOKED", "the account is disabled, locked out or expired", None),
    23: ("KDC_ERR_KEY_EXPIRED", "the password has expired and must be changed", None),
    24: ("KDC_ERR_PREAUTH_FAILED", "the password was wrong",
         "a mistyped or stale saved password; many of these across accounts is password spraying"),
    25: ("KDC_ERR_PREAUTH_REQUIRED", "pre-authentication is required: a normal first step of every logon", None),
    32: ("KRB_AP_ERR_TKT_EXPIRED", "the ticket has expired", None),
    37: ("KRB_AP_ERR_SKEW", "the clocks of the client and the domain controller differ by more than 5 minutes", None),
    41: ("KRB_AP_ERR_MODIFIED", "the ticket couldn't be decrypted by the service",
         "the service account's password changed, or a duplicate SPN"),
    52: ("KRB_ERR_RESPONSE_TOO_BIG", "the answer is too big for UDP: the client retries over TCP (normal)", None),
    68: ("KDC_ERR_WRONG_REALM", "the request belongs to another realm (domain)", None),
}
KERBEROS_ROUTINE = {25, 52}

SMB_STATUS = {
    "STATUS_LOGON_FAILURE": "the user name or password was wrong",
    "STATUS_ACCESS_DENIED": "the account isn't allowed to do this (share or file permissions)",
    "STATUS_BAD_NETWORK_NAME": "the share doesn't exist on that server",
    "STATUS_OBJECT_NAME_NOT_FOUND": "the file doesn't exist (often normal: programs look for optional files)",
    "STATUS_OBJECT_PATH_NOT_FOUND": "a folder in the path doesn't exist",
    "STATUS_ACCOUNT_LOCKED_OUT": "the account is locked out after too many wrong passwords",
    "STATUS_ACCOUNT_DISABLED": "the account is disabled",
    "STATUS_PASSWORD_EXPIRED": "the password has expired",
    "STATUS_PASSWORD_MUST_CHANGE": "the password must be changed before logging on",
    "STATUS_ACCOUNT_RESTRICTION": "an account restriction refused it (e.g. a blank password over the network)",
    "STATUS_SHARING_VIOLATION": "another program has the file open",
    "STATUS_NOT_SUPPORTED": "the server doesn't support the request",
    "STATUS_USER_SESSION_DELETED": "the server ended the session",
    "STATUS_NETWORK_SESSION_EXPIRED": "the session expired; the client must log on again",
    "STATUS_INSUFF_SERVER_RESOURCES": "the server ran out of resources",
}
SMB_ROUTINE = {"STATUS_MORE_PROCESSING_REQUIRED", "STATUS_BUFFER_OVERFLOW", "STATUS_NO_MORE_FILES", "STATUS_PENDING",
               "STATUS_END_OF_FILE", "STATUS_NOTIFY_ENUM_DIR", "STATUS_OBJECT_NAME_NOT_FOUND",
               "STATUS_INVALID_INFO_CLASS", "STATUS_NO_SUCH_FILE", "STATUS_NOT_FOUND", "STATUS_CANCELLED"}

LDAP_RESULTS = {1: "operations error", 2: "protocol error", 8: "stronger authentication (signing) required",
                32: "no such object", 34: "invalid DN syntax", 48: "inappropriate authentication",
                49: "invalid credentials (wrong password, or a locked or expired account)",
                50: "insufficient access rights", 53: "unwilling to perform"}
LDAP_ROUTINE = {0, 10, 14, 32}  # success, referral, SASL bind in progress, no such object (lookups)

FTP_REPLIES = {421: "the service is closing the connection (busy or idle timeout)",
               425: "the data connection couldn't be opened (firewall or NAT blocking active/passive mode)",
               426: "the data transfer was aborted", 430: "the user name or password was wrong",
               450: "the file is busy", 451: "the server hit a local error", 452: "the server is out of space",
               500: "the command wasn't recognised", 501: "the command's arguments were wrong",
               502: "that command isn't implemented", 503: "commands were sent in the wrong order",
               530: "the login was refused (wrong user or password, or anonymous login disabled)",
               532: "an account is needed to store files", 550: "the file is unavailable or permission was denied",
               552: "the storage allocation was exceeded", 553: "the file name isn't allowed"}

# Wireshark's TCP analysis, translated.
TCP_ANALYSIS = {
    "tcp.analysis.retransmission": (
        "Retransmission", "warn",
        "This data was already sent once. The first copy, or its acknowledgment, was lost or late, so the sender's "
        "timer ran out and it sent it again. A few are normal; many mean packet loss or a congested link."),
    "tcp.analysis.fast_retransmission": (
        "Fast retransmission", "warn",
        "The receiver signalled a gap with duplicate acknowledgments, so the sender resent the missing data without "
        "waiting for its timer: a packet was lost in the network."),
    "tcp.analysis.spurious_retransmission": (
        "Spurious retransmission", "info",
        "This data had already been acknowledged, so resending it was unnecessary: the sender's timer is too short "
        "for the delay on this path, or an acknowledgment was delayed."),
    "tcp.analysis.out_of_order": (
        "Out of order", "info",
        "This segment arrived after a later one: packets took different paths, or the capture point saw them "
        "reordered. Harmless if occasional."),
    "tcp.analysis.lost_segment": (
        "Previous segment not captured", "info",
        "There is a gap before this segment in what the capture saw. If the other side acknowledges the missing "
        "bytes later, the packet crossed the network and only the capture missed it (common at the very start of a "
        "capture, or when the capture drops packets); otherwise it was lost."),
    "tcp.analysis.ack_lost_segment": (
        "ACKed unseen segment", "info",
        "This acknowledges data the capture never saw. The data did arrive, so the capture missed it: it started "
        "mid-connection, dropped packets, or only sees one direction of the traffic."),
    "tcp.analysis.duplicate_ack": (
        "Duplicate ACK", "info",
        "The receiver acknowledged the same point again, telling the sender a later segment arrived but one before "
        "it is missing. Several in a row usually trigger a fast retransmission."),
    "tcp.analysis.zero_window": (
        "Zero window", "warn",
        "The receiver says its buffer is full and the sender must stop. The receiving application isn't reading fast "
        "enough: it is busy, slow, or waiting on its disk."),
    "tcp.analysis.zero_window_probe": (
        "Zero window probe", "info",
        "The sender pokes a receiver that advertised a zero window, to find out when it has room again."),
    "tcp.analysis.zero_window_probe_ack": (
        "Zero window probe ACK", "info", "The receiver's answer to a zero window probe: still full, or room again."),
    "tcp.analysis.window_full": (
        "Window full", "info",
        "The sender has as much unacknowledged data in flight as the receiver allows, so it must wait: the receiver's "
        "window, not the network, is limiting the speed."),
    "tcp.analysis.window_update": (
        "Window update", "info",
        "The receiver only announces it has more buffer space; after a zero window, this is what lets the sender "
        "continue."),
    "tcp.analysis.keep_alive": (
        "Keep-alive", "info",
        "An empty probe checking the other side is still there on an idle connection. Normal for long-lived sessions."),
    "tcp.analysis.keep_alive_ack": ("Keep-alive ACK", "info", "The answer to a keep-alive: the other side is still there."),
    "tcp.analysis.reused_ports": (
        "Ports reused", "info",
        "A new connection uses the same addresses and ports as an earlier one. Normal if the earlier one had closed; "
        "otherwise a sign of a busy client or a scan."),
}

# The same, as a short clause for the timeline.
TCP_ANALYSIS_SHORT = {
    "tcp.analysis.retransmission": "sends data again (retransmission)",
    "tcp.analysis.fast_retransmission": "resends lost data (fast retransmission)",
    "tcp.analysis.spurious_retransmission": "resends data that had already arrived",
    "tcp.analysis.out_of_order": "a segment arrives out of order",
    "tcp.analysis.lost_segment": "the capture missed the segment before this one",
    "tcp.analysis.ack_lost_segment": "acknowledges data the capture never saw",
    "tcp.analysis.duplicate_ack": "signals a missing segment (duplicate ACK)",
    "tcp.analysis.zero_window": "says its buffer is full: stop sending (zero window)",
    "tcp.analysis.zero_window_probe": "probes whether there is room again",
    "tcp.analysis.zero_window_probe_ack": "answers the probe",
    "tcp.analysis.window_full": "has filled the receiver's window and must wait",
    "tcp.analysis.window_update": "has room again (window update)",
    "tcp.analysis.keep_alive": "checks the idle connection is alive (keep-alive)",
    "tcp.analysis.keep_alive_ack": "answers the keep-alive",
    "tcp.analysis.reused_ports": "reuses the ports of an earlier connection",
}

# ---------------------------------------------------------------- helpers


def _v(f: dict, name: str, i: int = 0) -> str | None:
    vals = f.get(name) or []
    return vals[i] if len(vals) > i else None


def _n(f: dict, name: str, i: int = 0) -> int | None:
    v = _v(f, name, i)
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def _flag(f: dict, name: str) -> bool:
    """Set: a flag field that isn't 0, or a presence-only item (value "") such as tcp.analysis.retransmission."""
    v = _v(f, name)
    return v is not None and v != "0"


def _all(f: dict, name: str) -> list[str]:
    return list(f.get(name) or [])


def _ms(seconds: float) -> str:
    if seconds < 0.001:
        return f"{seconds * 1e6:.0f} µs"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 120:
        return f"{seconds:.2f} s"
    return f"{seconds / 60:.1f} min"


def _bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else plural or word + 's'}"


def service_name(port: int | None) -> str:
    return SERVICES.get(port or -1, "")


def _frames_list(frames: list[int], limit: int = 6) -> str:
    shown = ", ".join(str(n) for n in frames[:limit])
    return shown + (f" and {len(frames) - limit} more" if len(frames) > limit else "")


# ------------------------------------------------------------- conversations

class Frame:
    __slots__ = ("n", "ts", "info", "proto", "f", "side", "icmp")

    def __init__(self, rec: dict):
        self.n = int(rec["n"])
        self.ts = float(rec["ts"])
        self.info = str(rec.get("info") or "")
        self.proto = str(rec.get("proto") or "")
        self.f = rec.get("f") or {}
        self.side = ""          # "client", "server" or "icmp"
        self.icmp = None        # (type, code, sender, v6) for ICMP errors


def _addr(f: dict, which: str, i: int = 0) -> str | None:
    return _v(f, f"ip.{which}", i) or _v(f, f"ipv6.{which}", i)


def _icmp_error(f: dict):
    t, c = _n(f, "icmp.type"), _n(f, "icmp.code")
    if t in (3, 4, 5, 11, 12):
        return t, c or 0, False
    t6, c6 = _n(f, "icmpv6.type"), _n(f, "icmpv6.code")
    if t6 in (1, 2, 3, 4):
        return t6, c6 or 0, True
    return None


def group(records: list[dict]) -> list[dict]:
    """Frames by conversation: TCP and UDP streams, with the ICMP errors that quote them."""
    convs: dict[tuple, dict] = {}
    tuples: dict[tuple, tuple] = {}
    pending_icmp = []
    for rec in records:
        if rec.get("type") != "packet":
            continue
        fr = Frame(rec)
        f = fr.f
        err = _icmp_error(f)
        if err:
            # The quoted packet's addresses follow the ICMP packet's own.
            inner_src, inner_dst = _addr(f, "src", 1), _addr(f, "dst", 1)
            proto = "tcp" if "tcp.srcport" in f else "udp" if "udp.srcport" in f else None
            sport, dport = _n(f, f"{proto}.srcport") if proto else None, _n(f, f"{proto}.dstport") if proto else None
            fr.side = "icmp"
            fr.icmp = (err[0], err[1], _addr(f, "src"), err[2])
            pending_icmp.append((fr, (proto, inner_src, sport, inner_dst, dport)))
            continue
        for proto in ("tcp", "udp"):
            stream = _n(f, f"{proto}.stream")
            if stream is None or _n(f, f"{proto}.srcport") is None:
                continue
            key = (proto, stream)
            conv = convs.setdefault(key, {"proto": proto, "stream": stream, "frames": []})
            conv["frames"].append(fr)
            a = (_addr(f, "src"), _n(f, f"{proto}.srcport"))
            b = (_addr(f, "dst"), _n(f, f"{proto}.dstport"))
            tuples[(proto, *a, *b)] = key
            tuples[(proto, *b, *a)] = key
            break
    for fr, (proto, src, sport, dst, dport) in pending_icmp:
        key = tuples.get((proto, src, sport, dst, dport))
        if key is None:  # an error about a packet this selection doesn't include: its own entry
            key = (proto or "ip", f"{src}:{sport}>{dst}:{dport}")
            conv = convs.setdefault(key, {"proto": proto or "ip", "stream": None, "frames": [],
                                          "quoted": (src, sport, dst, dport)})
        convs[key]["frames"].append(fr)
    out = list(convs.values())
    for c in out:
        c["frames"].sort(key=lambda fr: fr.n)
    out.sort(key=lambda c: c["frames"][0].n)
    return out


def _endpoints(conv: dict):
    """(client ip, client port, server ip, server port): who opened it."""
    proto, frames = conv["proto"], conv["frames"]
    if conv.get("quoted"):
        src, sport, dst, dport = conv["quoted"]
        return src, sport, dst, dport
    first = next((fr for fr in frames if fr.side != "icmp"), frames[0])
    if proto == "tcp":
        syn = next((fr for fr in frames if _flag(fr.f, "tcp.flags.syn") and not _flag(fr.f, "tcp.flags.ack")), None)
        if syn:
            first = syn
        else:  # no SYN: the side with the higher port is usually the client
            sp, dp = _n(first.f, "tcp.srcport"), _n(first.f, "tcp.dstport")
            if sp is not None and dp is not None and sp < dp and sp < 1024:
                return (_addr(first.f, "dst"), dp, _addr(first.f, "src"), sp)
    return (_addr(first.f, "src"), _n(first.f, f"{proto}.srcport"), _addr(first.f, "dst"),
            _n(first.f, f"{proto}.dstport"))


def _rel(fr: Frame, t0: float) -> str:
    d = fr.ts - t0
    return "0" if d <= 0 else "+" + _ms(d)


def _who(side: str, cs: tuple) -> str:
    return f"{cs[0]}" if side == "client" else f"{cs[2]}"


def _app_text(fr: Frame) -> str | None:
    """The application-level meaning of a frame, from its Info, when it has one."""
    if fr.proto in ("TCP", "UDP", ""):
        return None
    info = re.sub(r"^(\[[^\]]*\]\s*)+", "", fr.info).strip()
    return f"{fr.proto}: {info}" if info else fr.proto


def explain_conversation(conv: dict) -> dict:
    proto = conv["proto"]
    frames = conv["frames"]
    cs = _endpoints(conv)
    client, cport, server, sport = cs
    for fr in frames:
        if fr.side == "icmp":
            continue
        fr.side = "client" if (_addr(fr.f, "src"), _n(fr.f, f"{proto}.srcport")) == (client, cport) else "server"
    t0 = frames[0].ts
    svc = service_name(sport) or service_name(cport)
    out = {
        "proto": proto.upper() if proto in ("tcp", "udp") else "IP",
        "stream": conv["stream"], "client": f"{client}:{cport}", "server": f"{server}:{sport}",
        "service": svc, "frames": len(frames), "first": frames[0].n, "last": frames[-1].n,
        "duration": frames[-1].ts - t0,
        "filter": f"{proto}.stream eq {conv['stream']}" if conv["stream"] is not None else "",
        "notes": [], "causes": [], "checks": [], "timeline": [],
    }
    if proto == "tcp":
        _diagnose_tcp(out, frames, cs, t0)
    elif proto == "udp":
        _diagnose_udp(out, frames, cs, t0)
    else:
        _diagnose_orphan_icmp(out, frames, cs)
    return out


def _icmp_sentence(fr: Frame, server: str) -> tuple[str, str, str]:
    """(short name, why, who said it) for an ICMP error frame."""
    t, c, sender, v6 = fr.icmp
    if (not v6 and t == 11) or (v6 and t == 3):
        name, why = "time exceeded", ("the packet's hop limit (TTL) ran out before it arrived: a routing loop, or a "
                                       "traceroute probing the path")
    elif (not v6 and t == 4):
        name, why = "source quench", "the sender was asked to slow down (obsolete)"
    elif (not v6 and t == 5):
        name, why = "redirect", "a router says another gateway is a better route"
    elif (not v6 and t == 12) or (v6 and t == 4):
        name, why = "parameter problem", "a router or the host couldn't process a header field"
    elif v6 and t == 2:
        name, why = "packet too big", "a link on the path has a smaller MTU: the sender must send smaller packets"
    else:
        name, why = (ICMPV6_UNREACHABLE if v6 else ICMP_UNREACHABLE).get(c, (f"unreachable (code {c})", "the packet couldn't be delivered"))
    who = "the destination itself" if sender == server else f"{sender} (a router or firewall on the path)"
    return name, why, who


def _diagnose_orphan_icmp(out: dict, frames: list[Frame], cs: tuple) -> None:
    fr = frames[0]
    name, why, who = _icmp_sentence(fr, cs[2])
    out.update(status="failed", title=f"ICMP: {name}",
               summary=f"{who[0].upper() + who[1:]} reported \"{name}\" about a packet from {cs[0]} to {cs[2]}"
                       f"{f' port {cs[3]}' if cs[3] else ''}: {why}. The packet it refers to isn't in this selection.")
    out["timeline"] = [{"n": f.n, "t": _rel(f, fr.ts), "who": f.icmp[2], "text": f"reports {_icmp_sentence(f, cs[2])[0]}"}
                       for f in frames]


# ---------------------------------------------------------------- TCP

def _diagnose_tcp(out: dict, frames: list[Frame], cs: tuple, t0: float) -> None:
    client, cport, server, sport = cs
    svc = f"port {sport}" + (f" ({out['service']})" if out["service"] else "")
    tcp = [fr for fr in frames if fr.side != "icmp"]
    icmp = [fr for fr in frames if fr.side == "icmp"]

    def flags(fr):
        f = fr.f
        return {k: _flag(f, f"tcp.flags.{k}") for k in ("syn", "ack", "fin", "reset", "push", "urg")}

    syns = [fr for fr in tcp if fr.side == "client" and flags(fr)["syn"] and not flags(fr)["ack"]]
    synacks = [fr for fr in tcp if fr.side == "server" and flags(fr)["syn"] and flags(fr)["ack"]]
    rsts = [fr for fr in tcp if flags(fr)["reset"]]
    fins = [fr for fr in tcp if flags(fr)["fin"]]
    nulls = [fr for fr in tcp if "tcp.flags.syn" in fr.f and not any(flags(fr).values())
             and not _flag(fr.f, "tcp.flags.ece") and not _flag(fr.f, "tcp.flags.cwr")]
    data = {s: sum(_n(fr.f, "tcp.len") or 0 for fr in tcp if fr.side == s) for s in ("client", "server")}
    data_frames = [fr for fr in tcp if (_n(fr.f, "tcp.len") or 0) > 0]
    an = {k: [fr for fr in tcp if _flag(fr.f, k)] for k in TCP_ANALYSIS}
    retrans = an["tcp.analysis.retransmission"] + an["tcp.analysis.fast_retransmission"]
    irtt = next((float(_v(fr.f, "tcp.analysis.initial_rtt")) for fr in tcp if _v(fr.f, "tcp.analysis.initial_rtt")), None)
    established = bool(synacks) and any(fr.side == "client" and flags(fr)["ack"] and not flags(fr)["syn"]
                                        and fr.n > synacks[0].n for fr in tcp)
    midstream = not syns and not synacks and bool(tcp)
    tls_hellos = [fr for fr in tcp if "1" in _all(fr.f, "tls.handshake.type") and fr.side == "client"]
    tls_server_hellos = [fr for fr in tcp if "2" in _all(fr.f, "tls.handshake.type") and fr.side == "server"]
    alerts = [(fr, _n(fr.f, "tls.alert_message.level"), d) for fr in tcp
              for d in (_n(fr.f, "tls.alert_message.desc", i) for i in range(len(_all(fr.f, "tls.alert_message.desc"))))
              if d is not None]
    fatal_alerts = [(fr, lvl, d) for fr, lvl, d in alerts if d != 0 and lvl != 1]
    http_err = [(fr, int(c)) for fr in tcp for c in _all(fr.f, "http.response.code") if c.isdigit() and int(c) >= 400]
    ftp_err = [(fr, int(c)) for fr in tcp for c in _all(fr.f, "ftp.response.code") if c.isdigit() and int(c) >= 400]
    smb_err = [(fr, name) for fr in tcp for name in re.findall(r"Error: (STATUS_[A-Z_0-9]+)", fr.info)
               if name not in SMB_ROUTINE]
    krb_err = [(fr, int(c)) for fr in tcp for c in _all(fr.f, "kerberos.error_code")
               if c.isdigit() and int(c) not in KERBEROS_ROUTINE]
    ldap_err = [(fr, int(c)) for fr in tcp for c in _all(fr.f, "ldap.resultCode")
                if c.isdigit() and int(c) not in LDAP_ROUTINE]

    # ---- facts
    facts = [["Client", f"{client}:{cport}"], ["Server", f"{server}:{sport}" + (f" ({out['service']})" if out["service"] else "")],
             ["Duration", _ms(out["duration"])],
             ["Data sent", f"client → server {_bytes(data['client'])}, server → client {_bytes(data['server'])}"]]
    if irtt is not None:
        facts.append(["Handshake round trip", _ms(irtt)])
    if retrans:
        facts.append(["Retransmissions", f"{len(retrans)} of {len(data_frames)} data segments"])
    hello_sni = next((_v(fr.f, "tls.handshake.extensions_server_name") for fr in tls_hellos
                      if _v(fr.f, "tls.handshake.extensions_server_name")), None)
    if hello_sni:
        facts.append(["TLS server name", hello_sni])
    out["facts"] = facts

    # ---- the story, most decisive finding first
    status, title, summary = "ok", "", ""
    causes: list[str] = []
    checks: list[str] = []
    notes: list[str] = []

    if nulls:
        status, title = "suspicious", "Hand-built TCP packets"
        summary = (f"{_plural(len(nulls), 'segment')} between {client} and {server} have no TCP flags at all (frames "
                   f"{_frames_list([f.n for f in nulls])}). No operating system sends that: the packets were built by a "
                   "program writing raw packets, as covert channels, implants and NULL scans do.")
        checks = ["Find the process on the sending host that opens raw sockets.",
                  "Look at what the payload carries (Follow Stream)."]
    elif not established and not midstream and syns and not synacks:
        tries = len(syns)
        span = syns[-1].ts - syns[0].ts
        if icmp:
            fr = icmp[0]
            name, why, who = _icmp_sentence(fr, server)
            t, c, sender, v6 = fr.icmp
            blocked = (not v6 and c in (9, 10, 13)) or (v6 and c in (1, 5))
            status = "failed"
            title = ("Blocked by a firewall" if blocked else "Port closed" if name == "port unreachable"
                     else "Unreachable" if "unreachable" in name or "no route" in name else f"ICMP {name}")
            summary = (f"{client} tried to connect to {server} on {svc}, and {who} answered with ICMP "
                       f"\"{name}\" (frame {fr.n}): {why}.")
            if blocked:
                causes = ["A firewall rule rejects this traffic (and says so, rather than silently dropping it).",
                          "If the reply comes from a router, the block is on the path, not on the server."]
                checks = [f"Find the rule on {sender} (or the firewall it belongs to) that matches {client} → {server}:{sport}.",
                          "Check whether other ports to the same server get through (Statistics → Conversations)."]
            elif name in ("host unreachable", "address unreachable"):
                causes = ["The server is switched off, disconnected, or has a different address now.",
                          "Its network segment is reachable but the host doesn't answer ARP / neighbour discovery."]
                checks = [f"Check that {server} is up and has that address.", "Look for ARP requests for it with no reply."]
            elif name in ("network unreachable", "no route to destination"):
                causes = ["A router on the path has no route to that network (missing route, VPN down)."]
                checks = [f"Check the routing table of {sender} for {server}.", "Check VPN or tunnel status."]
            elif name == "fragmentation needed":
                causes = ["A link on the path has a smaller MTU than the packets (a VPN, tunnel or PPPoE link)."]
                checks = ["Lower the MTU/MSS (MSS clamping on the tunnel), and make sure ICMP isn't blocked so path MTU discovery works."]
        elif any(fr.side == "server" and flags(fr)["reset"] for fr in rsts):
            fr = next(fr for fr in rsts if fr.side == "server")
            status, title = "failed", "Refused"
            summary = (f"{client} asked {server} to open a connection on {svc} and was refused straight away: "
                       f"{server} answered the SYN with a reset (frame {fr.n}, {_rel(fr, syns[0].ts).lstrip('+')} later).")
            causes = [f"Nothing is listening on port {sport} on {server}: the service is stopped, crashed, or "
                      "listening on another port or address.",
                      "A firewall on the host (or in front of it) rejects the connection with a reset."]
            checks = [f"On {server}: is the service running and listening on port {sport}?",
                      "Is a host firewall rejecting it?",
                      "Many refused connections from one client to many ports is a port scan."]
        else:
            status, title = "failed", "No answer"
            summary = (f"{client} asked {server} to open a connection on {svc} {_plural(tries, 'time')}"
                       + (f" over {_ms(span)}" if tries > 1 else "") + " and never got an answer: no SYN-ACK, no "
                       "reset, no ICMP error.")
            causes = [f"A firewall silently drops traffic to {server}:{sport}.",
                      f"{server} is down, or the address is wrong (nothing answers ARP for it).",
                      "A routing problem: the SYN goes out but the answer can't come back (asymmetric routing).",
                      "The capture only sees one direction of this traffic."]
            checks = [f"Do other hosts reach {server}:{sport} in this capture?",
                      f"Is {server} answering anything at all (ping, ARP)?",
                      "Check firewalls between the two for a silent DROP rule."]
    elif synacks and not established and not data_frames:
        rst_c = [fr for fr in rsts if fr.side == "client"]
        status = "suspicious" if rst_c else "failed"
        title = "Half-open connection" if rst_c else "Handshake never completed"
        if rst_c:
            summary = (f"{server} accepted the connection (SYN-ACK, frame {synacks[0].n}), but {client} reset it "
                       f"instead of completing the handshake (frame {rst_c[0].n}).")
            causes = ["A SYN (\"half-open\" or stealth) port scan: the scanner only wants to know the port is open.",
                      "A client that gave up waiting, or a load balancer health check."]
            checks = [f"Does {client} make many such connections to different ports or hosts? Then it is scanning.",
                      f"Is {client} a known scanner or monitoring system?"]
        else:
            summary = (f"{server} accepted the connection (SYN-ACK, frame {synacks[0].n}), but {client} never sent "
                       "the final ACK.")
            causes = ["The SYN-ACK didn't reach the client (dropped on the way back, asymmetric routing).",
                      "A SYN flood: forged SYNs whose source never answers."]
            checks = ["Look for many half-finished handshakes to this server (a SYN flood).",
                      "Check the return path from server to client."]
    else:
        # The connection was open: the application and transport tell the rest.
        problem = None
        if fatal_alerts:
            fr, lvl, desc = fatal_alerts[0]
            name, meaning, why = TLS_ALERTS.get(desc, (f"alert {desc}", "the TLS session was ended", None))
            by_server = fr.side == "server"
            if by_server and not tls_server_hellos:
                problem = ("failed", "TLS handshake refused by the server",
                           f"The TCP connection opened, {client} offered to start TLS"
                           + (f" for {hello_sni}" if hello_sni else "") + f", and {server} refused with the fatal alert "
                           f"\"{name}\" (frame {fr.n}): {meaning}.")
            elif not by_server:
                problem = ("failed", "Server rejected by the client",
                           f"{server} answered the TLS handshake, but {client} refused to continue with the fatal "
                           f"alert \"{name}\" (frame {fr.n}): {meaning}.")
            else:
                problem = ("failed", "TLS session aborted",
                           f"{'The server' if by_server else 'The client'} ended the TLS session with the fatal alert "
                           f"\"{name}\" (frame {fr.n}): {meaning}.")
            if why:
                causes.append(why[0].upper() + why[1:] + ".")
            if desc in (42, 45, 46, 48) and not by_server:
                checks += [f"Look at the certificate {server} sent (in the packet detail of its handshake) and who issued it.",
                           "If you expected a public certificate and see a private CA, something may be intercepting TLS."]
            elif desc in (40, 70, 71):
                checks += ["Compare the versions and cipher suites the client offers (Client Hello) with what the "
                           "server allows."]
            elif desc == 112:
                checks += [f"Check the server name {hello_sni or ''} is configured on {server}."]
        elif tls_hellos and not tls_server_hellos and (rsts or fins) and not any(
                fr.side == "server" and (_n(fr.f, "tcp.len") or 0) > 0 for fr in tcp):
            closer = next((fr for fr in rsts + fins if fr.n > tls_hellos[0].n), None)
            if closer is not None:
                problem = ("failed", "TLS handshake dropped",
                           f"{client} offered to start TLS" + (f" for {hello_sni}" if hello_sni else "") +
                           f", and {'the server' if closer.side == 'server' else 'the client'} closed the connection "
                           f"(frame {closer.n}) without a TLS answer.")
                causes += ["A firewall or proxy filtering by the TLS server name (SNI) cut it.",
                           "The server doesn't speak TLS on this port, or refused the offered versions without an alert."]
                checks += ["Try the same server name from another network.", "Check what the server expects on this port."]
        if not problem and (http_err or ftp_err or smb_err or krb_err or ldap_err):
            lines = []
            for fr, code in http_err[:4]:
                lines.append(f"HTTP {code} (frame {fr.n}): {HTTP_STATUS.get(code, 'a client error' if code < 500 else 'a server error')}")
            for fr, code in ftp_err[:4]:
                lines.append(f"FTP {code} (frame {fr.n}): {FTP_REPLIES.get(code, 'the server refused the command')}")
            for fr, name in smb_err[:4]:
                lines.append(f"SMB {name} (frame {fr.n}): {SMB_STATUS.get(name, 'the server refused the request')}")
            for fr, code in krb_err[:4]:
                kname, meaning, why = KERBEROS_ERRORS.get(code, (f"error {code}", "the domain controller refused", None))
                lines.append(f"Kerberos {kname} (frame {fr.n}): {meaning}")
                if why:
                    causes.append(why[0].upper() + why[1:] + ".")
            for fr, code in ldap_err[:4]:
                lines.append(f"LDAP result {code} (frame {fr.n}): {LDAP_RESULTS.get(code, 'the directory refused the request')}")
            kind = ("Login failed" if any(c in (530, 430) for _, c in ftp_err) or
                    any(n in ("STATUS_LOGON_FAILURE", "STATUS_ACCOUNT_LOCKED_OUT") for _, n in smb_err) or
                    any(c in (6, 18, 23, 24) for _, c in krb_err) or any(c == 49 for _, c in ldap_err)
                    else "Server errors" if any(c >= 500 for _, c in http_err) and not ftp_err else "Request refused")
            problem = ("problem", kind, f"The connection to {server} on {svc} worked, but the application said no: "
                       + "; ".join(_dedupe(lines)) + ".")
            if kind == "Login failed":
                causes.append("Wrong or outdated credentials; many failures for many accounts from one source is password "
                              "spraying or brute force.")
                checks.append(f"Count the failed logins from {client} (and to which accounts) across the capture.")
            if any(c >= 500 for _, c in http_err):
                checks.append(f"Look at the logs of the application behind {server} at that time.")
            if any(c == 404 for _, c in http_err):
                checks.append("Many 404s for unrelated paths from one client is a web scanner.")
        if problem:
            status, title, summary = problem
        # Transport findings: the main story if nothing else went wrong, a note otherwise.
        server_rst = [fr for fr in rsts if fr.side == "server"]
        client_rst = [fr for fr in rsts if fr.side == "client"]
        transport = None
        if server_rst and not problem:
            fr = server_rst[0]
            after = sum((_n(x.f, "tcp.len") or 0) for x in tcp if x.n < fr.n)
            transport = ("failed", "Reset by the server",
                         f"{server} aborted the connection with a reset (frame {fr.n}) after {_bytes(after)} had been "
                         f"exchanged" + (", in the middle of a transfer" if data["server"] and not any(
                             x.side == "server" and flags(x)["fin"] for x in tcp) else "") + ".")
            causes += ["The server application crashed, was restarted, or closed the socket abruptly.",
                       "A firewall, load balancer or IPS between them killed the session (idle timeout, policy, or "
                       "a signature match).", "The server hit a limit (too many connections, request too large)."]
            checks += [f"Look at {server}'s application logs around the time of frame {fr.n}.",
                       "If the reset's TTL differs from the server's other packets, a middlebox sent it."]
        elif client_rst and not problem and not any(x.side == "server" and flags(x)["fin"] and x.n < client_rst[0].n for x in tcp):
            fr = client_rst[0]
            transport = ("problem", "Reset by the client",
                         f"{client} aborted the connection with a reset (frame {fr.n}) rather than closing it.")
            causes += ["The user or program cancelled (closed a browser tab, stopped a download).",
                       "The client timed out waiting for the server."]
        zw = an["tcp.analysis.zero_window"]
        if zw:
            who = _who(zw[0].side, cs)
            t_stall = (max(f.ts for f in an["tcp.analysis.window_update"] + zw) - zw[0].ts) if an["tcp.analysis.window_update"] else None
            text = (f"{who} told the other side to stop sending (zero window, {_plural(len(zw), 'time')} from frame "
                    f"{zw[0].n})" + (f", stalling the transfer for {_ms(t_stall)}" if t_stall else "") +
                    ": the receiving application wasn't reading its data fast enough.")
            if not transport and not problem:
                transport = ("problem", "Receiver stopped reading", text)
                causes += [f"The program on {who} was busy, slow or blocked (CPU, disk, a lock).",
                           "Not a network problem: the network delivered the data, the application didn't take it."]
                checks += [f"Check CPU, memory and disk on {who} at that time.",
                           "Zero windows that last long, then a reset, often end in a timeout error for the user."]
            else:
                notes.append(text)
        if retrans:
            ratio = len(retrans) / max(1, len(data_frames))
            senders = Counter(_who(fr.side, cs) for fr in retrans)
            text = (f"{_plural(len(retrans), 'segment')} had to be sent again ({ratio:.0%} of the data segments, by "
                    f"{', '.join(f'{k} ({v})' for k, v in senders.items())}; first at frame {retrans[0].n}): packets "
                    "were lost or delayed on the way.")
            if not transport and not problem and (len(retrans) >= 3 or ratio >= 0.02):
                transport = ("problem", "Packet loss", text)
                causes += ["Congestion or a faulty link (Wi-Fi interference, a bad cable or port, duplex mismatch).",
                           "Retransmissions slow TCP right down: users feel this as a slow application."]
                checks += ["Do other connections over the same path show retransmissions too (Expert information)?",
                           "Check interface error counters on the switches and routers on the path."]
            else:
                notes.append(text)
        gaps = [f"\"{TCP_ANALYSIS[k][0].lower()}\" × {len(an[k])}" for k in
                ("tcp.analysis.lost_segment", "tcp.analysis.ack_lost_segment") if an[k]]
        if gaps:
            notes.append(f"The capture missed some of this connection's packets ({', '.join(gaps)}): the gaps are in "
                         "the capture, not necessarily in the network.")
        if irtt is not None and irtt > 0.3:
            notes.append(f"The handshake took {_ms(irtt)}: a distant or congested path (more than 300 ms round trip).")
        if transport and not problem:
            status, title, summary = transport
        if not title:
            closed = [fr for fr in fins]
            if midstream:
                title, summary = "Already open when the capture began", (
                    f"The capture started after this connection between {client} and {server} on {svc} was opened "
                    f"(no handshake seen); {_bytes(data['client'])} went to the server and {_bytes(data['server'])} came back.")
                status = "info"
            elif closed:
                title = "Completed normally"
                summary = (f"{client} connected to {server} on {svc}, sent {_bytes(data['client'])} and received "
                           f"{_bytes(data['server'])}, and the connection was closed in an orderly way (FIN).")
            elif rsts:
                fr = rsts[0]
                title = "Closed with a reset"
                summary = (f"The exchange on {svc} finished and {'the server' if fr.side == 'server' else 'the client'} "
                           f"closed with a reset (frame {fr.n}) instead of FIN: some programs do this to free the "
                           "connection quickly.")
                status = "info"
            else:
                title = "Still open at the end of the capture"
                status = "info"
                summary = (f"{client} sent {_bytes(data['client'])} to {server} on {svc} and received "
                           f"{_bytes(data['server'])}; the connection hadn't closed when the capture ended.")
        if problem and transport:
            notes.insert(0, transport[2])
    out.update(status=status, title=title, summary=summary, causes=_dedupe(causes), checks=_dedupe(checks),
               notes=_dedupe(notes))
    out["timeline"] = _tcp_timeline(tcp, icmp, cs, t0, syns, synacks)


def _tcp_timeline(tcp: list[Frame], icmp: list[Frame], cs: tuple, t0: float, syns, synacks) -> list[dict]:
    events = []
    seen_kind: Counter = Counter()
    first_data = set()
    synack_n = synacks[0].n if synacks else None
    handshake_ack = None
    for fr in tcp:
        f = fr.f
        syn, ack, fin, rst = (_flag(f, f"tcp.flags.{k}") for k in ("syn", "ack", "fin", "reset"))
        who, other = (_who(fr.side, cs), _who("server" if fr.side == "client" else "client", cs))
        texts = []
        if syn and not ack:
            texts.append(f"asks {other} to open a connection (SYN)" if fr is syns[0]
                         else "asks again: no answer yet (SYN retransmitted)")
        elif syn and ack:
            texts.append("accepts the connection (SYN, ACK)")
        elif synack_n and handshake_ack is None and fr.side == "client" and ack and fr.n > synack_n:
            handshake_ack = fr.n
            texts.append("confirms: the connection is open (ACK)")
        if rst:
            texts.append("aborts the connection (RST)")
        if fin:
            texts.append("has finished sending (FIN)")
        if not syn and not rst and not fin and "tcp.flags.syn" in f and not (ack or _flag(f, "tcp.flags.push")):
            texts.append("sends a segment with no flags at all: hand-built")
        app = _app_text(fr)
        length = _n(f, "tcp.len") or 0
        if app:
            texts.append(app)
        elif length and fr.side not in first_data:
            first_data.add(fr.side)
            texts.append(f"sends data ({length} bytes)")
        for key in TCP_ANALYSIS:
            if _flag(f, key) and seen_kind[key] < 3:
                seen_kind[key] += 1
                texts.append(TCP_ANALYSIS_SHORT[key])
        if texts and len(events) < MAX_TIMELINE:
            events.append({"n": fr.n, "t": _rel(fr, t0), "who": who, "text": "; ".join(texts)})
    for fr in icmp:
        name, why, who = _icmp_sentence(fr, cs[2])
        events.append({"n": fr.n, "t": _rel(fr, t0), "who": fr.icmp[2], "text": f"reports ICMP \"{name}\""})
    events.sort(key=lambda e: e["n"])
    return events[:MAX_TIMELINE]


# ---------------------------------------------------------------- UDP

def _diagnose_udp(out: dict, frames: list[Frame], cs: tuple, t0: float) -> None:
    client, cport, server, sport = cs
    svc = f"UDP port {sport}" + (f" ({out['service']})" if out["service"] else "")
    udp = [fr for fr in frames if fr.side != "icmp"]
    icmp = [fr for fr in frames if fr.side == "icmp"]
    sent = [fr for fr in udp if fr.side == "client"]
    back = [fr for fr in udp if fr.side == "server"]
    out["facts"] = [["Client", f"{client}:{cport}"], ["Server", f"{server}:{sport}" + (f" ({out['service']})" if out["service"] else "")],
                    ["Datagrams", f"{len(sent)} sent, {len(back)} back"], ["Duration", _ms(out["duration"])]]
    causes, checks, notes = [], [], []
    dns_q = [fr for fr in udp if _v(fr.f, "dns.flags.response") == "0"]
    dns_r = [fr for fr in udp if _v(fr.f, "dns.flags.response") == "1"]
    krb = [(fr, int(c)) for fr in udp for c in _all(fr.f, "kerberos.error_code") if c.isdigit()]
    status, title, summary = "ok", "", ""
    if icmp:
        fr = icmp[0]
        name, why, who = _icmp_sentence(fr, server)
        status = "failed"
        title = "Port closed" if name == "port unreachable" else ("Blocked by a firewall" if "prohibited" in name else f"ICMP {name}")
        summary = f"{client} sent datagrams to {server} on {svc}, and {who} answered ICMP \"{name}\" (frame {fr.n}): {why}."
        if name == "port unreachable":
            causes = [f"The service isn't running on {server}, or listens on another port."]
            checks = [f"On {server}: is anything listening on UDP port {sport}?"]
        elif "prohibited" in name:
            causes = ["A firewall rejects this traffic."]
            checks = [f"Find the rule on {fr.icmp[2]} that matches {client} → {server}:{sport}."]
    elif dns_q:
        names = sorted({_v(fr.f, "dns.qry.name") or "?" for fr in dns_q})
        answered_ids = {_v(fr.f, "dns.id") for fr in dns_r}
        unanswered = [fr for fr in dns_q if _v(fr.f, "dns.id") not in answered_ids]
        bad = [(fr, _n(fr.f, "dns.flags.rcode")) for fr in dns_r if (_n(fr.f, "dns.flags.rcode") or 0) != 0]
        out["facts"].append(["Names asked", ", ".join(names[:5]) + (" …" if len(names) > 5 else "")])
        if bad:
            fr, rc = bad[0]
            code, meaning = DNS_RCODES.get(rc, (f"error {rc}", "the server returned an error"))
            status = "problem" if rc == 3 else "failed"
            title = {3: "Name does not exist", 2: "DNS server failure", 5: "DNS query refused"}.get(rc, f"DNS error {code}")
            summary = f"{server} answered the query for {_v(fr.f, 'dns.qry.name')} with {code} (frame {fr.n}): {meaning}."
            if rc == 3:
                causes = ["A typo or an old name (a decommissioned server, a renamed host).",
                          "Software looking for optional names (WPAD, ISATAP) gets NXDOMAIN all day: normal.",
                          "Many NXDOMAINs for random-looking names from one host is malware trying generated "
                          "domain names (a DGA)."]
                checks = ["Is the name expected to exist? Who uses it?",
                          f"Count NXDOMAIN answers to {client} across the capture (Statistics → DNS)."]
            elif rc == 2:
                causes = ["The domain's own name servers are unreachable or misconfigured.",
                          "DNSSEC validation failed for the domain.", f"{server} can't reach its upstream servers."]
                checks = ["Query the same name through another resolver.", f"Check {server}'s connection to the internet."]
            elif rc == 5:
                causes = [f"{server} isn't configured to serve {client} (not its resolver, or an ACL)."]
                checks = [f"Check which DNS server {client} should be using (DHCP, network settings)."]
        elif unanswered and not dns_r:
            status, title = "failed", "DNS server didn't answer"
            summary = (f"{client} asked {server} for {', '.join(names[:3])} {_plural(len(dns_q), 'time')} and got no "
                       "answer.")
            causes = [f"{server} is down or not a DNS server.", "A firewall drops DNS to it.",
                      "The answers are lost on the way back."]
            checks = [f"Do other clients get answers from {server}?", f"Is {server} the right resolver for {client}?"]
        else:
            title = "Name resolved" if dns_r else "Query sent"
            answers = [a for fr in dns_r for a in _all(fr.f, "dns.a")]
            summary = (f"{client} asked {server} for {', '.join(names[:3])}"
                       + (f" and got {', '.join(answers[:4])}." if answers else " and got an answer."))
            if unanswered:
                notes.append(f"{_plural(len(unanswered), 'query', 'queries')} had to be repeated before an answer came.")
        if any(_flag(fr.f, "dns.flags.truncated") for fr in dns_r):
            notes.append("The answer was truncated: it was too big for UDP, so the client should repeat the query over TCP.")
    elif krb:
        bad = [(fr, c) for fr, c in krb if c not in KERBEROS_ROUTINE]
        if bad:
            fr, c = bad[0]
            kname, meaning, why = KERBEROS_ERRORS.get(c, (f"error {c}", "the domain controller refused the request", None))
            status = "problem"
            title = "Logon failed" if c in (6, 18, 23, 24) else "Kerberos error"
            summary = f"The domain controller {server} answered {client}'s Kerberos request with {kname} (frame {fr.n}): {meaning}."
            if why:
                causes.append(why[0].upper() + why[1:] + ".")
            if c == 37:
                checks.append(f"Compare the clocks of {client} and {server} (NTP).")
            elif c in (6, 24):
                checks.append(f"Count the failed logons from {client} and for which accounts across the capture.")
        else:
            title, summary = "Kerberos exchange", f"{client} and the domain controller {server} exchanged Kerberos messages normally."
    elif sent and not back:
        status, title = "info", "No reply seen"
        summary = (f"{client} sent {_plural(len(sent), 'datagram')} to {server} on {svc} and nothing came back. For some "
                   "protocols that is normal (syslog, NetFlow, SNMP traps); for a request/response protocol it means the "
                   "server didn't answer or a firewall dropped it.")
        checks = [f"Is this a one-way protocol? If not, is the service on {server} up?"]
    else:
        title = "Request and reply"
        summary = f"{client} and {server} exchanged {len(sent)} and {len(back)} datagrams over {svc}."
    out.update(status=status, title=title, summary=summary, causes=_dedupe(causes), checks=_dedupe(checks),
               notes=_dedupe(notes))
    events = []
    for fr in frames[:MAX_TIMELINE]:
        if fr.side == "icmp":
            events.append({"n": fr.n, "t": _rel(fr, t0), "who": fr.icmp[2],
                           "text": f"reports ICMP \"{_icmp_sentence(fr, server)[0]}\""})
        else:
            events.append({"n": fr.n, "t": _rel(fr, t0), "who": _who(fr.side, cs),
                           "text": _app_text(fr) or f"sends a datagram ({fr.info})"})
    out["timeline"] = events


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(i for i in items if i))


# ---------------------------------------------------------------- payloads

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


_SIGNATURES = [
    (re.compile(rb"^\x16\x03[\x00-\x04]"), "a TLS handshake record (the start of an encrypted session)"),
    (re.compile(rb"^\x17\x03[\x00-\x04]"), "TLS application data (encrypted)"),
    (re.compile(rb"^SSH-\d"), "an SSH version banner"),
    (re.compile(rb"^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT) \S+ HTTP/1\.[01]"), "an HTTP request"),
    (re.compile(rb"^HTTP/[12](\.[01])? \d{3}"), "an HTTP response"),
    (re.compile(rb"^\x00...\xfeSMB", re.S), "SMB2/SMB3 over the NetBIOS session service"),
    (re.compile(rb"^\x00...\xffSMB", re.S), "SMB1 over the NetBIOS session service"),
    (re.compile(rb"^\x03\x00..[\x02-\x0e]\xe0", re.S), "an RDP connection request (TPKT/X.224)"),
    (re.compile(rb"^MZ"), "a Windows program (PE file)"),
    (re.compile(rb"^\x7fELF"), "a Linux program (ELF file)"),
    (re.compile(rb"^PK\x03\x04"), "a ZIP archive (or DOCX/XLSX/JAR)"),
    (re.compile(rb"^\x1f\x8b\x08"), "gzip-compressed data"),
    (re.compile(rb"^%PDF-"), "a PDF document"),
    (re.compile(rb"^(\+OK|\* OK)"), "a POP3 or IMAP greeting"),
    (re.compile(rb"^\d{3}[ -][^\r\n]*\r?\n"), "text replies with 3-digit codes (FTP or SMTP style)"),
    (re.compile(rb"^\s*[{\[]\s*\""), "JSON"),
    (re.compile(rb"^\s*<(\?xml|!DOCTYPE|html)", re.I), "XML or HTML"),
]
_SHELL = re.compile(rb"(?im)^\s*(whoami|ipconfig|ifconfig|net (user|group|view|use)|systeminfo|tasklist|dir |ls -|"
                    rb"cat /etc/|uname -a|id\b|hostname|powershell|cmd(\.exe)? /c|wget |curl |chmod \+x|/bin/(ba)?sh)")
_B64 = re.compile(rb"^[A-Za-z0-9+/=\r\n]{48,}$")


def describe_payload(data: bytes) -> dict:
    """What a stream of bytes most likely is, in plain words, from its content alone."""
    n = len(data)
    if not n:
        return {"size": 0, "kind": "empty", "what": "No payload."}
    head = data[:65536]
    ent = _entropy(head)
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13)) / len(head)
    strings = []
    for m in re.finditer(rb"[ -~]{6,}", head):
        s = m.group().decode("ascii", "replace").strip()
        if s and s not in strings:
            strings.append(s[:100])
        if len(strings) >= 8:
            break
    what = next((desc for rx, desc in _SIGNATURES if rx.match(head)), None)
    kind = "text" if printable > 0.95 else "binary"
    if _SHELL.search(head) and printable > 0.8:
        what = ("text that looks like commands typed into a remote shell (" +
                ", ".join(sorted({m.group(1).decode(errors='replace').strip() for m in _SHELL.finditer(head)})[:5]) +
                "): an interactive backdoor or remote administration")
    elif not what and kind == "text" and _B64.match(head.strip()[:4096]):
        what = "Base64-encoded data: binary content disguised as text, a common way to smuggle data through text protocols"
    if not what:
        if kind == "text":
            what = "readable text in no protocol ANTA recognises"
        elif ent >= 7.5:
            what = ("random-looking bytes (encrypted or compressed) that don't start like TLS, SSH or any protocol ANTA "
                    "knows: a custom encrypted channel, as remote-access trojans and C2 implants use, or a VPN")
        elif ent < 4.0:
            what = "a structured binary protocol (many repeated or zero bytes: fixed-size fields)"
        else:
            what = "binary data in no protocol ANTA recognises"
    lines = []
    if kind == "text":
        lines = [ln.strip()[:120] for ln in head.decode("ascii", "replace").splitlines() if ln.strip()][:4]
    return {"size": n, "kind": kind, "entropy": round(ent, 2), "printable": round(printable, 3), "what": what,
            "strings": strings if kind == "binary" else [], "lines": lines}


def payload_summary(follow: dict) -> list[dict]:
    """Both directions of a followed stream, described."""
    chunks = follow.get("chunks") or []
    out = []
    for d, label in ((0, f"{follow.get('a')} → {follow.get('b')}"), (1, f"{follow.get('b')} → {follow.get('a')}")):
        data = b"".join(bytes.fromhex(c["hex"]) for c in chunks if c.get("dir") == d and c.get("hex"))
        if not data:
            continue
        sizes = [len(c["hex"]) // 2 for c in chunks if c.get("dir") == d][:12]
        desc = describe_payload(data)
        desc["direction"] = label
        desc["messages"] = sizes
        if len(sizes) >= 4 and len(set(sizes)) == 1:
            desc["what"] += f"; every message is exactly {sizes[0]} bytes, a fixed-size record (typical of beacons)"
        out.append(desc)
    return out


# ---------------------------------------------------------------- the whole selection

def explain(records: list[dict]) -> dict:
    convs = group(records)
    explained = [explain_conversation(c) for c in convs[:MAX_CONVERSATIONS]]
    counts = Counter(e["title"] for e in explained)
    return {"conversations": explained, "total": len(convs), "shown": len(explained),
            "summary": ", ".join(f"{v} {k.lower()}" for k, v in counts.most_common()),
            "frames": sum(1 for r in records if r.get("type") == "packet")}


# ---------------------------------------------------------------- one packet

def explain_frame(detail: dict) -> list[dict]:
    """What one packet means, in plain words: its flags and Wireshark's analysis
    translated, and any error code it carries."""
    f: dict[str, list[str]] = {}
    for name, value in detail.get("fields") or []:
        f.setdefault(name, []).append(value)
    lines = []

    def add(title, text, level="info"):
        lines.append({"title": title, "text": text, "level": level})

    info = str(detail.get("info") or "")
    if "tcp.flags.syn" in f:
        syn, ack, fin, rst, psh, urg = (_flag(f, f"tcp.flags.{k}") for k in ("syn", "ack", "fin", "reset", "push", "urg"))
        if not any((syn, ack, fin, rst, psh, urg)) and not _flag(f, "tcp.flags.ece") and not _flag(f, "tcp.flags.cwr"):
            add("No TCP flags", "A segment with no flags at all is never sent by a normal TCP stack: it was built by hand "
                "(a NULL scan or a covert channel).", "bad")
        elif fin and psh and urg and not ack:
            add("FIN, PSH and URG together", "An \"Xmas tree\" scan probe: no real connection sets these together.", "bad")
        elif syn and fin:
            add("SYN and FIN together", "Opening and closing at once is impossible: a crafted packet used to evade filters "
                "or fingerprint hosts.", "bad")
        elif syn and not ack:
            add("Connection request (SYN)", "The client asks to open a TCP connection. Next should come a SYN-ACK "
                "(accepted) or a reset (refused).")
        elif syn and ack:
            add("Connection accepted (SYN, ACK)", "The server agrees to open the connection; the client's ACK completes "
                "the three-way handshake.")
        elif rst:
            add("Reset (RST)", "This side aborts the connection at once. In answer to a SYN it means the port is closed "
                "(or a firewall rejects it); later it means the connection was killed (application, timeout or a "
                "middlebox).", "warn")
        elif fin:
            add("Finished (FIN)", "This side has no more data to send and starts an orderly close.")
    for key, (name, level, text) in TCP_ANALYSIS.items():
        if _flag(f, key):
            add(name, text, level)
    t, c = _n(f, "icmp.type"), _n(f, "icmp.code")
    if t is not None:
        if t == 3:
            nm, why = ICMP_UNREACHABLE.get(c or 0, (f"code {c}", "the packet couldn't be delivered"))
            add(f"Destination unreachable: {nm}", f"Sent back about an earlier packet: {why}.", "warn")
        elif t == 11:
            add("Time exceeded", "A packet's TTL ran out on the way: a routing loop, or a traceroute probing the path.", "warn")
        elif t == 8:
            add("Ping request", "An ICMP echo request: \"are you there?\". Many in a row to many addresses is a ping sweep.")
        elif t == 0:
            add("Ping reply", "The answer to an echo request: the host is up.")
        elif t == 5:
            add("Redirect", "A router tells the sender to use another gateway; unexpected redirects can be used to "
                "intercept traffic.", "warn")
    for desc in (_n(f, "tls.alert_message.desc", i) for i in range(len(f.get("tls.alert_message.desc", [])))):
        if desc is None:
            continue
        nm, meaning, why = TLS_ALERTS.get(desc, (f"alert {desc}", "the TLS session was ended", None))
        add(f"TLS alert: {nm}", meaning[0].upper() + meaning[1:] + "." + (f" Likely: {why}." if why else ""),
            "info" if desc == 0 else "bad")
    if "1" in f.get("tls.handshake.type", []):
        sni = _v(f, "tls.handshake.extensions_server_name")
        add("TLS Client Hello", "The client starts an encrypted session and lists what it supports" +
            (f"; it asks for the server name {sni}, which travels unencrypted" if sni else "") + ".")
    for code in f.get("http.response.code", []):
        if code.isdigit() and int(code) >= 400:
            add(f"HTTP {code}", HTTP_STATUS.get(int(code), "an error answer from the server") + ".", "warn")
    rc = _n(f, "dns.flags.rcode")
    if rc:
        nm, meaning = DNS_RCODES.get(rc, (f"error {rc}", "the DNS server returned an error"))
        add(f"DNS {nm}", meaning[0].upper() + meaning[1:] + ".", "warn")
    for code in f.get("kerberos.error_code", []):
        if code.isdigit():
            nm, meaning, why = KERBEROS_ERRORS.get(int(code), (f"error {code}", "the domain controller refused the request", None))
            add(f"Kerberos {nm}", meaning[0].upper() + meaning[1:] + "." + (f" {why[0].upper() + why[1:]}." if why else ""),
                "info" if int(code) in KERBEROS_ROUTINE else "warn")
    for name in re.findall(r"Error: (STATUS_[A-Z_0-9]+)", info):
        if name in SMB_STATUS or name not in SMB_ROUTINE:
            add(f"SMB {name}", SMB_STATUS.get(name, "the server refused the request") + ".", "warn")
    for code in f.get("ftp.response.code", []):
        if code.isdigit() and int(code) >= 400:
            add(f"FTP {code}", FTP_REPLIES.get(int(code), "the server refused the command") + ".", "warn")
    for code in f.get("ldap.resultCode", []):
        if code.isdigit() and int(code) not in LDAP_ROUTINE:
            add(f"LDAP result {code}", LDAP_RESULTS.get(int(code), "the directory refused the request") + ".", "warn")
    ttl = _n(f, "ip.ttl")
    if ttl is not None and ttl <= 1 and not t:
        add("TTL of 1 or less", "This packet can't cross a router: local-only by design (multicast, some discovery "
            "protocols) or a traceroute probe.")
    if detail.get("malformed"):
        add("Malformed", "Neither ANTA nor Wireshark could parse this packet as the protocol it seems to be: it is cut "
            "short or doesn't follow the specification. Sometimes a custom protocol on a standard port, or an attempt "
            "to evade inspection.", "warn")
    return lines


def stream_of(detail: dict) -> tuple[str, int] | None:
    for name, value in detail.get("fields") or []:
        if name in ("tcp.stream", "udp.stream") and str(value).isdigit():
            return name.split(".")[0], int(value)
    return None
