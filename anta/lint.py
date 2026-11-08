"""The protocol spell-checker: every packet held against the rules its protocol's standard sets,
like a spell-checker for networks. Each rule says what is wrong in plain words, which rule of
which standard it breaks (paraphrased, with the RFC and section), and why it matters: a stack
never sends it, so something built the packet by hand; it opens a door (request smuggling,
spoofing from off the link); or the version is one the standard forbids.

Every rule is a display filter; the engine counts them all in one pass over the capture
(--count-filter) and keeps the first frames each one matched.
"""
from __future__ import annotations

from dataclasses import dataclass

SEVERITIES = ("error", "warning", "note")


@dataclass(frozen=True)
class Rule:
    id: str
    protocol: str
    severity: str      # error: breaks a MUST; warning: no stack sends this (crafted, scanning); note: odd or outdated
    title: str         # what is wrong, in plain words
    rule: str          # the standard's rule, paraphrased, with where it is written
    why: str           # why it matters
    filter: str        # the display filter that finds it


RULES: tuple[Rule, ...] = (
    # ------------------------------------------------------------------ IP
    Rule("ip-reserved-bit", "IPv4", "warning", "The reserved flag bit is set",
         "RFC 791 §3.1: the first of the three flag bits is reserved and must be zero.",
         "No operating system sets it, so the packet was built by hand or by a scanning or fingerprinting tool "
         "(RFC 3514's “evil bit” was an April Fools' joke).",
         "ip.flags.rb == 1"),
    Rule("ip-df-fragment", "IPv4", "error", "A fragment of a datagram marked Don't Fragment",
         "RFC 791 §2.3: a datagram with the Don't Fragment flag set must not be fragmented.",
         "The headers contradict each other: a crafted packet, or a broken device on the path. Overlapping or odd "
         "fragments are a classic way to slip past inspection.",
         "ip.flags.df == 1 && (ip.flags.mf == 1 || ip.frag_offset > 0)"),
    Rule("ip-ttl-zero", "IPv4", "error", "Sent with a time to live of 0",
         "RFC 1122 §3.2.1.7: a host must not send a datagram with a TTL of zero.",
         "The first router must throw it away, so it can only reach the local link. Path-probing and evasion tools "
         "craft these.",
         "ip.ttl == 0"),
    Rule("ip-bad-source", "IPv4", "error", "A broadcast or multicast address as the source",
         "RFC 1122 §3.2.1.3: the source address of a datagram must be a host's own address, never a broadcast or "
         "multicast address.",
         "Real hosts can't send from these addresses: the source is spoofed, often to make others reply to a group "
         "(reflection) or to hide who sent it.",
         "ip.src == 224.0.0.0/4 || ip.src == 255.255.255.255"),
    Rule("ip-loopback-on-wire", "IP", "error", "A loopback address on the network",
         "RFC 1122 §3.2.1.3: addresses in 127.0.0.0/8 must never appear outside a host (and ::1 likewise, RFC 4291 §2.5.3).",
         "Seen on a real network (not the loopback interface), it is spoofed or leaking from a misconfigured device; "
         "services that trust “localhost” can be fooled by it.",
         "eth && (ip.src == 127.0.0.0/8 || ip.dst == 127.0.0.0/8 || ipv6.src == ::1 || ipv6.dst == ::1)"),
    Rule("nd-hop-limit", "ICMPv6", "error", "Neighbor Discovery from off the local link",
         "RFC 4861 §6.1 and §7.1: router and neighbor messages must have a hop limit of 255, and receivers must "
         "discard any that don't.",
         "A hop limit under 255 means the message crossed a router, so it can't be a real neighbor: someone off the "
         "link is trying to redirect traffic or poison neighbor caches.",
         "icmpv6.type >= 133 && icmpv6.type <= 137 && ipv6.hlim != 255"),
    # ------------------------------------------------------------------ TCP
    Rule("tcp-reserved-bits", "TCP", "warning", "Reserved TCP header bits are set",
         "RFC 9293 §3.1: the reserved control bits must be zero in segments a host sends.",
         "No normal stack sets them: crafted packets, or a fingerprinting tool seeing how the receiver reacts.",
         "tcp.flags.res > 0"),
    Rule("tcp-syn-fin", "TCP", "warning", "SYN and FIN in one segment (open and close at once)",
         "RFC 9293: a SYN opens a connection and a FIN closes one; no stack sends both together.",
         "Scanners and OS-fingerprinting tools send it because systems and firewalls react to it differently.",
         "tcp.flags.syn == 1 && tcp.flags.fin == 1"),
    Rule("tcp-syn-rst", "TCP", "warning", "SYN and RST in one segment",
         "RFC 9293: a reset ends a connection and a SYN starts one; they never go together.",
         "Built by hand: scanning, fingerprinting, or trying to confuse a firewall's connection tracking.",
         "tcp.flags.syn == 1 && tcp.flags.reset == 1"),
    Rule("tcp-null", "TCP", "warning", "A TCP segment with no flags at all (a NULL scan)",
         "RFC 9293 §3.10.7: every segment of a connection carries ACK after the first SYN; one with no control bits "
         "has no meaning and is dropped.",
         "The signature of a NULL scan: closed ports answer with a reset, open ports stay silent.",
         "tcp && tcp.flags & 0x0ff == 0"),
    Rule("tcp-xmas", "TCP", "warning", "FIN, PSH and URG without ACK (an Xmas scan)",
         "RFC 9293 §3.10.7: outside the first SYN, a segment without ACK is dropped.",
         "The signature of an Xmas scan (the header “lit up like a Christmas tree”).",
         "tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1 && tcp.flags.ack == 0"),
    Rule("tcp-urgent-without-urg", "TCP", "note", "An urgent pointer without the URG flag",
         "RFC 9293 §3.1: the urgent pointer is only to be read in segments with the URG bit set.",
         "Harmless to most stacks, but a value hidden where it is ignored can carry data or fingerprint a tool.",
         "tcp.flags.urg == 0 && tcp.urgent_pointer > 0"),
    Rule("tcp-mss-not-syn", "TCP", "note", "A maximum segment size option outside a SYN",
         "RFC 9293 §3.2: the MSS option may be sent only in segments with the SYN bit set.",
         "Stacks don't do this; packet crafting and some fuzzing tools do.",
         "tcp.options.mss_val && tcp.flags.syn == 0"),
    Rule("tcp-wscale-not-syn", "TCP", "note", "A window scale option outside a SYN",
         "RFC 7323 §2.2: the Window Scale option is sent only in a SYN segment.",
         "Stacks don't do this; it is crafted, or a buggy device rewriting headers.",
         "tcp.options.wscale.shift && tcp.flags.syn == 0"),
    Rule("tcp-wscale-too-big", "TCP", "note", "A window scale shift above 14",
         "RFC 7323 §2.3: the shift count is at most 14; a receiver must use 14 instead of anything larger.",
         "A larger value is a buggy or crafted stack, and a fingerprinting tool's probe.",
         "tcp.options.wscale.shift > 14"),
    Rule("tcp-to-broadcast", "TCP", "warning", "TCP sent to a broadcast or multicast address",
         "RFC 1122 §4.2.3.10: a SYN addressed to a broadcast or multicast address must be silently discarded; TCP is "
         "for one host talking to one host.",
         "Scanning a whole segment at once, or a misconfigured device.",
         "tcp && eth.dst.ig == 1"),
    Rule("port-zero", "TCP/UDP", "warning", "Traffic to port 0",
         "RFC 6335 §6: port 0 is reserved and is not used for services.",
         "Nothing listens on port 0: scanners and fingerprinting tools probe it to see how the system answers.",
         "tcp.dstport == 0 || udp.dstport == 0"),
    # ------------------------------------------------------------------ UDP
    Rule("udp-length", "UDP", "error", "A UDP length that doesn't match the packet",
         "RFC 768: the length field is the length of the datagram, header included.",
         "A wrong length is a malformed or crafted packet; receivers that trust it read the wrong bytes.",
         "udp.length.bad"),
    # ------------------------------------------------------------------ DNS
    Rule("dns-z-bit", "DNS", "error", "The DNS reserved Z bit is set",
         "RFC 1035 §4.1.1: the Z bit is reserved and must be zero in all queries and responses.",
         "Real resolvers leave it zero: a hand-built message, or data hidden in the header.",
         "dns && !mdns && !llmnr && dns.flags.z == 1"),
    Rule("dns-qdcount", "DNS", "error", "A DNS query asking more than one question",
         "RFC 9619: a message with opcode QUERY must not carry more than one question.",
         "Servers disagree on how to answer it, which tools exploit to confuse caches and inspection.",
         "dns && !mdns && !llmnr && dns.flags.opcode == 0 && dns.count.queries > 1"),
    Rule("dns-answers-in-query", "DNS", "note", "Answers inside a DNS query",
         "RFC 1035 §4.1: a standard query carries its question and an empty answer section; answers belong in "
         "responses.",
         "Answers have no meaning in a query: a way to carry data out in DNS (tunnels) or to probe a resolver.",
         "dns && !mdns && !llmnr && dns.flags.response == 0 && dns.count.answers > 0"),
    # ------------------------------------------------------------------ HTTP
    Rule("http-no-host", "HTTP", "error", "An HTTP/1.1 request without a Host header",
         "RFC 9112 §3.2: a client must send Host in every HTTP/1.1 request, and a server must answer one without it "
         "with 400 Bad Request.",
         "Browsers always send it: a script, a scanner or a hand-written request. Servers that accept it anyway may "
         "route it to an unexpected site.",
         "http.request && http.request.version == \"HTTP/1.1\" && !http.host"),
    Rule("http-cl-te", "HTTP", "error", "Content-Length and Transfer-Encoding in the same message",
         "RFC 9112 §6.1: a sender must not send Content-Length in a message that has Transfer-Encoding.",
         "The classic ingredient of HTTP request smuggling: a proxy and a server can disagree on where the request "
         "ends, and a second, hidden request slips through.",
         "http.content_length && http.transfer_encoding"),
    Rule("http-status-range", "HTTP", "error", "An HTTP status code outside 100–599",
         "RFC 9110 §15: status codes are three-digit numbers from 100 to 599.",
         "A broken or non-HTTP server on an HTTP port, or a hand-built response.",
         "http.response && (http.response.code < 100 || http.response.code > 599)"),
    # ------------------------------------------------------------------ TLS and other versions
    Rule("tls-sni-ip", "TLS", "error", "An IP address as the TLS server name",
         "RFC 6066 §3: literal IPv4 and IPv6 addresses are not permitted in the server name.",
         "Browsers never send it: a script or tool connecting to a bare address, often malware with a hard-coded "
         "server.",
         "tls.handshake.extensions_server_name matches \"^[0-9.]+$\" || tls.handshake.extensions_server_name contains \":\""),
    Rule("tls-sni-dot", "TLS", "note", "A TLS server name ending in a dot",
         "RFC 6066 §3: the host name is sent without a trailing dot.",
         "A tool or library that builds names by hand; servers may fail to match it to a certificate.",
         "tls.handshake.extensions_server_name matches \"\\\\.$\""),
    Rule("tls-old-version", "TLS", "warning", "A server agreed to SSL 3.0, TLS 1.0 or TLS 1.1",
         "RFC 8996: TLS 1.0 and 1.1 must not be used; RFC 7568: SSL 3.0 must not be used.",
         "These versions have known attacks (POODLE, BEAST): an old or misconfigured server, or a downgrade.",
         "tls.handshake.type == 2 && tls.record.version < 0x0303"),
    Rule("smb1", "SMB", "warning", "SMB version 1 in use",
         "Microsoft deprecated SMB1 (2014) and no longer installs it by default.",
         "SMB1 is what WannaCry and NotPetya spread through: an old device, or something asking for it on purpose.",
         "smb"),
    Rule("ssh-1", "SSH", "warning", "SSH protocol version 1",
         "RFC 4253 §5: SSH 2.0 replaced 1.x, whose design is broken.",
         "SSH-1 sessions can be hijacked and decrypted: an ancient device, or a client offering it to downgrade.",
         "ssh.protocol matches \"^SSH-1\\\\.\""),
)

_BY_ID = {r.id: r for r in RULES}


def filters() -> list[str]:
    return [r.filter for r in RULES]


def report(counts: list[dict]) -> dict:
    """What broke which rule, worst first, from the engine's counts (in RULES order)."""
    broken, passed = [], []
    for i, r in enumerate(RULES):
        c = counts[i] if i < len(counts) else None  # (no count: nothing broke it)
        entry = {"id": r.id, "protocol": r.protocol, "severity": r.severity, "title": r.title, "rule": r.rule, "why": r.why,
                 "filter": r.filter, "count": int((c or {}).get("count") or 0), "frames": list((c or {}).get("frames") or [])}
        (broken if entry["count"] else passed).append(entry)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    broken.sort(key=lambda e: (order[e["severity"]], -e["count"]))
    return {"broken": broken, "passed": [{k: e[k] for k in ("id", "protocol", "title", "rule")} for e in passed],
            "checked": len(RULES), "packets": sum(e["count"] for e in broken)}


def rule(rule_id: str) -> Rule | None:
    return _BY_ID.get(rule_id)
