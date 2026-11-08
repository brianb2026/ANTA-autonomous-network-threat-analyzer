"""Ask the capture: a question in plain words, answered with what a Wireshark user would
type or click: a display filter, a statistics tool, a view. Nothing is applied until the
user says so, and the answer shows which words became which part of the filter, so it also
teaches the filter language.

Questions are read by rules, here on this computer. A configured AI model is asked only
when the user presses its button (see translate_with_model): only the question goes to it,
never the capture, with internal addresses replaced by pseudonyms unless the user allowed
them, and the filter it suggests is checked by the engine before it is offered.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import re

MAX_QUESTION = 500

# ---------------------------------------------------------------- vocabulary

# Protocols and families, as people name them: (pattern, filter, words for the summary).
PROTOCOLS = [
    (r"https|tls|ssl", "tls", "TLS (HTTPS)"),
    (r"quic|http/?3", "quic", "QUIC"),
    (r"web(?: traffic| browsing| requests?)?|browsing", "http || tls || quic", "web traffic"),
    (r"http(?!s)(?:/1\.1)?", "http", "HTTP"),
    (r"dns|name lookups?|domain lookups?|lookups?", "dns", "DNS"),
    (r"m ?dns|bonjour", "mdns", "mDNS"),
    (r"llmnr", "llmnr", "LLMNR"),
    (r"netbios|nbns", "nbns", "NetBIOS name service"),
    (r"ssh|secure shell", "ssh", "SSH"),
    (r"telnet", "telnet", "Telnet"),
    (r"ftp(?:-data)?|file transfer protocol", "ftp || ftp-data", "FTP"),
    (r"smb2?|file shar(?:e|es|ing)|windows shares?|cifs", "smb || smb2", "SMB file sharing"),
    (r"rdp|remote desktop", "rdp", "Remote Desktop"),
    (r"e-?mail|mail", "smtp || imap || pop", "email"),
    (r"smtp", "smtp", "SMTP"),
    (r"imap", "imap", "IMAP"),
    (r"pop3?", "pop", "POP"),
    (r"dhcp|bootp", "dhcp", "DHCP"),
    (r"ntp|time sync(?:hronization)?", "ntp", "NTP"),
    (r"arp", "arp", "ARP"),
    (r"pings?|icmp(?:v6)?|echo requests?", "icmp || icmpv6", "ICMP (ping)"),
    (r"snmp", "snmp", "SNMP"),
    (r"ldap|active directory", "ldap", "LDAP"),
    (r"kerberos", "kerberos", "Kerberos"),
    (r"sip|voip|phone calls?", "sip", "SIP (VoIP)"),
    (r"ssdp|upnp", "ssdp", "SSDP"),
    (r"mysql", "mysql", "MySQL"),
    (r"postgres(?:ql)?|pgsql", "pgsql", "PostgreSQL"),
    (r"sql server|mssql|tds", "tds", "SQL Server"),
    (r"dce ?rpc|msrpc", "dcerpc", "DCE/RPC"),
    (r"dtls", "dtls", "DTLS"),
    (r"openvpn", "openvpn", "OpenVPN"),
    (r"igmp", "igmp", "IGMP"),
    (r"lldp", "lldp", "LLDP"),
    (r"spanning tree|stp", "stp", "Spanning Tree"),
    (r"ipv6", "ipv6", "IPv6"),
    (r"tcp", "tcp", "TCP"),
    (r"udp", "udp", "UDP"),
    (r"(?:un|not )encrypted|clear ?text|plain ?text", "http || ftp || telnet || pop || imap || smtp || snmp",
     "unencrypted protocols"),
    (r"encrypted", "tls || quic || ssh || dtls", "encrypted traffic"),
]

# Things that went wrong, or kinds of packet: (pattern, filter, summary words).
CONDITIONS = [
    (r"retransmi(?:ssions?|tted|ts?)|resent", "tcp.analysis.retransmission", "retransmissions"),
    (r"duplicate acks?|dup ?acks?", "tcp.analysis.duplicate_ack", "duplicate ACKs"),
    (r"zero windows?|window full", "tcp.analysis.zero_window || tcp.analysis.window_full", "full receive windows"),
    (r"lost segments?|packet loss|lost packets?", "tcp.analysis.lost_segment || tcp.analysis.retransmission",
     "lost packets"),
    (r"resets?|rsts?|refused connections?|connections? refused", "tcp.flags.reset == 1", "resets"),
    (r"(?:connection attempts?|new connections?|syns?|handshakes?)", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
     "connection attempts"),
    (r"nxdomain|no such (?:name|domain)|(?:failed|unanswered|bad) (?:dns )?(?:lookups?|queries)|dns (?:errors?|failures?)",
     "dns.flags.rcode != 0", "failed DNS lookups"),
    (r"404s?|not found", "http.response.code == 404", "HTTP 404 Not Found"),
    (r"server errors?|5\d\d errors?|500s?", "http.response.code >= 500", "HTTP server errors"),
    (r"http errors?|web errors?", "http.response.code >= 400", "HTTP errors"),
    (r"posts?|form submissions?|uploads? over http", 'http.request.method == "POST"', "HTTP POSTs"),
    (r"certificates?|certs?", "tls.handshake.type == 11", "TLS certificates"),
    (r"client hellos?|server names?|sni", "tls.handshake.type == 1", "TLS Client Hellos"),
    (r"user[- ]agents?", "http.user_agent", "HTTP user agents"),
    (r"cookies?", "http.cookie || http.set_cookie", "cookies"),
    (r"slow (?:responses?|acks?)|high latency|latency|slow", "tcp.analysis.ack_rtt > 0.2", "slow acknowledgements"),
    (r"broadcasts?", "eth.dst == ff:ff:ff:ff:ff:ff", "broadcasts"),
    (r"multicasts?", "ip.dst == 224.0.0.0/4 || ipv6.dst == ff00::/8", "multicasts"),
    (r"errors?|problems?|issues?|warnings?|anomal(?:y|ies)", "_ws.expert", "packets with expert notes"),
]

# Questions a tool or view answers better than a list of packets, named by what they ask
# about: (name, pattern, action, summary). Questions about who talked to whom, how much,
# when, which ports, protocols or names are read by their shape instead (see _about).
INTENTS = [
    ("logins", r"passwords?|credentials?|log ?ins?\b|logged in|sign[- ]?ins?|community strings?",
     {"kind": "stats", "tool": "logins"}, "logins sent in clear text"),
    ("rhythm", r"beacon\w*|call(?:s|ing|ed)? home|c2\b|command[- ]and[- ]control|periodic\w*|on a timer|heartbeats?|"
               r"check[- ]?ins?|regular intervals?|phon(?:e|es|ing|ed) home",
     {"kind": "stats", "tool": "rhythm"}, "channels on a timer (beacons)"),
    ("story", r"what happened|attack(?:s|ed|er|ers)?|compromised|infected|breach\w*|kill chain|storyline|story|"
              r"(?:been |got |get )hacked|pwned|owned by",
     {"kind": "view", "view": "story"}, "the attack storyline"),
    ("devices", r"(?:what|which|list|all|show)(?: me)? (?:the |all )?(?:devices|machines|computers)(?! (?:did|does|has|have|sent|talked))|"
                r"inventory|devices? (?:are |were )?(?:on|in) (?:the|my|this|our) network|operating systems",
     {"kind": "view", "view": "assets"}, "the devices on the network"),
    ("files", r"(?<!this )(?<!my )(?<!pcap )(?<!capture )file\b|files|attachments?|executables?|documents?|"
              r"programs? (?:sent|copied|downloaded)|downloads\b|"
              r"what (?:was|were|got) (?:downloaded|uploaded)|anything (?:downloaded|uploaded)|"
              r"what (?:did|does|has|was|were) .{1,80}? (?P<key>download(?:ed|s)?|upload(?:ed|s)?)$",
     {"kind": "view", "view": "files"}, "the files carried"),
    ("fingerprints", r"ja[34]s?|tls fingerprints?", {"kind": "stats", "tool": "fingerprints"}, "TLS fingerprints"),
    ("alerts", r"alerts?|threats?|suspicious|malicious|malware|anything (?:wrong|bad|bad happen\w*|weird|odd|unusual|strange)|"
               r"should i (?:worry|be worried)|dangerous|risky|scan(?:s|ned|ning|ner)?|sweeps?|brute[- ]?forc\w*|exploit\w*|"
               r"intrusions?|hack(?:s|ing|er|ers)?|bad (?:actors?|guys?|ips?|hosts?)|iocs?|indicators? of compromise|"
               r"(?:is|was|are|were|looks?) .{1,80}? (?P<key>safe|ok|okay|clean|legit\w*|bad|harmful|trustworthy|evil|benign|"
               r"fine|normal|a threat|a problem|dangerous|risky)$",
     {"kind": "view", "view": "alerts"}, "the alerts"),
    ("io", r"over time|traffic graph|throughput graph|bandwidth over time|busiest (?:time|moment|minute|second|hour|period)|"
           r"(?:when|what time) (?:was|is) (?:the )?(?:traffic )?(?:busiest|peak)|peak (?:time|traffic|usage)|spikes?",
     {"kind": "stats", "tool": "io"}, "traffic over time"),
    ("countries", r"countr(?:y|ies)|abroad|foreign|overseas|geo(?:graph\w*|location)?|where (?:did|does|do|is|are)\b.*\bgo",
     {"kind": "stats", "tool": "geo"}, "countries and networks"),
]
LATE_INTENTS = {"devices", "countries"}  # (read after the question's shape: "which devices sent the most" is about hosts)

UNITS = {"s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1, "m": 60, "min": 60, "mins": 60, "minute": 60,
         "minutes": 60, "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600}
UNIT_RE = r"(s|secs?|seconds?|m|mins?|minutes?|h|hrs?|hours?)\b"
NEGATE = (r"(?:not|no|except|excluding|exclude|without|ignoring|ignore|other than|but not|apart from|besides|aside from|"
          r"not counting|minus|leaving out|leave out|skip|skipping)\s+(?:for\s+)?(?:the\s+|any\s+)?$")
SRC_WORDS = r"(?:from|by|sent by|source|src|coming from|originating from)\s+(?:the\s+)?(?:host\s+|device\s+|ip\s+)?$"
DST_WORDS = (r"(?:to|towards|reaching|destination|dst|contacting|contacted|talking to|talked to|connect(?:ing|ed|s)? to|"
             r"going to|sent to)\s+(?:the\s+)?(?:host\s+|device\s+|ip\s+|server\s+)?$")
# "What happened to X", "alerts about X": X is the subject, either end.
ABOUT_WORDS = r"(?:happened to|happening to|about|with|regarding|involving|on|for)\s+(?:the\s+)?(?:host\s+|device\s+)?$"
FILE_EXT = {"exe", "dll", "msi", "zip", "rar", "7z", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "ps1", "bat",
            "vbs", "jar", "apk", "iso", "img", "bin", "txt", "csv", "png", "jpg", "jpeg", "gif", "js", "sh", "py",
            "cfg", "conf", "log", "tar", "gz", "tgz", "pcap", "pcapng"}

EXAMPLES = [
    "who did 10.0.0.5 talk to the most?",
    "who talked the most?",
    "what is 10.0.0.5?",
    "did 10.0.0.5 talk to 203.0.113.50?",
    "what ports is 10.0.0.5 listening on?",
    "what sites did 10.0.0.5 visit?",
    "any passwords sent in clear text?",
    "which devices call home on a timer?",
    "retransmissions to 203.0.113.50 in the first 5 minutes",
    "who used SSH?",
]

# ---------------------------------------------------------------- reading loosely

# Slips people type, read as what they meant.
SLIPS = {"teh": "the", "wat": "what", "waht": "what", "wht": "what", "whta": "what", "wich": "which", "whcih": "which",
         "wihch": "which", "hwo": "who", "woh": "who", "whos": "who is", "whats": "what is", "wheres": "where is",
         "whens": "when is", "hows": "how is", "dsn": "dns", "htpp": "http", "htttp": "http", "ip's": "ips",
         "recieve": "receive", "recieved": "received", "recieving": "receiving", "adress": "address",
         "adresses": "addresses", "addres": "address", "addreses": "addresses", "trafic": "traffic", "trafick": "traffic",
         "conect": "connect", "conected": "connected", "conection": "connection", "conections": "connections",
         "talkd": "talked", "tlaked": "talked", "taked": "talked", "domians": "domains", "protocals": "protocols",
         "protocal": "protocol", "prots": "ports", "u": "you", "ur": "your", "r": "are", "pls": "please",
         "plz": "please", "thru": "through", "w/": "with", "w/o": "without", "b/w": "between", "btwn": "between"}
# The words the rules read; a word one slip away from exactly one of them is read as it.
VOCAB = set("""
talk talked talking talks speak spoke speaking chat chatted chatting communicate communicated communicating
communication conversation conversations connect connected connecting connects connection connections contact
contacted contacting reach reached reaching visit visited visiting visits access accessed accessing query queried
queries send sent sending sends transfer transferred transfers upload uploaded uploads download downloaded downloads
receive received receiving receives fetch fetched which where what when whom whose most least busiest noisiest
biggest largest longest heaviest chattiest loudest quietest active traffic data bandwidth bytes packets packet
frames frame hosts host devices device machines machine computers computer servers server clients client address
addresses peers peer destination destinations sessions session flows stream streams ports port services service
listening listen protocol protocols application applications domains domain websites website sites site names
hostname hostnames lookup lookups looked resolve resolved resolves browse browsed between first last seen appear
appeared start started stopped long time capture minutes seconds hours country countries located location files
file passwords password credentials login logins alerts alert suspicious malicious malware attack attacked attacker
compromised infected beacon beacons timer periodic happened retransmissions retransmission resets duplicate errors
error failed failures encrypted unencrypted cleartext plaintext certificates certificate broadcast broadcasts
multicast larger smaller bigger after before during within except excluding without ignoring besides internal
external public private local outside inside internet total amount number many much count show list give tell
about everything everyone anyone anything everybody anybody someone somebody profile describe summary summarize
overview details information doing operating system vendor manufacturer telnet email kerberos netbios ping pings
there their these those other another anywhere somewhere through across often frequently times between
""".split())
# Ordinary words one slip from a rule's word: never "corrected".
COMMON = set("""
that than then them they this thus what with were wear went want week well will also only over into onto upon
from your yours mine ours just like more much must most some same such each both very even ever here hear near
make made take took gave give have having been being does done doing used uses user users using thing things
tasks task cost lose lots mist post past fast last lest best test text next nest rest west sort port part
sore more mode node code note vote role rule mile time tile type tape page wage case base vase rate date gate
late fate kind mind find bind wind hint mint able cable table where there these those three whose whole while
could would should shall still state stats start stare share shore store story about above among along alone
again agent avoid every never newer other others under until using value think thank sites times tines kites
going doing being having making taking coming seeing saying trying asking giving moving working looking showing
telling getting setting putting running walking talking sending holding keeping turning playing paying happens
happen really maybe right wrong after early later today night again since while among about above below around
there here where everywhere nowhere person people world thing things something nothing anything everything
please thanks thank sorry hello great good better worst worse least first second third fourth fifth sixth
little large small short tall long longer shorter older newer young often always never sometimes usually
number numbers order orders level levels point points place places group groups total totals count counts
change changes chance range ranges reason reasons answer answers question questions problem problems issue
issues result results record records report reports event events window windows network networks screen
inside outside within without between before behind beyond because become became brought bought thought
taught caught though through throughout enough every either neither whether rather other another
""".split())


def _osa(a: str, b: str) -> int:
    """Edit distance with swapped neighbours counted as one slip."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _one_slip(w: str, v: str, swap_only: bool) -> bool:
    """Whether `w` is `v` with one slip: two letters swapped, or (unless `swap_only`) one
    letter left out or doubled, or (in a long word) one letter wrong."""
    if len(w) == len(v):
        diff = [i for i in range(len(w)) if w[i] != v[i]]
        if len(diff) == 2 and diff[1] == diff[0] + 1 and w[diff[0]] == v[diff[1]] and w[diff[1]] == v[diff[0]]:
            return True
        return not swap_only and len(w) >= 6 and len(diff) == 1
    if swap_only or abs(len(w) - len(v)) != 1:
        return False
    short, long_ = (w, v) if len(w) < len(v) else (v, w)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def _fix_word(w: str) -> str:
    lw = w.lower()
    if lw in SLIPS:
        return SLIPS[lw]
    if len(lw) < 4 or lw in VOCAB or lw in COMMON or not lw.isalpha():
        return w
    hits = {v for v in VOCAB if abs(len(v) - len(lw)) <= 1 and _one_slip(lw, v, len(lw) == 4)}
    if not hits and len(lw) >= 9:
        hits = {v for v in VOCAB if abs(len(v) - len(lw)) <= 2 and len(v) >= 8 and _osa(lw, v) <= 2}
    if len(hits) > 1:  # a swap is the likeliest slip, then a letter left out or doubled
        swaps = {v for v in hits if len(v) == len(lw) and _one_slip(lw, v, True)}
        hits = swaps or {v for v in hits if len(v) != len(lw)} or hits
        if len(hits) > 1 and len({v.rstrip("s") for v in hits}) == 1:
            hits = {v for v in hits if v.endswith("s") == lw.endswith("s")} or hits
    return hits.pop() if len(hits) == 1 else w


def _normalize(question: str) -> tuple[str, str]:
    """The question as the rules read it: one line, plain quotes, short forms spelled out,
    slips fixed. Returns it and whether any word was read as another."""
    raw = re.sub(r"\s+", " ", (question or "").strip())[:MAX_QUESTION]
    raw = raw.translate(str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-",
                                       "—": "-"}))
    raw = re.sub(r"\b(who|what|where|when|how|that|it|there|which)'s\b", r"\1 is", raw, flags=re.I)
    raw = re.sub(r"\b(who|what|where|when|how|they|you|we)'re\b", r"\1 are", raw, flags=re.I)
    fixed = []
    changed = False
    for tok in re.split(r"(\s+)", raw):
        if not tok or tok.isspace() or re.search(r"[\d.:/@*\"]", tok.strip("?!,;()")) and tok.lower() not in SLIPS:
            fixed.append(tok)
            continue
        m = re.fullmatch(r"([(\"']*)([A-Za-z'/]+)([?!.,;:)\"']*)", tok)
        if not m:
            fixed.append(tok)
            continue
        new = _fix_word(m.group(2))
        if new.lower() != m.group(2).lower():
            changed = changed or m.group(2).lower() not in ("whos", "whats", "wheres", "whens", "hows", "pls", "plz",
                                                            "u", "ur", "r", "w/", "w/o", "b/w", "thru")
        fixed.append(m.group(1) + new + m.group(3))
    return "".join(fixed), "".join(fixed) if changed else ""


# ---------------------------------------------------------------- what a question is about

HOSTN = (r"(?:hosts?|ips?|ip address(?:es)?|ip addrs?|addresses|address|devices?|machines?|computers?|systems?|servers?|"
         r"clients?|endpoints?|nodes?|boxes|workstations?|laptops?|phones?|boxes|ones?)")
TALK = r"(?:talk\w*|speak\w*|spoke\w*|chat\w*|communicat\w*|convers\w*|interact\w*|exchang\w*)"
CONNECT = (r"(?:connect\w*|contact\w*|reach\w*|hit|hits|hitting|call(?:s|ed|ing)?|visit\w*|access\w*|ping(?:s|ed|ing)?|"
           r"went to|go(?:es)? to|going to|been to)")
SEND = r"(?:sen[dt]\w*|transfer\w*|upload\w*|push\w*|exfiltrat\w*|leak\w*|transmit\w*|stream\w*|egress\w*|outbound)"
RECV = r"(?:receiv\w*|got|gets?|getting|download\w*|pull\w*|fetch\w*|grab\w*|ingress\w*|inbound|incoming)"
PEERV = rf"(?:{TALK}|{CONNECT}|{SEND}|{RECV})"
PEERN = (r"(?:peers?|destinations?|contacts?|partners?|connections?|conversations?|neighbou?rs?|talkers?|counterparts?|"
         r"correspondents?|remote (?:hosts?|ends?|sides?|servers?|addresses|ips?)|servers?|clients?|endpoints?|targets?|"
         r"sources?|flows?|sessions?|links?|relationships?|associates?)")
NUM_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
             "eleven": 11, "twelve": 12, "fifteen": 15, "twenty": 20, "dozen": 12}
NUM = r"(\d{1,3}|" + "|".join(NUM_WORDS) + r")"
FILLER = re.compile(
    r"^(?:(?:hey|hi|hello|ok(?:ay)?|so|um+|uh+|well|quick question|question|yo|and|also|now|then|ok so)[,:]?\s+)*"
    r"(?:(?:can|could|would|will) you (?:please )?(?:tell me|show me|list|find(?: out)?|give me|check|figure out|"
    r"let me know|say|work out|see)?\s*|(?:please )?(?:tell me|show me|i (?:want|need|would like|wanna) to (?:know|see|"
    r"find out|understand|check)|i'd like to (?:know|see)|i(?: am|'m) (?:curious|wondering)(?: about)?|do you know|"
    r"any idea|let me (?:know|see)|help me (?:find|see|understand)|find out|figure out|i wonder|check)\s*)?(?:please\s+)?")
TAIL = re.compile(r"(?:,?\s*(?:please|thanks|thank you|thx|ty))?\s*$")
WHERE_TAIL = re.compile(r"\s*\b(?:in|on|from|within|across|inside|throughout|of) (?:this|the|my|our|that) "
                        r"(?:capture|pcap|pcapng|file|trace|recording|dump|data|traffic|network)\b(?! (?:start|begin|end))")


def _number(sk: str) -> int | None:
    m = re.search(rf"\btop {NUM}\b|\b{NUM} (?:most|biggest|largest|busiest|top|main|heaviest|noisiest|chattiest|loudest|"
                  rf"quietest|least|longest|highest|lowest|smallest)\b|\b(?:most|biggest|largest|busiest|longest) {NUM}\b|"
                  rf"\b(?:first|top) {NUM} (?:hosts?|peers?|ips?|talkers?|devices?|conversations?|ports?|names?|domains?)", sk)
    if not m:
        return None
    word = next(g for g in m.groups() if g)
    n = int(word) if word.isdigit() else NUM_WORDS[word]
    return max(1, min(n, 50))


def _rank(sk: str) -> str:
    if re.search(r"\blongest\b|\blast(?:ed|ing)\b|\bduration\b|long[- ](?:lived|running|lasting)", sk):
        return "duration"
    if re.search(r"\b(?:most|least|fewest|more|many)\s+(?:\w+\s+)?(?:connections?|sessions?|conversations?|flows?|streams?)\b|"
                 r"\b(?:often|frequent\w*|repeatedly|times|regularly)\b", sk):
        return "connections"
    if re.search(r"\b(?:packets?|frames?)\b", sk):
        return "packets"
    return "bytes"


def _scope_words(sk: str) -> str | None:
    if re.search(r"\b(?:external|public|outside|internet|off[- ]network|wan|remote(?! desktop)|foreign|cloud)\b", sk):
        return "public"
    if re.search(r"\b(?:internal|private|inside|lan|intranet|local (?:hosts?|devices?|machines?|ips?|addresses|computers?|"
                 r"clients?|servers?))\b", sk):
        return "private"
    return None


def _direction(sk: str, subject_first: bool) -> str:
    """Which way the question looks: "any", "out" (the subject sends), "in" (it receives),
    "servers" (what the subject connected to) or "clients" (who connected to it)."""
    if re.search(r"@a(?:'s|s)?\s+(?:\w+\s+){0,2}(?:servers?|destinations?|targets?)\b|"
                 r"\b(?:servers?|destinations?|targets?)\s+(?:\w+\s+){0,2}(?:of|for|from|by)\s+@a|"
                 r"\b(?:what|which) (?:\w+ )?(?:servers?|destinations?) (?:does|did|is|has|was) @a\b", sk):
        return "servers"
    if re.search(r"@a(?:'s|s)?\s+(?:\w+\s+){0,2}clients?\b|\bclients?\s+(?:\w+\s+){0,2}(?:of|for|to|on)\s+@a|"
                 r"\bsources?\s+(?:\w+\s+){0,3}(?:to|for|of)\s+@a", sk):
        return "clients"
    m = next((m for m in re.finditer(rf"\b(?:{SEND}|{RECV}|{CONNECT}|{TALK})", sk) if not re.fullmatch(
        r"connections?|conversations?|communications?|contacts|transfers?|downloads|uploads|streams?|exchanges?|"
        r"chats?|talks|calls|visits|accesses|interactions?", m.group(0))), None)
    if not m:
        return "any"
    word = m.group(0)
    before = m.start() < sk.find("@a") if "@a" in sk else False
    # "who sent data to @a" (@a receives) vs "where did @a send data" (@a sends).
    obj = before and not subject_first
    if re.fullmatch(SEND, word):
        return "in" if obj else "out"
    if re.fullmatch(RECV, word):
        return "out" if obj else "in"
    if re.fullmatch(CONNECT, word) and not re.match(r"ping", word):
        return "clients" if obj else "servers"
    return "any"


def _about(q: str, parts: list[dict]) -> dict | None:
    """What a question asks, when its shape says (who talked to whom, how much, when, which
    ports, protocols or names, what a host is), or None: then it's a filter or a view.
    Addresses it names become @a (and @b), a domain @d, in the skeleton the rules read."""
    subj = [p for p in parts if p["role"] in ("src", "dst", "addr", "any") and not p["negate"]]
    doms = [p for p in parts if p["role"] == "name" and not p["negate"]]
    sk = q
    marks = sorted([(p, "@a" if i == 0 else "@b") for i, p in enumerate(subj[:2])] +
                   [(p, "@d") for p in doms[:1]] +
                   [(p, "@n") for p in parts if p["role"] in ("src", "dst", "addr", "any") and p["negate"]],
                   key=lambda x: -x[0]["at"])
    for p, mark in marks:
        sk = sk[:p["at"]] + mark + sk[p["at"] + len(p["words"]):]
    sk = TAIL.sub("", FILLER.sub("", sk.strip())).strip()
    sk = WHERE_TAIL.sub("", sk).strip()
    sk = re.sub(r"\b(?:the )?(?:host|ip|ip address|address|device|machine|computer|server|box|node|subnet|network)\s+(@[abn])",
                r"\1", sk)
    sk = re.sub(r"(@[abn])\s+(?:host|ip|address|device|machine|computer|server|box|subnet|network)\b", r"\1", sk)
    a, b, d = "@a" in sk, "@b" in sk, "@d" in sk
    roles = {p["role"] for p in subj[:2]}
    two = (a and b and not (len(roles) == 1 and roles <= {"src", "dst", "any"})) or (a and d and not b)
    has_filter = any(p["role"] not in ("src", "dst", "addr", "any") for p in parts)
    wh = re.search(r"\b(?:who|whom|what|which|where|whose)\b", sk)
    first_a = bool(re.match(r"^(?:\w+\s+){0,2}@a\b", sk)) or bool(re.search(r"\b(?:did|does|has|have|is|was|were|do)\s+@a\b", sk))
    out = {"n": _number(sk), "rank": _rank(sk), "order": "least" if re.search(
        r"\b(?:least|fewest|smallest|lowest|quietest|less|minimum|bottom)\b", sk) else "most", "scope": _scope_words(sk)}

    def kind(name: str, **kw) -> dict:
        return {"kind": name, **out, **kw}

    # What the address (or name) is.
    if d and not a and re.search(
            r"\b(?:ips?|address(?:es)?|ip address(?:es)?)\s+(?:of|for|behind|is|are|does|did|belongs? to|has|uses|was)\s+@d|"
            r"@d(?:'s|s)?\s+(?:ips?|address(?:es)?|ip address(?:es)?)\b|@d\s+(?:resolve[sd]?|resolving|points?|maps?)\b|"
            r"^(?:resolve|look ?up|nslookup|dig)\s+@d$|^(?:what|where|who) (?:is|was) @d$|^@d$|which ips? (?:is|are|was) @d", sk):
        return kind("resolve")
    if a and not b and re.search(
            r"\b(?:countr(?:y|ies)|abroad|overseas|internationa\w*|geo\w*|located|location|city|region|isp|asn?|"
            r"as number|autonomous system|organi[sz]ation|company|hosting provider|provider)\b|"
            r"^where (?:is|was|are) @a(?: (?:located|from|based|hosted|in the world))?$|who (?:owns|hosts|runs|operates) @a", sk):
        return kind("geo", peers=bool(re.search(rf"\b{PEERV}|\bcountries\b", sk)))
    if a and not two and re.search(
            r"^(?:what|who) (?:is|was|are) @a$|^(?:what|how) about @a$|^(?:about )?@a$|^@a\?$|"
            r"\b(?:what|which|who) (?:is|was|are) (?:the |its |their )?(?:os|operating system|vendor|manufacturer|maker|brand|"
            r"mac(?: address)?|hostname|host name|name|role|device(?: type)?|computer name|owner|type|kind|identity)\s+"
            r"(?:of|for|on|behind|at)\s+@a|"
            r"\b(?:tell (?:me|us)|info\w*|details?|profile|summar\w*|describe|overview|look (?:up|into|at)|check (?:on|out)|"
            r"investigate|whois|identify)\s+(?:about |on |of |for |regarding )?@a|"
            r"\b(?:everything|anything|what do (?:you|we) know)\s+(?:about|on|regarding|for)\s+@a|"
            r"\b(?:what|which) (?:kind|type|sort|make|model) of (?:(?:device|host|machine|system|computer|thing|server|box|node|"
            r"endpoint|client|ip|address) )?(?:is|was) @a\b(?! (?:send|receiv|us|talk|do))|^is @a (?:an? )\w+$|"
            r"\b(?:what|which) (?:os|operating system|vendor|manufacturer|maker|brand|mac(?: address)?|hostname|host name|"
            r"name|role|device(?: type)?|computer name)\s+(?:is|does|did|has|for|of|on|belongs to|runs on|is on|is running on|was)?\s*@a|"
            r"@a(?:'s|s)? (?:name|hostname|host name|mac(?: address)?|vendor|manufacturer|os|operating system|role|identity|"
            r"profile|device type)\b|\b(?:what|which) ips? (?:is|has|uses|belongs to|was|goes with)\s+(?:mac(?: address)? )?@a|"
            r"\b(?:what|which) ips? (?:does|did) (?:mac(?: address)? )?@a (?:have|use)\b|"
            r"\bwho (?:owns|uses|is behind|is using) @a|\bwho has @a$|\b(?:what|who) is @a (?:doing|up to|for)\b|"
            r"\bwhat (?:has|is|was|did|does) @a (?:been )?(?:doing|up to|do|done)\b|"
            r"\bwhat(?: is| was)? (?:going on|happening|happened) with @a", sk):
        return kind("identity")
    # Ports and services (a port named by number is a filter, not this).
    if re.search(r"\b(?:ports?|services?|listen\w*|daemons?)\b(?!\s*\d)", sk) and \
            (a or re.search(r"\b(?:what|which|list|show|top|most|any|open|all|busiest|common|popular|how many|used)\b", sk)):
        serves = re.search(r"\blisten\w*|\bopen\b|\brunn?(?:s|ing)?\b|\boffer\w*|\bhost(?:s|ing|ed)\b|\bexpos\w*|\bprovid\w*|"
                           r"\bserv(?:e|es|ed|ing)\b|\bavailable\b|\bon @a\b|\b@a (?:has|have)\b|\bdoes @a have\b", sk)
        uses = re.search(r"\bconnect\w*|\btalk\w*|\breach\w*|\bcontact\w*|\baccess\w*|\bhit\b|\bgo(?:es)? to\b|\bwent to\b|"
                         r"\bdestination\w*|\boutbound\b|\bremote\b", sk)
        return kind("ports", dir="serves" if serves and not uses else "uses" if uses and not serves else "both")
    if re.search(r"\b(?:apps?|applications?|programs? (?:use|used|using)|services? people use)\b|"
                 r"\bwhat(?: is|'s)? (?:using|eating|hogging) (?:up )?(?:the |my |our |all the )?(?:network|bandwidth|internet|data)\b|"
                 r"\b(?:zoom|netflix|youtube|spotify|slack|teams|tiktok|steam|dropbox|windows update)\b(?! (?:from|to) )", sk) and \
            not re.search(r"\bprotocols?\b", sk):
        named = re.search(r"\b(zoom|netflix|youtube|spotify|slack|teams|tiktok|steam|dropbox|windows update)\b", sk)
        return kind("apps", named=named.group(1) if named else None)
    if re.search(r"\b(?:protocols?|(?:kinds?|types?|sorts?) of (?:traffic|data|packets|communication|"
                 r"connections?|stuff))\b", sk) and not re.search(r"\bprotocol (?:\w+ )?(?:analyzer|guide)\b", sk):
        return kind("protocols")
    count = re.search(r"\bhow many\b|\bnumber of\b|\bcount (?:of |the )?|\btotal (?:number|count)\b", sk)
    if count and not a:
        what = "hosts" if re.search(r"\b" + HOSTN + r"\b|\bips\b", sk) else \
            "conversations" if re.search(r"\b(?:conversations?|connections?|sessions?|flows?|streams?)\b", sk) else \
            "names" if re.search(r"\b(?:domains?|domain names|names|sites?|websites?|urls?)\b", sk) else "packets"
        return kind("count", what=what)
    # The names it looked up or visited.
    names_noun = re.search(r"\b(?:domains?|domain names?|websites?|web ?sites?|sites?|urls?|hostnames?|host names|"
                           r"server names|names|dns (?:names|queries|lookups|requests)|snis?|web pages?|pages)\b", sk)
    if (names_noun and not re.search(r"\b(?:who|whom|which (?:\w+ )?" + HOSTN + r")\b(?! (?:is|are) the)", sk)) or \
            (re.search(r"\bwhat\b", sk) and re.search(r"\blook(?:ed|s|ing)? ?up\b|\bresolv\w*|\bbrows\w*|\bvisit\w*|"
                                                     r"\bsurf\w*|\bsearch\w*|\bgoogl\w*", sk) and not re.search(r"\b" + HOSTN + r"\b", sk)):
        return kind("names")
    if two:
        return kind("pair")
    if a and re.match(r"^(?:when|what time|at what time|since when|until when|how long)\b", sk):
        return kind("when")
    if a and (
            (wh and re.search(rf"\b{PEERV}", sk) and not re.search(r"\bhow (?:much|many) (?:\w+ )?(?:data|traffic|bytes|"
                                                                  r"bandwidth|packets|frames)\b", sk)) or
            re.search(rf"@a(?:'s|s)?\s+(?:\w+\s+){{0,3}}{PEERN}\b|\b{PEERN}\s+(?:\w+\s+){{0,3}}(?:of|for|from|with|by|to|"
                      rf"involving|on|about|between)\s+@a|\b(?:top|most|biggest|main|primary|frequent|usual|regular|common|"
                      rf"favou?rite|best) (?:\w+ ){{0,2}}(?:{PEERN}|{HOSTN}|talkers?|buddies|friends)\b|"
                      rf"\b(?:list|show|give|find|get|display|count)(?: me)? (?:all |every |the )?(?:of )?(?:the )?(?:{HOSTN}|"
                      rf"everyone|everything|anyone|anything|everybody|anybody)\b|\b(?:everyone|everything|anyone|anything|"
                      rf"everybody|anybody|somebody|someone|nobody|anywhere|somewhere|where)\b.*\b{PEERV}|\b{PEERV}.*\b(?:everyone|"
                      rf"everything|anyone|anything|everybody|anybody|somebody|someone|anywhere|somewhere)\b|"
                      rf"\bhow many (?:\w+ )?(?:{HOSTN}|{PEERN}|different|unique|distinct)\b|"
                      rf"\b(?:what|which|who) (?:\w+ )?(?:{HOSTN}|{PEERN}) (?:does|did|is|has|have|was|were) @a\b|"
                      rf"\b(?:who|what|which|whom)\b.*@a.*\b(?:the )?(?:most|least)\b", sk)):
        return kind("peers", dir=_direction(sk, first_a))
    if re.search(r"\bhow (?:much|many) (?:\w+ ){0,2}(?:data|traffic|bytes|bandwidth|kb|mb|gb|kilobytes|megabytes|gigabytes|"
                 r"throughput|volume)\b|\bhow (?:much|many) (?:packets|frames)\b|\bhow (?:much|big|large|heavy|busy)\b|"
                 r"\b(?:total|amount|volume|quantity|sum|size) (?:of )?(?:the )?(?:data|traffic|bytes|bandwidth|packets|frames)\b|"
                 r"\bbandwidth (?:used|usage|consumed)\b|\bdata usage\b|\busage (?:of|for|by) @a", sk) and \
            not re.search(r"\bhow many (?:\w+ )?(?:hosts?|devices?|ips?|addresses|machines?|computers?|conversations?|"
                          r"connections?|sessions?|flows?|streams?|domains?|names|sites?|websites?)\b", sk):
        return kind("volume", dir=_direction(sk, first_a) if a else "any") if a or has_filter else kind("capture")
    when = re.search(r"\bwhen\b|\bwhat time\b|\bat what point\b|\bfirst (?:seen|appear\w*|time|packet|contact|show\w* up|"
                     r"activity|talk\w*|connect\w*|heard|noticed|start\w*)|\blast (?:seen|appear\w*|time|packet|contact|"
                     r"activity|active|heard|talk\w*|connect\w*)|\bhow long\b|\bsince when\b|\bstart(?:ed)? (?:time|talking|"
                     r"sending|appearing)|\bend time\b|\bduration\b|\btimeline\b|\bactive (?:for|from|between|during)\b|"
                     r"\b(?:went|go|goes|came|come|comes) (?:quiet|silent|offline|online)\b", sk)
    if when:
        return kind("when") if a or has_filter else kind("capture")
    # The whole capture: the busiest hosts and conversations, counts, an overview.
    if re.search(r"\b(?:biggest|largest|longest|top|busiest|heaviest|most active|main|chattiest)\s+(?:\w+\s+){0,2}"
                 r"(?:conversations?|flows?|connections?|sessions?|streams?|pairs?|transfers?)\b|"
                 r"\b(?:conversations?|flows?|connections?|sessions?|streams?|transfers?)\s+(?:\w+\s+){0,3}(?:the )?"
                 r"(?:most|longest|biggest|largest)\b|\bwhich (?:two |pair of )?(?:\w+ )?" + HOSTN + r"\s+(?:\w+\s+){0,3}"
                 r"(?:each other|together)\b|\b(?:most|longest)[- ]lasting\b|\blasted (?:the )?longest\b|"
                 r"^(?:list|show)(?: me)? (?:the |all )?(?:conversations|flows|connections|sessions)$", sk) and not a:
        return kind("conversations")
    if not a and re.search(
            r"\btop (?:\d+ |\w+ )?(?:talkers?|" + HOSTN + r"|ips|senders?|receivers?|users?|consumers?|uploaders?|downloaders?)\b|"
            r"\b(?:who|whom|whose|which (?:\w+ )?" + HOSTN + r"|what (?:\w+ )?" + HOSTN + r")\b(?: \w+){0,5} (?:the )?"
            r"(?:most|least|more|less|biggest|largest|highest|lowest|heaviest)\b|"
            r"\b(?:busiest|noisiest|chattiest|loudest|heaviest|biggest|largest|most active|least active|most talkative|"
            r"quietest|top|greediest)\s+(?:\w+\s+)?(?:" + HOSTN + r"|talkers?|senders?|receivers?|ips|users?|consumers?)\b|"
            r"\bbandwidth hogs?\b|\bhogg\w*|\btalk\w* (?:the )?(?:most|least)\b|\b(?:most|least) (?:active|chatty|talkative)\b|"
            r"\btalkers?\b", sk):
        return kind("talkers", dir=_direction(sk, False))
    if not a and (has_filter or d) and re.search(
            r"^(?:who|whom|whose)\b|^(?:which|what|list|show|find|name|get|give)(?: me)?(?: the| all| any)? (?:\w+ )?" + HOSTN +
            r"\b|\b(?:anyone|anybody|someone|somebody|any (?:\w+ )?" + HOSTN + r")\b|^(?:does|did|do|is|are|was|were) (?:any|some)",
            sk):
        return kind("hosts")
    if not a and not has_filter and re.search(
            r"^(?:summar\w*|overview|stats|statistics|recap|tl;?dr|breakdown|rundown)\b|\bgive me (?:a |an )?(?:summary|overview|"
            r"rundown|breakdown|recap)|\bwhat(?: is|'s)? (?:in|inside) (?:this|the|my|it)\b|\bwhat does (?:this|the|my|it) "
            r"(?:\w+ )?(?:contain|have|show)|\btell me about (?:this|the|my|it)\b|\bwhat(?: is)? going on\b|\bwhat(?: is)? happening\b|"
            r"\bdescribe (?:this|the|my|it)\b|^(?:capture|pcap|file|trace) (?:summary|overview|info\w*|details|properties|stats)$|"
            r"^how (?:long|big|large) is (?:it|this|the|my)\b", q):
        return kind("capture")
    return None


# What each kind of question opens, and how its summary reads.
def _about_action(about: dict, flt: str) -> dict | None:
    k = about["kind"]
    tool = {"apps": "apps", "peers": "conversations", "pair": "conversations", "conversations": "conversations", "talkers": "endpoints",
            "hosts": "endpoints", "volume": "endpoints", "ports": "endpoints", "protocols": "hierarchy", "names": "dns",
            "when": "io", "geo": "geo", "capture": "properties", "resolve": "dns"}.get(k)
    if k == "identity":
        return {"kind": "view", "view": "host", "addr": about.get("subject")}
    if k == "count":
        tool = {"hosts": "endpoints", "conversations": "conversations", "names": "dns"}.get(about.get("what"), "properties")
    if not tool:
        return None
    return {"kind": "stats", "tool": tool, **({"filter": flt} if flt else {})}


def _about_label(about: dict, labels: list[str]) -> str:
    k, s, o = about["kind"], about.get("subject") or "", about.get("other") or about.get("name") or ""
    least = about["order"] == "least"
    rank = {"bytes": "by data", "packets": "by packets", "connections": "by connections",
            "duration": "by duration"}[about["rank"]]
    timed = about["rank"] == "duration"
    size = ("shortest" if timed else "smallest") if least else "longest" if timed else "biggest"
    what = f" ({', '.join(labels)})" if labels else ""
    if k == "peers":
        d = about.get("dir", "any")
        head = {"any": f"Who {s} talked to", "out": f"Where {s} sent data", "in": f"Who sent data to {s}",
                "servers": f"What {s} connected to", "clients": f"Who connected to {s}"}[d]
        return f"{head}, {'least' if least else 'most'} {rank}{what}"
    if k == "talkers":
        head = {"out": "The hosts that sent the most", "in": "The hosts that received the most"}.get(
            about.get("dir"), "The busiest hosts")
        return (head.replace("most", "least").replace("busiest", "quietest") if least else head) + f" ({rank}){what}"
    return {
        "conversations": f"The {size} conversations{what}",
        "hosts": f"The hosts{what}",
        "pair": f"Traffic between {s} and {o}",
        "identity": f"What {s} is",
        "geo": f"The countries {s} talked to" if about.get("peers") else f"Where {s} is",
        "resolve": f"The addresses of {o}",
        "ports": (f"The ports and services of {s}" if s else "The busiest ports and services") + what,
        "protocols": (f"The protocols {s} used" if s else "The protocols in the capture") + what,
        "apps": (f"The applications {s} used" if s else "The applications on the network") + what,
        "names": (f"The names {s} looked up and visited" if s else "The names looked up and visited most") + what,
        "volume": f"How much traffic {s} sent and received" if s else f"How much traffic{what}",
        "when": f"When {s} was active{what}" if s else f"When it happened{what}",
        "capture": "This capture at a glance",
        "count": f"How many {about.get('what', 'packets')}{what}",
    }.get(k, "")

# ---------------------------------------------------------------- reading a question


def _ip_field(addr: str, role: str) -> str:
    """The filter for one address (or network) in a role: src, dst or addr."""
    try:
        net = ipaddress.ip_network(addr, strict=False)
    except ValueError:
        return f"eth.{role} == {addr.lower()}"  # a MAC address
    family = "ipv6" if net.version == 6 else "ip"
    return f"{family}.{role} == {addr}"


def _clock(m: re.Match, first: float, tz_min: int) -> float | None:
    """A time of day said in the question, as an epoch on the capture's first day (in the
    browser's time zone, which is what the packet list shows)."""
    h, mi, s = int(m.group("h")), int(m.group("mi")), int(m.group("s") or 0)
    ampm = (m.group("ampm") or "").lower()
    if ampm == "pm" and h < 12:
        h += 12
    if ampm == "am" and h == 12:
        h = 0
    if not (0 <= h < 24 and 0 <= mi < 60 and 0 <= s < 60):
        return None
    tz = dt.timezone(dt.timedelta(minutes=-tz_min))
    day = dt.datetime.fromtimestamp(first, tz)
    t = day.replace(hour=h, minute=mi, second=s, microsecond=0).timestamp()
    if t < first - 12 * 3600:  # (a capture that runs past midnight)
        t += 86400
    return t


CLOCK = r"(?P<h>\d{1,2}):(?P<mi>\d{2})(?::(?P<s>\d{2}))?\s*(?P<ampm>am|pm)?"


def parse(question: str, times: dict | None = None, tz_min: int = 0, hosts: dict | None = None) -> dict:
    """Read a question. `times` ({first, last, duration} of the capture) is needed only for
    questions about clock times or "the last N minutes"; without it such a question says so
    in `needs_times`. `hosts` ({name: address}, the names hosts announced) lets a question
    name a host the way the packet list shows it."""
    raw, read_as = _normalize(question)
    q = raw.lower().rstrip("?!. ")
    parts: list[dict] = []   # [{"words", "filter", "label", "negate"}]
    used: list[tuple[int, int]] = []
    needs_times = False

    def taken(a: int, b: int) -> bool:
        return any(a < y and b > x for x, y in used)

    def add(a: int, b: int, flt: str, label: str, role: str = "", **extra) -> None:
        before = q[:a]
        neg = bool(re.search(NEGATE, before[-40:]))
        used.append((a, b))
        parts.append({"words": raw[a:b], "filter": flt, "label": label, "negate": neg, "role": role, "at": a, **extra})

    def address(a: int, b: int, addr: str) -> None:
        before = q[:a][-40:]
        role = "addr" if re.search(ABOUT_WORDS, before) else "src" if re.search(SRC_WORDS, before) else \
            "dst" if re.search(DST_WORDS, before) else "addr"
        prev = next((p for p in reversed(parts) if p.get("addr")), None)
        conj = prev and re.fullmatch(r"\s*(,|or|and|&|/|and/or)\s*(?:the\s+|also\s+)?", q[prev["at"] + len(prev["words"]):a])
        if between and a >= between.start() and b <= between.end():
            role = "addr"
        elif conj:  # "from A or B", "A, B and C": one of them, said once
            role = prev["role"]
            if role in ("addr", "any") and conj.group(1) != "and":
                role = prev["role"] = "any"
                prev["filter"] = _ip_field(prev["addr"], "addr")
        label = f"{'from' if role == 'src' else 'to' if role == 'dst' else 'involving'} {addr}"
        add(a, b, _ip_field(addr, "addr" if role == "any" else role), label, role, addr=addr)

    # Addresses: IPv4 (and networks), IPv6, MAC; who sends and who receives from the words before them.
    addr_re = re.compile(r"(?<![\w:.])(?:(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|"
                         r"[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:/\d{1,3})?)(?::(?P<port>\d{1,5}))?(?![\w:.])")
    between = re.search(r"between\s+(\S+)\s+and\s+(\S+)", q)
    for m in addr_re.finditer(q):
        token = m.group(0)
        port = m.group("port")
        addr = token[: -(len(port) + 1)] if port and token.count(":") == 1 else token
        if port and token.count(":") != 1:
            port = None
            addr = token
        mac = re.fullmatch(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", addr)
        if mac:
            addr = addr.replace("-", ":")
        else:
            try:
                ipaddress.ip_network(addr, strict=False)
            except ValueError:
                continue
        address(m.start(), m.end() - (len(port) + 1 if port else 0), addr)
        if port:
            add(m.end() - len(port) - 1, m.end(), f"tcp.port == {port} || udp.port == {port}", f"port {port}", "port")

    # Hosts by the names they announced ("what did desktop-7h2 talk to").
    for m in re.finditer(r"(?<![\w.-])[a-z0-9][a-z0-9._-]{1,62}[a-z0-9](?![\w-])", q) if hosts else ():
        name = m.group(0)
        if taken(m.start(), m.end()) or name in VOCAB or name in COMMON or not re.search(r"[a-z]", name) or \
                not re.search(r"[\d._-]", name) and len(name) < 5:
            continue
        addr = hosts.get(name)
        if addr:
            address(m.start(), m.end(), addr)

    # Ports said in words.
    for m in re.finditer(r"\bports?\s+(\d{1,5}(?:\s*(?:,|and|or)\s*\d{1,5})*)", q):
        if taken(m.start(), m.end()):
            continue
        ports = [p for p in re.findall(r"\d{1,5}", m.group(1)) if 0 < int(p) < 65536]
        if ports:
            flt = " || ".join(f"tcp.port == {p} || udp.port == {p}" for p in ports) if len(ports) == 1 else \
                f"tcp.port in {{{', '.join(ports)}}} || udp.port in {{{', '.join(ports)}}}"
            add(m.start(), m.end(), flt, f"port {', '.join(ports)}", "port")

    # Domains (and file names, which look like them).
    for m in re.finditer(r"(?<![\w@.-])((?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23})(?![\w.-])", q):
        if taken(m.start(), m.end()):
            continue
        name = m.group(1).lstrip("*.")
        ext = name.rsplit(".", 1)[-1]
        if ext in FILE_EXT:
            add(m.start(), m.end(), f'frame contains "{name}"', f"mentioning {name}", "file")
            continue
        if name in ("e.g", "i.e") or re.fullmatch(r"[\d.]+", name):
            continue
        before = q[: m.start()][-40:]
        role = "dst" if re.search(DST_WORDS, before) else "name"
        flt = (f'dns.qry.name contains "{name}" || tls.handshake.extensions_server_name contains "{name}" || '
               f'http.host contains "{name}"')
        add(m.start(), m.end(), flt, f"{'to ' if role == 'dst' else 'naming '}{name}", "name", name=name)

    # Time: "first/last N minutes", "after N seconds", clock times.
    for m in re.finditer(r"\b(?:in\s+|during\s+)?(?:the\s+)?(first|last|after|before|within)\s+(\d+(?:\.\d+)?)\s*" + UNIT_RE, q):
        if taken(m.start(), m.end()):
            continue
        n = float(m.group(2)) * UNITS[m.group(3)]
        which = m.group(1)
        if which in ("first", "within", "before"):
            add(m.start(), m.end(), f"frame.time_relative <= {n:g}", f"in the first {m.group(2)} {m.group(3)}", "time")
        elif which == "after":
            add(m.start(), m.end(), f"frame.time_relative >= {n:g}", f"after {m.group(2)} {m.group(3)}", "time")
        else:  # last N: from the end of the capture
            if not times:
                needs_times = True
                continue
            start = max(0.0, float(times.get("duration") or 0) - n)
            add(m.start(), m.end(), f"frame.time_relative >= {start:g}", f"in the last {m.group(2)} {m.group(3)}", "time")
    for m in re.finditer(r"\bbetween\s+" + CLOCK + r"\s+and\s+(?P<h2>\d{1,2}):(?P<mi2>\d{2})(?::(?P<s2>\d{2}))?\s*(?P<ampm2>am|pm)?", q):
        if not times:
            needs_times = True
            continue
        a = _clock(m, times["first"], tz_min)
        m2 = re.match(CLOCK, f"{m.group('h2')}:{m.group('mi2')}{':' + m.group('s2') if m.group('s2') else ''} "
                             f"{m.group('ampm2') or m.group('ampm') or ''}".strip())
        b = _clock(m2, times["first"], tz_min) if m2 else None
        if a is not None and b is not None:
            add(m.start(), m.end(), f"frame.time_epoch >= {a:.0f} && frame.time_epoch <= {b:.0f}",
                f"between {m.group(0)[8:].strip()}", "time")
    for m in re.finditer(r"\b(after|since|from|before|until|till|by)\s+" + CLOCK, q):
        if taken(m.start(), m.end()):
            continue
        if not times:
            needs_times = True
            continue
        t = _clock(m, times["first"], tz_min)
        if t is None:
            continue
        op = ">=" if m.group(1) in ("after", "since", "from") else "<="
        add(m.start(), m.end(), f"frame.time_epoch {op} {t:.0f}", m.group(0), "time")

    # Sizes.
    for m in re.finditer(r"\b(?:bigger|larger|more|over|above|longer)\s+than\s+(\d+)\s*(bytes?|kb|k)?\b|"
                         r"\b(?:smaller|less|under|below|shorter)\s+than\s+(\d+)\s*(bytes?|kb|k)?\b", q):
        if taken(m.start(), m.end()):
            continue
        big = m.group(1) is not None
        n = int(m.group(1) or m.group(3)) * (1024 if (m.group(2) or m.group(4) or "").startswith("k") else 1)
        add(m.start(), m.end(), f"frame.len {'>' if big else '<'} {n}", f"{'larger' if big else 'smaller'} than {n} bytes",
            "size")
    m = re.search(r"\b(?:big|large|huge|jumbo) (?:packets?|frames?)", q)
    if m and not taken(m.start(), m.end()):
        add(m.start(), m.end(), "frame.len > 1000", "larger than 1000 bytes", "size")

    # Conditions, then protocols (longest words first, each phrase once).
    for table, role in ((CONDITIONS, "condition"), (PROTOCOLS, "protocol")):
        for pattern, flt, label in table:
            for m in re.finditer(r"(?<![\w.-])(?:" + pattern + r")(?![\w-])", q):
                if not taken(m.start(), m.end()):
                    add(m.start(), m.end(), flt, label, role)

    # What the question is after, when a tool answers it better (words a protocol already
    # took, such as "file" in "file sharing", don't count).
    parts.sort(key=lambda p: p["at"])

    def intent_of(late: bool) -> dict | None:
        for name, pattern, action, label in INTENTS:
            if (name in LATE_INTENTS) != late:
                continue
            m = next((m for m in re.finditer(r"(?<![\w-])(?:" + pattern + r")(?![\w-])", q)
                      if not any(m.start("key" if "key" in m.re.groupindex and m.group("key") else 0) < y and
                                 m.end("key" if "key" in m.re.groupindex and m.group("key") else 0) > x for x, y in used)), None)
            if m:
                return {"name": name, "action": action, "label": label}
        return None

    intent = intent_of(False)
    about = None if intent else _about(q, parts)
    if not intent and not about:
        intent = intent_of(True)
    if about:
        subj = [p for p in parts if p["role"] in ("src", "dst", "addr", "any") and not p["negate"]][:2]
        doms = [p for p in parts if p["role"] == "name" and not p["negate"]]
        if subj:
            about["subject"] = subj[0]["addr"]
            if about["kind"] == "volume" and about.get("dir") == "any" and subj[0]["role"] in ("src", "dst"):
                about["dir"] = "out" if subj[0]["role"] == "src" else "in"  # ("how many packets from X")
        if about["kind"] == "talkers" and about["rank"] == "bytes" and any(p["role"] == "condition" for p in parts):
            about["rank"] = "packets"  # ("the most retransmissions": a count of packets)
        if about["kind"] == "pair" and len(subj) > 1:
            about["other"] = subj[1]["addr"]
        if doms:
            about["name"] = doms[0]["name"]
        # A question about a host is about all its traffic, both ways ("who talked to X":
        # X's conversations); how much it sent keeps the words' direction in the filter.
        whole = [dict(p, role="addr", filter=_ip_field(p["addr"], "addr"), label=f"involving {p['addr']}")
                 if any(p is s for s in subj) and p["role"] != "any" else p for p in parts]
        if about["kind"] not in ("volume", "hosts", "talkers", "conversations", "count"):
            parts = whole
        about["filter"] = _filter_of(whole)
    elif intent:
        # A question a tool answers ("any passwords sent in clear text?") is that tool, not a
        # filter of the words around it, unless it names something to narrow to or asks for packets.
        narrowing = any(p["role"] in ("src", "dst", "addr", "any", "name", "port", "time", "size", "file") for p in parts)
        if not narrowing and not re.search(r"\b(?:packets?|frames?|show me the packets|filter)\b", q):
            parts = []
    plan = _combine(raw, parts, intent, needs_times, about)
    plan["read_as"] = read_as
    return plan


def _group(flt: str) -> str:
    return f"({flt})" if ("||" in flt or "&&" in flt) else flt


def _filter_of(parts: list[dict]) -> str:
    """The parts as one filter: the same kind of thing OR'ed (two protocols, two senders),
    different kinds AND'ed, negated ones as "and not"."""
    groups: dict[str, list[str]] = {}
    negs: list[str] = []
    order: list[str] = []
    for p in parts:
        role = p["role"]
        if p["negate"]:
            negs.append(f"!{_group(p['filter'])}")
            continue
        if role not in groups:
            groups[role] = []
            order.append(role)
        if p["filter"] not in groups[role]:
            groups[role].append(p["filter"])
    clauses = []
    for role in order:
        fl = groups[role]
        if role == "addr" and len(fl) > 1:  # two addresses named: traffic between them
            clauses.append(" && ".join(fl))
        else:
            clauses.append(fl[0] if len(fl) == 1 else " || ".join(_group(f) for f in fl))
    clauses = [_group(c) if len(clauses) + len(negs) > 1 else c for c in clauses] + negs
    return " && ".join(clauses)


def _combine(raw: str, parts: list[dict], intent: dict | None, needs_times: bool, about: dict | None = None) -> dict:
    """The plan: the parts' filter, what opens it, and how the question was read."""
    flt = _filter_of(parts)
    labels = [("not " if p["negate"] else "") + p["label"] for p in parts]
    if about:
        tool = _about_action(about, about["filter"])
        named = (about.get("subject"), about.get("other"))
        rest = [("not " if p["negate"] else "") + p["label"] for p in parts
                if p["negate"] or p["role"] not in ("src", "dst", "addr", "any") or p.get("addr") not in named]
        summary = _about_label(about, rest)
        out_about = {k: v for k, v in about.items() if v is not None}
        return {"question": raw, "understood": True, "filter": flt, "summary": summary,
                "parts": [{"words": p["words"], "filter": p["filter"], "label": p["label"], "negate": p["negate"]}
                          for p in parts],
                "action": {"kind": "packets"} if flt else tool, "also": tool if flt else None,
                "intent": about["kind"], "about": out_about, "needs_times": needs_times, "source": "rules",
                "examples": []}
    action = {"kind": "packets"} if flt else None
    also = None
    if intent and intent["action"]:
        if flt:
            also = intent["action"]  # the packets first; the tool as the other way in
        else:
            action = intent["action"]
    understood = bool(flt or (intent and intent["action"]))
    if flt and intent and intent["action"]:  # ("did 10.0.0.5 send a password?": the logins, its packets)
        summary = f"{intent['label'][0].upper()}{intent['label'][1:]} ({', '.join(labels)})"
    elif flt:
        summary = "Packets: " + ", ".join(labels)
    elif intent:
        summary = intent["label"][0].upper() + intent["label"][1:]
    else:
        summary = ""
    return {"question": raw, "understood": understood, "filter": flt, "summary": summary,
            "parts": [{"words": p["words"], "filter": p["filter"], "label": p["label"], "negate": p["negate"]}
                      for p in parts],
            "action": action, "also": also, "intent": intent["name"] if intent else None,
            "needs_times": needs_times, "source": "rules", "examples": [] if understood else EXAMPLES}


# ---------------------------------------------------------------- asking a model

ASK_SCHEMA = {
    "type": "object",
    "properties": {
        "filter": {"type": "string", "description": "a Wireshark display filter, or empty when a view answers better"},
        "view": {"type": "string", "enum": ["packets", "alerts", "story", "assets", "files", "conversations", "endpoints",
                                            "hierarchy", "io", "dns", "http", "tls", "fingerprints", "logins", "rhythm",
                                            "geo", "expert"]},
        "explanation": {"type": "string", "description": "one sentence: what the filter or view shows"},
    },
    "required": ["filter", "view", "explanation"],
    "additionalProperties": False,
}
STATS_VIEWS = {"conversations", "endpoints", "hierarchy", "io", "dns", "http", "tls", "fingerprints", "logins", "rhythm",
               "geo", "expert"}

ASK_PROMPT = """You translate a network analyst's question about one packet capture into what to look at \
in ANTA, a passive network analyzer that works like Wireshark: a Wireshark display filter, and the view that \
answers best. Use only display filter fields from this list (Wireshark 4.6 syntax, sets as {80, 443}), or an \
empty filter when a view answers the question better (who talked most: conversations; passwords in clear text: \
logins; beacons or timers: rhythm; what happened: story; devices: assets; files: files). Names like \
internal-host-1 stand for addresses on the user's network: write them in the filter exactly where the address \
would go (ip.addr == internal-host-1).

Fields: FIELDS

Answer with only the JSON object."""


def model_prompt(fields: list[str]) -> str:
    return ASK_PROMPT.replace("FIELDS", " ".join(fields))


def model_answer(data: dict) -> dict:
    """A model's answer, checked: a short filter, a known view."""
    if not isinstance(data, dict):
        raise ValueError("not an object")
    flt = str(data.get("filter") or "").strip()[:2000]
    view = str(data.get("view") or "packets")
    if view not in ASK_SCHEMA["properties"]["view"]["enum"]:
        view = "packets"
    if any(c in flt for c in "\x00\r\n"):
        raise ValueError("the filter has control characters")
    action = {"kind": "packets"} if view == "packets" else \
        {"kind": "stats", "tool": view} if view in STATS_VIEWS else {"kind": "view", "view": view}
    return {"filter": flt, "action": action if (flt or view != "packets") else None,
            "also": {"kind": "packets"} if flt and view != "packets" else None,
            "summary": re.sub(r"[\x00-\x1f\x7f]+", " ", str(data.get("explanation") or ""))[:300]}


async def translate_with_model(settings, question: str, fields: list[str]) -> dict:
    """Ask the configured AI model (Claude, OpenAI, Gemini or an OpenAI-compatible server)
    for a filter and view. Only the question is sent, internal addresses replaced with
    pseudonyms unless the user allowed them; the answer's pseudonyms are put back."""
    from .agent import Pseudonyms
    from .agent_providers import ask_model_json
    names = Pseudonyms(not settings.values["share_internal"])
    data = await ask_model_json(settings, model_prompt(fields), names.scrub_text(question[:MAX_QUESTION]), ASK_SCHEMA)
    out = model_answer(data)
    out["filter"] = names.restore(out["filter"])
    out["summary"] = names.restore(out["summary"])
    return out
