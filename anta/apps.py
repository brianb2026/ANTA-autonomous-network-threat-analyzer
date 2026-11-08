"""Apps on your network: the capture's connections grouped into the applications people
recognise (Zoom, Slack, Windows Update, Netflix…), with how much each moved, which devices
used it and when, so "what is using my network?" has an answer without reading packets.

A connection is named from what the capture says about its server: the TLS server name, the
HTTP Host, or a name a DNS answer in the capture gave its address; failing those, from its
protocol (SSH, file sharing, DNS…). The catalog below matches names by domain suffix.
"""
from __future__ import annotations

from collections import defaultdict

from . import netmap

# (application, category, domain suffixes)
CATALOG = [
    ("Zoom", "Video calls", ["zoom.us", "zoom.com", "zoomgov.com"]),
    ("Microsoft Teams", "Video calls", ["teams.microsoft.com", "teams.live.com", "skype.com", "lync.com", "teams.cdn.office.net"]),
    ("Google Meet", "Video calls", ["meet.google.com"]),
    ("Webex", "Video calls", ["webex.com", "wbx2.com"]),
    ("Slack", "Messaging", ["slack.com", "slack-edge.com", "slack-msgs.com", "slack-files.com", "slack-imgs.com"]),
    ("Discord", "Messaging", ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"]),
    ("WhatsApp", "Messaging", ["whatsapp.net", "whatsapp.com"]),
    ("Signal", "Messaging", ["signal.org", "whispersystems.org"]),
    ("Telegram", "Messaging", ["telegram.org", "t.me"]),
    ("Microsoft 365", "Email and office", ["outlook.office365.com", "office365.com", "office.com", "office.net", "outlook.com",
                                          "microsoftonline.com", "sharepoint.com", "live.com", "msftauth.net"]),
    ("OneDrive", "Cloud storage", ["onedrive.com", "onedrive.live.com", "1drv.com", "microsoftpersonalcontent.com"]),
    ("Gmail", "Email and office", ["mail.google.com", "imap.gmail.com", "smtp.gmail.com", "gmail.com"]),
    ("Google Docs and Drive", "Cloud storage", ["docs.google.com", "drive.google.com", "googledrive.com"]),
    ("YouTube", "Video streaming", ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "youtube-nocookie.com"]),
    ("Netflix", "Video streaming", ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net", "nflxext.com"]),
    ("Disney+", "Video streaming", ["disneyplus.com", "dssott.com", "bamgrid.com", "disney-plus.net"]),
    ("Prime Video", "Video streaming", ["primevideo.com", "aiv-cdn.net", "aiv-delivery.net", "amazonvideo.com"]),
    ("Twitch", "Video streaming", ["twitch.tv", "ttvnw.net", "jtvnw.net"]),
    ("Spotify", "Music", ["spotify.com", "scdn.co", "spotifycdn.com", "spotifycdn.net"]),
    ("Apple Music and iTunes", "Music", ["itunes.apple.com", "music.apple.com"]),
    ("Windows Update", "Software updates", ["windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com",
                                            "windowsupdate.microsoft.com"]),
    ("Apple software updates", "Software updates", ["swcdn.apple.com", "swscan.apple.com", "mesu.apple.com",
                                                    "updates.cdn-apple.com", "swdist.apple.com"]),
    ("Google software updates", "Software updates", ["dl.google.com", "update.googleapis.com", "edgedl.me.gvt1.com"]),
    ("iCloud", "Cloud storage", ["icloud.com", "icloud-content.com", "apple-cloudkit.com"]),
    ("Apple services", "Operating system", ["apple.com", "mzstatic.com", "apple-dns.net", "aaplimg.com", "push.apple.com"]),
    ("Microsoft services", "Operating system", ["microsoft.com", "msn.com", "bing.com", "windows.com", "msedge.net",
                                                "azureedge.net", "events.data.microsoft.com"]),
    ("Dropbox", "Cloud storage", ["dropbox.com", "dropboxapi.com", "dropboxusercontent.com", "db.tt"]),
    ("Box", "Cloud storage", ["box.com", "boxcdn.net"]),
    ("GitHub", "Developer tools", ["github.com", "githubusercontent.com", "githubassets.com", "github.io"]),
    ("Stack Overflow", "Developer tools", ["stackoverflow.com", "sstatic.net", "stackexchange.com"]),
    ("Python docs and packages", "Developer tools", ["python.org", "pypi.org", "pythonhosted.org"]),
    ("npm and jsDelivr", "Developer tools", ["npmjs.org", "npmjs.com", "jsdelivr.net", "unpkg.com"]),
    ("Atlassian (Jira, Confluence)", "Work apps", ["atlassian.net", "atlassian.com", "jira.com"]),
    ("Asana", "Work apps", ["asana.com"]),
    ("Salesforce", "Work apps", ["salesforce.com", "force.com"]),
    ("Facebook and Messenger", "Social media", ["facebook.com", "fbcdn.net", "messenger.com", "facebook.net"]),
    ("Instagram", "Social media", ["instagram.com", "cdninstagram.com"]),
    ("TikTok", "Social media", ["tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com", "ibytedtos.com"]),
    ("X (Twitter)", "Social media", ["twitter.com", "x.com", "twimg.com", "t.co"]),
    ("Reddit", "Social media", ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"]),
    ("LinkedIn", "Social media", ["linkedin.com", "licdn.com"]),
    ("Steam", "Games", ["steampowered.com", "steamcontent.com", "steamcommunity.com", "steamstatic.com"]),
    ("Xbox", "Games", ["xboxlive.com", "xbox.com"]),
    ("PlayStation", "Games", ["playstation.net", "playstation.com", "sonyentertainmentnetwork.com"]),
    ("Amazon shopping", "Shopping", ["amazon.com", "amazon.co.uk", "amazon.de", "ssl-images-amazon.com", "media-amazon.com"]),
    ("Wikipedia", "Reference", ["wikipedia.org", "wikimedia.org"]),
    ("News sites", "News", ["nytimes.com", "nyt.com", "cnn.com", "bbc.com", "bbc.co.uk", "theguardian.com", "reuters.com",
                            "washingtonpost.com", "ycombinator.com"]),
    ("Google search and services", "Search", ["google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
                                              "1e100.net", "google-analytics.com"]),
    ("Certificate checks", "Operating system", ["ocsp.digicert.com", "ocsp.pki.goog", "ocsp.sectigo.com", "crl.microsoft.com",
                                                "ocsp.apple.com", "r3.o.lencr.org", "ocsp.globalsign.com"]),
    ("Connectivity checks", "Operating system", ["connectivitycheck.gstatic.com", "captive.apple.com", "msftconnecttest.com",
                                                 "msftncsi.com", "detectportal.firefox.com"]),
    ("Amazon Web Services", "Cloud hosting", ["amazonaws.com", "cloudfront.net"]),
    ("Content delivery networks", "Cloud hosting", ["akamaiedge.net", "akamai.net", "akamaihd.net", "fastly.net",
                                                    "cloudflare.com", "edgekey.net", "edgesuite.net"]),
]
# Named by protocol when the server has no name the catalog knows.
PROTOCOL_APPS = {
    "dns": ("DNS", "Network services"), "mdns": ("mDNS (device discovery)", "Network services"),
    "llmnr": ("LLMNR (name lookups)", "Network services"), "nbns": ("NetBIOS names", "Network services"),
    "ssdp": ("UPnP discovery", "Network services"), "dhcp": ("DHCP", "Network services"), "ntp": ("Time sync (NTP)", "Network services"),
    "ssh": ("SSH", "Remote access"), "rdp": ("Remote Desktop", "Remote access"), "telnet": ("Telnet", "Remote access"),
    "vnc": ("VNC", "Remote access"), "smb": ("File sharing (SMB)", "File sharing"), "smb2": ("File sharing (SMB)", "File sharing"),
    "nbss": ("File sharing (SMB)", "File sharing"), "ftp": ("FTP", "File sharing"), "ftp-data": ("FTP", "File sharing"),
    "smtp": ("Email (SMTP)", "Email and office"), "imap": ("Email (IMAP)", "Email and office"), "pop": ("Email (POP)", "Email and office"),
    "ldap": ("Directory (LDAP)", "Network services"), "kerberos": ("Windows sign-in (Kerberos)", "Network services"),
    "dcerpc": ("Windows RPC", "Network services"), "mysql": ("MySQL", "Databases"), "pgsql": ("PostgreSQL", "Databases"),
    "tds": ("SQL Server", "Databases"), "sip": ("Voice calls (SIP)", "Video calls"), "snmp": ("SNMP", "Network services"),
    "quic": ("Other web (QUIC)", "Other web"), "http": ("Other web (HTTP)", "Other web"), "tls": ("Other web (HTTPS)", "Other web"),
}
PORT_APPS = {3478: ("Video calls (STUN/TURN)", "Video calls"), 5223: ("Apple push notifications", "Operating system"),
             9100: ("Printing", "Printing"), 631: ("Printing", "Printing"), 515: ("Printing", "Printing"),
             1194: ("VPN (OpenVPN)", "VPN"), 51820: ("VPN (WireGuard)", "VPN"), 500: ("VPN (IPsec)", "VPN"),
             4500: ("VPN (IPsec)", "VPN"), 8883: ("IoT messaging (MQTT)", "IoT"), 1883: ("IoT messaging (MQTT)", "IoT"),
             5353: ("mDNS (device discovery)", "Network services")}

_SUFFIX = sorted(((suffix, name, cat) for name, cat, suffixes in CATALOG for suffix in suffixes), key=lambda x: -len(x[0]))


def by_name(host: str) -> tuple[str, str] | None:
    """The catalog's application for a server name (the longest matching suffix wins)."""
    h = (host or "").lower().rstrip(".").split(":")[0]
    if not h:
        return None
    for suffix, name, cat in _SUFFIX:
        if h == suffix or h.endswith("." + suffix):
            return name, cat
    return None


def _payload(rec: dict, side: str) -> int:
    return int((rec.get(side) or {}).get("payload_bytes") or 0)


def classify(sessions: list[dict], names: dict[str, str] | None = None) -> dict:
    """{apps: [...], categories: [...], devices: {ip: [...]}}: what each application moved, who used it."""
    names = names or {}
    dns_names: dict[str, list[str]] = defaultdict(list)  # address -> names DNS answers gave it in this capture
    for rec in sessions:
        for q in rec.get("dns") or []:
            qn = str(q.get("qname") or "").lower().rstrip(".")
            for a in q.get("answers") or []:
                if qn and qn not in dns_names[str(a)]:
                    dns_names[str(a)].append(qn)

    apps: dict[str, dict] = {}
    per_device: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(lambda: [0, 0, 0]))  # ip -> app -> [up, down, n]
    for rec in sessions:
        if rec.get("proto") not in ("tcp", "udp"):
            continue
        dst = rec["dst_ip"]
        candidates = []
        tls = rec.get("tls") or {}
        if tls.get("sni"):
            candidates.append(str(tls["sni"]).lower())
        for h in rec.get("http") or []:
            if h.get("host"):
                candidates.append(str(h["host"]).split(":")[0].lower())
        candidates += dns_names.get(dst, [])
        if names.get(dst):
            candidates.append(str(names[dst]).lower())
        found, server_name = None, ""
        for c in candidates:
            found = by_name(c)
            if found:
                server_name = c
                break
        if not found:
            app = (rec.get("app") or "").lower()
            if rec.get("dst_port") in PORT_APPS:
                found = PORT_APPS[rec["dst_port"]]
            elif app in PROTOCOL_APPS:
                found = PROTOCOL_APPS[app]
            else:
                found = (f"Other ({str(rec.get('proto')).upper()} {rec.get('dst_port')})", "Other")
            server_name = candidates[0] if candidates else ""
        name, cat = found
        up, down = _payload(rec, "c2s"), _payload(rec, "s2c")
        a = apps.setdefault(name, {"app": name, "category": cat, "up": 0, "down": 0, "sessions": 0, "devices": defaultdict(int),
                                   "servers": set(), "names": defaultdict(int), "first": rec.get("start") or 0,
                                   "last": rec.get("end") or 0})
        a["up"] += up
        a["down"] += down
        a["sessions"] += 1
        client = rec["src_ip"]
        a["devices"][client] += up + down
        if len(a["servers"]) < 200:
            a["servers"].add(dst)
        if server_name:
            a["names"][server_name] += 1
        a["first"] = min(a["first"], rec.get("start") or a["first"])
        a["last"] = max(a["last"], rec.get("end") or a["last"])
        d = per_device[client][name]
        d[0] += up
        d[1] += down
        d[2] += 1

    out = []
    for a in apps.values():
        devices = sorted(a["devices"].items(), key=lambda kv: -kv[1])
        local = [ip for ip, _ in devices if netmap.scope_of(ip) != "public"]
        servers = sorted(a["servers"])
        v4 = [s for s in servers if ":" not in s][:60]
        v6 = [s for s in servers if ":" in s][:30]
        parts = ([f"ip.addr in {{{', '.join(v4)}}}"] if v4 else []) + ([f"ipv6.addr in {{{', '.join(v6)}}}"] if v6 else [])
        out.append({
            "app": a["app"], "category": a["category"], "bytes": a["up"] + a["down"], "up": a["up"], "down": a["down"],
            "sessions": a["sessions"], "devices": len(devices), "top_devices": [ip for ip, _ in devices[:5]],
            "local_devices": len(local), "names": [n for n, _ in sorted(a["names"].items(), key=lambda kv: -kv[1])[:5]],
            "servers": len(a["servers"]), "first": a["first"], "last": a["last"],
            "filter": " || ".join(parts),
        })
    out.sort(key=lambda r: -r["bytes"])
    cats: dict[str, dict] = {}
    for r in out:
        c = cats.setdefault(r["category"], {"category": r["category"], "bytes": 0, "apps": 0, "sessions": 0})
        c["bytes"] += r["bytes"]
        c["apps"] += 1
        c["sessions"] += r["sessions"]
    devices = {ip: sorted(({"app": n, "category": apps[n]["category"], "up": v[0], "down": v[1], "sessions": v[2]}
                           for n, v in m.items()), key=lambda x: -(x["up"] + x["down"]))[:40]
               for ip, m in per_device.items() if netmap.scope_of(ip) != "public"}
    return {"apps": out, "categories": sorted(cats.values(), key=lambda c: -c["bytes"]), "devices": devices,
            "total": sum(r["bytes"] for r in out)}
