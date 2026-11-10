"""Installed software, read from the outside: which programs and versions each device runs,
from what its own traffic says about itself, and which of them are out of date. Nothing is
installed on the devices and nothing is sent to them.

Where versions come from:
  a client's HTTP User-Agent ("curl/8.4.0", "Firefox/128.0", "Windows NT 6.1", "Debian
  APT-HTTP/1.3 (2.4.11)", "pip/23.3 {... "python":"3.11.6" ...}", "Electron/28.1.0");
  update checks whose address carries a release ("/ubuntu/dists/jammy/", "/debian/dists/
  bookworm/"); a server's Server and X-Powered-By headers ("Apache/2.4.49 (Ubuntu)",
  "PHP/7.4.3"); and greeting lines ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
  "220 (vsFTPd 2.3.4)"). HTTP is read only where it is cleartext or was decrypted with the
  user's own key log.

How "out of date" is judged: a table of end-of-support dates and well-known flawed versions,
as known in 2026, compared with today's date; browsers by how many releases they trail the one
expected at the time of the capture. Distributions backport fixes without changing the version
(Ubuntu's OpenSSH 8.9p1 is patched), so a version with a distribution's suffix is "check", not
"vulnerable". Software can also report a version it isn't (a browser freezes its OS version):
these say what the traffic claims.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from collections import defaultdict

from . import netmap

LOCAL = ("private", "link-local", "cgnat")  # (devices on this network; multicast and broadcast run no software)
TABLE_AS_OF = "2026"
SEVERITY = {"vulnerable": 0, "unsupported": 1, "ending": 2, "old": 3, "check": 4, "ok": 5, "unknown": 6}
STATUS_TEXT = {"vulnerable": "Known flaw", "unsupported": "No longer supported", "ending": "Support ends soon",
               "old": "Out of date", "check": "Check it", "ok": "Current", "unknown": "No information"}
MAX_HOSTS = 2000
MAX_ITEMS = 120  # per host


def _d(s: str) -> dt.date:
    return dt.date.fromisoformat(s)


def vtuple(v: str) -> tuple:
    """"1.0.1f" -> (1, 0, 1, 6); "8.9p1" -> (8, 9, 0, 1); "2.4.52" -> (2, 4, 52)."""
    v = v.strip().lower()
    m = re.match(r"(\d+(?:\.\d+)*)(?:p(\d+))?([a-z])?", v)
    if not m:
        return ()
    nums = [int(x) for x in m.group(1).split(".")]
    if m.group(2):  # OpenSSH portable "p" releases: 8.9p1 -> (8, 9, 0, 1)
        nums += [0] * (3 - len(nums))
        nums.append(int(m.group(2)))
    elif m.group(3):
        nums.append(ord(m.group(3)) - 96)
    return tuple(nums)


def _major(v: str) -> int | None:
    m = re.match(r"(\d+)", v or "")
    return int(m.group(1)) if m else None


# ---------------------------------------------------------------- recognising software

# (pattern on a User-Agent, name, kind); the version is group 1 when there is one.
UA_RULES = [
    (r"\bEdg(?:e|A|iOS)?/(\d[\d.]*)", "Microsoft Edge", "browser"),
    (r"\bOPR/(\d[\d.]*)", "Opera", "browser"),
    (r"\bSamsungBrowser/(\d[\d.]*)", "Samsung Internet", "browser"),
    (r"\bFirefox/(\d[\d.]*)", "Firefox", "browser"),
    (r"\bFxiOS/(\d[\d.]*)", "Firefox", "browser"),
    (r"\bElectron/(\d[\d.]*)", "Electron (app framework)", "library"),
    (r"\b(?:Chrome|CriOS)/(\d[\d.]*)", "Chrome", "browser"),
    (r"\bVersion/(\d[\d.]*)(?: Mobile/\S+)? Safari/", "Safari", "browser"),
    (r"^curl/(\d[\d.]*)", "curl", "tool"),
    (r"\bcurl/(\d[\d.]*)", "curl", "tool"),
    (r"^Wget/(\d[\d.]*)", "Wget", "tool"),
    (r"^python-requests/(\d[\d.]*)", "Python requests", "library"),
    (r"^Python-urllib/(\d[\d.]*)", "Python", "runtime"),
    (r"^Python/(\d[\d.]*)", "Python", "runtime"),
    (r"\bPython/(\d[\d.]*)", "Python", "runtime"),
    (r"^aiohttp/(\d[\d.]*)", "Python aiohttp", "library"),
    (r"^python-httpx/(\d[\d.]*)", "Python httpx", "library"),
    (r"^Go-http-client/(\d[\d.]*)", "Go HTTP client", "library"),
    (r"^okhttp/(\d[\d.]*)", "OkHttp (Android/Java)", "library"),
    (r"^Java/(\d[\d._]*)", "Java", "runtime"),
    (r"^Apache-HttpClient/(\d[\d.]*)", "Apache HttpClient (Java)", "library"),
    (r"^axios/(\d[\d.]*)", "axios (Node.js)", "library"),
    (r"^node-fetch(?:/(\d[\d.]*))?", "node-fetch (Node.js)", "library"),
    (r"^Dalvik/(\d[\d.]*)", "Android runtime (Dalvik/ART)", "runtime"),
    (r"\bWindowsPowerShell/(\d[\d.]*)", "Windows PowerShell", "tool"),
    (r"\bPowerShell/(\d[\d.]*)", "PowerShell", "tool"),
    (r"^Microsoft-CryptoAPI/(\d[\d.]*)", "Windows CryptoAPI (certificate checks)", "system"),
    (r"^Windows-Update-Agent/(\d[\d.]*)", "Windows Update agent", "system"),
    (r"^Microsoft-Delivery-Optimization/(\d[\d.]*)", "Windows Delivery Optimization", "system"),
    (r"^Microsoft BITS/(\d[\d.]*)", "Windows BITS (background downloads)", "system"),
    (r"^Debian APT-HTTP/[\d.]+ \((\d[\d.~a-z]*)\)", "APT (Debian/Ubuntu package manager)", "system"),
    (r"^pip/(\d[\d.]*)", "pip (Python packages)", "tool"),
    (r"^npm/(\d[\d.]*)", "npm (Node.js packages)", "tool"),
    (r"\bnode/v(\d[\d.]*)", "Node.js", "runtime"),
    (r"^Homebrew/(\d[\d.]*)", "Homebrew", "tool"),
    (r"^git/(\d[\d.]*)", "Git", "tool"),
    (r"^libwww-perl/(\d[\d.]*)", "Perl LWP", "library"),
    (r"^Valve/Steam HTTP Client (\d[\d.]*)", "Steam", "app"),
    (r"^Spotify/(\d[\d.]*)", "Spotify", "app"),
    (r"^VLC/(\d[\d.]*)", "VLC", "app"),
    (r"^Microsoft Office/(\d[\d.]*)", "Microsoft Office", "app"),
    (r"^Zoom(?:/| )(\d[\d.]*)?", "Zoom", "app"),
    (r"^Dropbox(?:Desktop)?(?:Client)?/(\d[\d.]*)", "Dropbox", "app"),
    (r"^Transmission/(\d[\d.]*)", "Transmission (BitTorrent)", "app"),
    (r"^qBittorrent/v?(\d[\d.]*)", "qBittorrent (BitTorrent)", "app"),
    (r"^Roku/DVP-(\d[\d.]*)", "Roku OS", "system"),
]
_UA_RULES = [(re.compile(p), name, kind) for p, name, kind in UA_RULES]
# Tokens that are part of every browser's User-Agent, not software of their own.
NOT_PRODUCTS = {"mozilla", "applewebkit", "khtml", "gecko", "safari", "mobile", "version", "like", "chrome", "crios",
                "firefox", "edg", "edge", "opr", "cfnetwork", "darwin", "samsungbrowser", "electron", "windows", "linux"}

WINDOWS_NT = {"5.0": "Windows 2000", "5.1": "Windows XP", "5.2": "Windows XP x64 / Server 2003", "6.0": "Windows Vista",
              "6.1": "Windows 7", "6.2": "Windows 8", "6.3": "Windows 8.1", "10.0": "Windows 10 or 11"}
DARWIN = {19: ("10.15 Catalina", "13"), 20: ("11 Big Sur", "14"), 21: ("12 Monterey", "15"), 22: ("13 Ventura", "16"),
          23: ("14 Sonoma", "17"), 24: ("15 Sequoia", "18"), 25: ("26 Tahoe", "26")}
UBUNTU = {"trusty": "14.04", "xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04", "noble": "24.04",
          "mantic": "23.10", "oracular": "24.10", "plucky": "25.04", "questing": "25.10"}
DEBIAN = {"stretch": "9", "buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13"}


def from_user_agent(ua: str) -> list[tuple[str, str, str, str]]:
    """[(name, version, kind, the text it came from)] from one User-Agent."""
    found: list[tuple[str, str, str, str]] = []
    names: set[str] = set()

    def add(name, version, kind, text):
        if name not in names:
            names.add(name)
            found.append((name, version or "", kind, text))

    ua = ua.strip()[:512]
    browser = None
    electron = "Electron/" in ua
    if electron and (m := re.search(r"\(KHTML, like Gecko\) ([A-Za-z][\w.-]{1,40})/(\d[\w.]*) ", ua)):
        if m.group(1) not in ("Chrome", "Version", "Safari"):
            add(m.group(1), m.group(2), "app", m.group(0).split(") ", 1)[1].strip())
    for rx, name, kind in _UA_RULES:
        m = rx.search(ua)
        if not m:
            continue
        if kind == "browser" and electron:  # (an app built on Electron carries its own Chrome, not a browser)
            continue
        if kind == "browser":
            if browser:  # (a Chrome-based browser says Chrome and Safari too)
                continue
            browser = name
        add(name, m.group(1) if m.groups() else "", kind, m.group(0))
    if name_os := _os_from_ua(ua):
        name, version, kind, text = name_os
        # Safari on iOS 26 and later says "iPhone OS 18_6" whatever the system: its own version is the system's.
        safari = next((f for f in found if f[0] == "Safari"), None)
        if name == "iOS / iPadOS" and version.startswith("18.6") and safari and (_major(safari[1]) or 0) >= 26:
            version = str(_major(safari[1]))
        add(name, version, kind, text)
    # pip says its Python and system in JSON after the version.
    if ua.startswith("pip/") and "{" in ua:
        try:
            info = json.loads(ua[ua.index("{"):])
            if isinstance(info, dict) and isinstance(info.get("python"), str):
                add("Python", info["python"][:20], "runtime", f'"python":"{info["python"][:20]}"')
        except ValueError:
            pass
    # Anything else that names itself Product/version (apps, devices) is kept as it says.
    if not ua.startswith("Mozilla/") and not found:
        m = re.match(r"([A-Za-z][\w .+-]{1,40}?)/v?(\d[\w.]*)", ua)
        if m and m.group(1).lower() not in NOT_PRODUCTS:
            add(m.group(1).strip(), m.group(2), "app", m.group(0))
    return found


def _os_from_ua(ua: str) -> tuple[str, str, str, str] | None:
    if m := re.search(r"Windows NT (\d+\.\d+)", ua):
        return (WINDOWS_NT.get(m.group(1), f"Windows NT {m.group(1)}"), m.group(1), "os", m.group(0))
    if m := re.search(r"(?:iPhone|CPU) OS (\d+)_(\d+)(?:_(\d+))?", ua):
        return ("iOS / iPadOS", ".".join(x for x in m.groups() if x), "os", m.group(0))
    if m := re.search(r"Android (\d+(?:\.\d+)*)(; K\))?", ua):
        return ("Android", "" if m.group(2) else m.group(1), "os", m.group(0))  # ("Android 10; K": Chrome's frozen value)
    if m := re.search(r"Mac OS X (\d+)[_.](\d+)(?:[_.](\d+))?", ua):
        v = ".".join(x for x in m.groups() if x)
        if v == "10.15.7" or tuple(int(x) for x in m.groups() if x) >= (10, 15):
            return ("macOS", "", "os", m.group(0))  # (browsers have frozen this since macOS 11)
        return ("macOS", v, "os", m.group(0))
    if m := re.search(r"\bDarwin/(\d+)\.", ua):
        d = DARWIN.get(int(m.group(1)))
        label = f"Apple OS (Darwin {m.group(1)}: macOS {d[0]} or iOS {d[1]})" if d else f"Apple OS (Darwin {m.group(1)})"
        return (label, m.group(1), "os", m.group(0))
    if m := re.search(r"\bCrOS \S+ (\d[\d.]*)", ua):
        return ("ChromeOS", m.group(1), "os", m.group(0))
    if re.search(r"\bUbuntu\b", ua):
        return ("Ubuntu", "", "os", "Ubuntu")
    return None


def from_uri(host: str, uri: str) -> list[tuple[str, str, str, str]]:
    """A release named in an update check's address."""
    out = []
    path = (uri or "")[:400]
    if m := re.search(r"/dists/([a-z]+)(?:-(?:updates|security|backports|proposed))?/", path):
        code = m.group(1)
        if code in UBUNTU and ("ubuntu" in (host or "") or "/ubuntu" in path):
            out.append(("Ubuntu", UBUNTU[code], "os", f"{host}{path[:60]}"))
        elif code in DEBIAN:
            out.append(("Debian", DEBIAN[code], "os", f"{host}{path[:60]}"))
        elif code in UBUNTU:
            out.append(("Ubuntu", UBUNTU[code], "os", f"{host}{path[:60]}"))
    if m := re.search(r"/update/\d+/(Firefox|Thunderbird)/(\d[\d.]*)/", path):
        out.append((m.group(1), m.group(2), "browser" if m.group(1) == "Firefox" else "app", f"{host}{path[:60]}"))
    return out


SERVER_TOKENS = [
    (r"Apache/(\d[\d.]*)", "Apache HTTP Server"), (r"nginx/(\d[\d.]*)", "nginx"), (r"lighttpd/(\d[\d.]*)", "lighttpd"),
    (r"Microsoft-IIS/(\d[\d.]*)", "Microsoft IIS"), (r"OpenSSL/(\d[\d.]*[a-z]?)", "OpenSSL"), (r"PHP/(\d[\d.]*)", "PHP"),
    (r"Boa/(\d[\d.a-z]*)", "Boa web server"), (r"GoAhead-?Webs?(?:/(\d[\d.]*))?", "GoAhead web server"),
    (r"RomPager/(\d[\d.]*)", "RomPager (embedded web server)"), (r"mini_httpd/(\d[\d.]*)", "mini_httpd"),
    (r"micro_httpd", "micro_httpd"), (r"uhttpd", "uhttpd (OpenWrt)"), (r"Jetty\(?(\d[\d.]*)", "Jetty"),
    (r"Werkzeug/(\d[\d.]*)", "Werkzeug (Python)"), (r"gunicorn(?:/(\d[\d.]*))?", "Gunicorn (Python)"),
    (r"Python/(\d[\d.]*)", "Python"), (r"Kestrel", "Kestrel (.NET)"), (r"Express", "Express (Node.js)"),
    (r"ASP\.NET", "ASP.NET"), (r"Caddy", "Caddy"), (r"(?:CUPS|IPP)/(\d[\d.]*)", "CUPS (printing)"),
    (r"Tomcat/(\d[\d.]*)|Apache-Coyote", "Apache Tomcat"), (r"Node\.js", "Node.js"),
    (r"Synology", "Synology DSM"), (r"Netgear|NETGEAR", "NETGEAR firmware"), (r"Hikvision|DNVRS-Webs", "Hikvision firmware"),
]
_SERVER_TOKENS = [(re.compile(p, re.I), n) for p, n in SERVER_TOKENS]


def from_server_header(text: str) -> list[tuple[str, str, str, str]]:
    out, names = [], set()
    text = (text or "")[:256]
    for rx, name in _SERVER_TOKENS:
        m = rx.search(text)
        if m and name not in names:
            names.add(name)
            version = next((g for g in m.groups() if g), "") if m.groups() else ""
            out.append((name, version, "server", m.group(0)))
    if m := re.search(r"\((Ubuntu|Debian|Red Hat|CentOS|Fedora|Rocky Linux|AlmaLinux|Win64|Win32|Raspbian)\)", text):
        osname = {"Win64": "Windows", "Win32": "Windows"}.get(m.group(1), m.group(1))
        if osname not in names:
            out.append((osname, "", "os", m.group(0)))
    if not out and (m := re.match(r"([A-Za-z][\w.-]{1,40})/v?(\d[\w.]*)", text)):
        out.append((m.group(1), m.group(2), "server", m.group(0)))
    return out


GREETINGS = [
    (r"^SSH-[\d.]+-OpenSSH_for_Windows_(\d[\w.]*)", "OpenSSH for Windows"), (r"^SSH-[\d.]+-OpenSSH_(\d[\w.]*)", "OpenSSH"), (r"^SSH-[\d.]+-dropbear_(\d[\d.]*)", "Dropbear SSH"),
    (r"^SSH-[\d.]+-PuTTY_Release_(\d[\d.]*)", "PuTTY"), (r"^SSH-[\d.]+-libssh2?_(\d[\d.]*)", "libssh"),
    (r"^SSH-[\d.]+-paramiko_(\d[\d.]*)", "Paramiko (Python SSH)"), (r"^SSH-[\d.]+-Cisco-(\d[\d.]*)", "Cisco SSH"),
    (r"^SSH-[\d.]+-(?:ROSSSH|MikroTik)", "MikroTik RouterOS SSH"), (r"^SSH-[\d.]+-Go\b", "Go SSH library"),
    (r"vsFTPd (\d[\d.]*)", "vsftpd"), (r"ProFTPD (\d[\d.a-z]*)", "ProFTPD"), (r"Pure-FTPd", "Pure-FTPd"),
    (r"FileZilla Server (?:version )?(\d[\d.]*)", "FileZilla Server"), (r"Microsoft FTP Service", "Microsoft FTP (IIS)"),
    (r"Postfix", "Postfix (mail)"), (r"Exim (\d[\d.]*)", "Exim (mail)"), (r"Sendmail (\d[\d.]*)", "Sendmail"),
    (r"Microsoft ESMTP MAIL Service", "Microsoft Exchange / IIS SMTP"), (r"Dovecot", "Dovecot (mail)"),
    (r"Courier", "Courier (mail)"), (r"OpenSMTPD", "OpenSMTPD"),
]
_GREETINGS = [(re.compile(p), n) for p, n in GREETINGS]


def from_greeting(line: str) -> list[tuple[str, str, str, str]]:
    out = []
    line = (line or "")[:128]
    for rx, name in _GREETINGS:
        m = rx.search(line)
        if m:
            out.append((name, m.group(1) if m.groups() else "", "server", line[:90]))
            break
    if m := re.search(r"\b(Ubuntu|Debian|Raspbian|FreeBSD)[- ]?(\S*)", line):
        hint = m.group(1)
        detail = m.group(2)
        # OpenSSH's package suffix names the release: "Ubuntu-3ubuntu0.10" is 22.04, "Debian-2+deb12u3" is Debian 12.
        version = ""
        if hint == "Debian" and (d := re.search(r"deb(\d+)u", detail)):
            version = d.group(1)
        if hint == "Ubuntu" and out and out[0][0] == "OpenSSH":
            version = OPENSSH_UBUNTU.get(out[0][1], "")
        out.append((hint, version, "os", line[:90]))
    elif re.search(r"\(Ubuntu\)", line):
        out.append(("Ubuntu", "", "os", line[:90]))
    return out


# OpenSSH's version in each Ubuntu release (the release a banner's "Ubuntu-…" suffix points to).
OPENSSH_UBUNTU = {"6.6.1p1": "14.04", "7.2p2": "16.04", "7.6p1": "18.04", "8.2p1": "20.04", "8.9p1": "22.04", "9.6p1": "24.04",
                  "9.7p1": "24.10", "9.9p1": "25.04"}

# ---------------------------------------------------------------- judging versions

# End of support (the vendor's own last date; extended paid support noted where it exists).
OS_EOL = {
    "Ubuntu": {"14.04": "2019-04-30", "16.04": "2021-04-30", "18.04": "2023-05-31", "20.04": "2025-05-31",
               "22.04": "2027-04-30", "24.04": "2029-04-30", "23.10": "2024-07-11", "24.10": "2025-07-10",
               "25.04": "2026-01-15", "25.10": "2026-07-09"},
    "Debian": {"9": "2022-06-30", "10": "2024-06-30", "11": "2026-08-31", "12": "2028-06-30", "13": "2030-06-30"},
}
UBUNTU_LTS = {"14.04", "16.04", "18.04", "20.04", "22.04", "24.04"}
WINDOWS_EOL = {"5.0": "2010-07-13", "5.1": "2014-04-08", "5.2": "2015-07-14", "6.0": "2017-04-11", "6.1": "2020-01-14",
               "6.2": "2016-01-12", "6.3": "2023-01-10"}
IIS = {"5.0": ("Windows 2000", "2010-07-13"), "5.1": ("Windows XP", "2014-04-08"), "6.0": ("Windows Server 2003", "2015-07-14"),
       "7.0": ("Windows Server 2008", "2020-01-14"), "7.5": ("Windows Server 2008 R2", "2020-01-14"),
       "8.0": ("Windows Server 2012", "2023-10-10"), "8.5": ("Windows Server 2012 R2", "2023-10-10"),
       "10.0": ("Windows Server 2016 or newer", "")}
PHP_EOL = {"5": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01", "7.2": "2020-11-30", "7.3": "2021-12-06",
           "7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31",
           "8.4": "2028-12-31"}
OPENSSL_EOL = {"0.9": "2015-12-31", "1.0": "2019-12-31", "1.1.0": "2019-09-11", "1.1.1": "2023-09-11", "3.0": "2026-09-07",
               "3.1": "2025-03-14", "3.2": "2025-11-23", "3.3": "2026-04-09", "3.4": "2026-10-22", "3.5": "2030-04-08"}
PYTHON_EOL = {"2": "2020-01-01", "3.6": "2021-12-23", "3.7": "2023-06-27", "3.8": "2024-10-07", "3.9": "2025-10-31",
              "3.10": "2026-10-31", "3.11": "2027-10-31", "3.12": "2028-10-31", "3.13": "2029-10-31"}
NODE_EOL = {"12": "2022-04-30", "14": "2023-04-30", "16": "2023-09-11", "18": "2025-04-30", "20": "2026-04-30",
            "22": "2027-04-30", "24": "2028-04-30"}
# Browsers: a known release and the average days between releases, to estimate the version
# current at the time of the capture.
BROWSER_PACE = {"Chrome": (138, "2025-06-24", 31.5), "Microsoft Edge": (138, "2025-06-26", 31.5),
                "Firefox": (140, "2025-06-24", 29.0), "Electron (app framework)": (37, "2025-06-24", 56.0)}
FIREFOX_ESR = {115, 128, 140}


def _eol_verdict(label: str, end: str, today: dt.date, extra: str = "") -> tuple[str, str, str]:
    when = _d(end)
    if when < today:
        return ("unsupported", f"{label} stopped getting security fixes on {when:%B} {when.day}, {when.year}.{extra}",
                "Upgrade to a supported release; it gets no more security fixes.")
    if (when - today).days <= 180:
        return ("ending", f"{label} stops getting security fixes on {when:%B} {when.day}, {when.year}.{extra}",
                "Plan the upgrade before that date.")
    return ("ok", f"{label} is supported until {when:%B %Y}.{extra}", "")


def _branch(table: dict, version: str) -> str | None:
    """The longest key of the table the version starts with ("7.4.33" -> "7.4")."""
    parts = version.split(".")
    for n in range(len(parts), 0, -1):
        key = ".".join(parts[:n])
        if key in table:
            return key
    return None


def judge(name: str, version: str, today: dt.date, captured: dt.date | None = None, seen: dict | None = None,
          backports: bool = False, role: str = "runs") -> tuple[str, str, str]:
    """(status, why, what to do) for one piece of software; role "serves" when it is a server's."""
    v = version or ""
    vt = vtuple(v)
    captured = captured or today
    if name in BROWSER_PACE and vt:
        known, on, pace = BROWSER_PACE[name]
        expected = known + int((captured - _d(on)).days / pace) - 2  # (2 releases of slack: the pace drifts)
        newest = max(expected, (seen or {}).get(name, 0))
        behind = newest - vt[0]
        if name == "Firefox" and vt[0] in FIREFOX_ESR and behind >= 4:
            return ("check", f"Firefox {vt[0]} is behind the newest Firefox, unless it is the Extended Support Release "
                             f"{vt[0]} ESR, which still gets fixes for a while.", "Check whether it's ESR; if not, update Firefox.")
        if behind >= 8:
            return ("unsupported", f"{name} {vt[0]} is about {behind} releases behind the version current when this was "
                                   "captured; old versions get no security fixes.", f"Update {name.split(' (')[0]}.")
        if behind >= 3:
            return ("old", f"{name} {vt[0]} is about {behind} releases behind the version current when this was captured.",
                    f"Update {name.split(' (')[0]}; it normally updates itself, so something may be stopping it.")
        return ("ok", f"{name} {vt[0]} was current or close to it when this was captured.", "")
    if name in ("Ubuntu", "Debian") and v in OS_EOL[name]:
        label = f"{name} {v}" + (" LTS" if name == "Ubuntu" and v in UBUNTU_LTS else "")
        extra = " Ubuntu Pro (Expanded Security Maintenance) can extend an LTS release." if name == "Ubuntu" and v in UBUNTU_LTS else ""
        if name == "Debian" and v in ("11", "12"):
            extra = " (Includes Debian LTS.)"
        return _eol_verdict(label, OS_EOL[name][v], today, extra)
    if name in WINDOWS_NT.values() or name.startswith("Windows NT"):
        nt = next((k for k, n in WINDOWS_NT.items() if n == name), v)
        if nt in WINDOWS_EOL:
            return _eol_verdict(name, WINDOWS_EOL[nt], today)
        if nt == "10.0":
            return ("check", "Windows 10 and 11 both report \"Windows NT 10.0\". Windows 10's support ended on October 14, 2025 "
                             "(paid Extended Security Updates continue for some).",
                    "Check which it is; move Windows 10 machines to Windows 11 or Extended Security Updates.")
    if name == "macOS" and vt:
        if vt < (10, 15):
            return ("unsupported", f"macOS {v} has had no security fixes for years.", "Upgrade macOS or replace the Mac.")
        return ("unknown", "", "")
    if name.startswith("Apple OS (Darwin") and vt:
        if vt[0] <= 22:
            return ("unsupported", f"Darwin {vt[0]} is macOS {DARWIN.get(vt[0], ('13 or older',))[0]} or the iOS of that year; "
                                   "Apple updates only its newest three macOS releases.", "Update the device's system.")
        if vt[0] == 23:
            return ("ending", "Darwin 23 is macOS 14 Sonoma or iOS 17, the oldest releases Apple still updated in 2026.",
                    "Plan the system update.")
        return ("ok", "", "")
    if name == "iOS / iPadOS" and vt:
        if vt[0] <= 15:
            return ("unsupported", f"iOS {vt[0]} gets no regular security fixes.", "Update the device, or replace it if it can't.")
        if vt[0] <= 17:
            return ("old", f"iOS {vt[0]} is behind; Apple fixes the newest release first and older ones only partly.",
                    "Update the device's system.")
        return ("ok", "", "")
    if name == "Android" and vt:
        if vt[0] <= 12:
            return ("unsupported", f"Android {vt[0]} is out of Google's monthly security fixes (they cover the newest releases).",
                    "Update the device if its maker offers it; otherwise it stays exposed.")
        return ("ok", "", "")
    if name == "OpenSSH" and vt:
        if (8, 5, 0, 1) <= vt <= (9, 7, 0, 1) and role == "serves":  # (the flaw is in the server, sshd)
            if backports:
                return ("check", f"OpenSSH {v} is in the range hit by \"regreSSHion\" (CVE-2024-6387, remote code execution on "
                                 "Linux), but the distribution's version suffix means it may carry the fix.",
                        "Install the distribution's updates (apt upgrade) to be sure it's the patched package.")
            return ("vulnerable", f"OpenSSH {v} is in the range hit by \"regreSSHion\" (CVE-2024-6387): an attacker can run "
                                  "code on Linux servers with no login.", "Update to OpenSSH 9.8p1 or newer.")
        if vt < (7, 4):
            return ("old", f"OpenSSH {v} is very old and has many published flaws.", "Update OpenSSH.")
        return ("ok", "", "")
    if name == "Apache HTTP Server" and vt:
        if v in ("2.4.49", "2.4.50"):
            return ("vulnerable", f"Apache {v} has a path traversal flaw (CVE-2021-41773/CVE-2021-42013) attackers use to read "
                                  "files and run code.", "Update to Apache 2.4.51 or newer at once.")
        if vt < (2, 4):
            return ("unsupported", f"Apache {v} is from a release line the Apache project ended in 2017.", "Move to Apache 2.4.")
        if backports:
            return ("check", "Distributions patch Apache without changing its version.", "Keep the distribution's updates installed.")
        return ("ok", "", "")
    if name == "nginx" and vt:
        if vt < (1, 26):
            note = " Distributions patch it without changing the version." if backports else ""
            return ("check" if backports else "old", f"nginx {v} is from a release line nginx no longer maintains.{note}",
                    "Update nginx (or keep the distribution's updates installed).")
        return ("ok", "", "")
    if name == "Microsoft IIS" and v in IIS:
        system, end = IIS[v]
        if v == "6.0":
            return ("vulnerable", "IIS 6.0 is Windows Server 2003 (no fixes since 2015), with a known WebDAV flaw attackers use "
                                  "(CVE-2017-7269).", "Replace the server.")
        if end:
            return _eol_verdict(f"IIS {v} ({system})", end, today)
        return ("check", "IIS 10.0 is Windows Server 2016 or newer; Server 2016's support ends January 12, 2027.",
                "Check which Windows Server it is.")
    if name == "PHP" and vt:
        key = "5" if vt[0] <= 5 else _branch(PHP_EOL, v)
        if key:
            return _eol_verdict(f"PHP {key if key != '5' else v}", PHP_EOL[key], today,
                                " Distributions may patch it longer." if backports else "")
    if name == "OpenSSL" and vt:
        if vt[:3] == (1, 0, 1) and (len(vt) == 3 or vt[3] <= 6):
            return ("vulnerable", f"OpenSSL {v} has Heartbleed (CVE-2014-0160): the server's memory, keys and passwords leak.",
                    "Update OpenSSL, then replace the server's keys and certificates.")
        key = _branch(OPENSSL_EOL, v)
        if key:
            return _eol_verdict(f"OpenSSL {key}", OPENSSL_EOL[key], today, " Distributions may patch it longer." if backports else "")
    if name == "vsftpd" and v == "2.3.4":
        return ("vulnerable", "vsftpd 2.3.4 is the release that shipped with a backdoor (CVE-2011-2523).", "Replace it at once.")
    if name == "ProFTPD" and v.lower() == "1.3.5":
        return ("vulnerable", "ProFTPD 1.3.5 lets anyone copy files on the server (mod_copy, CVE-2015-3306).", "Update ProFTPD.")
    if name.startswith("RomPager") and vt and vt < (4, 34):
        return ("vulnerable", f"RomPager {v} has the \"Misfortune Cookie\" flaw (CVE-2014-9222) that takes over routers.",
                "Update the device's firmware, or replace the device.")
    if name == "Boa web server":
        return ("unsupported", "The Boa web server hasn't been maintained since 2005; devices still using it rarely get fixes.",
                "Update the device's firmware, or replace it.")
    if name == "Exim (mail)" and vt and (4, 87) <= vt < (4, 92):
        return ("vulnerable", f"Exim {v} lets attackers run commands (CVE-2019-10149).", "Update Exim.")
    if name == "curl" and vt and (7, 69) <= vt <= (8, 3):
        return ("check", f"curl {v} has a SOCKS5 proxy flaw (CVE-2023-38545); it matters only when it uses a SOCKS5 proxy.",
                "Update curl to 8.4.0 or newer.")
    if name == "Python" and vt:
        key = "2" if vt[0] == 2 else _branch(PYTHON_EOL, ".".join(map(str, vt[:2])))
        if key:
            return _eol_verdict(f"Python {key if key != '2' else '2'}", PYTHON_EOL[key], today)
    if name == "Node.js" and vt:
        key = str(vt[0]) if str(vt[0]) in NODE_EOL else None
        if key:
            return _eol_verdict(f"Node.js {key}", NODE_EOL[key], today)
    if name == "Java" and v.startswith(("1.6", "1.7", "1.5")):
        return ("unsupported", f"Java {v[:3]} gets no public security fixes.", "Move to a supported Java (17 or 21).")
    return ("unknown", "", "")


# ---------------------------------------------------------------- the inventory


def _filter_for(ip: str, how: str, text: str, port: int | None) -> str:
    v = "ipv6" if ":" in ip else "ip"
    t = text.replace("\\", "").replace('"', "")[:80]
    if how == "ua":
        return f'{v}.addr == {ip} && http.user_agent contains "{t}"'
    if how == "uri":
        return f'{v}.addr == {ip} && http.request.uri contains "{t}"'
    if how == "server":
        return f'{v}.addr == {ip} && http.server contains "{t}"'
    if how == "ssh":
        return f'{v}.addr == {ip} && ssh.protocol contains "{t}"'
    return f"{v}.addr == {ip} && tcp.port == {port}" if port else f"{v}.addr == {ip}"


def inventory(sessions: list[dict], scope_of=None, today: dt.date | None = None) -> dict:
    """Every device's software as its traffic reports it, each judged against the table."""
    scope_of = scope_of or netmap.scope_of
    today = today or dt.date.today()
    hosts: dict[str, dict[tuple, dict]] = defaultdict(dict)

    def note(ip, name, version, kind, text, how, s, port=None, role="runs", match=None):
        if not ip or len(hosts) >= MAX_HOSTS and ip not in hosts:
            return
        items = hosts[ip]
        key = (name, version)
        it = items.get(key)
        if it is None:
            if len(items) >= MAX_ITEMS:
                return
            # The same program with no version adds nothing once a version is known.
            if not version and any(k[0] == name for k in items):
                return
            for k in [k for k in items if k[0] == name and not k[1] and version]:
                del items[k]
            it = items[key] = {"name": name, "version": version, "kind": kind, "evidence": text[:120], "how": how,
                               "role": role, "count": 0, "first": s.get("start") or 0, "last": s.get("end") or 0,
                               "filter": _filter_for(ip, how, match if match is not None else text, port),
                               "backports": False}
        it["count"] += 1
        if role == "serves":  # (the same program as a server is judged as one: its flaws are a server's)
            it["role"] = "serves"
        it["first"] = min(it["first"], s.get("start") or it["first"])
        it["last"] = max(it["last"], s.get("end") or 0)
        if how in ("ssh", "greeting", "server") and re.search(r"ubuntu|debian|deb\d+u|\+deb|el\d|fc\d|raspbian", text, re.I):
            it["backports"] = True

    for s in sessions:
        src, dst = s.get("src_ip"), s.get("dst_ip")
        for h in (s.get("http") or []) + (s.get("http_files") or []):
            ua = h.get("user_agent") or ""
            if ua:
                for name, ver, kind, text in from_user_agent(ua):
                    # (the filter matches the User-Agent text, which can't hold a quote for the filter language)
                    note(src, name, ver, kind, text, "ua", s, match=text if '"' not in text else ua.split(" ", 1)[0].split('"')[0])
            if h.get("uri"):
                for name, ver, kind, text in from_uri(str(h.get("host") or ""), str(h["uri"])):
                    path = str(h["uri"])
                    note(src, name, ver, kind, text, "uri", s, match=path[:path.find("/", path.find("/dists/") + 7) + 1]
                         if "/dists/" in path else path[:60])
        resp = s.get("http_response") or {}
        for field in ("server", "powered_by"):
            if resp.get(field):
                for name, ver, kind, text in from_server_header(str(resp[field])):
                    note(dst, name, ver, kind, text, "server" if field == "server" else "port", s, s.get("dst_port"), "serves")
        banner = s.get("banner") or {}
        for side, ip, role in (("server", dst, "serves"), ("client", src, "runs")):
            line = banner.get(side)
            if not line:
                continue
            for name, ver, kind, text in from_greeting(line):
                how = "ssh" if line.startswith("SSH-") else "greeting"
                note(ip, name, ver, kind, line[:60] if how == "ssh" else text, how, s, s.get("dst_port"), role)

    # The newest version of each browser anyone here runs: a device far behind its neighbours is behind.
    seen: dict[str, int] = {}
    for items in hosts.values():
        for it in items.values():
            if it["name"] in BROWSER_PACE and (m := _major(it["version"])):
                seen[it["name"]] = max(seen.get(it["name"], 0), m)
    out_hosts = []
    totals: dict[str, int] = defaultdict(int)
    for ip, items in hosts.items():
        scope = scope_of(ip)
        local = scope in LOCAL
        rows = []
        for it in items.values():
            captured = dt.date.fromtimestamp(it["first"]) if it["first"] else today
            status, why, advice = judge(it["name"], it["version"], today, captured, seen, it.pop("backports"), it["role"])
            it.update(status=status, status_text=STATUS_TEXT[status], why=why, advice=advice)
            rows.append(it)
        rows.sort(key=lambda r: (SEVERITY[r["status"]], {"os": 0, "server": 1, "browser": 2}.get(r["kind"], 3), r["name"]))
        worst = rows[0]["status"] if rows else "unknown"
        if local:
            for r in rows:
                totals[r["status"]] += 1
        out_hosts.append({"ip": ip, "scope": scope, "local": local, "software": rows, "worst": worst,
                          "problems": sum(1 for r in rows if SEVERITY[r["status"]] <= SEVERITY["old"])})
    out_hosts.sort(key=lambda h: (not h["local"], SEVERITY[h["worst"]], -h["problems"], h["ip"]))
    return {"hosts": out_hosts, "totals": dict(totals), "table_as_of": TABLE_AS_OF, "today": today.isoformat(),
            "local_hosts": sum(1 for h in out_hosts if h["local"]),
            "notes": ["Versions are what the traffic claims; software can report a version it isn't.",
                      "Distributions (Ubuntu, Debian, Red Hat) patch flaws without changing the version, so those say "
                      "\"Check it\" rather than \"Known flaw\".",
                      f"The end-of-support table is as known in {TABLE_AS_OF}; check the vendor before acting on a date.",
                      "Encrypted connections (HTTPS) hide their User-Agents unless decrypted with your own key log."]}
