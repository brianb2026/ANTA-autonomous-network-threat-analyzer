"""What a downloaded file is, from its first bytes and its name.

Used by the download detector: the bytes are what the file really is, whatever
the URL or Content-Type claim.
"""
from __future__ import annotations

import ipaddress
import re

# (magic prefix as hex, description, kind) - kind: executable, script, installer,
# document, archive or other.
MAGIC = [
    ("4d5a", "Windows executable (PE)", "executable"),
    ("7f454c46", "Linux executable (ELF)", "executable"),
    ("cffaedfe", "macOS executable (Mach-O)", "executable"),
    ("cefaedfe", "macOS executable (Mach-O)", "executable"),
    ("feedfacf", "macOS executable (Mach-O)", "executable"),
    ("feedface", "macOS executable (Mach-O)", "executable"),
    ("cafebabe", "Java class or macOS universal binary", "executable"),
    ("4c0000000114020000000000c000000000000046", "Windows shortcut (LNK)", "script"),
    ("d0cf11e0a1b11ae1", "Office/OLE file (DOC, XLS or MSI)", "document"),
    ("504b0304", "ZIP archive (also JAR, DOCX, XLSX, APK)", "archive"),
    ("526172211a07", "RAR archive", "archive"),
    ("377abcaf271c", "7-Zip archive", "archive"),
    ("4d534346", "Windows cabinet (CAB)", "archive"),
    ("1f8b08", "gzip archive", "archive"),
    ("25504446", "PDF document", "document"),
    ("7b5c727466", "RTF document", "document"),
    ("2321", "script (#!)", "script"),
    ("213c617263683e0a64656269616e", "Debian package (.deb)", "archive"),
    ("213c617263683e0a", "ar archive", "archive"),
    ("edabeedb", "RPM package", "archive"),
    ("78617221", "xar archive (macOS .pkg)", "archive"),
    ("fd377a585a00", "xz archive", "archive"),
    ("425a68", "bzip2 archive", "archive"),
    ("28b52ffd", "Zstandard archive", "archive"),
    ("89504e470d0a1a0a", "PNG image", "other"),
    ("ffd8ff", "JPEG image", "other"),
    ("47494638", "GIF image", "other"),
]

EXEC_EXT = {"exe", "dll", "scr", "cpl", "com", "pif", "sys", "msi", "msix", "appx", "jar", "elf", "so",
            "dylib", "app", "apk"}
SCRIPT_EXT = {"ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "bat", "cmd", "lnk", "sct", "iqy",
              "url", "reg", "sh", "py", "applescript"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "one", "iso", "img", "vhd", "vhdx"}
# Also ordinary web content (pages load JavaScript over HTTP all day): reported only
# when something else about the download is off.
WEAK_EXT = {"js", "url", "py", "sh", "reg", "iqy"}
EXEC_TYPES = {"application/x-msdownload", "application/x-msdos-program", "application/x-dosexec",
              "application/vnd.microsoft.portable-executable", "application/x-executable", "application/octet-stream",
              "application/x-msi", "application/x-ms-installer", "application/java-archive"}
# Command-line and scripting downloaders: how droppers fetch their payloads.
SCRIPTED_AGENTS = re.compile(r"curl|wget|powershell|certutil|bitsadmin|python-requests|python-urllib|go-http-client|"
                             r"libwww-perl|winhttp|aria2|httpie|okhttp|java/|mshta", re.I)


def describe(magic_hex: str) -> tuple[str, str]:
    """(description, kind) of a file from its first bytes."""
    m = (magic_hex or "").lower()
    for prefix, desc, kind in MAGIC:
        if m.startswith(prefix):
            return desc, kind
    return "", "other"


def name_of(uri: str | None, filename: str | None) -> str:
    """The file's name: Content-Disposition first, else the last part of the URL path."""
    if filename:
        return filename.strip().replace("\\", "/").rsplit("/", 1)[-1][:200]
    path = (uri or "").split("?", 1)[0].split("#", 1)[0]
    return path.rstrip("/").rsplit("/", 1)[-1][:200]


def extension(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def is_ip_host(host: str | None) -> bool:
    h = (host or "").strip()
    if h.startswith("["):
        h = h[1:].split("]", 1)[0]
    elif h.count(":") == 1:
        h = h.split(":", 1)[0]
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False
