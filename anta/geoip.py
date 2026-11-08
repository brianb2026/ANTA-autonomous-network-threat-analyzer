"""Offline country and autonomous-system (AS) lookup.

The data is iptoasn.com's ip2asn table (public domain, PDDL): every routed IPv4 and
IPv6 range with the AS announcing it, that AS's registered country and its name.
A copy ships with ANTA (anta/geo/ip2asn-combined.tsv.gz); a newer one downloaded
from Settings is kept in the data folder and used instead. Lookups never leave the
computer. The country is where the network's operator is registered, which for
cloud and CDN ranges is not necessarily where the server stands.
"""
from __future__ import annotations

import bisect
import gzip
import os
import socket
import threading
import time

import numpy as np

from . import paths

FILE_NAME = "ip2asn-combined.tsv.gz"
SOURCE_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
MAX_DOWNLOAD = 64 * 1024 * 1024

COUNTRY_NAMES = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan", "AL": "Albania", "AM": "Armenia",
    "AO": "Angola", "AR": "Argentina", "AT": "Austria", "AU": "Australia", "AZ": "Azerbaijan", "BA": "Bosnia",
    "BD": "Bangladesh", "BE": "Belgium", "BG": "Bulgaria", "BH": "Bahrain", "BO": "Bolivia", "BR": "Brazil",
    "BY": "Belarus", "BZ": "Belize", "CA": "Canada", "CH": "Switzerland", "CL": "Chile", "CN": "China",
    "CO": "Colombia", "CR": "Costa Rica", "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany", "DK": "Denmark",
    "DO": "Dominican Republic", "DZ": "Algeria", "EC": "Ecuador", "EE": "Estonia", "EG": "Egypt", "ES": "Spain",
    "FI": "Finland", "FR": "France", "GB": "United Kingdom", "GE": "Georgia", "GH": "Ghana", "GR": "Greece",
    "GT": "Guatemala", "HK": "Hong Kong", "HN": "Honduras", "HR": "Croatia", "HU": "Hungary", "ID": "Indonesia",
    "IE": "Ireland", "IL": "Israel", "IN": "India", "IQ": "Iraq", "IR": "Iran", "IS": "Iceland", "IT": "Italy",
    "JM": "Jamaica", "JO": "Jordan", "JP": "Japan", "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia",
    "KP": "North Korea", "KR": "South Korea", "KW": "Kuwait", "KZ": "Kazakhstan", "LA": "Laos", "LB": "Lebanon",
    "LK": "Sri Lanka", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia", "LY": "Libya", "MA": "Morocco",
    "MD": "Moldova", "ME": "Montenegro", "MK": "North Macedonia", "MM": "Myanmar", "MN": "Mongolia", "MT": "Malta",
    "MX": "Mexico", "MY": "Malaysia", "NG": "Nigeria", "NI": "Nicaragua", "NL": "Netherlands", "NO": "Norway",
    "NP": "Nepal", "NZ": "New Zealand", "OM": "Oman", "PA": "Panama", "PE": "Peru", "PH": "Philippines",
    "PK": "Pakistan", "PL": "Poland", "PR": "Puerto Rico", "PT": "Portugal", "PY": "Paraguay", "QA": "Qatar",
    "RO": "Romania", "RS": "Serbia", "RU": "Russia", "SA": "Saudi Arabia", "SC": "Seychelles", "SE": "Sweden",
    "SG": "Singapore", "SI": "Slovenia", "SK": "Slovakia", "SY": "Syria", "TH": "Thailand", "TJ": "Tajikistan",
    "TM": "Turkmenistan", "TN": "Tunisia", "TR": "Türkiye", "TW": "Taiwan", "TZ": "Tanzania", "UA": "Ukraine",
    "UG": "Uganda", "US": "United States", "UY": "Uruguay", "UZ": "Uzbekistan", "VE": "Venezuela", "VG": "British Virgin Islands",
    "VN": "Vietnam", "YE": "Yemen", "ZA": "South Africa", "ZM": "Zambia", "ZW": "Zimbabwe", "EU": "European Union",
}


def bundled_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "geo", FILE_NAME)


def user_path() -> str:
    return os.path.join(paths.app_data_dir(), "geo", FILE_NAME)


def country_name(code: str | None) -> str:
    return COUNTRY_NAMES.get(code or "", code or "")


class GeoDB:
    """Range lookups over the ip2asn table, loaded once in the background."""

    def __init__(self, path: str | None = None):
        self.path = path
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._loading = False
        self.error: str | None = None
        self.records: list[tuple[int, str, str]] = []   # (asn, country, AS name)
        self.v4_start = self.v4_end = self.v4_rec = None
        self.v6_start: list[int] = []
        self.v6_end: list[int] = []
        self.v6_rec: list[int] = []
        self.rows = 0
        self.loaded_at = 0.0

    def source(self) -> str | None:
        if self.path:
            return self.path
        for p in (user_path(), bundled_path()):
            if os.path.exists(p):
                return p
        return None

    def info(self) -> dict:
        src = self.source()
        st = os.stat(src) if src and os.path.exists(src) else None
        return {"available": bool(src), "loaded": self._ready.is_set() and not self.error, "error": self.error,
                "path": src, "bundled": src == bundled_path(), "rows": self.rows,
                "file_date": st.st_mtime if st else None, "source_url": SOURCE_URL}

    def start(self) -> None:
        """Load in a background thread (about a second), so the first lookups don't wait."""
        with self._lock:
            if self._loading or self._ready.is_set():
                return
            self._loading = True
        threading.Thread(target=self._load, name="anta-geoip", daemon=True).start()

    def reload(self) -> None:
        with self._lock:
            self._ready.clear()
            self._loading = False
        self.start()

    def _load(self) -> None:
        src = self.source()
        try:
            if not src:
                raise FileNotFoundError("no GeoIP database")
            records: dict[tuple, int] = {}
            v4s, v4e, v4r, v6s, v6e, v6r = [], [], [], [], [], []
            inet4 = socket.inet_aton
            with gzip.open(src, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.rstrip("\n").split("\t", 4)
                    if len(parts) != 5 or parts[2] == "0":
                        continue  # "Not routed"
                    a, b, asn, cc, name = parts
                    key = (int(asn), cc if cc != "None" else "", name[:120])
                    idx = records.setdefault(key, len(records))
                    if ":" in a:
                        v6s.append(int.from_bytes(socket.inet_pton(socket.AF_INET6, a), "big"))
                        v6e.append(int.from_bytes(socket.inet_pton(socket.AF_INET6, b), "big"))
                        v6r.append(idx)
                    else:
                        v4s.append(int.from_bytes(inet4(a), "big"))
                        v4e.append(int.from_bytes(inet4(b), "big"))
                        v4r.append(idx)
            order = np.argsort(np.array(v4s, dtype=np.uint32), kind="stable")
            self.v4_start = np.array(v4s, dtype=np.uint32)[order]
            self.v4_end = np.array(v4e, dtype=np.uint32)[order]
            self.v4_rec = np.array(v4r, dtype=np.int32)[order]
            pairs = sorted(zip(v6s, v6e, v6r, strict=True))
            self.v6_start = [p[0] for p in pairs]
            self.v6_end = [p[1] for p in pairs]
            self.v6_rec = [p[2] for p in pairs]
            self.records = [None] * len(records)  # type: ignore[list-item]
            for key, i in records.items():
                self.records[i] = key
            self.rows = len(v4s) + len(v6s)
            self.error = None
            self.loaded_at = time.time()
        except Exception as exc:  # a missing or broken file leaves lookups empty, never fails a request
            self.error = str(exc)
        finally:
            self._ready.set()

    def wait(self, timeout: float = 30) -> bool:
        self.start()
        return self._ready.wait(timeout) and not self.error

    def lookup(self, ip: str) -> dict | None:
        """{"country", "country_name", "asn", "as_name"} for a public address, else None."""
        if not self._ready.is_set():
            self.start()
            return None
        if self.error:
            return None
        try:
            if ":" in ip:
                n = int.from_bytes(socket.inet_pton(socket.AF_INET6, ip), "big")
                i = bisect.bisect_right(self.v6_start, n) - 1
                if i < 0 or n > self.v6_end[i]:
                    return None
                rec = self.records[self.v6_rec[i]]
            else:
                n = int.from_bytes(socket.inet_aton(ip), "big")
                if self.v4_start is None or not len(self.v4_start):
                    return None
                i = int(np.searchsorted(self.v4_start, np.uint32(n), side="right")) - 1
                if i < 0 or n > int(self.v4_end[i]):
                    return None
                rec = self.records[int(self.v4_rec[i])]
        except (OSError, ValueError):
            return None
        asn, cc, name = rec
        return {"country": cc, "country_name": country_name(cc), "asn": asn, "as_name": name}


_default: GeoDB | None = None


def default() -> GeoDB:
    global _default
    if _default is None:
        _default = GeoDB()
    return _default
