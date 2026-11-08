"""Alert sources the analyst chose to ignore: an address, a network or a MAC address, for
every kind of alert or for one kind (a central router that keeps tripping "Shared Periodic
Traffic", say). An alert is ignored when its source or the device it blames matches a rule;
alerts *to* that address still show.

Ignored alerts are set aside, not deleted: taking the rule off brings them back. The rules
are saved owner-only in the data folder and apply to every capture.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile

from . import paths

MAX_RULES = 200
MAX_NOTE = 200
_MAC = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$")


class IgnoreError(ValueError):
    pass


def path() -> str:
    return os.path.join(paths.app_data_dir(), "ignored-sources.json")


def canonical(source: str) -> str:
    """An address, network (CIDR) or MAC address, written one way; IgnoreError if it is none."""
    text = re.sub(r"\s+", "", str(source or "")).lower()
    if not text:
        raise IgnoreError("give an address, a network (like 10.0.0.0/24) or a MAC address")
    if _MAC.match(text):
        return text.replace("-", ":")
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            return str(net.network_address) if net.num_addresses == 1 else str(net)
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise IgnoreError(f"{source!r} isn't an address, a network (like 10.0.0.0/24) or a MAC address") from None


def clean_rule(rule, kinds) -> dict:
    """One rule as saved: {source, kind ("" = every kind), note}."""
    if isinstance(rule, str):
        rule = {"source": rule}
    if not isinstance(rule, dict):
        raise IgnoreError("each rule is {source, kind, note}")
    kind = str(rule.get("kind") or "")
    if kind and kind not in kinds:
        raise IgnoreError(f"no such kind of alert: {kind!r}")
    note = re.sub(r"[\x00-\x1f\x7f]+", " ", str(rule.get("note") or "")).strip()[:MAX_NOTE]
    return {"source": canonical(rule.get("source")), "kind": kind, "note": note}


def clean(rules, kinds) -> list[dict]:
    if not isinstance(rules, list):
        raise IgnoreError("rules are a list")
    out: list[dict] = []
    seen = set()
    for r in rules[:MAX_RULES]:
        r = clean_rule(r, kinds)
        if (r["source"], r["kind"]) not in seen:
            seen.add((r["source"], r["kind"]))
            out.append(r)
    return out


def load(kinds) -> list[dict]:
    try:
        with open(path(), encoding="utf-8") as fh:
            rules = json.load(fh).get("rules") or []
    except (OSError, ValueError, TypeError, AttributeError):
        return []
    out = []
    for r in rules if isinstance(rules, list) else []:  # (one bad line in a hand-edited file drops only itself)
        try:
            out.append(clean_rule(r, kinds))
        except IgnoreError:
            continue
    return out[:MAX_RULES]


def save(rules, kinds) -> list[dict]:
    rules = clean(rules, kinds)
    directory = os.path.dirname(path())
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".ignored-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"rules": rules}, fh, indent=1)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return rules


class Matcher:
    """Saved rules, ready to test alerts against."""

    def __init__(self, rules: list[dict]):
        self.rules = rules
        self._compiled = []
        for i, r in enumerate(rules):
            src = r["source"]
            net = None if _MAC.match(src) else ipaddress.ip_network(src, strict=False)
            self._compiled.append((i, net, src, r["kind"]))

    def __bool__(self) -> bool:
        return bool(self._compiled)

    def match(self, alert: dict) -> int | None:
        """The index of the first rule that ignores this alert, or None."""
        if not self._compiled:
            return None
        actors = [a for a in (alert.get("src_ip"), alert.get("offender")) if isinstance(a, str) and a]
        if not actors:
            return None
        addrs = []
        for a in actors:
            try:
                addrs.append(ipaddress.ip_address(a))
            except ValueError:
                addrs.append(a.lower())  # (a MAC: the device an ARP alert blames)
        for i, net, src, kind in self._compiled:
            if kind and alert.get("kind") != kind:
                continue
            for a in addrs:
                if (net is not None and not isinstance(a, str) and a.version == net.version and a in net) or a == src:
                    return i
        return None
