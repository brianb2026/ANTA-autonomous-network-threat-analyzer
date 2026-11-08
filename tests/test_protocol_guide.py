"""The protocol guide in Help: every protocol's filter and example filters are filters ANTA
accepts (so "Show its packets" and "Try" always work), and every entry is complete."""
import json
import os
import re
import subprocess

GUIDE = os.path.join(os.path.dirname(__file__), "..", "anta", "web", "protocol-guide.json")


def load():
    with open(GUIDE, encoding="utf-8") as fh:
        return json.load(fh)


def test_every_entry_is_complete():
    g = load()
    cats = {c[0] for c in g["categories"]}
    ids = [p["id"] for p in g["protocols"]]
    assert len(ids) == len(set(ids)) and len(ids) >= 50
    for p in g["protocols"]:
        assert p["cat"] in cats, p["id"]
        for key in ("name", "full", "ports", "filter", "what", "see", "watch"):
            assert isinstance(p[key], str) and p[key].strip(), (p["id"], key)
        assert p["abbrs"] and all(isinstance(a, str) for a in p["abbrs"]), p["id"]
        if p["col"]:
            re.compile(p["col"])
        assert all(len(t) == 2 for t in p["try"]), p["id"]
    assert all(any(p["cat"] == c for p in g["protocols"]) for c in cats)  # (no empty group)


def test_every_filter_is_one_anta_accepts(engine):
    g = load()
    filters = [p["filter"] for p in g["protocols"]] + [t[0] for p in g["protocols"] for t in p["try"]]
    args = [engine]
    for f in filters:
        args += ["--check-filter", f]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    bad = [(r["filter"], r.get("error")) for r in map(json.loads, out.splitlines()) if not r["ok"]]
    assert not bad
