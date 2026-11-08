"""The protocol spell-checker: each rule is a display filter the engine counts in one pass; a lab
capture breaks most of them once, and ordinary traffic breaks none."""
import asyncio
import json
import os

import pytest

from anta import lint
from anta.tools import samples
from conftest import run_engine
from test_server import AUTH, make_client


def test_the_catalog_is_sound(engine):
    ids = [r.id for r in lint.RULES]
    assert len(ids) == len(set(ids)) and len(ids) >= 25
    for r in lint.RULES:
        assert r.severity in lint.SEVERITIES and r.title and r.why and ("RFC" in r.rule or "Microsoft" in r.rule)
        check = run_engine(engine, "--check-filter", r.filter)
        assert check and check[0]["ok"], (r.id, check)


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    path = tmp_path_factory.mktemp("lint") / "lab.pcap"
    samples.write_pcap(str(path), samples.lint_lab())
    return str(path)


def counts(engine, path):
    args = ["--stats", "-r", path]
    for f in lint.filters():
        args += ["--count-filter", f]
    return next(r for r in run_engine(engine, *args) if r.get("type") == "stats")["counts"]


def test_the_lab_breaks_the_rules_it_was_built_to_break(engine, lab):
    rep = lint.report(counts(engine, lab))
    broken = {e["id"]: e for e in rep["broken"]}
    assert set(broken) == {"tcp-syn-fin", "tcp-syn-rst", "tcp-null", "tcp-xmas", "port-zero", "tcp-mss-not-syn",
                           "tcp-reserved-bits", "ip-reserved-bit", "ip-ttl-zero", "ip-bad-source", "dns-z-bit", "dns-qdcount", "http-no-host",
                           "http-cl-te", "http-status-range", "tls-sni-ip"}
    assert broken["ip-ttl-zero"]["count"] == 1 and broken["ip-ttl-zero"]["frames"] == [9]
    assert broken["http-cl-te"]["rule"].startswith("RFC 9112 §6.1") and "smuggling" in broken["http-cl-te"]["why"]
    assert [e["severity"] for e in rep["broken"]] == sorted((e["severity"] for e in rep["broken"]), key=lint.SEVERITIES.index)
    assert rep["checked"] == len(lint.RULES) and len(rep["passed"]) == len(lint.RULES) - len(broken)
    assert rep["packets"] == sum(e["count"] for e in rep["broken"])


def test_ordinary_traffic_breaks_nothing(engine, data_dir):
    rep = lint.report(counts(engine, os.path.join(data_dir, "http_download.pcap")))
    assert rep["broken"] == []


def test_the_engine_counts_many_filters_in_one_pass(engine, lab):
    got = counts(engine, lab)
    assert len(got) == len(lint.RULES) and all(set(c) == {"count", "frames"} for c in got)
    assert run_engine(engine, "--stats", "-r", lab, "--count-filter", "tcp.flags.res > 0")[-1]["counts"][0]["count"] == 1


def test_the_lint_endpoint(engine, lab):
    async def go():
        dash, c = await make_client()
        try:
            dash.packets.reset(lab)
            d = await (await c.get("/api/lint", headers=AUTH)).json()
            assert len(d["broken"]) == 16
            only = await (await c.get("/api/lint?dfilter=udp", headers=AUTH)).json()  # (limited like the statistics)
            assert {e["id"] for e in only["broken"]} == {"ip-reserved-bit", "ip-ttl-zero", "ip-bad-source", "dns-z-bit",
                                                         "dns-qdcount"}
            assert (await c.get("/api/lint")).status == 401
        finally:
            await c.close()
    asyncio.run(go())
    nothing = lint.report([])  # (no counts: everything passes, nothing breaks)
    assert nothing["broken"] == [] and len(nothing["passed"]) == len(lint.RULES) and json.dumps(nothing)
