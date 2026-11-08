"""Python analytics: features, detectors, explanations, validation, stdin ingestion."""
import json
import os
import random
import subprocess
import sys

import pytest

from anta.analyzer import Analyzer, Config
from anta.features import registered_domain, shannon_entropy, string_entropy
from conftest import (ATTACKER_HOSTS, C2_FIXED, C2_JITTER, C2_KEEPALIVE, EXFIL_DST, MODELS, ROOT, run_engine,
                      sessions)


def model_or_none():
    from anta.model import AnomalyModel
    return AnomalyModel(MODELS) if AnomalyModel.available(MODELS) else None


def analyze(records, config=None):
    a = Analyzer(model_or_none(), config)
    for rec in records:
        a.ingest(rec)
    return a


def by_kind(analyzer, kind):
    return [x for x in analyzer.alerts.values() if x["kind"] == kind]


def test_entropy_basics():
    assert shannon_entropy([]) == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abab") == pytest.approx(1.0)
    assert string_entropy("abcdefgh") == pytest.approx(3.0)
    assert registered_domain("a.b.exfil-cdn.net") == "exfil-cdn.net"
    assert registered_domain("www.bbc.co.uk") == "bbc.co.uk"


@pytest.fixture(scope="module")
def demo(demo_records):
    return analyze(demo_records)


def test_detects_c2_beacon_with_spec_sentence(demo):
    beacons = {b["dst_ip"]: b for b in by_kind(demo, "beacon")}
    b = beacons[C2_FIXED]
    assert b["headline"].startswith(f"High-confidence automated beaconing detected to {C2_FIXED}:443.")
    assert "every exactly 4.2 seconds with < 1% variance" in b["headline"]
    assert b["severity"] == "critical" and b["export_flows"] > 100
    assert b["stream"]["ja3"] and "update.cdn-telemetry.net" in b["stream"]["dns_context"]


def test_detects_jittered_beacon(demo):
    """Cobalt-Strike-style sleep with ±20% random jitter still scores as a beacon."""
    (b,) = [x for x in by_kind(demo, "beacon") if x["dst_ip"] == C2_JITTER]
    assert "symmetric jitter" in b["headline"] and 15 <= b["metrics"]["jitter_pct"] <= 25
    assert 22 <= b["metrics"]["period"] <= 28


def test_detects_persistent_connection_beacon(demo):
    (b,) = [x for x in by_kind(demo, "beacon") if x["dst_ip"] == C2_KEEPALIVE]
    assert "single persistent connection every exactly 15.0 seconds" in b["headline"]


def test_detects_dns_tunnel(demo):
    (d,) = by_kind(demo, "dns_tunnel")
    assert d["src_ip"] == "10.0.0.31" and d["target"] == "exfil-cdn.net"
    assert d["metrics"]["mean_entropy"] > 4.0


def test_detects_exfiltration(demo):
    (e,) = by_kind(demo, "exfil")
    assert e["src_ip"] == "10.0.0.44" and e["dst_ip"] == EXFIL_DST


def test_fleet_heartbeats_are_low_severity_not_c2(demo):
    """Slack keepalives and EDR check-ins are perfectly periodic but shared by many hosts."""
    shared = {a["dst_ip"]: a for a in by_kind(demo, "shared")}
    assert set(shared) == {"3.92.181.120", "52.40.17.9"}
    assert all(a["severity"] == "low" and a["hosts"] >= 4 for a in shared.values())
    assert not [b for b in by_kind(demo, "beacon") if b["dst_ip"] in shared]


def test_no_actionable_alerts_on_benign_hosts(demo):
    actionable = [a for a in demo.alerts.values() if a["severity"] != "low"]
    assert {a["src_ip"] for a in actionable} <= ATTACKER_HOSTS


def test_held_out_benign_capture_raises_no_high_severity_alerts(engine, data_dir):
    a = analyze(run_engine(engine, "-r", os.path.join(data_dir, "benign_val.pcap")))
    assert not [x for x in a.alerts.values() if x["severity"] in ("critical", "high")]
    medium = [x for x in a.alerts.values() if x["severity"] == "medium"]
    assert len(medium) <= 0.002 * a.counters["sessions"] + 1  # ML false-positive budget


def test_allowlist_suppresses_destination(demo_records):
    cfg = Config(allowlist_cidrs=["192.168.1.0/24"], allowlist_domains=["exfil-cdn.net"])
    a = analyze(demo_records, cfg)
    assert C2_FIXED not in {x["dst_ip"] for x in a.alerts.values()}
    assert not by_kind(a, "dns_tunnel")


def test_config_file_loading(tmp_path):
    p = tmp_path / "anta.toml"
    p.write_text('[beacon]\nbeacon_min_events = 12\n[allow]\nallowlist_domains = ["corp.example"]\n')
    cfg = Config.load(str(p))
    assert cfg.beacon_min_events == 12 and cfg.allowlist_domains == ["corp.example"]
    p.write_text("[x]\nno_such_setting = 1\n")
    with pytest.raises(ValueError):
        Config.load(str(p))
    p.write_text('[x]\nbeacon_min_events = "lots"\n')
    with pytest.raises(ValueError):
        Config.load(str(p))


def test_hostile_records_are_rejected_not_crashing(demo_records):
    """Records may come from external telemetry on stdin: garbage must never crash or leak through."""
    rng = random.Random(1)
    a = Analyzer(model_or_none())
    base = next(r for r in sessions(demo_records) if r.get("tls"))
    junk = [None, -1, 1e309, "x" * 100_000, [], {}, {"a": 1}, [[1]], True, "../../etc/passwd", "1.2.3.4; rm -rf /"]
    for _ in range(3000):
        rec = json.loads(json.dumps(base))
        for _ in range(rng.randint(1, 4)):
            key = rng.choice(list(rec))
            rec[key] = rng.choice(junk)
        a.ingest(rec)
    assert a.counters["invalid"] > 0
    for alert in a.alerts.values():  # anything that got through has clean, typed fields
        json.dumps(alert, allow_nan=False)


def test_spoofed_capture_path_is_not_exportable(demo_records):
    a = Analyzer(model_or_none())
    a.ingest({"type": "hello", "capture": "/real/capture.pcap"})
    for rec in demo_records:
        if rec["type"] == "session":
            rec = dict(rec, capture="/etc/passwd")
        a.ingest(rec)
    assert a.alerts and not any(x["exportable"] for x in a.alerts.values())
    assert all(info["capture"] is None for info in a.export_index.values())


def test_stdin_mode_reads_engine_output(engine, data_dir):
    """`anta analyze` consumes engine JSON lines from stdin (sys.stdin.readline loop)."""
    eng = subprocess.Popen([engine, "-r", os.path.join(data_dir, "mixed_demo.pcap")], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL)
    out = subprocess.run([sys.executable, "-m", "anta", "--model", MODELS, "analyze"], stdin=eng.stdout,
                         capture_output=True, text=True, cwd=ROOT, check=True)
    eng.wait()
    assert f"automated beaconing detected to {C2_FIXED}:443" in out.stdout
    assert "DNS tunneling detected from 10.0.0.31" in out.stdout


@pytest.mark.skipif(model_or_none() is None, reason="model not trained (run `make train`)")
def test_model_was_calibrated_on_held_out_data():
    with open(os.path.join(MODELS, "meta.json")) as fh:
        meta = json.load(fh)
    assert meta["calibration"]["source"] == "validation"
    assert meta["calibration"]["fp_rate"] <= 0.01
    assert meta["onnx_max_error"] < 1e-4


@pytest.mark.skipif(model_or_none() is None, reason="model not trained (run `make train`)")
def test_onnx_model_flags_anomalous_attack_sessions(demo, demo_records):
    model = model_or_none()
    (e,) = by_kind(demo, "exfil")
    assert e["metrics"]["ml_score"] < model.threshold
    # The in-session C2 beacon looks like the benign long-lived keepalives (the
    # timing detector is what alerts on it), but the model still ranks it among
    # the most unusual 1% of sessions in the capture.
    from anta.features import feature_vector, session_features
    scores, c2 = [], []
    for rec in demo_records:
        if rec.get("type") == "session" and rec.get("final") and rec["proto"] == "tcp" and rec.get("events"):
            s = float(model.scores(feature_vector(session_features(rec)))[0])
            if rec["dst_ip"] == C2_KEEPALIVE:
                c2.append(s)
            elif rec["src_ip"] not in ATTACKER_HOSTS:
                scores.append(s)
    assert c2 and sum(s < min(c2) for s in scores) <= 0.01 * len(scores)
