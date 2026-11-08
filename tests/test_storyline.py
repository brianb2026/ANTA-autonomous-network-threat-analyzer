"""Attack storyline: alerts linked into one story per device, in time order and attack stage."""
from anta.storyline import build


def alert(id_, kind, severity, t, src="10.0.0.5", dst=None, **kw):
    return {"id": id_, "kind": kind, "severity": severity, "title": kind.title(), "headline": f"{kind} headline",
            "first_seen": t, "last_seen": t + 5, "src_ip": src, "dst_ip": dst, **kw}


def test_one_device_through_the_stages():
    alerts = [
        alert("A3", "exfil", "high", 300, dst="203.0.113.50"),
        alert("A1", "download", "high", 100, dst="198.51.100.9"),
        alert("A2", "beacon", "critical", 200, dst="192.0.2.77"),
        alert("A9", "shared", "low", 50, dst="151.101.1.1"),            # (shared cloud traffic: not a story)
        alert("A4", "anomaly", "medium", 400, dst="203.0.113.60", triage={"status": "false_positive"}),
    ]
    [s] = build(alerts, {"10.0.0.5": "DESKTOP-7"})["stories"]
    assert [x["id"] for x in s["steps"]] == ["A1", "A2", "A3"]
    assert s["stages"] == ["delivery", "c2", "exfil"] and s["severity"] == "critical" and s["name"] == "DESKTOP-7"
    assert s["summary"].startswith("DESKTOP-7 received suspicious software (198.51.100.9) at ")
    assert ", then started calling home (192.0.2.77) at " in s["summary"] and ", and then sent data out" in s["summary"]


def test_spreading_links_two_devices():
    alerts = [alert("A1", "beacon", "critical", 100, dst="192.0.2.77"),
              alert("A2", "smb_file", "high", 200, dst="10.0.0.9", target="10.0.0.9")]
    stories = {s["device"]: s for s in build(alerts)["stories"]}
    assert stories["10.0.0.5"]["links"] == ["10.0.0.9"] and stories["10.0.0.9"]["links"] == ["10.0.0.5"]
    got = stories["10.0.0.9"]["steps"][0]
    assert got["stage"] == "delivery" and got["received_from"] == "10.0.0.5" and got["id"] == "A2"
    assert stories["10.0.0.5"]["stages"] == ["c2", "lateral"]


def test_the_culprit_is_the_subject_and_the_worst_story_comes_first():
    alerts = [alert("A1", "scan", "medium", 100, src="10.0.0.40", dst="10.0.0.1"),
              alert("A2", "arp_spoof", "critical", 150, src=None, offender="10.0.0.66"),
              alert("A3", "intel_match", "critical", 120, dst="203.0.113.9", metrics={"kind": "sha256"})]
    stories = build(alerts)["stories"]
    # Two critical stories that got one stage each: the earlier first; the medium one last.
    assert [s["device"] for s in stories] == ["10.0.0.5", "10.0.0.66", "10.0.0.40"]
    by = {s["device"]: s for s in stories}
    assert by["10.0.0.66"]["stages"] == ["position"] and by["10.0.0.40"]["stages"] == ["recon"]
    assert by["10.0.0.5"]["stages"] == ["delivery"]  # a known-bad file is delivery, not calling home
    assert build([])["stories"] == []
