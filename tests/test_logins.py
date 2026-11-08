"""Logins sent in clear text (like Wireshark's Tools > Credentials): the protocol, the account
and whether the server accepted it, read from FTP, POP, IMAP, SMTP AUTH, HTTP Basic and login
forms, LDAP simple binds, Telnet and SNMP community strings. The passwords themselves must
never come out of the engine: every capture here uses passwords that are checked for."""
import base64
import json
import subprocess

import pytest

from anta import logins as login_report
from anta.analyzer import Analyzer
from anta.security import validate_session
from anta.storyline import build as storyline
from anta.tools import samples
from conftest import run_engine

SECRET = "Sup3rS3cret!"  # noqa: S105 - every password in the lab: it must appear nowhere in the output


def b64(s: str) -> bytes:
    return base64.b64encode(s.encode())


@pytest.fixture(scope="module")
def lab(engine, tmp_path_factory):
    path = str(tmp_path_factory.mktemp("logins") / "logins.pcap")
    samples.write_pcap(path, samples.login_lab(SECRET))
    return path


def test_every_kind_of_cleartext_login(engine, lab):
    out = subprocess.run([engine, "--index", "-r", lab], capture_output=True, text=True, check=True).stdout
    assert SECRET not in out and b64(SECRET).decode() not in out and "guest@example.com" not in out
    logins = {}
    for rec in map(json.loads, out.splitlines()):
        for l in rec.get("logins") or []:
            logins[(l["proto"], l["method"])] = l
    def check(proto, method, user, accepted, **extra):
        l = logins[(proto, method)]
        assert (l["user"], l["accepted"]) == (user, accepted), l
        for k, v in extra.items():
            assert l.get(k, False) == v, (l, k)
    check("FTP", "USER/PASS", "anonymous", True, anonymous=True)  # (the last FTP session wins the key)
    check("POP", "USER/PASS", "bob", False)
    check("IMAP", "LOGIN", "carol smith", True)
    check("SMTP", "AUTH LOGIN", "dave", True)
    check("SMTP", "AUTH PLAIN", "erin", False)
    check("HTTP", "Basic", "frank", True)
    check("HTTP", "form", "grace@corp.example", None)
    check("LDAP", "simple bind", "cn=heidi,dc=corp,dc=example", True)
    check("Telnet", "login prompt", "ivan", True)
    check("SNMP", "community", "", None, default_secret=True)
    ftp = [l for rec in map(json.loads, out.splitlines()) for l in rec.get("logins") or [] if l["proto"] == "FTP"]
    assert {(l["user"], l["accepted"]) for l in ftp} == {("alice", True), ("anonymous", True)}


def test_no_password_reaches_the_session_records(engine, lab):
    recs = run_engine(engine, "-r", lab)
    text = json.dumps(recs)
    assert SECRET not in text and "public" not in text.replace('"default_secret"', "")


def test_one_alert_per_client_server_and_service(engine, lab):
    a = Analyzer()
    for rec in run_engine(engine, "-r", lab):
        a.ingest(rec)
    alerts = [x for x in a.alerts.values() if x["kind"] == "cleartext_login"]
    text = json.dumps(alerts)
    assert SECRET not in text and b64(SECRET).decode() not in text and "guest@example.com" not in text
    by = {(x["dst_port"], x["metrics"]["service"]): x for x in alerts}
    # Anonymous FTP carries no real password: alice is the only FTP account named.
    assert set(by) == {(21, "FTP"), (110, "POP"), (143, "IMAP"), (25, "SMTP"), (587, "SMTP"), (8080, "HTTP"),
                       (80, "HTTP"), (389, "LDAP"), (23, "Telnet"), (161, "SNMP")}
    ftp = by[(21, "FTP")]
    assert ftp["severity"] == "medium" and ftp["title"] == "Password Sent in Clear Text"
    assert ftp["metrics"]["users"] == "alice" and ftp["metrics"]["accepted"] == 1
    assert ftp["headline"].startswith("10.20.0.5 logged in to FTP on 10.20.0.80:21 as alice")
    assert any("SFTP" in d for d in ftp["details"]) and any("never shows" in d for d in ftp["details"])
    assert "refused" in by[(110, "POP")]["details"][0]
    assert "factory default" in by[(161, "SNMP")]["headline"]
    assert ftp["exportable"] and ftp["export_flows"] == 1  # (its packets: the alert's Save packets)
    # A habit to fix, not an attack step: no storyline.
    assert storyline(list(a.alerts.values()))["stories"] == []


def test_the_report_lists_every_account_and_what_to_use_instead(engine, lab):
    out = subprocess.run([engine, "--index", "-r", lab], capture_output=True, text=True, check=True).stdout
    sessions = [validate_session(r) for r in map(json.loads, out.splitlines()) if r.get("type") == "session"]
    rep = login_report.report(sessions)
    assert SECRET not in json.dumps(rep)
    rows = {(r["service"], r["user"]): r for r in rep["logins"]}
    assert rows[("FTP", "alice")]["status"] == "accepted" and rows[("POP", "bob")]["status"] == "refused"
    assert rows[("HTTP", "grace@corp.example")]["status"] == "unknown"
    assert rows[("Telnet", "ivan")]["safer"] == "SSH" and rows[("FTP", "anonymous")]["anonymous"]
    assert rows[("FTP", "alice")]["flow"] == {"src": "10.20.0.5", "dst": "10.20.0.80", "proto": "tcp",
                                              "sport": 40001, "dport": 21}
    assert rep["total"] == 11 and rep["accounts"] == 10 and rep["accepted"] == 6
    assert rep["logins"][0]["accepted"]  # those that worked come first


def test_records_from_elsewhere_are_checked():
    rec = {"type": "session", "proto": "tcp", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1,
           "dst_port": 21, "start": 1, "end": 2, "logins": [
               {"proto": "FTP" * 20, "method": "USER/PASS", "user": "x" * 999, "accepted": "yes", "ts": 1.5},
               "junk"]}
    [l] = validate_session(rec)["logins"]
    assert len(l["proto"]) == 16 and len(l["user"]) == 256 and l["accepted"] is None
    assert l["anonymous"] is False and l["default_secret"] is False
