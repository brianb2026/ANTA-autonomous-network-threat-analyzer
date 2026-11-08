"""Windows domain traffic: LDAP and CLDAP, SMB2 with an NTLM logon (and the files
it copies), DCE/RPC. The packet-list text is what Wireshark 4.6 shows for these
captures (built by anta.tools.samples)."""
import hashlib

import pytest

from anta import netmap
from anta.analyzer import Analyzer
from anta.tools import samples
from conftest import run_engine, sessions

CLIENT, DC = "10.0.0.5", "10.0.0.10"
PROGRAM = samples.windows_exe(6000, seed=5)


@pytest.fixture(scope="module")
def domain_pcap(tmp_path_factory):
    frames = samples.ldap_session(CLIENT, 50400, DC)
    frames += samples.smb2_file_session(CLIENT, 50500, DC, [
        ("\\\\DC-1\\ADMIN$", "svc.exe", PROGRAM, True),
        ("\\\\DC-1\\SYSVOL", "example.com\\scripts\\logon.bat", b"@echo off\r\n", False)], t0=frames[-1][0] + 1)
    frames += samples.dcerpc_session(CLIENT, 50600, DC, t0=frames[-1][0] + 1)
    path = tmp_path_factory.mktemp("windows") / "domain.pcap"
    samples.write_pcap(path, frames)
    return str(path)


def infos(engine, path, *args):
    return [(r["proto"], r["info"]) for r in run_engine(engine, "--packets", "-r", path, "--limit", "1000", *args)
            if r["type"] == "packet" and r["proto"] not in ("TCP",)]


def test_ldap_and_cldap_read_like_wireshark(engine, domain_pcap):
    rows = infos(engine, domain_pcap)
    for row in [("LDAP", 'bindRequest(1) "cn=admin,dc=example,dc=com" simple '),
                ("LDAP", 'searchResEntry(2) "cn=a,dc=example,dc=com"  | searchResEntry(2) "cn=b,dc=example,dc=com"  '
                         '| searchResDone(2) success  [2 results]'),
                ("LDAP", "searchResDone(3) noSuchObject (no such object)  [2 results]"),  # the connection's total
                ("LDAP", "unbindRequest(4) "),
                ("CLDAP", 'searchResEntry(5) "<ROOT>" searchResDone(5) success  [1 result]')]:
        assert row in rows
    dc = run_engine(engine, "--packets", "-r", domain_pcap, "-Y", 'mscldap.nb_hostname == "DC-1"')
    assert [r for r in dc if r["type"] == "packet"]


def test_smb2_with_an_ntlm_logon(engine, domain_pcap):
    rows = infos(engine, domain_pcap)
    for row in [("SMB2", "Session Setup Request, NTLMSSP_NEGOTIATE"),
                ("SMB2", "Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED, NTLMSSP_CHALLENGE"),
                ("SMB2", "Session Setup Request, NTLMSSP_AUTH, User: CORP\\alice"),
                ("SMB2", "Tree Connect Response, Tree: '\\\\DC-1\\ADMIN$'"),
                ("SMB2", "Write Request Len:1904 Off:4096, File: svc.exe"),
                ("SMB2", "Read Response, File: example.com\\scripts\\logon.bat"),
                ("SMB2", "Close Response, File: svc.exe")]:
        assert row in rows
    # A single pass can't look back at the request: Wireshark names the file only on requests then.
    one = infos(engine, domain_pcap, "--single-pass")
    assert ("SMB2", "Close Response") in one and ("SMB2", "Close Request, File: svc.exe") in one
    user = run_engine(engine, "--packets", "-r", domain_pcap, "-Y", 'ntlmssp.auth.username == "alice"')
    assert len([r for r in user if r["type"] == "packet"]) == 1


def test_files_copied_over_smb_are_hashed(engine, domain_pcap):
    files = {f["name"]: f for s in sessions(run_engine(engine, "-r", domain_pcap)) for f in s.get("smb_files", [])}
    exe = files["svc.exe"]
    assert exe["op"] == "write" and exe["share"] == "\\\\DC-1\\ADMIN$" and exe["complete"]
    assert exe["sha256"] == hashlib.sha256(PROGRAM).hexdigest() and exe["size"] == len(PROGRAM)
    bat = files["example.com\\scripts\\logon.bat"]
    assert bat["op"] == "read" and bat["sha256"] == hashlib.sha256(b"@echo off\r\n").hexdigest()


def test_program_written_to_an_admin_share_is_critical(engine, domain_pcap):
    analyzer = Analyzer()
    for rec in run_engine(engine, "-r", domain_pcap):
        analyzer.ingest(rec)
    alerts = [a for a in analyzer.alerts.values() if a["kind"] == "smb_file"]
    assert len(alerts) == 1  # the logon script read from SYSVOL is routine
    a = alerts[0]
    assert a["severity"] == "critical" and a["src_ip"] == CLIENT and a["dst_ip"] == DC
    assert "administrative share" in a["headline"] and a["file"]["sha256"] == hashlib.sha256(PROGRAM).hexdigest()
    assert a["file"]["url"] == "\\\\DC-1\\ADMIN$\\svc.exe"


def test_dcerpc_and_the_endpoint_mapper(engine, domain_pcap):
    rows = infos(engine, domain_pcap)
    for row in [("DCERPC", "Bind: call_id: 2, Fragment: Single, 2 context items: EPMv4 V3.0 (32bit NDR), "
                           "EPMv4 V3.0 (64bit NDR)"),
                ("DCERPC", "Bind_ack: call_id: 2, Fragment: Single, max_xmit: 5840 max_recv: 5840, 2 results: "
                           "Acceptance, Provider rejection"),
                ("EPM", "Map request, DRSUAPI, 32bit NDR"),
                ("SAMR", "Unknown operation 999 request"),
                ("DCERPC", "Fault: call_id: 6, Fragment: Single, Ctx: 0, status: nca_op_rng_error")]:
        assert row in rows
    # Two calls in one segment on context 0: Wireshark joins PDUs with " # " only after a
    # non-zero context, so the second call's Info replaces the first's.
    assert rows.count(("SAMR", "Close request")) == 2
    samr = run_engine(engine, "--packets", "-r", domain_pcap, "-Y", "samr.opnum == 1")
    assert len([r for r in samr if r["type"] == "packet"]) == 4  # Close, alone and paired, both ways


def test_who_the_hosts_are(engine, domain_pcap):
    stats = next(r for r in run_engine(engine, "--stats", "-r", domain_pcap) if r["type"] == "stats")
    nodes = {n["addr"]: n for n in netmap.build(stats)["nodes"]}
    client = nodes[CLIENT]
    assert "alice" in client["users"] and "CORP" in client["domains"]
    assert any(name == "WS-1" and src == "NTLM" for name, src in client["names"])
    assert any(name == "DC-1" for name, _ in nodes[DC]["names"])
