"""Check ANTA's display filters against Wireshark's: same filter, same matching frames?

  python -m anta.tools.compare_filters capture.pcap [more.pcap ...] [-Y FILTER ...]

Without -Y it runs a built-in set covering protocols, addresses, ports, flags,
TCP analysis, strings, slices, sets and Wireshark's default coloring rules.
Needs tshark (ships with Wireshark).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from .compare_wireshark import ROOT, find_tshark

FILTERS = [
    "tcp", "udp", "arp", "icmp", "icmpv6", "dns", "mdns", "http", "tls", "ssh", "dhcp", "ntp", "nbns", "ftp",
    "ftp-data", "ipv6", "vlan", "data", "igmp", "ssdp", "llmnr",
    "ip.addr == 172.17.1.230", "ip.src == 192.168.1.254", "ip.dst != 172.17.1.5", "ip.addr == 192.168.0.0/16",
    "ip.addr == 10.0.0.0/8 && !(ip.src == 10.0.0.1)", "tcp.port == 22", "tcp.dstport == 443",
    "udp.port in {53, 67, 68}", "udp.port in {50..70}", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    "tcp.flags & 0x12 == 0x12", "tcp.flags.reset == 1", "tcp.flags.fin == 1", "frame.len > 1000",
    "frame.len <= 60", "tcp.len > 0", "tcp.analysis.flags", "tcp.analysis.retransmission",
    "tcp.analysis.duplicate_ack", "tcp.analysis.lost_segment", "tcp.analysis.out_of_order",
    "tcp.analysis.window_update", "tcp.analysis.keep_alive", "tcp.stream == 3", "udp.stream == 1",
    'dns.qry.name contains "google"', "dns.flags.response == 1", "dns.qry.type == 1", "dns.a",
    'http.request.method == "GET"', "http.response.code == 200", "http.request", "http.host",
    "tls.handshake.type == 1", "tls.handshake.extensions_server_name", "tls.record.content_type == 23",
    "eth.dst == ff:ff:ff:ff:ff:ff", "eth.dst.ig == 1", "ip.ttl < 64", "ip.ttl == 128", "icmp.type == 8",
    "arp.opcode == 1", 'frame contains "SSH"', 'tcp contains "220"', 'frame.protocols contains "ftp"',
    'ssh.protocol matches "OpenSSH"', "dhcp.option.dhcp == 1", "!(arp or icmp)", "not tcp and not udp",
    "ip.proto == 6", "ip.flags.df == 1", "frame.time_relative > 100", "tcp.window_size > 60000",
    "tcp.srcport > 1024 and tcp.dstport < 1024", "ipv6.addr == fe80::/10", "eth[0] & 1",
    "ip.dst == 224.0.0.0/4", "udp.length > 100", "tcp.seq == 1", "tcp.ack == 1", "frame.number > 100 && frame.number < 200",
    "tcp.reassembled_in", "icmp.resp_in", "icmp.resp_to", "tcp.options.mss_val == 1460",
    # expert items and the analysis behind them
    "_ws.expert", "tcp.analysis.acks_frame", "tcp.analysis.ack_rtt > 0.01", "tcp.analysis.partial_ack",
    "tcp.analysis.ambiguous_ack", "tcp.analysis.duplicate_ack_num == 2", "tcp.connection.syn",
    "tcp.connection.synack", "tcp.connection.fin_active", "tcp.connection.fin_passive", "tcp.connection.rst",
    "tcp.ack.nonzero", "tcp.options.mss.absent", "tcp.options.sack_perm.absent", "icmp.type.error",
    "icmp.type.deprecated", "icmp.resp_not_found", "ip.ttl.too_small", "ip.ttl.lncb", "dns.response_in",
    "dns.response_to", "dns.time > 0.05", "dns.retransmit_request", "dns.retransmit_response_in", "dhcp.secs > 0",
    "dhcp.secs_le", "dhcp.type == 2", "dhcp.flags.bc == 1", "tls.handshake.legacy_version",
    "tls.malformed.buffer_too_small", "udp.length.bad", "ip.bogus_ip_length", "dns.response_missing",
    # Windows logons and host announcements: who a machine and its user are
    'kerberos.CNameString and !(kerberos.CNameString contains "$")', "kerberos.msg_type == 10",
    "kerberos.error_code == 25", 'kerberos.realm contains "."', "kerberos.addr_nb", "browser.response_computer_name",
    "browser.server", "browser.command == 0x01", "browser.os_major == 10", "nbdgm.source_name", "mailslot",
    # Active Directory: LDAP, SMB, NTLM, DCE/RPC; and QUIC's Client Hello
    "ldap", "cldap", "ldap.protocolOp == 3", "ldap.resultCode == 0", "ldap.mechanism", "ldap.sasl_buffer_length > 100",
    "mscldap.nb_hostname", 'mscldap.domain contains "."', "nbss", "smb", "smb2", "smb2.cmd == 5",
    "smb2.flags.response == 1", "smb2.nt_status != 0", 'smb2.filename contains "samr"', 'smb2.tree contains "IPC$"',
    "smb2.ioctl.function == 0x0011c017", "smb2.read_length > 100", "ntlmssp", "ntlmssp.messagetype == 3",
    "ntlmssp.auth.username", "dcerpc", "dcerpc.pkt_type == 11", "dcerpc.opnum == 0", "dcerpc.cn_ctx_id == 1",
    "samr", "lsarpc", "drsuapi", "epm", "rpc_netlogon", "ldap.bindResponse_resultCode == 0", "drsuapi.opnum == 12", "samr.opnum == 64",
    "dcerpc.cn_bind_to_uuid == 12345778-1234-abcd-ef00-0123456789ac", "quic", 'tls.handshake.ja4 contains "q13"',
]


def colorfilters() -> list[str]:
    path = os.path.join(ROOT, "anta", "web", "colorfilters.json")
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        return [r["filter"] for r in json.load(fh)]


def wireshark_frames(tshark: str, path: str, flt: str) -> set[int] | None:
    out = subprocess.run([tshark, "-2", "-r", path, "-Y", flt, "-T", "fields", "-e", "frame.number"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return None
    return {int(x) for x in out.stdout.split()}


def anta_frames(engine: str, path: str, flt: str) -> set[int] | str:
    frames: set[int] = set()
    start = 1
    while True:
        out = subprocess.run([engine, "--packets", "-r", path, "-Y", flt, "--from", str(start), "--limit", "100000"],
                             capture_output=True, text=True)
        if out.returncode != 0:
            return out.stderr.strip()
        nxt = None
        for line in out.stdout.splitlines():
            rec = json.loads(line)
            if rec.get("type") == "packet":
                frames.add(rec["n"])
            elif rec.get("type") == "page":
                nxt = rec.get("next")
        if not nxt:
            return frames
        start = nxt


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("captures", nargs="+")
    ap.add_argument("-Y", dest="filters", action="append", help="filter to check (repeatable)")
    ap.add_argument("--engine", default=os.path.join(ROOT, "build", "anta-engine"))
    args = ap.parse_args()
    tshark = find_tshark()
    if not tshark:
        print("tshark not found (install Wireshark)", file=sys.stderr)
        return 2
    filters = args.filters or FILTERS + colorfilters()
    failures = 0
    for path in args.captures:
        agree = 0
        for flt in filters:
            ws = wireshark_frames(tshark, path, flt)
            an = anta_frames(args.engine, path, flt)
            if ws is None:
                print(f"  {os.path.basename(path)}: Wireshark rejects {flt!r}")
                continue
            if isinstance(an, str):
                print(f"  {os.path.basename(path)}: ANTA rejects {flt!r}: {an}")
                failures += 1
                continue
            if ws == an:
                agree += 1
                continue
            failures += 1
            only_ws, only_an = sorted(ws - an), sorted(an - ws)
            print(f"  {os.path.basename(path)}: {flt!r}: Wireshark {len(ws)} frames, ANTA {len(an)}; "
                  f"only Wireshark {only_ws[:8]}{'…' if len(only_ws) > 8 else ''}, "
                  f"only ANTA {only_an[:8]}{'…' if len(only_an) > 8 else ''}")
        print(f"{os.path.basename(path)}: {agree}/{len(filters)} filters match exactly")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
