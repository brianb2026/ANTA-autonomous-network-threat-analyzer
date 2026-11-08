"""Regenerate the engine's protocol name tables (engine/src/names_data.inc).

Windows protocols identify things by number: NT status codes, file-system
control codes, SMB2 information levels, and DCE/RPC interfaces (UUIDs) with
their operation numbers. The names are Microsoft's (MS-ERREF, MS-FSCC, MS-SMB2
and each interface's IDL); this reads them as an installed Wireshark lists
them, so the engine shows the same text:

    python -m anta.tools.gen_names [path/to/tshark]
"""
from __future__ import annotations

import collections
import os
import subprocess
import sys

from anta.tools.compare_wireshark import find_tshark

OUT = os.path.join(os.path.dirname(__file__), "..", "..", "engine", "src", "names_data.inc")

# DCE/RPC interfaces: UUID, major version, the name in bind context lists, the
# protocol column, and the field holding its operation names (its prefix is the
# display-filter name, except where FILTER_NAMES says otherwise).
INTERFACES = [
    ("e1af8308-5d1f-11c9-91a4-08002b14a0fa", 3, "EPMv4", "EPM", "epm.opnum"),
    ("12345778-1234-abcd-ef00-0123456789ac", 1, "SAMR", "SAMR", "samr.opnum"),
    ("12345778-1234-abcd-ef00-0123456789ab", 0, "LSARPC", "LSARPC", "lsarpc.opnum"),
    ("12345678-1234-abcd-ef00-01234567cffb", 1, "RPC_NETLOGON", "RPC_NETLOGON", "netlogon.opnum"),
    ("e3514235-4b06-11d1-ab04-00c04fc2dcd2", 4, "DRSUAPI", "DRSUAPI", "drsuapi.opnum"),
    ("4b324fc8-1670-01d3-1278-5a47bf6ee188", 3, "SRVSVC", "SRVSVC", "srvsvc.opnum"),
    ("6bffd098-a112-3610-9833-46c3f87e345a", 1, "WKSSVC", "WKSSVC", "wkssvc.opnum"),
    ("338cd001-2244-31f1-aaaa-900038001003", 1, "WINREG", "WINREG", "winreg.opnum"),
    ("367abb81-9844-35f1-ad32-98f038001003", 2, "SVCCTL", "SVCCTL", "svcctl.opnum"),
    ("1ff70682-0a51-30e8-076d-740be8cee98b", 1, "ATSVC", "ATSVC", "atsvc.opnum"),
    ("86d35949-83c9-4044-b424-db363231fd0c", 1, "TaskSchedulerService", "TaskSchedulerService",
     "taskschedulerservice.opnum"),
    ("12345678-1234-abcd-ef00-0123456789ab", 1, "SPOOLSS", "SPOOLSS", "spoolss.opnum"),
    ("76f03f96-cdfd-44fc-a22c-64950a001209", 1, "IREMOTEWINSPOOL", "IREMOTEWINSPOOL", "iremotewinspool.opnum"),
    ("c681d488-d850-11d0-8c52-00c04fd90f7e", 1, "EFS", "EFS", "efs.opnum"),
    ("3919286a-b10c-11d0-9ba8-00c04fd92ef5", 0, "DSSETUP", "DSSETUP", "dssetup.opnum"),
    ("82273fdc-e32a-18c3-3f78-827929dc23ea", 0, "EVENTLOG", "EVENTLOG", "eventlog.opnum"),
    ("4fc742e0-4a10-11cf-8273-00aa004ae673", 3, "NETDFS", "NETDFS", "netdfs.opnum"),
    ("000001a0-0000-0000-c000-000000000046", 0, "ISystemActivator", "ISystemActivator", "isystemactivator.opnum"),
    ("99fcfec4-5260-101b-bbcb-00aa0021347a", 0, "IOXIDResolver", "IOXIDResolver", "oxid.opnum"),
    ("4d9f4ab8-7d1c-11cf-861e-0020af6e7c57", 0, "REMACT", "REMACT", "remact.opnum"),
    ("f309ad18-d86a-11d0-a075-00c04fb68820", 0, "IWBEMLEVEL1LOGIN", "IWBEMLEVEL1LOGIN", "IWbemLevel1Login.opnum"),
    ("9556dc99-828c-11cf-a37e-00aa003240c7", 0, "IWBEMSERVICES", "IWBEMSERVICES", "IWbemServices.opnum"),
    ("50abc2a4-574d-40b3-9d66-ee4fd5fba076", 5, "DNSSERVER", "DNSSERVER", "dnsserver.opnum"),
    ("894de0c0-0d55-11d3-a322-00c04fa321a1", 1, "INITSHUTDOWN", "INITSHUTDOWN", "initshutdown.opnum"),
    ("afa8bd80-7d8a-11c9-bef4-08002b102989", 1, "MGMT", "MGMT", "mgmt.opnum"),
    ("f5cc59b4-4264-101a-8c59-08002b2f8426", 1, "FRSRPC", "FRSRPC", "frsrpc.opnum"),
    ("897e2e5f-93f3-4376-9c9c-fd2277495c27", 1, "FRSTRANS", "FRSTRANS", "frstrans.opnum"),
    ("6bffd098-a112-3610-9833-012892020162", 0, "RPC_BROWSER", "RPC_BROWSER", "browser.opnum"),
    ("ccd8c074-d0e5-4a40-92b4-d074faa6ba28", 1, "WITNESS", "WITNESS", "witness.opnum"),
    ("8d9f4e40-a03d-11ce-8f69-08003e30051b", 1, "PNP", "PNP", "pnp.opnum"),
    ("a4f1db00-ca47-1067-b31f-00dd010662da", 0, "MAPI", "MAPI", "mapi.opnum"),
]

FILTER_NAMES = {"netlogon.opnum": "rpc_netlogon", "browser.opnum": "rpc_browser"}

TABLES = [  # (C name, field)
    ("kNtStatus", "smb2.nt_status"),
    ("kFsctl", "smb2.ioctl.function"),
    ("kSmb2FileInfo", "smb2.file_info.infolevel"),
    ("kSmb2FsInfo", "smb2.fs_info.infolevel"),
    ("kSmb2FindLevel", "smb2.find.infolevel"),
    ("kRpcFault", "dcerpc.cn_status"),
    ("kRpcRejectReason", "dcerpc.cn_reject_reason"),
    ("kSmb1Cmd", "smb.cmd"),
]


def c_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main(argv: list[str]) -> int:
    tshark = argv[1] if len(argv) > 1 else find_tshark()
    if not tshark:
        print("gen_names: tshark not found; pass its path", file=sys.stderr)
        return 1
    dump = subprocess.run([tshark, "-G", "values"], capture_output=True, text=True, check=True).stdout
    wanted = {f for _, f in TABLES} | {i[4] for i in INTERFACES}
    values: dict[str, dict[int, str]] = collections.defaultdict(dict)
    for line in dump.splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[0] == "V" and parts[1] in wanted:
            values[parts[1]][int(parts[2], 0)] = parts[3]
    out = ["// Generated by anta/tools/gen_names.py: Microsoft's names for Windows protocol", "// numbers, as Wireshark shows them. Do not edit.", ""]

    def table(name: str, entries: dict[int, str]):
        out.append(f"static const NameEntry {name}[] = {{")
        for code in sorted(entries):
            out.append(f"    {{0x{code:08x}u, {c_str(entries[code])}}},")
        out.append("};")

    for name, field in TABLES:
        table(name, values[field])
    for uuid, ver, _, proto, field in INTERFACES:
        table(f"kOps_{proto}_{ver}", values[field])
    out.append("static const RpcInterface kRpcInterfaces[] = {")
    for uuid, ver, ctx, proto, field in INTERFACES:
        ops = f"kOps_{proto}_{ver}"
        flt = FILTER_NAMES.get(field, field.split(".")[0])
        out.append(f"    {{{c_str(uuid)}, {ver}, {c_str(ctx)}, {c_str(proto)}, {c_str(flt)}, {c_str(field)}, {ops}, "
                   f"sizeof({ops}) / sizeof({ops}[0])}},")
    out.append("};")
    with open(OUT, "w") as f:
        f.write("\n".join(out) + "\n")
    counts = ", ".join(f"{n} {len(values[f])}" for n, f in TABLES)
    print(f"gen_names: {counts}; {len(INTERFACES)} RPC interfaces -> {os.path.normpath(OUT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
