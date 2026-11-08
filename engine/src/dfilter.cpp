#include "dfilter.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <regex>

namespace anta {

// ------------------------------------------------------------ frame fields

void FrameFields::proto(const char* name, size_t offset, size_t length) {
    protos.push_back({name, static_cast<uint32_t>(offset), static_cast<uint32_t>(length)});
}

void FrameFields::uint(const char* name, uint64_t v) {
    FieldValue f;
    f.type = FieldValue::kUint;
    f.u = v;
    fields.push_back({name, std::move(f)});
}

void FrameFields::sint(const char* name, int64_t v) {
    FieldValue f;
    f.type = FieldValue::kInt;
    f.u = static_cast<uint64_t>(v);
    fields.push_back({name, std::move(f)});
}

void FrameFields::real(const char* name, double v) {
    FieldValue f;
    f.type = FieldValue::kDouble;
    f.d = v;
    fields.push_back({name, std::move(f)});
}

void FrameFields::string(const char* name, std::string v) {
    FieldValue f;
    f.type = FieldValue::kString;
    f.s = std::move(v);
    fields.push_back({name, std::move(f)});
}

void FrameFields::ipv4(const char* name, const uint8_t* a) {
    FieldValue f;
    f.type = FieldValue::kIPv4;
    f.s.assign(reinterpret_cast<const char*>(a), 4);
    fields.push_back({name, std::move(f)});
}

void FrameFields::ipv6(const char* name, const uint8_t* a) {
    FieldValue f;
    f.type = FieldValue::kIPv6;
    f.s.assign(reinterpret_cast<const char*>(a), 16);
    fields.push_back({name, std::move(f)});
}

void FrameFields::mac(const char* name, const uint8_t* a) {
    FieldValue f;
    f.type = FieldValue::kMac;
    f.s.assign(reinterpret_cast<const char*>(a), 6);
    fields.push_back({name, std::move(f)});
}

void FrameFields::bytes(const char* name, const uint8_t* p, size_t n) {
    FieldValue f;
    f.type = FieldValue::kBytes;
    f.s.assign(reinterpret_cast<const char*>(p), n);
    fields.push_back({name, std::move(f)});
}

bool FrameFields::has_proto(const char* name) const {
    for (const auto& p : protos)
        if (p.name == name || std::strcmp(p.name, name) == 0) return true;
    return false;
}

const FieldValue* FrameFields::first(const char* name) const {
    for (const auto& f : fields)
        if (f.name == name || std::strcmp(f.name, name) == 0) return &f.value;
    return nullptr;
}

bool FrameFields::has_outer_proto(const char* name) const {
    size_t n = std::min(protos.size(), outer_protos);
    for (size_t i = 0; i < n; ++i)
        if (protos[i].name == name || std::strcmp(protos[i].name, name) == 0) return true;
    return false;
}

const FieldValue* FrameFields::first_outer(const char* name) const {
    size_t n = std::min(fields.size(), outer_fields);
    for (size_t i = 0; i < n; ++i)
        if (fields[i].name == name || std::strcmp(fields[i].name, name) == 0) return &fields[i].value;
    return nullptr;
}

std::string FrameFields::protocols() const {
    std::string out;
    for (size_t i = 0; i < protos.size(); ++i) {
        const char* n = protos[i].name;
        if (std::strcmp(n, "frame") == 0 || std::strchr(n, '.') || n[0] == '_') continue;  // pseudo-protocols
        if (!out.empty()) out += ':';
        out += n;
        if (std::strcmp(n, "eth") == 0 || std::strcmp(n, "vlan") == 0 || std::strcmp(n, "sll") == 0) {
            // Wireshark lists the EtherType dispatch step after these
            for (size_t j = i + 1; j < protos.size(); ++j) {
                const char* m = protos[j].name;
                if (std::strchr(m, '.') || m[0] == '_') continue;
                if (std::strcmp(m, "vlan") && std::strcmp(m, "llc")) out += ":ethertype";
                break;
            }
        }
    }
    return out;
}

// --------------------------------------------------------------- registry

namespace {

enum class Kind : uint8_t { Proto, Uint, Int, Bool, Double, String, IPv4, IPv6, Mac, Bytes, Any };

struct Entry {
    const char* name;
    Kind kind;
    const char* desc;
};

// Fields the decoder records, then names Wireshark knows that we never see
// (so filters written for Wireshark, like its default coloring rules, still
// compile and simply don't match).
const Entry kFields[] = {
    {"frame", Kind::Proto, "Frame"},
    {"frame.number", Kind::Uint, "Frame number"},
    {"frame.len", Kind::Uint, "Frame length on the wire"},
    {"frame.cap_len", Kind::Uint, "Frame length captured"},
    {"frame.time_epoch", Kind::Double, "Arrival time (seconds since 1970)"},
    {"frame.time_relative", Kind::Double, "Time since the first frame"},
    {"frame.time_delta", Kind::Double, "Time since the previous frame"},
    {"frame.protocols", Kind::String, "Protocols in frame"},
    {"_ws.expert", Kind::Proto, "Expert info"},
    {"_ws.malformed", Kind::Proto, "Malformed packet"},
    {"eth", Kind::Proto, "Ethernet"},
    {"eth.src", Kind::Mac, "Source MAC"},
    {"eth.dst", Kind::Mac, "Destination MAC"},
    {"eth.addr", Kind::Mac, "Source or destination MAC"},
    {"eth.type", Kind::Uint, "EtherType"},
    {"eth.dst.ig", Kind::Bool, "Destination is a group (multicast/broadcast) address"},
    {"eth.src.oui_resolved", Kind::String, "Source vendor"},
    {"eth.dst.oui_resolved", Kind::String, "Destination vendor"},
    {"vlan", Kind::Proto, "802.1Q VLAN"},
    {"vlan.id", Kind::Uint, "VLAN ID"},
    {"vlan.priority", Kind::Uint, "VLAN priority"},
    {"mpls", Kind::Proto, "MPLS"},
    {"mpls.label", Kind::Uint, "MPLS label"},
    {"pppoes", Kind::Proto, "PPPoE session"},
    {"ppp", Kind::Proto, "PPP"},
    {"llc", Kind::Proto, "Logical-Link Control"},
    {"sll", Kind::Proto, "Linux cooked capture"},
    {"sll.src.eth", Kind::Mac, "Source MAC (cooked capture)"},
    {"sll.src.oui_resolved", Kind::String, "Source vendor (cooked capture)"},
    {"wlan", Kind::Proto, "IEEE 802.11"},
    {"radiotap", Kind::Proto, "Radiotap"},
    {"nflog", Kind::Proto, "Linux netfilter log"},
    {"arp", Kind::Proto, "ARP"},
    {"arp.opcode", Kind::Uint, "ARP opcode (1 request, 2 reply)"},
    {"arp.src.hw_mac", Kind::Mac, "Sender MAC"},
    {"arp.src.proto_ipv4", Kind::IPv4, "Sender IP"},
    {"arp.dst.hw_mac", Kind::Mac, "Target MAC"},
    {"arp.dst.proto_ipv4", Kind::IPv4, "Target IP"},
    {"ip", Kind::Proto, "IPv4"},
    {"ip.version", Kind::Uint, "IP version"},
    {"ip.hdr_len", Kind::Uint, "Header length"},
    {"ip.dsfield.dscp", Kind::Uint, "DSCP"},
    {"ip.len", Kind::Uint, "Total length"},
    {"ip.id", Kind::Uint, "Identification"},
    {"ip.flags.rb", Kind::Bool, "Reserved bit"},
    {"ip.flags.df", Kind::Bool, "Don't fragment"},
    {"ip.flags.mf", Kind::Bool, "More fragments"},
    {"ip.frag_offset", Kind::Uint, "Fragment offset"},
    {"ip.ttl", Kind::Uint, "Time to live"},
    {"ip.ttl.too_small", Kind::Proto, "Time to live is low"},
    {"ip.bogus_ip_length", Kind::Proto, "Total length exceeds the packet"},
    {"ip.ttl.lncb", Kind::Proto, "Unexpected TTL for the Local Network Control Block"},
    {"ip.proto", Kind::Uint, "Protocol"},
    {"ip.src", Kind::IPv4, "Source address"},
    {"ip.dst", Kind::IPv4, "Destination address"},
    {"ip.addr", Kind::IPv4, "Source or destination address"},
    {"ipv6", Kind::Proto, "IPv6"},
    {"ipv6.tclass", Kind::Uint, "Traffic class"},
    {"ipv6.flow", Kind::Uint, "Flow label"},
    {"ipv6.plen", Kind::Uint, "Payload length"},
    {"ipv6.nxt", Kind::Uint, "Next header"},
    {"ipv6.hlim", Kind::Uint, "Hop limit"},
    {"ipv6.src", Kind::IPv6, "Source address"},
    {"ipv6.dst", Kind::IPv6, "Destination address"},
    {"ipv6.addr", Kind::IPv6, "Source or destination address"},
    {"gre", Kind::Proto, "GRE"},
    {"erspan", Kind::Proto, "ERSPAN"},
    {"vxlan", Kind::Proto, "VXLAN"},
    {"vxlan.vni", Kind::Uint, "VXLAN network identifier"},
    {"geneve", Kind::Proto, "Geneve"},
    {"tcp", Kind::Proto, "TCP"},
    {"tcp.srcport", Kind::Uint, "Source port"},
    {"tcp.dstport", Kind::Uint, "Destination port"},
    {"tcp.port", Kind::Uint, "Source or destination port"},
    {"tcp.stream", Kind::Uint, "Stream index"},
    {"tcp.len", Kind::Uint, "Segment length"},
    {"tcp.seq", Kind::Uint, "Sequence number (relative)"},
    {"tcp.seq_raw", Kind::Uint, "Sequence number (raw)"},
    {"tcp.nxtseq", Kind::Uint, "Next sequence number"},
    {"tcp.ack", Kind::Uint, "Acknowledgment number (relative)"},
    {"tcp.ack_raw", Kind::Uint, "Acknowledgment number (raw)"},
    {"tcp.hdr_len", Kind::Uint, "Header length"},
    {"tcp.flags", Kind::Uint, "Flags"},
    {"tcp.flags.fin", Kind::Bool, "FIN"},
    {"tcp.flags.syn", Kind::Bool, "SYN"},
    {"tcp.flags.reset", Kind::Bool, "RST"},
    {"tcp.flags.push", Kind::Bool, "PSH"},
    {"tcp.flags.ack", Kind::Bool, "ACK"},
    {"tcp.flags.urg", Kind::Bool, "URG"},
    {"tcp.flags.ece", Kind::Bool, "ECE"},
    {"tcp.flags.cwr", Kind::Bool, "CWR"},
    {"tcp.flags.res", Kind::Uint, "Reserved"},
    {"tcp.window_size_value", Kind::Uint, "Window (as sent)"},
    {"tcp.window_size", Kind::Uint, "Calculated window size"},
    {"tcp.urgent_pointer", Kind::Uint, "Urgent pointer"},
    {"tcp.options.mss_val", Kind::Uint, "MSS option"},
    {"tcp.options.wscale.shift", Kind::Uint, "Window scale option"},
    {"tcp.analysis.flags", Kind::Proto, "Any TCP analysis flag"},
    {"tcp.analysis.retransmission", Kind::Proto, "Retransmission"},
    {"tcp.analysis.fast_retransmission", Kind::Proto, "Fast retransmission"},
    {"tcp.analysis.spurious_retransmission", Kind::Proto, "Spurious retransmission"},
    {"tcp.analysis.out_of_order", Kind::Proto, "Out-of-order segment"},
    {"tcp.analysis.lost_segment", Kind::Proto, "Previous segment not captured"},
    {"tcp.analysis.ack_lost_segment", Kind::Proto, "ACKed unseen segment"},
    {"tcp.analysis.duplicate_ack", Kind::Proto, "Duplicate ACK"},
    {"tcp.analysis.duplicate_ack_num", Kind::Uint, "Duplicate ACK number"},
    {"tcp.analysis.duplicate_ack_frame", Kind::Uint, "Original ACK frame"},
    {"tcp.analysis.window_update", Kind::Proto, "Window update"},
    {"tcp.analysis.window_full", Kind::Proto, "Window full"},
    {"tcp.analysis.zero_window", Kind::Proto, "Zero window"},
    {"tcp.analysis.zero_window_probe", Kind::Proto, "Zero window probe"},
    {"tcp.analysis.zero_window_probe_ack", Kind::Proto, "Zero window probe ACK"},
    {"tcp.analysis.keep_alive", Kind::Proto, "Keep-alive"},
    {"tcp.analysis.keep_alive_ack", Kind::Proto, "Keep-alive ACK"},
    {"tcp.analysis.reused_ports", Kind::Proto, "Port numbers reused"},
    {"tcp.analysis.initial_rtt", Kind::Double, "Initial round-trip time"},
    {"tcp.analysis.acks_frame", Kind::Uint, "ACK to the segment in frame"},
    {"tcp.analysis.ack_rtt", Kind::Double, "Round-trip time to ACK the segment"},
    {"tcp.analysis.partial_ack", Kind::Proto, "Partial acknowledgement of a segment"},
    {"tcp.analysis.ambiguous_ack", Kind::Proto, "Ambiguous ACK (Karn)"},
    {"tcp.connection.syn", Kind::Proto, "Connection establish request (SYN)"},
    {"tcp.connection.synack", Kind::Proto, "Connection establish acknowledge (SYN+ACK)"},
    {"tcp.connection.fin", Kind::Proto, "Connection finish (FIN)"},
    {"tcp.connection.fin_active", Kind::Proto, "This frame initiates the connection closing"},
    {"tcp.connection.fin_passive", Kind::Proto, "This frame undergoes the connection closing"},
    {"tcp.connection.rst", Kind::Proto, "Connection reset (RST)"},
    {"tcp.ack.nonzero", Kind::Proto, "Nonzero ACK number without the ACK flag"},
    {"tcp.options.mss.absent", Kind::Proto, "SYN without an MSS option"},
    {"tcp.options.sack_perm.absent", Kind::Proto, "SYN without a SACK permitted option"},
    {"tcp.options.sack.dsack", Kind::Proto, "Duplicate SACK (data received twice)"},
    {"tcp.options.sack.dsack_le", Kind::Uint, "D-SACK left edge"},
    {"tcp.options.sack.dsack_re", Kind::Uint, "D-SACK right edge"},
    {"tcp.reassembled_in", Kind::Uint, "Message reassembled in frame"},
    {"udp", Kind::Proto, "UDP"},
    {"udp.srcport", Kind::Uint, "Source port"},
    {"udp.dstport", Kind::Uint, "Destination port"},
    {"udp.port", Kind::Uint, "Source or destination port"},
    {"udp.length", Kind::Uint, "Length"},
    {"udp.length.bad", Kind::Proto, "Bad length"},
    {"udp.stream", Kind::Uint, "Stream index"},
    {"icmp", Kind::Proto, "ICMP"},
    {"icmp.type", Kind::Uint, "Type"},
    {"icmp.code", Kind::Uint, "Code"},
    {"icmp.ident", Kind::Uint, "Identifier"},
    {"icmp.seq", Kind::Uint, "Sequence number"},
    {"icmp.resp_in", Kind::Uint, "Response in frame"},
    {"icmp.resp_to", Kind::Uint, "Response to frame"},
    {"icmp.resp_not_found", Kind::Proto, "No response seen"},
    {"icmp.type.error", Kind::Proto, "Type indicates an error"},
    {"icmp.type.deprecated", Kind::Proto, "Type is deprecated"},
    {"icmpv6", Kind::Proto, "ICMPv6"},
    {"icmpv6.type", Kind::Uint, "Type"},
    {"icmpv6.code", Kind::Uint, "Code"},
    {"igmp", Kind::Proto, "IGMP"},
    {"igmp.type", Kind::Uint, "Type"},
    {"dns", Kind::Proto, "DNS"},
    {"mdns", Kind::Proto, "Multicast DNS"},
    {"llmnr", Kind::Proto, "Link-local multicast name resolution"},
    {"dns.id", Kind::Uint, "Transaction ID"},
    {"dns.flags.response", Kind::Bool, "Is a response"},
    {"dns.flags.opcode", Kind::Uint, "Opcode"},
    {"dns.flags.z", Kind::Bool, "Z (reserved)"},
    {"dns.flags.rcode", Kind::Uint, "Reply code"},
    {"dns.qry.name", Kind::String, "Query name"},
    {"dns.qry.type", Kind::Uint, "Query type"},
    {"dns.count.queries", Kind::Uint, "Questions"},
    {"dns.count.answers", Kind::Uint, "Answer RRs"},
    {"dns.resp.name", Kind::String, "Answer name"},
    {"dns.resp.type", Kind::Uint, "Answer type"},
    {"dns.a", Kind::IPv4, "Address (A)"},
    {"dns.aaaa", Kind::IPv6, "Address (AAAA)"},
    {"dns.cname", Kind::String, "Canonical name"},
    {"dns.ptr.domain_name", Kind::String, "Pointer domain name"},
    {"dns.response_in", Kind::Uint, "Response in frame"},
    {"dns.response_to", Kind::Uint, "Request in frame"},
    {"dns.response_missing", Kind::Proto, "No response seen"},
    {"dns.time", Kind::Double, "Time from request to response"},
    {"dns.retransmit_request", Kind::Proto, "Query retransmission"},
    {"dns.retransmit_request_in", Kind::Uint, "Original request in frame"},
    {"dns.retransmit_response", Kind::Proto, "Response retransmission"},
    {"dns.retransmit_response_in", Kind::Uint, "Original response in frame"},
    {"dhcp", Kind::Proto, "DHCP"},
    {"dhcp.type", Kind::Uint, "Message type (1 request, 2 reply)"},
    {"dhcp.hops", Kind::Uint, "Hops"},
    {"dhcp.id", Kind::Uint, "Transaction ID"},
    {"dhcp.secs", Kind::Uint, "Seconds elapsed"},
    {"dhcp.secs_le", Kind::Proto, "Seconds elapsed sent little-endian"},
    {"dhcp.flags.bc", Kind::Bool, "Broadcast flag"},
    {"dhcp.option.dhcp", Kind::Uint, "DHCP message type"},
    {"dhcp.hw.mac_addr", Kind::Mac, "Client MAC"},
    {"dhcp.ip.client", Kind::IPv4, "Client IP"},
    {"dhcp.ip.your", Kind::IPv4, "Your (client) IP"},
    {"dhcp.option.hostname", Kind::String, "Host name"},
    {"dhcp.option.vendor_class_id", Kind::String, "Vendor class"},
    {"dhcp.option.requested_ip_address", Kind::IPv4, "Requested IP"},
    {"dhcp.option.router", Kind::IPv4, "Router"},
    {"dhcp.option.domain_name_server", Kind::IPv4, "DNS server"},
    {"dhcp.option.dhcp_server_id", Kind::IPv4, "DHCP server"},
    {"dhcpv6", Kind::Proto, "DHCPv6"},
    {"dhcpv6.msgtype", Kind::Uint, "Message type"},
    {"ldap", Kind::Proto, "LDAP"},
    {"cldap", Kind::Proto, "Connectionless LDAP (domain controller pings)"},
    {"ldap.messageID", Kind::Uint, "Message ID"},
    {"ldap.protocolOp", Kind::Uint, "Operation (0 bind, 3 search request, 4 search entry, 5 search done ...)"},
    {"ldap.resultCode", Kind::Uint, "Result code (0 success, 32 no such object ...)"},
    {"ldap.bindResponse_resultCode", Kind::Uint, "Bind result (0 success, 49 invalid credentials ...)"},
    {"ldap.extendedResponse_resultCode", Kind::Uint, "Extended operation result"},
    {"ldap.errorMessage", Kind::String, "Error message"},
    {"ldap.name", Kind::String, "Bind name"},
    {"ldap.mechanism", Kind::String, "SASL mechanism"},
    {"ldap.baseObject", Kind::String, "Search base"},
    {"ldap.scope", Kind::Uint, "Search scope"},
    {"ldap.objectName", Kind::String, "Entry name"},
    {"ldap.requestName", Kind::String, "Extended request OID"},
    {"ldap.responseName", Kind::String, "Extended response OID"},
    {"ldap.sasl_buffer_length", Kind::Uint, "SASL buffer length"},
    {"mscldap.netlogon.opcode", Kind::Uint, "Netlogon response type"},
    {"mscldap.netlogon.flags", Kind::Uint, "Domain controller flags"},
    {"mscldap.forest", Kind::String, "Forest"},
    {"mscldap.domain", Kind::String, "Domain"},
    {"mscldap.hostname", Kind::String, "Domain controller host name"},
    {"mscldap.nb_domain", Kind::String, "NetBIOS domain"},
    {"mscldap.nb_hostname", Kind::String, "Domain controller NetBIOS name"},
    {"mscldap.username", Kind::String, "User name"},
    {"mscldap.sitename", Kind::String, "Domain controller site"},
    {"mscldap.clientsitename", Kind::String, "Client site"},
    {"nbss", Kind::Proto, "NetBIOS session service"},
    {"nbss.type", Kind::Uint, "Message type"},
    {"nbss.length", Kind::Uint, "Message length"},
    {"smb", Kind::Proto, "SMB (version 1)"},
    {"smb.cmd", Kind::Uint, "SMB1 command"},
    {"smb2", Kind::Proto, "SMB2/SMB3 file sharing"},
    {"smb2.cmd", Kind::Uint, "Command (3 tree connect, 5 create, 8 read, 9 write, 11 ioctl ...)"},
    {"smb2.flags.response", Kind::Bool, "Is a response"},
    {"smb2.nt_status", Kind::Uint, "NT status (0 success)"},
    {"smb2.msg_id", Kind::Uint, "Message ID"},
    {"smb2.sesid", Kind::Uint, "Session ID"},
    {"smb2.tid", Kind::Uint, "Tree ID"},
    {"smb2.tree", Kind::String, "Share path (Tree Connect)"},
    {"smb2.filename", Kind::String, "File name (Create)"},
    {"smb2.ioctl.function", Kind::Uint, "FSCTL code"},
    {"smb2.read_length", Kind::Uint, "Read length"},
    {"smb2.write_length", Kind::Uint, "Write length"},
    {"smb2.file_offset", Kind::Uint, "File offset"},
    {"ntlmssp", Kind::Proto, "NTLM authentication"},
    {"gss-api", Kind::Proto, "GSS-API security token"},
    {"spnego", Kind::Proto, "SPNEGO (Kerberos or NTLM negotiation)"},
    {"ntlmssp.messagetype", Kind::Uint, "1 negotiate, 2 challenge, 3 authenticate"},
    {"ntlmssp.auth.username", Kind::String, "User name"},
    {"ntlmssp.auth.domain", Kind::String, "Domain"},
    {"ntlmssp.auth.hostname", Kind::String, "Client host name"},
    {"dcerpc", Kind::Proto, "DCE/RPC (Windows remote procedure calls)"},
    {"dcerpc.pkt_type", Kind::Uint, "Packet type (0 request, 2 response, 3 fault, 11 bind, 12 bind ack ...)"},
    {"dcerpc.cn_call_id", Kind::Uint, "Call ID"},
    {"dcerpc.cn_ctx_id", Kind::Uint, "Context ID"},
    {"dcerpc.opnum", Kind::Uint, "Operation number"},
    {"dcerpc.cn_bind_to_uuid", Kind::String, "Interface UUID in a bind"},
    {"dcerpc.auth_type", Kind::Uint, "Authentication (9 SPNEGO, 10 NTLM, 16 Kerberos)"},
    {"dcerpc.auth_level", Kind::Uint, "Authentication level (6 privacy: encrypted)"},
    {"epm", Kind::Proto, "Endpoint mapper"},
    {"epm.opnum", Kind::Uint, "Operation number"},
    {"samr", Kind::Proto, "SAM remote (accounts and groups)"},
    {"samr.opnum", Kind::Uint, "Operation number"},
    {"lsarpc", Kind::Proto, "Local security authority"},
    {"lsarpc.opnum", Kind::Uint, "Operation number"},
    {"rpc_netlogon", Kind::Proto, "Netlogon (secure channel, logons)"},
    {"netlogon.opnum", Kind::Uint, "Operation number"},
    {"drsuapi", Kind::Proto, "Directory replication (DCSync uses it)"},
    {"drsuapi.opnum", Kind::Uint, "Operation number"},
    {"srvsvc", Kind::Proto, "Server service (shares, sessions)"},
    {"srvsvc.opnum", Kind::Uint, "Operation number"},
    {"wkssvc", Kind::Proto, "Workstation service"},
    {"wkssvc.opnum", Kind::Uint, "Operation number"},
    {"winreg", Kind::Proto, "Remote registry"},
    {"winreg.opnum", Kind::Uint, "Operation number"},
    {"svcctl", Kind::Proto, "Service control manager (remote service creation)"},
    {"svcctl.opnum", Kind::Uint, "Operation number"},
    {"atsvc", Kind::Proto, "AT scheduler"},
    {"atsvc.opnum", Kind::Uint, "Operation number"},
    {"taskschedulerservice", Kind::Proto, "Task scheduler"},
    {"taskschedulerservice.opnum", Kind::Uint, "Operation number"},
    {"spoolss", Kind::Proto, "Print spooler"},
    {"spoolss.opnum", Kind::Uint, "Operation number"},
    {"iremotewinspool", Kind::Proto, "Print spooler (async)"},
    {"iremotewinspool.opnum", Kind::Uint, "Operation number"},
    {"efs", Kind::Proto, "Encrypting File System RPC"},
    {"efs.opnum", Kind::Uint, "Operation number"},
    {"dssetup", Kind::Proto, "Directory role"},
    {"dssetup.opnum", Kind::Uint, "Operation number"},
    {"eventlog", Kind::Proto, "Event log"},
    {"eventlog.opnum", Kind::Uint, "Operation number"},
    {"netdfs", Kind::Proto, "DFS"},
    {"netdfs.opnum", Kind::Uint, "Operation number"},
    {"isystemactivator", Kind::Proto, "DCOM activation"},
    {"isystemactivator.opnum", Kind::Uint, "Operation number"},
    {"oxid", Kind::Proto, "DCOM OXID resolver"},
    {"oxid.opnum", Kind::Uint, "Operation number"},
    {"remact", Kind::Proto, "DCOM remote activation"},
    {"remact.opnum", Kind::Uint, "Operation number"},
    {"IWbemLevel1Login", Kind::Proto, "WMI login"},
    {"IWbemLevel1Login.opnum", Kind::Uint, "Operation number"},
    {"IWbemServices", Kind::Proto, "WMI services"},
    {"IWbemServices.opnum", Kind::Uint, "Operation number"},
    {"dnsserver", Kind::Proto, "DNS server management"},
    {"dnsserver.opnum", Kind::Uint, "Operation number"},
    {"initshutdown", Kind::Proto, "Remote shutdown"},
    {"initshutdown.opnum", Kind::Uint, "Operation number"},
    {"mgmt", Kind::Proto, "RPC management"},
    {"mgmt.opnum", Kind::Uint, "Operation number"},
    {"frsrpc", Kind::Proto, "File replication"},
    {"frsrpc.opnum", Kind::Uint, "Operation number"},
    {"frstrans", Kind::Proto, "DFS replication"},
    {"frstrans.opnum", Kind::Uint, "Operation number"},
    {"rpc_browser", Kind::Proto, "Computer browser RPC"},
    {"browser.opnum", Kind::Uint, "Operation number"},
    {"witness", Kind::Proto, "Cluster witness"},
    {"witness.opnum", Kind::Uint, "Operation number"},
    {"pnp", Kind::Proto, "Plug and Play"},
    {"pnp.opnum", Kind::Uint, "Operation number"},
    {"mapi", Kind::Proto, "Exchange MAPI"},
    {"mapi.opnum", Kind::Uint, "Operation number"},
    {"kerberos", Kind::Proto, "Kerberos"},
    {"kerberos.msg_type", Kind::Int, "Message type (10 AS-REQ, 11 AS-REP, 12 TGS-REQ, 13 TGS-REP, 30 error)"},
    {"kerberos.pvno", Kind::Int, "Protocol version"},
    {"kerberos.CNameString", Kind::String, "Client name (user or machine account)"},
    {"kerberos.SNameString", Kind::String, "Service name"},
    {"kerberos.realm", Kind::String, "Realm"},
    {"kerberos.crealm", Kind::String, "Client realm"},
    {"kerberos.name_type", Kind::Int, "Name type"},
    {"kerberos.error_code", Kind::Int, "Error code"},
    {"kerberos.e_text", Kind::String, "Error text"},
    {"kerberos.addr_nb", Kind::String, "Client NetBIOS name"},
    {"kerberos.tkt_vno", Kind::Int, "Ticket version"},
    {"nbdgm", Kind::Proto, "NetBIOS datagram service"},
    {"nbdgm.type", Kind::Uint, "Message type"},
    {"nbdgm.src.ip", Kind::IPv4, "Source IP"},
    {"nbdgm.src.port", Kind::Uint, "Source port"},
    {"nbdgm.source_name", Kind::String, "Source name"},
    {"nbdgm.destination_name", Kind::String, "Destination name"},
    {"smb", Kind::Proto, "SMB"},
    {"smb.cmd", Kind::Uint, "SMB command"},
    {"smb.trans_name", Kind::String, "Transaction name"},
    {"mailslot", Kind::Proto, "SMB mailslot"},
    {"mailslot.name", Kind::String, "Mailslot name"},
    {"browser", Kind::Proto, "Windows browser protocol"},
    {"browser.command", Kind::Uint, "Browser command"},
    {"browser.server", Kind::String, "Server (computer) name"},
    {"browser.response_computer_name", Kind::String, "Response computer name"},
    {"browser.os_major", Kind::Uint, "Windows major version"},
    {"browser.os_minor", Kind::Uint, "Windows minor version"},
    {"browser.server_type", Kind::Uint, "Server type flags"},
    {"browser.server_type.workstation", Kind::Bool, "Workstation"},
    {"browser.server_type.server", Kind::Bool, "Server"},
    {"browser.server_type.domain_controller", Kind::Bool, "Domain controller"},
    {"browser.server_type.ntw", Kind::Bool, "NT workstation"},
    {"browser.server_type.nts", Kind::Bool, "NT server"},
    {"browser.comment", Kind::String, "Comment"},
    {"nbns", Kind::Proto, "NetBIOS name service"},
    {"nbns.name", Kind::String, "Name"},
    {"ntp", Kind::Proto, "NTP"},
    {"ssdp", Kind::Proto, "SSDP"},
    {"tftp", Kind::Proto, "TFTP"},
    {"syslog", Kind::Proto, "Syslog"},
    {"quic", Kind::Proto, "QUIC"},
    {"lldp", Kind::Proto, "LLDP"},
    {"stp", Kind::Proto, "Spanning tree"},
    {"stp.type", Kind::Uint, "BPDU type"},
    {"http", Kind::Proto, "HTTP"},
    {"http.request", Kind::Proto, "Is a request"},
    {"http.response", Kind::Proto, "Is a response"},
    {"http.request.method", Kind::String, "Request method"},
    {"http.request.uri", Kind::String, "Request URI"},
    {"http.request.full_uri", Kind::String, "Full request URI (http://host/path)"},
    {"http.request_in", Kind::Uint, "Frame of the request a response answers"},
    {"http.response_in", Kind::Uint, "Frame of the response that answers a request"},
    {"http.time", Kind::Double, "Seconds from the request to its response"},
    {"http.request.version", Kind::String, "Request version"},
    {"http.response.code", Kind::Uint, "Status code"},
    {"http.response.phrase", Kind::String, "Status phrase"},
    {"http.host", Kind::String, "Host"},
    {"http.user_agent", Kind::String, "User-Agent"},
    {"http.server", Kind::String, "Server"},
    {"http.content_type", Kind::String, "Content-Type"},
    {"http.content_length", Kind::Uint, "Content-Length"},
    {"http.transfer_encoding", Kind::String, "Transfer-Encoding"},
    {"ocsp", Kind::Proto, "OCSP"},
    {"json", Kind::Proto, "JSON"},
    {"xml", Kind::Proto, "XML"},
    {"http2", Kind::Proto, "HyperText Transfer Protocol 2"},
    {"http2.altsvc.field_value", Kind::String, "Field/Value"},
    {"http2.altsvc.origin", Kind::String, "Origin"},
    {"http2.altsvc.origin.len", Kind::Uint, "Origin Length"},
    {"http2.continuation.header", Kind::Bytes, "Header Block Fragment"},
    {"http2.data.data", Kind::Bytes, "Data"},
    {"http2.data.padding", Kind::Bytes, "Padding"},
    {"http2.exclusive", Kind::Bool, "Exclusive"},
    {"http2.flags", Kind::Uint, "Flags"},
    {"http2.flags.ack.ping", Kind::Bool, "ACK"},
    {"http2.flags.ack.settings", Kind::Bool, "ACK"},
    {"http2.flags.eh", Kind::Bool, "End Headers"},
    {"http2.flags.end_stream", Kind::Bool, "End Stream"},
    {"http2.flags.padded", Kind::Bool, "Padded"},
    {"http2.flags.priority", Kind::Bool, "Priority"},
    {"http2.goaway.addata", Kind::Bytes, "Additional Debug Data"},
    {"http2.goaway.error", Kind::Uint, "Error"},
    {"http2.goaway.last_stream_id", Kind::Uint, "Last-Stream-ID"},
    {"http2.goaway.r", Kind::Uint, "Reserved"},
    {"http2.header", Kind::Proto, "Header"},
    {"http2.header.count", Kind::Uint, "Header Count"},
    {"http2.header.index", Kind::Uint, "Index"},
    {"http2.header.length", Kind::Uint, "Header Length"},
    {"http2.header.name", Kind::String, "Name"},
    {"http2.header.name.length", Kind::Uint, "Name Length"},
    {"http2.header.repr", Kind::String, "Representation"},
    {"http2.header.unescaped", Kind::String, "Unescaped"},
    {"http2.header.value", Kind::String, "Value"},
    {"http2.header.value.length", Kind::Uint, "Value Length"},
    {"http2.header_table_size_update", Kind::Proto, "Header table size update"},
    {"http2.header_table_size_update.header_table_size", Kind::Uint, "Header table size"},
    {"http2.headers", Kind::Bytes, "Header Block Fragment"},
    {"http2.headers.accept", Kind::String, "accept"},
    {"http2.headers.accept_charset", Kind::String, "accept-charset"},
    {"http2.headers.accept_encoding", Kind::String, "accept-encoding"},
    {"http2.headers.accept_language", Kind::String, "accept-language"},
    {"http2.headers.accept_ranges", Kind::String, "accept-ranges"},
    {"http2.headers.access_control_allow_origin", Kind::String, "access-control-allow-origin"},
    {"http2.headers.age", Kind::Uint, "age"},
    {"http2.headers.allow", Kind::String, "allow"},
    {"http2.headers.authority", Kind::String, ":authority"},
    {"http2.headers.authorization", Kind::String, "authorization"},
    {"http2.headers.cache_control", Kind::String, "cache-control"},
    {"http2.headers.content_disposition", Kind::String, "content-disposition"},
    {"http2.headers.content_encoding", Kind::String, "content-encoding"},
    {"http2.headers.content_language", Kind::String, "content-language"},
    {"http2.headers.content_length", Kind::Uint, "content-length"},
    {"http2.headers.content_location", Kind::String, "content-location"},
    {"http2.headers.content_range", Kind::String, "content-range"},
    {"http2.headers.content_type", Kind::String, "content-type"},
    {"http2.headers.cookie", Kind::String, "cookie"},
    {"http2.headers.date", Kind::String, "date"},
    {"http2.headers.etag", Kind::String, "etag"},
    {"http2.headers.expect", Kind::String, "expect"},
    {"http2.headers.expires", Kind::String, "expires"},
    {"http2.headers.from", Kind::String, "from"},
    {"http2.headers.if_match", Kind::String, "if-match"},
    {"http2.headers.if_modified_since", Kind::String, "if-modified-since"},
    {"http2.headers.if_none_match", Kind::String, "if-none-match"},
    {"http2.headers.if_range", Kind::String, "if-range"},
    {"http2.headers.if_unmodified_since", Kind::String, "if-unmodified-since"},
    {"http2.headers.last_modified", Kind::String, "last-modified"},
    {"http2.headers.link", Kind::String, "link"},
    {"http2.headers.location", Kind::String, "location"},
    {"http2.headers.max_forwards", Kind::Uint, "max-forwards"},
    {"http2.headers.method", Kind::String, ":method"},
    {"http2.headers.padding", Kind::Bytes, "Padding"},
    {"http2.headers.path", Kind::String, ":path"},
    {"http2.headers.protocol", Kind::String, ":protocol"},
    {"http2.headers.proxy_authenticate", Kind::String, "proxy-authenticate"},
    {"http2.headers.proxy_authorization", Kind::String, "proxy-authorization"},
    {"http2.headers.range", Kind::String, "range"},
    {"http2.headers.referer", Kind::String, "referer"},
    {"http2.headers.refresh", Kind::String, "refresh"},
    {"http2.headers.retry_after", Kind::String, "retry-after"},
    {"http2.headers.scheme", Kind::String, ":scheme"},
    {"http2.headers.server", Kind::String, "server"},
    {"http2.headers.set_cookie", Kind::String, "set-cookie"},
    {"http2.headers.status", Kind::Uint, ":status"},
    {"http2.headers.strict_transport_security", Kind::String, "strict-transport-security"},
    {"http2.headers.user_agent", Kind::String, "user-agent"},
    {"http2.headers.vary", Kind::String, "vary"},
    {"http2.headers.via", Kind::String, "via"},
    {"http2.headers.weight", Kind::Uint, "Weight"},
    {"http2.headers.weight_real", Kind::Uint, "Weight real"},
    {"http2.headers.www_authenticate", Kind::String, "www-authenticate"},
    {"http2.length", Kind::Uint, "Length"},
    {"http2.magic", Kind::String, "Magic"},
    {"http2.origin", Kind::Proto, "Origin"},
    {"http2.origin.origin", Kind::String, "Origin"},
    {"http2.origin.origin_len", Kind::Uint, "Origin Length"},
    {"http2.pad_length", Kind::Uint, "Pad Length"},
    {"http2.padding", Kind::Uint, "Pad Length"},
    {"http2.ping", Kind::Bytes, "Ping"},
    {"http2.pong", Kind::Bytes, "Pong"},
    {"http2.priority_update_field_value", Kind::String, "Priority Update Field Value"},
    {"http2.priority_update_stream_id", Kind::Uint, "Priority Update Stream ID"},
    {"http2.push_promise.header", Kind::Bytes, "Header Block Fragment"},
    {"http2.push_promise.padding", Kind::Bytes, "Padding"},
    {"http2.push_promise.promised_stream_id", Kind::Uint, "Promised-Stream-ID"},
    {"http2.push_promise.r", Kind::Uint, "Reserved"},
    {"http2.r", Kind::Uint, "Reserved"},
    {"http2.request.full_uri", Kind::String, "Full request URI"},
    {"http2.request_in", Kind::Uint, "Request in frame"},
    {"http2.response_in", Kind::Uint, "Response in frame"},
    {"http2.rst_stream.error", Kind::Uint, "Error"},
    {"http2.settings", Kind::Proto, "Settings"},
    {"http2.settings.enable_push", Kind::Uint, "Enable PUSH"},
    {"http2.settings.extended_connect", Kind::Uint, "Extended CONNECT"},
    {"http2.settings.header_table_size", Kind::Uint, "Header table size"},
    {"http2.settings.id", Kind::Uint, "Settings Identifier"},
    {"http2.settings.initial_window_size", Kind::Uint, "Initial Window Size"},
    {"http2.settings.max_concurrent_streams", Kind::Uint, "Max concurrent streams"},
    {"http2.settings.max_frame_size", Kind::Uint, "Max frame size"},
    {"http2.settings.max_header_list_size", Kind::Uint, "Max header list size"},
    {"http2.settings.no_rfc7540_priorities", Kind::Uint, "No RFC7540 Priorities"},
    {"http2.settings.tls_reneg_permitted", Kind::Uint, "TLS Renegotiation Permitted"},
    {"http2.settings.unknown", Kind::Uint, "Unknown Settings"},
    {"http2.stream", Kind::Proto, "Stream"},
    {"http2.stream_dependency", Kind::Uint, "Stream Dependency"},
    {"http2.streamid", Kind::Uint, "Stream Identifier"},
    {"http2.time", Kind::Double, "Time since request"},
    {"http2.type", Kind::Uint, "Type"},
    {"http2.unknown", Kind::Bytes, "Unknown"},
    {"http2.window_update.r", Kind::Uint, "Reserved"},
    {"http2.window_update.window_size_increment", Kind::Uint, "Window Size Increment"},
    {"tls", Kind::Proto, "TLS"},
    {"tls.record.content_type", Kind::Uint, "Record content type"},
    {"tls.record.opaque_type", Kind::Uint, "Record type (TLS 1.3, encrypted)"},
    {"tls.record.version", Kind::Uint, "Record version"},
    {"tls.record.length", Kind::Uint, "Record length"},
    {"tls.reassembled_in", Kind::Uint, "Decrypted message reassembled in frame"},
    {"tls.handshake.type", Kind::Uint, "Handshake type"},
    {"tls.handshake.legacy_version", Kind::Proto, "legacy_version set alongside supported_versions"},
    {"tls.malformed.buffer_too_small", Kind::Proto, "Malformed: data too short"},
    {"tls.handshake.extensions_server_name", Kind::String, "Server name (SNI)"},
    {"tls.handshake.ja3_hash", Kind::String, "JA3 hash"},
    {"tcp.option_kind", Kind::Uint, "TCP option kind"},
    {"dhcp.option.request_list_item", Kind::Uint, "Parameter Request List Item"},
    {"tls.handshake.ja3", Kind::String, "JA3"},
    {"tls.handshake.ja3_full", Kind::String, "JA3 fullstring"},
    {"tls.handshake.ja3s", Kind::String, "JA3S"},
    {"tls.handshake.ja3s_full", Kind::String, "JA3S fullstring"},
    {"tls.handshake.ja4", Kind::String, "JA4"},
    {"tls.alert_message.desc", Kind::Uint, "Alert description"},
    {"dtls", Kind::Proto, "DTLS"},
    {"dtls.record.content_type", Kind::Uint, "Record content type"},
    {"dtls.record.version", Kind::Uint, "Record version"},
    {"dtls.record.epoch", Kind::Uint, "Record epoch"},
    {"dtls.record.sequence_number", Kind::Uint, "Record sequence number"},
    {"dtls.record.length", Kind::Uint, "Record length"},
    {"dtls.handshake.type", Kind::Uint, "Handshake type"},
    {"dtls.handshake.length", Kind::Uint, "Handshake message length"},
    {"dtls.handshake.message_seq", Kind::Uint, "Handshake message sequence"},
    {"dtls.handshake.fragment_offset", Kind::Uint, "Handshake fragment offset"},
    {"dtls.handshake.fragment_length", Kind::Uint, "Handshake fragment length"},
    {"dtls.handshake.extensions_server_name", Kind::String, "Server name (SNI)"},
    {"dtls.handshake.ja3", Kind::String, "JA3"},
    {"dtls.handshake.ja3_full", Kind::String, "JA3 fullstring"},
    {"dtls.handshake.ja3s", Kind::String, "JA3S"},
    {"dtls.handshake.ja3s_full", Kind::String, "JA3S fullstring"},
    {"dtls.handshake.ja4", Kind::String, "JA4"},
    {"dtls.alert_message.level", Kind::Uint, "Alert level"},
    {"dtls.alert_message.desc", Kind::Uint, "Alert description"},
    {"ssh", Kind::Proto, "SSH"},
    {"ssh.protocol", Kind::String, "Protocol banner"},
    {"ssh.message_code", Kind::Uint, "Message code"},
    {"ftp", Kind::Proto, "FTP"},
    {"ftp.request.command", Kind::String, "Request command"},
    {"ftp.request.arg", Kind::String, "Request argument"},
    {"ftp.response.code", Kind::Uint, "Response code"},
    {"ftp-data", Kind::Proto, "FTP data"},
    {"smtp", Kind::Proto, "SMTP"},
    {"pop", Kind::Proto, "POP"},
    {"imap", Kind::Proto, "IMAP"},
    {"telnet", Kind::Proto, "Telnet"},
    {"data", Kind::Proto, "Undissected data"},
    {"media", Kind::Proto, "Media type body"},
    {"data-text-lines", Kind::Proto, "Line-based text data"},
    {"png", Kind::Proto, "PNG image"},
    {"image-jfif", Kind::Proto, "JPEG image"},
    {"image-gif", Kind::Proto, "GIF image"},
    {"ssl", Kind::Proto, "TLS (old name)"},
    {"mysql", Kind::Proto, "MySQL"},
    {"mysql.packet_length", Kind::Uint, "Packet length"},
    {"mysql.packet_number", Kind::Uint, "Packet number in the exchange"},
    {"mysql.protocol", Kind::Uint, "Protocol version (server greeting)"},
    {"mysql.version", Kind::String, "Server version"},
    {"mysql.thread_id", Kind::Uint, "Connection (thread) ID"},
    {"mysql.user", Kind::String, "User name (login)"},
    {"mysql.schema", Kind::String, "Database"},
    {"mysql.command", Kind::Uint, "Command (3 query, 1 quit ...)"},
    {"mysql.query", Kind::String, "SQL statement"},
    {"mysql.response_code", Kind::Uint, "Response code (0 OK, 254 EOF, 255 error)"},
    {"mysql.error_code", Kind::Uint, "Error code"},
    {"mysql.sqlstate", Kind::String, "SQLSTATE"},
    {"mysql.error.message", Kind::String, "Error message"},
    {"mysql.affected_rows", Kind::Uint, "Rows affected"},
    {"mysql.num_fields", Kind::Uint, "Columns in a result"},
    {"mysql.eof", Kind::Uint, "End-of-data marker"},
    {"pgsql", Kind::Proto, "PostgreSQL"},
    {"pgsql.type", Kind::String, "Message type (\"Error\", \"Simple query\" ...)"},
    {"pgsql.length", Kind::Uint, "Message length"},
    {"pgsql.query", Kind::String, "SQL query"},
    {"pgsql.parameter_name", Kind::String, "Parameter name"},
    {"pgsql.parameter_value", Kind::String, "Parameter value"},
    {"pgsql.status", Kind::Uint, "Transaction status (73 idle, 84 in a transaction, 69 failed)"},
    {"pgsql.severity", Kind::String, "Severity (ERROR, FATAL ...)"},
    {"pgsql.text", Kind::String, "Severity, not translated"},
    {"pgsql.code", Kind::String, "SQLSTATE code"},
    {"pgsql.message", Kind::String, "Error or notice message"},
    {"pgsql.detail", Kind::String, "Detail"},
    {"pgsql.hint", Kind::String, "Hint"},
    {"pgsql.position", Kind::String, "Position in the query"},
    {"pgsql.file", Kind::String, "Server source file"},
    {"pgsql.line", Kind::String, "Server source line"},
    {"pgsql.routine", Kind::String, "Server routine"},
    {"tds", Kind::Proto, "Microsoft SQL Server (TDS)"},
    {"tds.type", Kind::Uint, "Packet type (1 SQL batch, 4 response, 16 login ...)"},
    {"tds.status", Kind::Uint, "Status (1: last packet of a message)"},
    {"tds.length", Kind::Uint, "Packet length"},
    {"tds.channel", Kind::Uint, "Channel"},
    {"tds.packet_number", Kind::Uint, "Packet number"},
    {"tds.window", Kind::Uint, "Window"},
    {"tds.query", Kind::String, "SQL batch text"},
    {"tds.error", Kind::Proto, "Error token"},
    {"tds.error.number", Kind::Uint, "SQL error number"},
    {"tds.error.state", Kind::Uint, "Error state"},
    {"tds.error.class", Kind::Uint, "Error severity class"},
    {"tds.error.msgtext", Kind::String, "Error message"},
    {"tds.error.servername", Kind::String, "Server name"},
    {"tds.error.procname", Kind::String, "Procedure name"},
    {"tds.error.linenumber", Kind::Uint, "Line number"},
    {"tds.info", Kind::Proto, "Info message token"},
    {"tds.info.number", Kind::Uint, "Message number"},
    {"tds.info.state", Kind::Uint, "Message state"},
    {"tds.info.class", Kind::Uint, "Message severity class"},
    {"tds.info.msgtext", Kind::String, "Message"},
    {"tds.info.servername", Kind::String, "Server name"},
    {"tds.info.procname", Kind::String, "Procedure name"},
    {"tds.info.linenumber", Kind::Uint, "Line number"},
};

const char* const kUnseenProtocols[] = {
    "hsrp", "ospf", "pim", "eigrp", "bgp", "vrrp", "carp", "rip", "glbp", "sctp", "smb", "smb2", "nbss", "netbios",
    "dcerpc", "http2", "cdp", "gvrp", "ismp", "systemd_journal", "sysdig", "mstp", "edp", "stt", "kerberos", "ldap",
    "snmp", "sip", "rtp", "rtcp", "nfs", "rdp", "radius", "cflow", "dhcpfo", "isakmp", "l2tp", "pptp", "openvpn",
    "wireguard", "rtsp", "mqtt", "modbus", "dnp3", "bacnet", "s7comm", "enip", "cip",
    "redis", "mongo", "amqp", "irc", "xmpp", "sflow", "tacplus", "kafka", "websocket", "grpc", "urlencoded-form",
    "eapol", "lacp", "cdp", "vtp", "dtp", "pvst", "bfd", "isis", "ldp", "rsvp", "msdp", "pim", "dvmrp", "olsr",
};

const char* const kUnseenFields[] = {
    "hsrp.state", "ospf.msg", "sctp.chunk_type", "eth.fcs.status", "ip.checksum.status", "tcp.checksum.status",
    "udp.checksum.status", "sctp.checksum.status", "mstp.checksum.status", "cdp.checksum.status",
    "edp.checksum.status", "wlan.fcs.status", "stt.checksum.status", "ip.checksum", "tcp.checksum", "udp.checksum",
};

struct Resolved {
    std::string name;  // canonical spelling
    Kind kind = Kind::Any;
    bool seen = true;  // false: Wireshark knows it, we never record it
};

bool resolve(const std::string& name, Resolved& out) {
    for (const auto& e : kFields)
        if (name == e.name) {
            out = {e.name, e.kind, true};
            if (name == "ssl") out.name = "tls";
            return true;
        }
    for (const char* p : kUnseenProtocols)
        if (name == p) {
            out = {name, Kind::Proto, false};
            return true;
        }
    for (const char* f : kUnseenFields)
        if (name == f) {
            out = {name, Kind::Any, false};
            return true;
        }
    return false;
}

// ------------------------------------------------------------------ lexer

struct Token {
    enum Type { End, Word, String, LParen, RParen, LBrace, RBrace, LBracket, RBracket, Comma, Op };
    Type type = End;
    std::string text;
    size_t pos = 0;
};

bool word_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == ':' || c == '-' || c == '/';
}

bool lex(const std::string& s, std::vector<Token>& out, std::string& error) {
    size_t i = 0;
    while (i < s.size()) {
        char c = s[i];
        if (std::isspace(static_cast<unsigned char>(c))) {
            ++i;
            continue;
        }
        Token t;
        t.pos = i;
        std::string two = s.substr(i, 2), three = s.substr(i, 3);
        if (c == '(' || c == ')' || c == '{' || c == '}' || c == '[' || c == ']' || c == ',') {
            t.type = c == '(' ? Token::LParen : c == ')' ? Token::RParen : c == '{' ? Token::LBrace
                   : c == '}' ? Token::RBrace : c == '[' ? Token::LBracket : c == ']' ? Token::RBracket : Token::Comma;
            t.text = std::string(1, c);
            ++i;
        } else if (three == "===" || three == "!==") {
            t.type = Token::Op;
            t.text = three;
            i += 3;
        } else if (two == "==" || two == "!=" || two == ">=" || two == "<=" || two == "&&" || two == "||" ||
                   two == "^^") {
            t.type = Token::Op;
            t.text = two;
            i += 2;
        } else if (c == '>' || c == '<' || c == '!' || c == '&' || c == '~') {
            t.type = Token::Op;
            t.text = std::string(1, c);
            ++i;
        } else if (c == '=') {
            error = "\"=\" is not a valid operator (use \"==\").";
            return false;
        } else if (c == '"') {
            std::string v;
            ++i;
            bool closed = false;
            while (i < s.size()) {
                char d = s[i++];
                if (d == '"') {
                    closed = true;
                    break;
                }
                if (d == '\\' && i < s.size()) {
                    char e = s[i++];
                    if (e == 'n') v += '\n';
                    else if (e == 't') v += '\t';
                    else if (e == 'r') v += '\r';
                    else if (e == 'x' && i + 1 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i])) &&
                             std::isxdigit(static_cast<unsigned char>(s[i + 1]))) {
                        v += static_cast<char>(std::strtoul(s.substr(i, 2).c_str(), nullptr, 16));
                        i += 2;
                    } else {
                        v += e;
                    }
                    continue;
                }
                v += d;
            }
            if (!closed) {
                error = "The string starting at column " + std::to_string(t.pos + 1) + " is not closed.";
                return false;
            }
            t.type = Token::String;
            t.text = v;
        } else if (word_char(c)) {
            size_t j = i;
            while (j < s.size() && word_char(s[j])) ++j;
            t.type = Token::Word;
            t.text = s.substr(i, j - i);
            i = j;
        } else {
            error = "\"" + std::string(1, c) + "\" was unexpected in this context.";
            return false;
        }
        out.push_back(t);
    }
    Token end;
    end.pos = s.size();
    out.push_back(end);
    return true;
}

// --------------------------------------------------------------- literals

struct Literal {
    // Numbers (also booleans and byte slices read as integers)
    bool is_num = false;
    bool is_double = false;
    uint64_t u = 0;
    double d = 0;
    // Strings, addresses, MACs and byte strings
    std::string s;
    int prefix = -1;  // CIDR length for addresses
};

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool parse_number(const std::string& t, uint64_t& v) {
    if (t.empty()) return false;
    std::string s = t;
    int base = 10;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s = s.substr(2);
    } else if (s.size() > 2 && s[0] == '0' && (s[1] == 'b' || s[1] == 'B')) {
        base = 2;
        s = s.substr(2);
    } else if (s.size() > 1 && s[0] == '0') {
        base = 8;
        s = s.substr(1);
    }
    if (s.empty()) return false;
    char* end = nullptr;
    errno = 0;
    unsigned long long x = std::strtoull(s.c_str(), &end, base);
    if (!end || *end || errno) return false;
    v = x;
    return true;
}

bool parse_ipv4(const std::string& t, std::string& out) {
    unsigned a[4];
    char tail;
    if (std::sscanf(t.c_str(), "%u.%u.%u.%u%c", &a[0], &a[1], &a[2], &a[3], &tail) != 4) return false;
    out.clear();
    for (unsigned x : a) {
        if (x > 255) return false;
        out.push_back(static_cast<char>(x));
    }
    return true;
}

bool parse_ipv6(const std::string& t, std::string& out) {
    // hex groups with at most one "::", optionally ending in a dotted IPv4
    std::vector<std::string> head, tail;
    size_t dc = t.find("::");
    if (dc != std::string::npos && t.find("::", dc + 1) != std::string::npos) return false;
    auto split = [](const std::string& s, std::vector<std::string>& v) {
        if (s.empty()) return;
        size_t a = 0;
        while (true) {
            size_t b = s.find(':', a);
            v.push_back(s.substr(a, b == std::string::npos ? std::string::npos : b - a));
            if (b == std::string::npos) break;
            a = b + 1;
        }
    };
    if (dc == std::string::npos) split(t, head);
    else {
        split(t.substr(0, dc), head);
        split(t.substr(dc + 2), tail);
    }
    std::vector<uint16_t> words;
    auto add = [&](std::vector<std::string>& parts, std::vector<uint16_t>& w) {
        for (size_t i = 0; i < parts.size(); ++i) {
            const std::string& p = parts[i];
            if (i + 1 == parts.size() && p.find('.') != std::string::npos) {
                std::string v4;
                if (!parse_ipv4(p, v4)) return false;
                w.push_back(static_cast<uint16_t>((static_cast<uint8_t>(v4[0]) << 8) | static_cast<uint8_t>(v4[1])));
                w.push_back(static_cast<uint16_t>((static_cast<uint8_t>(v4[2]) << 8) | static_cast<uint8_t>(v4[3])));
                continue;
            }
            if (p.empty() || p.size() > 4) return false;
            for (char c : p)
                if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
            w.push_back(static_cast<uint16_t>(std::strtoul(p.c_str(), nullptr, 16)));
        }
        return true;
    };
    std::vector<uint16_t> hw, tw;
    if (!add(head, hw) || !add(tail, tw)) return false;
    if (dc == std::string::npos ? hw.size() != 8 : hw.size() + tw.size() > 7) return false;
    words = hw;
    words.resize(8 - tw.size(), 0);
    words.insert(words.end(), tw.begin(), tw.end());
    out.clear();
    for (uint16_t w : words) {
        out.push_back(static_cast<char>(w >> 8));
        out.push_back(static_cast<char>(w & 0xFF));
    }
    return true;
}

bool parse_bytes(const std::string& t, std::string& out, size_t want = 0) {
    // aa:bb:cc, aa-bb-cc, aabb.ccdd.eeff, or plain hex digits
    std::string hex;
    char sep = 0;
    for (char c : t) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            hex += c;
        } else if (c == ':' || c == '-' || c == '.') {
            if (sep && c != sep) return false;
            sep = c;
        } else {
            return false;
        }
    }
    if (sep == ':' || sep == '-') {  // each group one byte (one or two digits)
        out.clear();
        size_t a = 0;
        while (a <= t.size()) {
            size_t b = t.find(sep, a);
            std::string g = t.substr(a, b == std::string::npos ? std::string::npos : b - a);
            if (g.empty() || g.size() > 2) return false;
            out.push_back(static_cast<char>(std::strtoul(g.c_str(), nullptr, 16)));
            if (b == std::string::npos) break;
            a = b + 1;
        }
    } else {
        if (hex.empty() || hex.size() % 2) return false;
        out.clear();
        for (size_t i = 0; i < hex.size(); i += 2)
            out.push_back(static_cast<char>(std::strtoul(hex.substr(i, 2).c_str(), nullptr, 16)));
    }
    return want == 0 || out.size() == want;
}

// ------------------------------------------------------------------ parser

}  // namespace

struct DisplayFilter::Node {
    enum Type { And, Or, Xor, Not, Test, False } type = Test;
    std::unique_ptr<Node> a, b;

    // Test
    enum Op { Exists, Eq, Ne, AllEq, AnyNe, Gt, Lt, Ge, Le, Contains, Matches, In, NotIn, BitAnd } op = Exists;
    std::string field;
    Kind kind = Kind::Any;
    bool seen = true;
    bool slice = false;
    long s_from = 0;
    long s_len = -1;  // -1: to the end
    Literal lit;
    bool masked = false;  // "field & mask <op> value"
    Literal mask;
    std::vector<std::pair<Literal, Literal>> set;
    // The same set when every element is an unsigned number: sorted, merged ranges for a
    // binary search (a selection of packets is a frame.number set of thousands of ranges).
    std::vector<std::pair<uint64_t, uint64_t>> uset;
    bool uset_ok = false;
    std::regex re;
};

namespace {

using Node = DisplayFilter::Node;

class Parser {
public:
    Parser(std::vector<Token> t) : t_(std::move(t)) {}

    std::unique_ptr<Node> parse(std::string& error) {
        auto n = expr();
        if (n && peek().type != Token::End) fail(peek(), "\"" + peek().text + "\" was unexpected in this context.");
        if (!err_.empty()) {
            error = err_;
            return nullptr;
        }
        return n;
    }

private:
    std::vector<Token> t_;
    size_t i_ = 0;
    std::string err_;
    // Evaluating and freeing the tree recurse along it: bound how deep it can get (the length
    // limit no longer does, since a selection of packets is a long filter).
    int depth_ = 0;
    size_t joins_ = 0;
    static constexpr int kMaxDepth = 200;
    static constexpr size_t kMaxJoins = 4000;

    const Token& peek(size_t k = 0) const { return t_[std::min(i_ + k, t_.size() - 1)]; }
    Token take() { return t_[std::min(i_++, t_.size() - 1)]; }
    bool is_word(const Token& t, const char* w) const { return t.type == Token::Word && lower(t.text) == w; }
    bool is_op(const Token& t, const char* o) const { return t.type == Token::Op && t.text == o; }
    std::unique_ptr<Node> fail(const Token& t, const std::string& msg) {
        if (err_.empty()) err_ = t.type == Token::End && msg.find("unexpected") != std::string::npos
                                     ? "Unexpected end of filter expression."
                                     : msg;
        return nullptr;
    }

    std::unique_ptr<Node> binary(Node::Type type, std::unique_ptr<Node> a, std::unique_ptr<Node> b) {
        if (++joins_ > kMaxJoins) return fail(peek(), "The filter has too many terms.");
        auto n = std::make_unique<Node>();
        n->type = type;
        n->a = std::move(a);
        n->b = std::move(b);
        return n;
    }

    std::unique_ptr<Node> expr() {
        auto left = xor_expr();
        while (left && (is_word(peek(), "or") || is_op(peek(), "||"))) {
            take();
            auto right = xor_expr();
            if (!right) return nullptr;
            left = binary(Node::Or, std::move(left), std::move(right));
        }
        return left;
    }

    std::unique_ptr<Node> xor_expr() {
        auto left = and_expr();
        while (left && (is_word(peek(), "xor") || is_op(peek(), "^^"))) {
            take();
            auto right = and_expr();
            if (!right) return nullptr;
            left = binary(Node::Xor, std::move(left), std::move(right));
        }
        return left;
    }

    std::unique_ptr<Node> and_expr() {
        auto left = unary();
        while (left && (is_word(peek(), "and") || is_op(peek(), "&&"))) {
            take();
            auto right = unary();
            if (!right) return nullptr;
            left = binary(Node::And, std::move(left), std::move(right));
        }
        return left;
    }

    std::unique_ptr<Node> unary() {
        struct Depth {
            int& d;
            explicit Depth(int& v) : d(v) { ++d; }
            ~Depth() { --d; }
        } guard(depth_);
        if (depth_ > kMaxDepth) return fail(peek(), "The filter is nested too deeply.");
        if (is_word(peek(), "not") || is_op(peek(), "!")) {
            take();
            auto inner = unary();
            if (!inner) return nullptr;
            auto n = std::make_unique<Node>();
            n->type = Node::Not;
            n->a = std::move(inner);
            return n;
        }
        if (peek().type == Token::LParen) {
            take();
            auto inner = expr();
            if (!inner) return nullptr;
            if (peek().type != Token::RParen) return fail(peek(), "Missing \")\".");
            take();
            return inner;
        }
        return test();
    }

    std::unique_ptr<Node> test() {
        Token f = take();
        if (f.type == Token::End) return fail(f, "Unexpected end of filter expression.");
        if (f.type != Token::Word) return fail(f, "\"" + f.text + "\" was unexpected in this context.");
        Resolved r;
        if (!resolve(f.text, r)) {
            // A bare value where a field was expected.
            return fail(f, "\"" + f.text + "\" is not a valid protocol or protocol field.");
        }
        auto n = std::make_unique<Node>();
        n->type = Node::Test;
        n->field = r.name;
        n->kind = r.kind;
        n->seen = r.seen;
        if (peek().type == Token::LBracket) {
            take();
            Token sl = take();
            if (sl.type != Token::Word || peek().type != Token::RBracket || !parse_slice(sl.text, *n))
                return fail(sl, "\"" + sl.text + "\" is not a valid slice.");
            take();
            if (n->kind != Kind::Proto && n->kind != Kind::Mac && n->kind != Kind::Bytes &&
                n->kind != Kind::String && n->kind != Kind::IPv4 && n->kind != Kind::IPv6 && n->kind != Kind::Any)
                return fail(f, "\"" + f.text + "\" cannot be sliced.");
        }
        const Token& o = peek();
        std::string ow = o.type == Token::Word ? lower(o.text) : (o.type == Token::Op ? o.text : "");
        static const std::pair<const char*, Node::Op> ops[] = {
            {"==", Node::Eq}, {"eq", Node::Eq}, {"any_eq", Node::Eq}, {"!=", Node::Ne}, {"ne", Node::Ne},
            {"all_ne", Node::Ne}, {"===", Node::AllEq}, {"all_eq", Node::AllEq}, {"!==", Node::AnyNe},
            {"any_ne", Node::AnyNe}, {">", Node::Gt}, {"gt", Node::Gt}, {"<", Node::Lt}, {"lt", Node::Lt},
            {">=", Node::Ge}, {"ge", Node::Ge}, {"<=", Node::Le}, {"le", Node::Le}, {"contains", Node::Contains},
            {"matches", Node::Matches}, {"~", Node::Matches}, {"in", Node::In}, {"&", Node::BitAnd},
            {"bitand", Node::BitAnd}};
        bool found = false;
        if (ow == "not" && is_word(peek(1), "in")) {
            take();
            take();
            n->op = Node::NotIn;
            found = true;
        } else {
            for (const auto& [name, op] : ops)
                if (ow == name) {
                    take();
                    n->op = op;
                    found = true;
                    break;
                }
        }
        if (!found) {
            n->op = Node::Exists;
            return n;
        }
        if (n->op == Node::In || n->op == Node::NotIn) {
            if (peek().type != Token::LBrace) return fail(peek(), "Expected a set {...} after \"in\".");
            take();
            // Wireshark 4.6: elements separated by commas, none leading, doubled or trailing.
            auto unexpected = [&](const Token& t) {
                if (t.type == Token::End) return fail(t, "Unexpected end of filter expression.");
                return fail(t, "\"" + (t.type == Token::String ? "\"" + t.text + "\"" : t.text) +
                                   "\" was unexpected in this context.");
            };
            for (bool first = true;; first = false) {
                if (!first) {
                    if (peek().type == Token::RBrace) break;
                    if (peek().type != Token::Comma) return unexpected(peek());
                    take();
                }
                if (peek().type != Token::Word && peek().type != Token::String) return unexpected(peek());
                Token v = take();
                std::string lo = v.text, hi;
                if (v.type == Token::Word) {
                    size_t dd = v.text.find("..");
                    if (dd != std::string::npos) {
                        lo = v.text.substr(0, dd);
                        hi = v.text.substr(dd + 2);
                        if (hi.empty()) {  // "3 .. 5" written with spaces
                            Token h = take();
                            hi = h.text;
                        }
                    } else if (peek().type == Token::Word && peek().text.rfind("..", 0) == 0) {
                        Token h = take();
                        hi = h.text.substr(2);
                        if (hi.empty()) hi = take().text;
                    }
                }
                Literal a, b;
                if (!literal(*n, lo, v.type == Token::String, a)) return nullptr;
                if (!hi.empty()) {
                    if (!literal(*n, hi, false, b)) return nullptr;
                } else {
                    b = a;
                }
                n->set.emplace_back(std::move(a), std::move(b));
            }
            take();
            if (n->set.empty()) return fail(peek(), "The set is empty.");
            n->uset_ok = std::all_of(n->set.begin(), n->set.end(), [](const auto& r) {
                return r.first.is_num && !r.first.is_double && r.second.is_num && !r.second.is_double;
            });
            if (n->uset_ok) {
                for (const auto& [lo, hi] : n->set)
                    if (lo.u <= hi.u) n->uset.emplace_back(lo.u, hi.u);
                std::sort(n->uset.begin(), n->uset.end());
                std::vector<std::pair<uint64_t, uint64_t>> merged;
                for (const auto& r : n->uset) {
                    if (merged.empty() || (merged.back().second != UINT64_MAX && r.first > merged.back().second + 1))
                        merged.push_back(r);
                    else  // (overlapping or adjacent, or the last range already runs to the end)
                        merged.back().second = std::max(merged.back().second, r.second);
                }
                n->uset = std::move(merged);
            }
            return n;
        }
        Token v = take();
        if (v.type != Token::Word && v.type != Token::String)
            return fail(v, v.type == Token::End ? "Unexpected end of filter expression."
                                                : "\"" + v.text + "\" was unexpected in this context.");
        if (n->op == Node::Matches) {
            std::string pat = v.text;
            auto flags = std::regex::ECMAScript;
            if (pat.rfind("(?i)", 0) == 0) {
                pat = pat.substr(4);
                flags |= std::regex::icase;
            }
            try {
                n->re = std::regex(pat, flags);
            } catch (const std::regex_error&) {
                return fail(v, "\"" + v.text + "\" is not a valid regular expression.");
            }
            if (n->kind != Kind::String && n->kind != Kind::Proto && n->kind != Kind::Bytes && n->kind != Kind::Any &&
                !n->slice)
                return fail(v, "\"matches\" needs a text field, not " + n->field + ".");
            return n;
        }
        if (n->op == Node::Contains && n->kind != Kind::String && n->kind != Kind::Proto && n->kind != Kind::Bytes &&
            n->kind != Kind::Mac && n->kind != Kind::Any && !n->slice)
            return fail(v, "\"contains\" needs a text or byte field, not " + n->field + ".");
        if (!literal(*n, v.text, v.type == Token::String, n->lit)) return nullptr;
        if (n->op == Node::BitAnd) {  // optionally compared: "tcp.flags & 0x12 == 0x12"
            const Token& r = peek();
            std::string rw = r.type == Token::Word ? lower(r.text) : (r.type == Token::Op ? r.text : "");
            static const std::pair<const char*, Node::Op> rel[] = {
                {"==", Node::Eq}, {"eq", Node::Eq}, {"!=", Node::Ne}, {"ne", Node::Ne}, {">", Node::Gt},
                {"gt", Node::Gt}, {"<", Node::Lt}, {"lt", Node::Lt}, {">=", Node::Ge}, {"ge", Node::Ge},
                {"<=", Node::Le}, {"le", Node::Le}};
            for (const auto& [name, op] : rel)
                if (rw == name) {
                    take();
                    Token v2 = take();
                    if (v2.type != Token::Word) return fail(v2, "Expected a number after \"" + rw + "\".");
                    Literal value;
                    if (!parse_number(v2.text, value.u)) return fail(v2, "\"" + v2.text + "\" is not a valid number.");
                    value.is_num = true;
                    n->masked = true;
                    n->mask = n->lit;
                    n->lit = value;
                    n->op = op;
                    break;
                }
        }
        return n;
    }

    static bool parse_slice(const std::string& s, Node& n) {
        // [i], [i:len], [i-j], [i:], [:len]
        auto num = [](const std::string& x, long& v) {
            if (x.empty()) return false;
            char* end = nullptr;
            v = std::strtol(x.c_str(), &end, 10);
            return end && !*end;
        };
        n.slice = true;
        size_t c = s.find(':'), d = s.find('-', 1);
        long a = 0, b = 0;
        if (c != std::string::npos) {
            if (c > 0 && !num(s.substr(0, c), a)) return false;
            if (c + 1 < s.size()) {
                if (!num(s.substr(c + 1), b) || b <= 0) return false;
                n.s_len = b;
            }
            n.s_from = a;
            return true;
        }
        if (d != std::string::npos) {
            if (!num(s.substr(0, d), a) || !num(s.substr(d + 1), b) || b < a) return false;
            n.s_from = a;
            n.s_len = b - a + 1;
            return true;
        }
        if (!num(s, a)) return false;
        n.s_from = a;
        n.s_len = 1;
        return true;
    }

    // Convert a literal for comparison with `n`'s field type.
    bool literal(const Node& n, const std::string& text, bool quoted, Literal& out) {
        Token at;
        auto bad = [&](const std::string& what) {
            fail(at, "\"" + text + "\" is not a valid " + what + ".");
            return false;
        };
        if (!n.seen || n.kind == Kind::Any) {  // a field we never record: anything goes
            out.s = text;
            out.is_num = !quoted && parse_number(text, out.u);
            return true;
        }
        if (n.slice || n.kind == Kind::Proto || n.kind == Kind::Bytes) {
            if (quoted) {
                out.s = text;
                return true;
            }
            if (n.op != Node::Contains && parse_number(text, out.u) && text.find(':') == std::string::npos) {
                out.is_num = true;
                return true;
            }
            if (!parse_bytes(text, out.s)) return bad("byte string");
            return true;
        }
        switch (n.kind) {
            case Kind::Uint:
            case Kind::Int:
            case Kind::Bool: {
                std::string l = lower(text);
                if (n.kind == Kind::Bool && (l == "true" || l == "false")) {
                    out.is_num = true;
                    out.u = l == "true";
                    return true;
                }
                if (quoted || !parse_number(text, out.u)) {
                    if (n.kind == Kind::Int && !text.empty() && text[0] == '-') {
                        uint64_t v;
                        if (parse_number(text.substr(1), v)) {
                            out.is_num = true;
                            out.u = static_cast<uint64_t>(-static_cast<int64_t>(v));
                            return true;
                        }
                    }
                    return bad("number");
                }
                out.is_num = true;
                return true;
            }
            case Kind::Double: {
                char* end = nullptr;
                out.d = std::strtod(text.c_str(), &end);
                if (quoted || text.empty() || !end || *end) return bad("number");
                out.is_double = true;
                return true;
            }
            case Kind::String: out.s = text; return true;
            case Kind::IPv4:
            case Kind::IPv6: {
                std::string addr = text;
                size_t slash = text.find('/');
                if (slash != std::string::npos) {
                    char* end = nullptr;
                    long p = std::strtol(text.c_str() + slash + 1, &end, 10);
                    if (!end || *end || p < 0 || p > (n.kind == Kind::IPv4 ? 32 : 128)) return bad("network prefix");
                    out.prefix = static_cast<int>(p);
                    addr = text.substr(0, slash);
                }
                bool ok = n.kind == Kind::IPv4 ? parse_ipv4(addr, out.s) : parse_ipv6(addr, out.s);
                if (quoted || !ok) return bad(n.kind == Kind::IPv4 ? "IPv4 address" : "IPv6 address");
                return true;
            }
            case Kind::Mac:
                if (quoted || !parse_bytes(text, out.s, 6)) return bad("Ethernet address");
                return true;
            default: return bad("value");
        }
    }
};

// -------------------------------------------------------------- evaluation

int cmp_bytes(const std::string& a, const std::string& b) {
    int c = std::memcmp(a.data(), b.data(), std::min(a.size(), b.size()));
    if (c) return c < 0 ? -1 : 1;
    return a.size() < b.size() ? -1 : a.size() > b.size() ? 1 : 0;
}

bool prefix_eq(const std::string& addr, const std::string& net, int prefix) {
    if (addr.size() != net.size()) return false;
    if (prefix < 0) return addr == net;
    int full = prefix / 8, rest = prefix % 8;
    if (std::memcmp(addr.data(), net.data(), static_cast<size_t>(full)) != 0) return false;
    if (!rest) return true;
    uint8_t mask = static_cast<uint8_t>(0xFF << (8 - rest));
    return (static_cast<uint8_t>(addr[full]) & mask) == (static_cast<uint8_t>(net[full]) & mask);
}

// One comparable value pulled out of the frame for a test.
struct Item {
    bool num = false;
    bool dbl = false;
    uint64_t u = 0;
    double d = 0;
    std::string s;      // text or bytes
    bool addr = false;  // s holds an address (prefix-aware equality)
};

uint64_t as_uint(const std::string& b) {
    uint64_t v = 0;
    for (size_t i = 0; i < b.size() && i < 8; ++i) v = (v << 8) | static_cast<uint8_t>(b[i]);
    return v;
}

// <0, 0, >0 like strcmp; `ok` false when the two can't be compared.
int compare(const Item& it, const Literal& lit, bool& ok) {
    ok = true;
    if (it.dbl || lit.is_double) {
        double a = it.dbl ? it.d : static_cast<double>(it.u);
        double b = lit.is_double ? lit.d : static_cast<double>(lit.u);
        if (!it.dbl && !it.num) {
            ok = false;
            return 0;
        }
        return a < b ? -1 : a > b ? 1 : 0;
    }
    if (lit.is_num) {
        uint64_t a = it.num ? it.u : as_uint(it.s);
        if (!it.num && it.s.size() > 8) {
            ok = false;
            return 0;
        }
        return a < lit.u ? -1 : a > lit.u ? 1 : 0;
    }
    if (it.num) {
        ok = false;
        return 0;
    }
    if (it.addr && lit.prefix >= 0) return prefix_eq(it.s, lit.s, lit.prefix) ? 0 : cmp_bytes(it.s, lit.s);
    return cmp_bytes(it.s, lit.s);
}

void gather(const Node& n, const FrameFields& f, std::vector<Item>& out) {
    auto take_slice = [&](const std::string& bytes) {
        long from = n.s_from < 0 ? static_cast<long>(bytes.size()) + n.s_from : n.s_from;
        if (from < 0 || static_cast<size_t>(from) > bytes.size()) return;
        size_t len = n.s_len < 0 ? bytes.size() - static_cast<size_t>(from) : static_cast<size_t>(n.s_len);
        if (static_cast<size_t>(from) + len > bytes.size()) return;
        Item it;
        it.s = bytes.substr(static_cast<size_t>(from), len);
        out.push_back(std::move(it));
    };
    if (n.kind == Kind::Proto) {
        for (const auto& p : f.protos)
            if (n.field == p.name) {
                std::string bytes;
                if (f.frame && p.offset <= f.frame_len)
                    bytes.assign(reinterpret_cast<const char*>(f.frame) + p.offset,
                                 std::min<size_t>(p.length, f.frame_len - p.offset));
                if (n.slice) take_slice(bytes);
                else {
                    Item it;
                    it.s = std::move(bytes);
                    out.push_back(std::move(it));
                }
            }
        return;
    }
    for (const auto& fld : f.fields) {
        if (n.field != fld.name) continue;
        const FieldValue& v = fld.value;
        Item it;
        switch (v.type) {
            case FieldValue::kUint:
            case FieldValue::kInt:
                it.num = true;
                it.u = v.u;
                break;
            case FieldValue::kDouble:
                it.dbl = true;
                it.d = v.d;
                break;
            case FieldValue::kIPv4:
            case FieldValue::kIPv6:
                it.addr = true;
                it.s = v.s;
                break;
            default: it.s = v.s;
        }
        if (n.slice) {
            if (it.num || it.dbl) continue;
            take_slice(it.s);
        } else {
            out.push_back(std::move(it));
        }
    }
}

bool eval(const Node& n, const FrameFields& f) {
    switch (n.type) {
        case Node::And: return eval(*n.a, f) && eval(*n.b, f);
        case Node::Or: return eval(*n.a, f) || eval(*n.b, f);
        case Node::Xor: return eval(*n.a, f) != eval(*n.b, f);
        case Node::Not: return !eval(*n.a, f);
        case Node::False: return false;
        case Node::Test: break;
    }
    if (!n.seen) return false;
    std::vector<Item> items;
    gather(n, f, items);
    if (items.empty()) return false;
    if (n.masked) {
        uint64_t m = n.mask.is_num ? n.mask.u : as_uint(n.mask.s);
        for (auto& it : items) {
            uint64_t v = it.num ? it.u : as_uint(it.s);
            it = Item();
            it.num = true;
            it.u = v & m;
        }
    }
    if (n.op == Node::Exists) return true;
    auto one = [&](const Item& it) -> bool {
        bool ok = true;
        switch (n.op) {
            case Node::Eq:
            case Node::AllEq: return compare(it, n.lit, ok) == 0 && ok;
            case Node::Ne:
            case Node::AnyNe: {
                int c = compare(it, n.lit, ok);
                return ok && c != 0;
            }
            case Node::Gt: return compare(it, n.lit, ok) > 0 && ok;
            case Node::Lt: return compare(it, n.lit, ok) < 0 && ok;
            case Node::Ge: return compare(it, n.lit, ok) >= 0 && ok;
            case Node::Le: return compare(it, n.lit, ok) <= 0 && ok;
            case Node::Contains: {
                if (it.num || it.dbl) return false;
                const std::string& needle = n.lit.s;
                return it.s.find(needle) != std::string::npos;
            }
            case Node::Matches:
                if (it.num || it.dbl) return false;
                return std::regex_search(it.s, n.re);
            case Node::In:
            case Node::NotIn: {
                bool in = false;
                if (n.uset_ok && it.num && !it.dbl) {  // sorted ranges: a binary search
                    auto r = std::upper_bound(n.uset.begin(), n.uset.end(), std::make_pair(it.u, UINT64_MAX));
                    in = r != n.uset.begin() && std::prev(r)->second >= it.u;
                    return n.op == Node::In ? in : !in;
                }
                for (const auto& [lo, hi] : n.set) {
                    bool ok1 = true, ok2 = true;
                    int a = compare(it, lo, ok1);
                    int b = compare(it, hi, ok2);
                    if (ok1 && ok2 && a >= 0 && b <= 0) {
                        in = true;
                        break;
                    }
                }
                return n.op == Node::In ? in : !in;
            }
            case Node::BitAnd: {
                uint64_t v = it.num ? it.u : as_uint(it.s);
                return n.lit.is_num ? (v & n.lit.u) != 0 : (v & as_uint(n.lit.s)) != 0;
            }
            default: return false;
        }
    };
    // "!=" / "not in": every occurrence; "===": every occurrence; the rest: any.
    if (n.op == Node::Ne || n.op == Node::AllEq || n.op == Node::NotIn)
        return std::all_of(items.begin(), items.end(), one);
    return std::any_of(items.begin(), items.end(), one);
}

}  // namespace

DisplayFilter::~DisplayFilter() = default;

namespace {
// Error messages quote the filter; keep them printable whatever bytes it held.
std::string printable(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t n = c < 0x80 ? 1 : c >= 0xF0 && c < 0xF5 ? 4 : c >= 0xE0 ? 3 : c >= 0xC2 ? 2 : 0;
        bool ok = n > 1 && i + n <= s.size();
        for (size_t k = 1; ok && k < n; ++k) ok = (static_cast<unsigned char>(s[i + k]) & 0xC0) == 0x80;
        if (n == 1 && c >= 0x20 && c != 0x7F) {
            out += static_cast<char>(c);
        } else if (ok) {
            out.append(s, i, n);
            i += n - 1;
        } else {
            static const char hex[] = "0123456789abcdef";
            out += "\\x";
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
    return out;
}
}  // namespace

std::unique_ptr<DisplayFilter> DisplayFilter::compile(const std::string& text, std::string& error) {
    auto f = compile_unchecked(text, error);
    if (!f) error = printable(error);
    return f;
}

std::unique_ptr<DisplayFilter> DisplayFilter::compile_unchecked(const std::string& text, std::string& error) {
    error.clear();
    std::string trimmed = text;
    trimmed.erase(0, trimmed.find_first_not_of(" \t\r\n"));
    trimmed.erase(trimmed.find_last_not_of(" \t\r\n") + 1);
    if (trimmed.empty()) {
        error = "The filter is empty.";
        return nullptr;
    }
    if (trimmed.size() > (16u << 20)) {  // (a selection of many packets is long; depth and terms are bounded)
        error = "The filter is too long.";
        return nullptr;
    }
    std::vector<Token> tokens;
    if (!lex(trimmed, tokens, error)) return nullptr;
    Parser p(std::move(tokens));
    auto root = p.parse(error);
    if (!root) return nullptr;
    std::unique_ptr<DisplayFilter> f(new DisplayFilter());
    f->root_ = std::move(root);
    return f;
}

bool DisplayFilter::match(const FrameFields& frame) const { return root_ && eval(*root_, frame); }

std::string filter_literal(const FieldValue& v) {
    char buf[64];
    const auto* b = reinterpret_cast<const uint8_t*>(v.s.data());
    switch (v.type) {
        case FieldValue::kUint: return std::to_string(v.u);
        case FieldValue::kInt: return std::to_string(static_cast<int64_t>(v.u));
        case FieldValue::kDouble:
            // The shortest fixed-point form that reads back as the same value, so a
            // filter built from it matches (times like 1756493140.598248).
            for (int digits = 0; digits <= 9; ++digits) {
                std::snprintf(buf, sizeof buf, "%.*f", digits, v.d);
                if (std::strtod(buf, nullptr) == v.d) return buf;
            }
            std::snprintf(buf, sizeof buf, "%.17g", v.d);
            return buf;
        case FieldValue::kIPv4:
            std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
            return buf;
        case FieldValue::kIPv6: {
            // RFC 5952: longest run of zero groups as "::"
            uint16_t g[8];
            for (int i = 0; i < 8; ++i) g[i] = static_cast<uint16_t>((b[2 * i] << 8) | b[2 * i + 1]);
            int best = -1, best_len = 0;
            for (int i = 0; i < 8;) {
                int j = i;
                while (j < 8 && g[j] == 0) ++j;
                if (j - i > best_len && j - i > 1) {
                    best = i;
                    best_len = j - i;
                }
                i = j == i ? i + 1 : j;
            }
            std::string out;
            for (int i = 0; i < 8; ++i) {
                if (i == best) {
                    out += "::";
                    i += best_len - 1;
                    continue;
                }
                if (!out.empty() && out.back() != ':') out += ':';
                std::snprintf(buf, sizeof buf, "%x", g[i]);
                out += buf;
            }
            return out;
        }
        case FieldValue::kMac:
        case FieldValue::kBytes: {
            std::string out;
            for (size_t i = 0; i < v.s.size(); ++i) {
                std::snprintf(buf, sizeof buf, i ? ":%02x" : "%02x", b[i]);
                out += buf;
            }
            return out;
        }
        case FieldValue::kString: {
            std::string out = "\"";
            for (char c : v.s) {
                if (c == '"' || c == '\\') out += '\\';
                out += c;
            }
            return out + "\"";
        }
        default: return "";
    }
}

std::vector<std::string> filter_field_catalog() {
    std::vector<std::string> out;
    static const char* names[] = {"Protocol", "Unsigned integer", "Signed integer", "Boolean", "Time offset",
                                  "Character string", "IPv4 address", "IPv6 address", "Ethernet address",
                                  "Byte sequence", "Any"};
    for (const auto& e : kFields) {
        if (std::strcmp(e.name, "ssl") == 0) continue;
        out.push_back(std::string(e.name) + "\t" + names[static_cast<int>(e.kind)] + "\t" + e.desc);
    }
    return out;
}

}  // namespace anta
