// Layer 2-4 dissection into a flat PacketInfo record.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace anta {

// Link types we know how to strip (values are LINKTYPE_* / DLT_* numbers). Any
// other value read from a capture is still a valid LinkType; it just isn't decoded.
enum class LinkType : int {
    Null = 0,          // BSD loopback, 4-byte host-order AF family
    Ethernet = 1,
    Ppp = 9,
    Raw12 = 12,        // DLT_RAW on most BSDs
    Raw14 = 14,        // DLT_RAW on OpenBSD
    PppHdlc = 50,
    Raw = 101,         // LINKTYPE_RAW
    CiscoHdlc = 104,
    Ieee80211 = 105,
    Loop = 108,        // OpenBSD loopback, network-order family
    LinuxSll = 113,    // Linux "cooked" capture v1 (any device, older libpcap)
    Radiotap = 127,    // 802.11 with radiotap header
    User2 = 149,       // macOS PKTAP on older releases
    Ppi = 192,         // 802.11 with PPI header
    Ipv4 = 228,
    Ipv6 = 229,
    Nflog = 239,       // Linux netfilter log
    Pktap = 258,       // macOS PKTAP (per-packet process/interface metadata)
    LinuxSll2 = 276,   // Linux "cooked" capture v2 (default for `-i any` today)
};

struct IpAddr {
    uint8_t family = 0;                 // 4 or 6
    std::array<uint8_t, 16> bytes{};    // IPv4 uses the first 4 bytes

    std::string str() const;
    bool operator==(const IpAddr& o) const { return family == o.family && bytes == o.bytes; }
    bool operator<(const IpAddr& o) const {
        return family != o.family ? family < o.family : bytes < o.bytes;
    }
};

struct PacketInfo {
    uint64_t ts_us = 0;            // capture timestamp, microseconds since epoch
    uint32_t wire_len = 0;         // original frame length
    IpAddr src, dst;
    uint8_t proto = 0;             // 6 = TCP, 17 = UDP
    uint16_t sport = 0, dport = 0;

    // TCP-only fields (host byte order)
    uint32_t seq = 0, ack = 0;
    uint8_t tcp_flags = 0;
    uint16_t window = 0;

    const uint8_t* l4 = nullptr;       // start of the TCP/UDP/ICMP header
    uint16_t l4_hlen = 0;              // TCP/UDP header length (TCP options live in between)
    uint8_t ttl = 0;                   // IPv4 TTL / IPv6 hop limit of the innermost IP header
    uint8_t tunnels = 0;               // encapsulation layers removed (GRE, VXLAN, IP-in-IP, ...)
    const uint8_t* payload = nullptr;  // L4 payload, points into the frame buffer
    uint32_t payload_len = 0;          // bytes actually captured (may be < claimed if snaplen cut)
    uint32_t payload_claimed = 0;      // bytes the IP header says are present
};

enum class DissectResult { Ok, NotIp, Truncated, Fragment, UnsupportedL4 };

// Parse a captured frame. `caplen` is the number of bytes available in `data`.
// Tunnels (GRE incl. ERSPAN, VXLAN, Geneve, IP-in-IP) are unwrapped: the result
// describes the innermost conversation. For ICMP/other L4 protocols the result is
// UnsupportedL4 but addresses, `l4` and `payload` are still filled in.
DissectResult dissect(LinkType link, const uint8_t* data, size_t caplen, PacketInfo& out);

// The sender's hardware and IPv4 address from an ARP packet (reply or request).
// For the non-IP ARP frames `dissect` rejects, so the analysis path can spot an IP
// claimed by two MACs (cache poisoning) without the full inspector.
struct ArpClaim {
    uint8_t mac[6];
    uint32_t ipv4;  // network byte order
};
bool parse_arp(LinkType link, const uint8_t* data, size_t caplen, ArpClaim& out);

// True for link types this build can decode down to the network layer.
bool link_type_supported(LinkType link);
const char* link_type_name(LinkType link);

}  // namespace anta
