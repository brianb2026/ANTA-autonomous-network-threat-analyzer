// Wire-format protocol headers. All multi-byte fields are network byte order;
// callers convert with ntohs/ntohl. Structs are packed so they can be overlaid
// directly on frame memory (we still bounds-check before every overlay).
#pragma once

#include <cstdint>

namespace anta::wire {

#pragma pack(push, 1)

struct EthernetHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
};

struct VlanTag {
    uint16_t tci;
    uint16_t ethertype;
};

struct Ipv4Header {
    uint8_t ver_ihl;      // version (4 bits) | IHL in 32-bit words (4 bits)
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;    // flags (3 bits) | fragment offset (13 bits)
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;

    uint8_t version() const { return ver_ihl >> 4; }
    uint8_t header_len() const { return static_cast<uint8_t>((ver_ihl & 0x0F) * 4); }
};

struct Ipv6Header {
    uint32_t ver_tc_flow; // version (4) | traffic class (8) | flow label (20)
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t saddr[16];
    uint8_t daddr[16];
};

struct Ipv6ExtHeader {
    uint8_t next_header;
    uint8_t hdr_ext_len;  // in 8-octet units, not counting the first 8
};

struct TcpHeader {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_off;     // data offset in 32-bit words (high 4 bits)
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;

    uint8_t header_len() const { return static_cast<uint8_t>((data_off >> 4) * 4); }
};

struct UdpHeader {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
};

#pragma pack(pop)

static_assert(sizeof(EthernetHeader) == 14, "ethernet header must be 14 bytes");
static_assert(sizeof(Ipv4Header) == 20, "ipv4 header must be 20 bytes");
static_assert(sizeof(Ipv6Header) == 40, "ipv6 header must be 40 bytes");
static_assert(sizeof(TcpHeader) == 20, "tcp header must be 20 bytes");
static_assert(sizeof(UdpHeader) == 8, "udp header must be 8 bytes");

constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t ETHERTYPE_ARP = 0x0806;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;
constexpr uint16_t ETHERTYPE_QINQ = 0x88A8;

constexpr uint8_t IPPROTO_TCP_ = 6;
constexpr uint8_t IPPROTO_UDP_ = 17;

constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_PSH = 0x08;
constexpr uint8_t TCP_ACK = 0x10;

}  // namespace anta::wire
