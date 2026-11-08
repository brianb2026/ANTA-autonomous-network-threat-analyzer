#include "packet.h"

#include <algorithm>
#include <cstring>

#include "headers.h"
#include "platform.h"

namespace anta {

using namespace wire;

std::string IpAddr::str() const {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (family == 4) {
        inet_ntop(AF_INET, bytes.data(), buf, sizeof(buf));
    } else if (family == 6) {
        inet_ntop(AF_INET6, bytes.data(), buf, sizeof(buf));
    }
    return buf;
}

namespace {

constexpr int kMaxDepth = 4;  // nested link layers / tunnels we will unwrap

template <typename T>
const T* overlay(const uint8_t* base, size_t len, size_t off) {
    if (off > len || sizeof(T) > len - off) return nullptr;
    return reinterpret_cast<const T*>(base + off);
}

inline bool have(size_t n, size_t off, size_t len) { return off <= n && len <= n - off; }
inline uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
inline uint16_t le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
inline uint32_t le32(const uint8_t* p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

DissectResult parse_ipv4(const uint8_t* data, size_t caplen, size_t off, PacketInfo& out, int depth);
DissectResult parse_ipv6(const uint8_t* data, size_t caplen, size_t off, PacketInfo& out, int depth);
DissectResult from_link(LinkType link, const uint8_t* data, size_t caplen, size_t off, PacketInfo& out, int depth);

DissectResult parse_l3(uint16_t ethertype, const uint8_t* data, size_t caplen, size_t off, PacketInfo& out,
                       int depth) {
    if (ethertype == ETHERTYPE_IPV4) return parse_ipv4(data, caplen, off, out, depth);
    if (ethertype == ETHERTYPE_IPV6) return parse_ipv6(data, caplen, off, out, depth);
    if (ethertype == 0) {  // no ethertype: peek the IP version nibble
        if (off >= caplen) return DissectResult::Truncated;
        uint8_t version = data[off] >> 4;
        if (version == 4) return parse_ipv4(data, caplen, off, out, depth);
        if (version == 6) return parse_ipv6(data, caplen, off, out, depth);
    }
    return DissectResult::NotIp;
}

// Ethernet II / 802.3, with VLAN stacks, LLC/SNAP, MPLS and PPPoE sessions.
DissectResult parse_ethernet(const uint8_t* data, size_t caplen, size_t off, PacketInfo& out, int depth) {
    auto* eth = overlay<EthernetHeader>(data, caplen, off);
    if (!eth) return DissectResult::Truncated;
    uint16_t type = ntohs(eth->ethertype);
    off += sizeof(EthernetHeader);
    for (int i = 0; i < 3 && (type == ETHERTYPE_VLAN || type == ETHERTYPE_QINQ || type == 0x9100); ++i) {
        auto* tag = overlay<VlanTag>(data, caplen, off);
        if (!tag) return DissectResult::Truncated;
        type = ntohs(tag->ethertype);
        off += sizeof(VlanTag);
    }
    if (type <= 1500) {  // 802.3 length field: LLC follows; only SNAP carries an ethertype
        if (!have(caplen, off, 8)) return DissectResult::Truncated;
        if (data[off] != 0xAA || data[off + 1] != 0xAA || data[off + 2] != 0x03) return DissectResult::NotIp;
        type = be16(data + off + 6);
        off += 8;
    }
    if (type == 0x8847 || type == 0x8848) {  // MPLS: skip labels to bottom of stack
        for (int i = 0; i < 8; ++i) {
            if (!have(caplen, off, 4)) return DissectResult::Truncated;
            bool bottom = data[off + 2] & 0x01;
            off += 4;
            if (bottom) return parse_l3(0, data, caplen, off, out, depth);
        }
        return DissectResult::NotIp;
    }
    if (type == 0x8864) {  // PPPoE session: 6-byte header + PPP protocol
        if (!have(caplen, off, 8)) return DissectResult::Truncated;
        uint16_t ppp = be16(data + off + 6);
        off += 8;
        if (ppp == 0x0021) return parse_ipv4(data, caplen, off, out, depth);
        if (ppp == 0x0057) return parse_ipv6(data, caplen, off, out, depth);
        return DissectResult::NotIp;
    }
    return parse_l3(type, data, caplen, off, out, depth);
}

DissectResult parse_ppp(const uint8_t* data, size_t caplen, size_t off, PacketInfo& out, int depth) {
    if (have(caplen, off, 2) && data[off] == 0xFF && data[off + 1] == 0x03) off += 2;  // HDLC address/control
    if (!have(caplen, off, 1)) return DissectResult::Truncated;
    uint16_t proto;
    if (data[off] & 0x01) {  // protocol-field compression: one byte
        proto = data[off];
        off += 1;
    } else {
        if (!have(caplen, off, 2)) return DissectResult::Truncated;
        proto = be16(data + off);
        off += 2;
    }
    if (proto == 0x0021) return parse_ipv4(data, caplen, off, out, depth);
    if (proto == 0x0057) return parse_ipv6(data, caplen, off, out, depth);
    return DissectResult::NotIp;
}

// IEEE 802.11 data frame -> LLC/SNAP -> ethertype. Encrypted frames can't be read.
DissectResult parse_80211(const uint8_t* data, size_t caplen, size_t off, PacketInfo& out, int depth) {
    if (!have(caplen, off, 24)) return DissectResult::Truncated;
    uint16_t fc = le16(data + off);
    uint8_t type = (fc >> 2) & 0x3, subtype = (fc >> 4) & 0xF, flags = fc >> 8;
    if (type != 2 || (subtype & 0x4)) return DissectResult::NotIp;  // not data, or a null/no-data frame
    if (flags & 0x40) return DissectResult::NotIp;                    // protected (encrypted)
    size_t hlen = 24;
    if ((flags & 0x03) == 0x03) hlen += 6;  // four-address (WDS)
    if (subtype & 0x8) {                    // QoS data
        hlen += 2;
        if (flags & 0x80) hlen += 4;        // HT control
    }
    off += hlen;
    if (!have(caplen, off, 8)) return DissectResult::Truncated;
    if (data[off] != 0xAA || data[off + 1] != 0xAA || data[off + 2] != 0x03) return DissectResult::NotIp;
    return parse_l3(be16(data + off + 6), data, caplen, off + 8, out, depth);
}

DissectResult from_link(LinkType link, const uint8_t* data, size_t caplen, size_t off, PacketInfo& out,
                        int depth) {
    if (depth > kMaxDepth) return DissectResult::NotIp;
    switch (link) {
        case LinkType::Ethernet: return parse_ethernet(data, caplen, off, out, depth);
        case LinkType::Null:
        case LinkType::Loop: return parse_l3(0, data, caplen, off + 4, out, depth);
        case LinkType::Raw:
        case LinkType::Raw12:
        case LinkType::Raw14:
        case LinkType::Ipv4:
        case LinkType::Ipv6: return parse_l3(0, data, caplen, off, out, depth);
        case LinkType::LinuxSll:
            if (!have(caplen, off, 16)) return DissectResult::Truncated;
            return parse_l3(be16(data + off + 14), data, caplen, off + 16, out, depth);
        case LinkType::LinuxSll2:
            if (!have(caplen, off, 20)) return DissectResult::Truncated;
            return parse_l3(be16(data + off), data, caplen, off + 20, out, depth);
        case LinkType::Ppp:
        case LinkType::PppHdlc: return parse_ppp(data, caplen, off, out, depth);
        case LinkType::CiscoHdlc:
            if (!have(caplen, off, 4)) return DissectResult::Truncated;
            return parse_l3(be16(data + off + 2), data, caplen, off + 4, out, depth);
        case LinkType::Ieee80211: return parse_80211(data, caplen, off, out, depth);
        case LinkType::Radiotap: {
            if (!have(caplen, off, 4)) return DissectResult::Truncated;
            size_t len = le16(data + off + 2);
            if (len < 8 || !have(caplen, off, len)) return DissectResult::Truncated;
            return parse_80211(data, caplen, off + len, out, depth);
        }
        case LinkType::Ppi: {
            if (!have(caplen, off, 8)) return DissectResult::Truncated;
            size_t len = le16(data + off + 2);
            auto inner = static_cast<LinkType>(le32(data + off + 4));
            if (len < 8 || !have(caplen, off, len) || inner == LinkType::Ppi) return DissectResult::Truncated;
            return from_link(inner, data, caplen, off + len, out, depth + 1);
        }
        case LinkType::Pktap:
        case LinkType::User2: {
            if (!have(caplen, off, 12)) return DissectResult::Truncated;
            size_t len = le32(data + off);
            auto inner = static_cast<LinkType>(le32(data + off + 8));
            if (len < 12 || !have(caplen, off, len) || inner == LinkType::Pktap || inner == LinkType::User2)
                return DissectResult::Truncated;
            return from_link(inner, data, caplen, off + len, out, depth + 1);
        }
        case LinkType::Nflog: {
            if (!have(caplen, off, 4)) return DissectResult::Truncated;
            size_t pos = off + 4;
            while (have(caplen, pos, 4)) {
                size_t tlv_len = le16(data + pos);
                uint16_t tlv_type = le16(data + pos + 2);
                if (tlv_len < 4 || !have(caplen, pos, tlv_len)) return DissectResult::Truncated;
                if (tlv_type == 9) return parse_l3(0, data, std::min(caplen, pos + tlv_len), pos + 4, out, depth);
                pos += (tlv_len + 3) & ~static_cast<size_t>(3);
            }
            return DissectResult::NotIp;
        }
    }
    return DissectResult::NotIp;
}

// Unwrap well-known tunnels so analysis sees the inner conversation.
DissectResult maybe_tunnel(const uint8_t* data, size_t caplen, size_t off, size_t end, uint8_t proto,
                           PacketInfo& out, int depth, bool& handled) {
    handled = false;
    if (depth >= kMaxDepth) return DissectResult::Ok;
    size_t limit = std::min(caplen, end);
    if (proto == 4 || proto == 41) {  // IP-in-IP / IPv6-in-IP
        handled = true;
        out.tunnels++;
        return proto == 4 ? parse_ipv4(data, limit, off, out, depth + 1) : parse_ipv6(data, limit, off, out, depth + 1);
    }
    if (proto == 47) {  // GRE (incl. ERSPAN II/III)
        if (!have(limit, off, 4)) return DissectResult::Truncated;
        uint16_t flags = be16(data + off), type = be16(data + off + 2);
        if ((flags & 0x7) != 0) return DissectResult::Ok;  // PPTP enhanced GRE etc.: leave as GRE
        size_t hlen = 4 + ((flags & 0x8000) ? 4 : 0) + ((flags & 0x2000) ? 4 : 0) + ((flags & 0x1000) ? 4 : 0);
        size_t inner = off + hlen;
        if (type == 0x88BE) inner += 8;  // ERSPAN type II
        if (type == 0x22EB) {            // ERSPAN type III (+8 if the platform sub-header is present)
            if (!have(limit, inner, 12)) return DissectResult::Truncated;
            inner += 12 + ((data[inner + 11] & 0x01) ? 8 : 0);
        }
        handled = true;
        out.tunnels++;
        if (type == 0x6558 || type == 0x88BE || type == 0x22EB) return parse_ethernet(data, limit, inner, out, depth + 1);
        if (type == ETHERTYPE_IPV4 || type == ETHERTYPE_IPV6) return parse_l3(type, data, limit, inner, out, depth + 1);
        handled = false;
        out.tunnels--;
    }
    return DissectResult::Ok;
}

DissectResult parse_l4(const uint8_t* data, size_t caplen, size_t off, size_t l4_claimed, uint8_t proto,
                       PacketInfo& out, int depth) {
    out.proto = proto;
    bool tunneled = false;
    DissectResult tr = maybe_tunnel(data, caplen, off, off + l4_claimed, proto, out, depth, tunneled);
    if (tunneled || tr != DissectResult::Ok) return tr;

    out.l4 = data + std::min(off, caplen);
    if (proto == IPPROTO_TCP_) {
        auto* tcp = overlay<TcpHeader>(data, caplen, off);
        if (!tcp) return DissectResult::Truncated;
        size_t hlen = tcp->header_len();
        if (hlen < sizeof(TcpHeader) || !have(caplen, off, hlen)) return DissectResult::Truncated;
        out.sport = ntohs(tcp->sport);
        out.dport = ntohs(tcp->dport);
        out.seq = ntohl(tcp->seq);
        out.ack = ntohl(tcp->ack);
        out.tcp_flags = tcp->flags;
        out.window = ntohs(tcp->window);
        out.l4_hlen = static_cast<uint16_t>(hlen);
        off += hlen;
        out.payload_claimed = l4_claimed > hlen ? static_cast<uint32_t>(l4_claimed - hlen) : 0;
    } else if (proto == IPPROTO_UDP_) {
        auto* udp = overlay<UdpHeader>(data, caplen, off);
        if (!udp) return DissectResult::Truncated;
        out.sport = ntohs(udp->sport);
        out.dport = ntohs(udp->dport);
        out.l4_hlen = sizeof(UdpHeader);
        size_t udp_len = ntohs(udp->len);
        size_t claimed = udp_len >= sizeof(UdpHeader) ? udp_len - sizeof(UdpHeader) : 0;
        if (l4_claimed >= sizeof(UdpHeader) && claimed > l4_claimed - sizeof(UdpHeader))
            claimed = l4_claimed - sizeof(UdpHeader);
        size_t inner = off + sizeof(UdpHeader);
        // VXLAN (4789) and Geneve (6081) carry whole frames: unwrap when the header checks out.
        if (depth < kMaxDepth && out.dport == 4789 && have(caplen, inner, 8) && (data[inner] & 0x08)) {
            out.tunnels++;
            return parse_ethernet(data, std::min(caplen, inner + claimed), inner + 8, out, depth + 1);
        }
        if (depth < kMaxDepth && out.dport == 6081 && have(caplen, inner, 8) && (data[inner] >> 6) == 0) {
            size_t glen = 8 + static_cast<size_t>(data[inner] & 0x3F) * 4;
            uint16_t gtype = be16(data + inner + 2);
            size_t gend = std::min(caplen, inner + claimed);
            if (gtype == 0x6558) {
                out.tunnels++;
                return parse_ethernet(data, gend, inner + glen, out, depth + 1);
            }
            if (gtype == ETHERTYPE_IPV4 || gtype == ETHERTYPE_IPV6) {
                out.tunnels++;
                return parse_l3(gtype, data, gend, inner + glen, out, depth + 1);
            }
        }
        off = inner;
        out.payload_claimed = static_cast<uint32_t>(claimed);
    } else {
        // ICMP and friends: no ports, but keep the header bytes for decoders.
        size_t avail = caplen > off ? caplen - off : 0;
        out.payload = data + std::min(off, caplen);
        out.payload_claimed = static_cast<uint32_t>(l4_claimed);
        out.payload_len = static_cast<uint32_t>(std::min(avail, l4_claimed));
        return DissectResult::UnsupportedL4;
    }
    size_t avail = caplen > off ? caplen - off : 0;
    // Ethernet frames can carry trailing padding: never read past what IP claims.
    out.payload_len = static_cast<uint32_t>(avail < out.payload_claimed ? avail : out.payload_claimed);
    out.payload = data + off;
    return DissectResult::Ok;
}

DissectResult parse_ipv4(const uint8_t* data, size_t caplen, size_t off, PacketInfo& out, int depth) {
    auto* ip = overlay<Ipv4Header>(data, caplen, off);
    if (!ip) return DissectResult::Truncated;
    if (ip->version() != 4) return DissectResult::NotIp;
    size_t hlen = ip->header_len();
    if (hlen < sizeof(Ipv4Header) || !have(caplen, off, hlen)) return DissectResult::Truncated;

    out.src.family = out.dst.family = 4;
    out.src.bytes.fill(0);
    out.dst.bytes.fill(0);
    std::memcpy(out.src.bytes.data(), &ip->saddr, 4);
    std::memcpy(out.dst.bytes.data(), &ip->daddr, 4);
    out.ttl = ip->ttl;

    uint16_t frag = ntohs(ip->frag_off);
    if ((frag & 0x2000) || (frag & 0x1FFF)) {
        out.proto = ip->protocol;
        return DissectResult::Fragment;
    }
    size_t total = ntohs(ip->total_len);
    size_t l4_claimed = total > hlen ? total - hlen : 0;
    // TSO-offloaded captures report total_len 0; fall back to what we captured.
    if (total == 0) l4_claimed = caplen - off - hlen;
    return parse_l4(data, caplen, off + hlen, l4_claimed, ip->protocol, out, depth);
}

DissectResult parse_ipv6(const uint8_t* data, size_t caplen, size_t off, PacketInfo& out, int depth) {
    auto* ip6 = overlay<Ipv6Header>(data, caplen, off);
    if (!ip6) return DissectResult::Truncated;
    if ((ntohl(ip6->ver_tc_flow) >> 28) != 6) return DissectResult::NotIp;

    out.src.family = out.dst.family = 6;
    std::memcpy(out.src.bytes.data(), ip6->saddr, 16);
    std::memcpy(out.dst.bytes.data(), ip6->daddr, 16);
    out.ttl = ip6->hop_limit;

    size_t remaining = ntohs(ip6->payload_len);
    if (remaining == 0) remaining = caplen > off + sizeof(Ipv6Header) ? caplen - off - sizeof(Ipv6Header) : 0;
    uint8_t next = ip6->next_header;
    off += sizeof(Ipv6Header);

    // Walk extension headers until we hit an upper-layer protocol.
    for (int hops = 0; hops < 8; ++hops) {
        switch (next) {
            case 0:    // hop-by-hop
            case 43:   // routing
            case 60: { // destination options
                auto* ext = overlay<Ipv6ExtHeader>(data, caplen, off);
                if (!ext) return DissectResult::Truncated;
                size_t len = (static_cast<size_t>(ext->hdr_ext_len) + 1) * 8;
                if (len > remaining) return DissectResult::Truncated;
                next = ext->next_header;
                off += len;
                remaining -= len;
                continue;
            }
            case 51: { // authentication header: length in 4-octet units minus 2
                auto* ext = overlay<Ipv6ExtHeader>(data, caplen, off);
                if (!ext) return DissectResult::Truncated;
                size_t len = (static_cast<size_t>(ext->hdr_ext_len) + 2) * 4;
                if (len > remaining) return DissectResult::Truncated;
                next = ext->next_header;
                off += len;
                remaining -= len;
                continue;
            }
            case 44:   // fragment
                out.proto = 44;
                return DissectResult::Fragment;
            default:
                return parse_l4(data, caplen, off, remaining, next, out, depth);
        }
    }
    return DissectResult::UnsupportedL4;
}

}  // namespace

DissectResult dissect(LinkType link, const uint8_t* data, size_t caplen, PacketInfo& out) {
    return from_link(link, data, caplen, 0, out, 0);
}

bool parse_arp(LinkType link, const uint8_t* data, size_t caplen, ArpClaim& out) {
    // Find the ethertype and the start of its payload for the link types that carry ARP.
    size_t off = 0;
    uint16_t type = 0;
    if (link == LinkType::Ethernet) {
        if (!have(caplen, 0, sizeof(EthernetHeader))) return false;
        type = be16(data + 12);
        off = sizeof(EthernetHeader);
        for (int i = 0; i < 3 && (type == ETHERTYPE_VLAN || type == ETHERTYPE_QINQ || type == 0x9100); ++i) {
            if (!have(caplen, off, sizeof(VlanTag))) return false;
            type = be16(data + off + 2);
            off += sizeof(VlanTag);
        }
    } else if (link == LinkType::LinuxSll) {
        if (!have(caplen, 0, 16)) return false;
        type = be16(data + 14);
        off = 16;
    } else if (link == LinkType::LinuxSll2) {
        if (!have(caplen, 0, 20)) return false;
        type = be16(data);
        off = 20;
    } else {
        return false;
    }
    if (type != ETHERTYPE_ARP || !have(caplen, off, 8)) return false;
    // htype(2) ptype(2) hlen(1) plen(1) oper(2), then sha[hlen] spa[plen] tha[hlen] tpa[plen].
    if (be16(data + off + 2) != ETHERTYPE_IPV4 || data[off + 4] != 6 || data[off + 5] != 4) return false;
    if (!have(caplen, off + 8, 10)) return false;  // sha(6) + spa(4)
    std::memcpy(out.mac, data + off + 8, 6);
    std::memcpy(&out.ipv4, data + off + 14, 4);
    return true;
}

bool link_type_supported(LinkType link) {
    switch (link) {
        case LinkType::Null: case LinkType::Ethernet: case LinkType::Ppp: case LinkType::Raw12:
        case LinkType::Raw14: case LinkType::PppHdlc: case LinkType::Raw: case LinkType::CiscoHdlc:
        case LinkType::Ieee80211: case LinkType::Loop: case LinkType::LinuxSll: case LinkType::Radiotap:
        case LinkType::User2: case LinkType::Ppi: case LinkType::Ipv4: case LinkType::Ipv6:
        case LinkType::Nflog: case LinkType::Pktap: case LinkType::LinuxSll2:
            return true;
    }
    return false;
}

const char* link_type_name(LinkType link) {
    switch (link) {
        case LinkType::Null: return "BSD loopback";
        case LinkType::Ethernet: return "Ethernet";
        case LinkType::Ppp: return "PPP";
        case LinkType::Raw12: case LinkType::Raw14: case LinkType::Raw: return "Raw IP";
        case LinkType::PppHdlc: return "PPP in HDLC framing";
        case LinkType::CiscoHdlc: return "Cisco HDLC";
        case LinkType::Ieee80211: return "IEEE 802.11";
        case LinkType::Loop: return "OpenBSD loopback";
        case LinkType::LinuxSll: return "Linux cooked capture v1";
        case LinkType::Radiotap: return "802.11 + radiotap";
        case LinkType::User2: case LinkType::Pktap: return "Apple PKTAP";
        case LinkType::Ppi: return "802.11 + PPI";
        case LinkType::Ipv4: return "Raw IPv4";
        case LinkType::Ipv6: return "Raw IPv6";
        case LinkType::Nflog: return "Linux netfilter log";
        case LinkType::LinuxSll2: return "Linux cooked capture v2";
    }
    return "unknown";
}

}  // namespace anta
