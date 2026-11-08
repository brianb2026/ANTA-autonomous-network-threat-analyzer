#include "sanitize.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <random>

#include "crypto.h"

namespace anta {

namespace {

constexpr uint64_t kY2kUs = 946684800ULL * 1000000ULL;  // 2000-01-01 00:00:00 UTC

uint16_t be16(const std::vector<uint8_t>& f, size_t o) { return static_cast<uint16_t>(f[o] << 8 | f[o + 1]); }
void put16(std::vector<uint8_t>& f, size_t o, uint16_t v) {
    f[o] = static_cast<uint8_t>(v >> 8);
    f[o + 1] = static_cast<uint8_t>(v);
}

uint32_t sum16(const uint8_t* p, size_t n, uint32_t acc = 0) {
    for (size_t i = 0; i + 1 < n; i += 2) acc += static_cast<uint32_t>(p[i] << 8 | p[i + 1]);
    if (n & 1) acc += static_cast<uint32_t>(p[n - 1] << 8);
    return acc;
}

uint16_t fold(uint32_t acc) {
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return static_cast<uint16_t>(~acc & 0xffff);
}

bool bit(const uint8_t* p, size_t i) { return (p[i / 8] >> (7 - i % 8)) & 1; }
void set_bit(uint8_t* p, size_t i, bool v) {
    if (v) p[i / 8] |= static_cast<uint8_t>(0x80 >> (i % 8));
    else p[i / 8] &= static_cast<uint8_t>(~(0x80 >> (i % 8)));
}

// IPv4 blocks that keep their kind: a stand-in stays inside the block (its first bits fixed).
struct Block {
    uint32_t net;
    int bits;
};
constexpr Block kV4Blocks[] = {
    {0x0A000000, 8},  {0xAC100000, 12}, {0xC0A80000, 16}, {0x64400000, 10}, {0xA9FE0000, 16},  // private, CGN, link-local
    {0xC0000000, 24}, {0xC0000200, 24}, {0xC6336400, 24}, {0xCB007100, 24}, {0xC6120000, 15},  // special, documentation
};

bool kept_v4(uint32_t a) { return (a >> 24) == 0 || (a >> 24) == 127 || (a >> 24) >= 224; }

int v4_fixed_bits(uint32_t a) {
    for (const auto& b : kV4Blocks)
        if ((a >> (32 - b.bits)) == (b.net >> (32 - b.bits))) return b.bits;
    return 0;
}

std::string mac_str(const uint8_t* m) {
    char buf[18];
    std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    return buf;
}

std::string ip_str(const uint8_t* a, bool v6) {
    IpAddr ip;
    ip.family = v6 ? 6 : 4;
    std::memcpy(ip.bytes.data(), a, v6 ? 16 : 4);
    return ip.str();
}

}  // namespace

Sanitizer::Sanitizer(SanitizeOptions opts) : opts_(opts) {
    std::random_device rd;  // the platform's CSPRNG (arc4random, getrandom, rand_s)
    for (size_t i = 0; i < sizeof key_bytes_; i += 4) {
        uint32_t v = rd();
        std::memcpy(key_bytes_ + i, &v, 4);
    }
}

Sanitizer::Sanitizer(SanitizeOptions opts, const uint8_t key[32]) : opts_(opts) {
    std::memcpy(key_bytes_, key, sizeof key_bytes_);
}

uint32_t Sanitizer::prf32(const char* domain, const uint8_t* data, size_t len) {
    std::vector<uint8_t> msg(domain, domain + std::strlen(domain) + 1);
    msg.insert(msg.end(), data, data + len);
    uint8_t out[32];
    hmac_sha256(key_bytes_, sizeof key_bytes_, msg.data(), msg.size(), out);
    return static_cast<uint32_t>(out[0]) << 24 | out[1] << 16 | out[2] << 8 | out[3];
}

bool Sanitizer::prf_bit(const char* domain, uint32_t tweak, const uint8_t* bits, size_t nbits) {
    uint8_t msg[4 + 2 + 16] = {};
    std::memcpy(msg, &tweak, 4);
    msg[4] = static_cast<uint8_t>(nbits >> 8);
    msg[5] = static_cast<uint8_t>(nbits);
    for (size_t i = 0; i < nbits; ++i) set_bit(msg + 6, i, bit(bits, i));
    return prf32(domain, msg, 6 + (nbits + 7) / 8) & 1;
}

// Crypto-PAn's construction: each bit flipped or not by a keyed function of the bits
// before it, so two addresses sharing an n-bit prefix share an n-bit stand-in prefix.
void Sanitizer::prefix_preserve(const char* domain, uint32_t tweak, const uint8_t* in, uint8_t* out, size_t fixed,
                                size_t total) {
    for (size_t i = 0; i < total; ++i)
        set_bit(out, i, i < fixed ? bit(in, i) : bit(in, i) ^ prf_bit(domain, tweak, in, i));
}

// The host part of an IPv4 address: a keyed shuffle of 1-254 within each /24, so .0 and
// .255 (network, broadcast) stay what they are. The shuffle is a four-round Feistel network
// on the octet's two nibbles (its round tables from one keyed hash per /24), cycle-walked
// so it never lands on 0 or 255.
uint8_t Sanitizer::last_octet(uint32_t net, uint8_t host) {
    if (host == 0 || host == 255) return host;
    auto it = octets_.find(net);
    if (it == octets_.end()) {
        uint8_t seed[3] = {static_cast<uint8_t>(net >> 16), static_cast<uint8_t>(net >> 8), static_cast<uint8_t>(net)};
        std::vector<uint8_t> msg = {'v', '4', '-', 'h', 'o', 's', 't', 0, seed[0], seed[1], seed[2]};
        std::array<uint8_t, 32> tables;
        hmac_sha256(key_bytes_, sizeof key_bytes_, msg.data(), msg.size(), tables.data());
        it = octets_.emplace(net, tables).first;
    }
    const auto& t = it->second;
    auto round_fn = [&](int round, uint8_t v) {
        uint8_t byte = t[static_cast<size_t>(round * 8 + v / 2)];
        return static_cast<uint8_t>((v & 1) ? byte >> 4 : byte & 15);
    };
    auto perm = [&](uint8_t x) {  // P on 0..255
        uint8_t l = x >> 4, r = x & 15;
        for (int round = 0; round < 4; ++round) {
            uint8_t nr = l ^ round_fn(round, r);
            l = r;
            r = nr;
        }
        return static_cast<uint8_t>(l << 4 | r);
    };
    auto unperm = [&](uint8_t y) {  // P's inverse: the rounds run backward
        uint8_t l = y >> 4, r = y & 15;
        for (int round = 3; round >= 0; --round) {
            uint8_t pl = r ^ round_fn(round, l);
            r = l;
            l = pl;
        }
        return static_cast<uint8_t>(l << 4 | r);
    };
    // π, the permutation of 1..254 P gives by walking past 0 and 255, and its inverse.
    auto pi = [&](uint8_t x) { uint8_t y = perm(x); while (y == 0 || y == 255) y = perm(y); return y; };
    auto pi_inv = [&](uint8_t y) { uint8_t x = unperm(y); while (x == 0 || x == 255) x = unperm(x); return x; };
    // Each host goes to the next one in π's order: one cycle through all 254, so no host is
    // ever its own stand-in (a plain shuffle leaves about one in 254 where it was).
    uint8_t pos = pi_inv(host);
    return pi(pos == 254 ? 1 : static_cast<uint8_t>(pos + 1));
}

// A keyed permutation of 24 bits (a four-round Feistel network): the low 24 bits of an
// IPv6 interface ID, so a solicited-node multicast address keeps matching its host.
uint32_t Sanitizer::feistel24(uint32_t v) {
    uint32_t l = (v >> 12) & 0xfff, r = v & 0xfff;
    for (uint8_t round = 0; round < 4; ++round) {
        uint8_t msg[3] = {round, static_cast<uint8_t>(r >> 8), static_cast<uint8_t>(r)};
        uint32_t nl = r, nr = l ^ (prf32("v6-low", msg, 3) & 0xfff);
        l = nl;
        r = nr;
    }
    return l << 12 | r;
}

std::array<uint8_t, 4> Sanitizer::ipv4(const uint8_t a[4]) {
    std::array<uint8_t, 4> out;
    std::memcpy(out.data(), a, 4);
    map4(out.data());
    return out;
}

std::array<uint8_t, 16> Sanitizer::ipv6(const uint8_t a[16]) {
    std::array<uint8_t, 16> out;
    std::memcpy(out.data(), a, 16);
    map6(out.data());
    return out;
}

std::array<uint8_t, 6> Sanitizer::mac(const uint8_t m[6]) {
    std::array<uint8_t, 6> out;
    std::memcpy(out.data(), m, 6);
    map_mac(out.data());
    return out;
}

void Sanitizer::map4(uint8_t* a) {
    uint32_t u = static_cast<uint32_t>(a[0]) << 24 | a[1] << 16 | a[2] << 8 | a[3];
    if (kept_v4(u)) return;  // this network, loopback, multicast, broadcast
    auto hit = v4_.find(u);
    if (hit == v4_.end()) {
        uint32_t net = u >> 8;
        auto nh = v4_net_.find(net);
        if (nh == v4_net_.end()) {
            int fixed = v4_fixed_bits(u);
            uint8_t in[4] = {a[0], a[1], a[2], 0}, out[4] = {};
            uint32_t mapped = 0;
            for (uint32_t tweak = 0;; ++tweak) {
                prefix_preserve("v4", tweak, in, out, static_cast<size_t>(fixed), 24);
                mapped = static_cast<uint32_t>(out[0]) << 16 | out[1] << 8 | out[2];
                uint32_t full = mapped << 8;
                // A public address stays public; no two networks share a stand-in; a network
                // never stands in for itself (unless its kind fixes all of it: the documentation /24s).
                bool ok = !v4_used_.count(mapped) && (fixed || (!kept_v4(full) && !v4_fixed_bits(full))) &&
                          (fixed >= 24 || (mapped != net && !v4_net_.count(mapped)));  // (nor as another real one)
                if (ok || tweak > 64) break;
            }
            v4_used_[mapped] = true;
            nh = v4_net_.emplace(net, mapped).first;
        }
        uint32_t stand_in = nh->second << 8 | last_octet(net, a[3]);
        hit = v4_.emplace(u, stand_in).first;
        uint8_t b[4] = {static_cast<uint8_t>(stand_in >> 24), static_cast<uint8_t>(stand_in >> 16),
                        static_cast<uint8_t>(stand_in >> 8), static_cast<uint8_t>(stand_in)};
        if (key_.size() < 200000) key_.push_back({"ipv4", ip_str(a, false), ip_str(b, false)});
    }
    a[0] = static_cast<uint8_t>(hit->second >> 24);
    a[1] = static_cast<uint8_t>(hit->second >> 16);
    a[2] = static_cast<uint8_t>(hit->second >> 8);
    a[3] = static_cast<uint8_t>(hit->second);
}

void Sanitizer::map6(uint8_t* a) {
    static const uint8_t zero[16] = {};
    if (std::memcmp(a, zero, 15) == 0 && a[15] <= 1) return;  // :: and ::1
    if (a[0] == 0xff) {  // multicast: kept, except a solicited-node address names its host's last 24 bits
        static const uint8_t sn[13] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff};
        if (std::memcmp(a, sn, 13) == 0) {
            uint32_t low = feistel24(static_cast<uint32_t>(a[13]) << 16 | a[14] << 8 | a[15]);
            a[13] = static_cast<uint8_t>(low >> 16);
            a[14] = static_cast<uint8_t>(low >> 8);
            a[15] = static_cast<uint8_t>(low);
        }
        return;
    }
    static const uint8_t mapped4[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    static const uint8_t nat64[12] = {0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0};
    if (std::memcmp(a, mapped4, 12) == 0 || std::memcmp(a, nat64, 12) == 0) {  // an IPv4 address inside
        map4(a + 12);
        return;
    }
    std::array<uint8_t, 16> real;
    std::memcpy(real.data(), a, 16);
    auto hit = v6_.find(real);
    if (hit == v6_.end()) {
        std::array<uint8_t, 16> out;
        std::memcpy(out.data(), net6(a).data(), 8);
        // The interface ID: the same host keeps the same stand-in ID on every network (as
        // SLAAC gives it), its last 24 bits by a permutation (see feistel24).
        uint32_t high = prf32("v6-iid", a + 8, 8);
        uint32_t high2 = prf32("v6-iid2", a + 8, 8);
        uint32_t low = feistel24(static_cast<uint32_t>(a[13]) << 16 | a[14] << 8 | a[15]);
        out[8] = static_cast<uint8_t>(high >> 24);
        out[9] = static_cast<uint8_t>(high >> 16);
        out[10] = static_cast<uint8_t>(high >> 8);
        out[11] = static_cast<uint8_t>(high);
        out[12] = static_cast<uint8_t>(high2);
        out[13] = static_cast<uint8_t>(low >> 16);
        out[14] = static_cast<uint8_t>(low >> 8);
        out[15] = static_cast<uint8_t>(low);
        hit = v6_.emplace(real, out).first;
        if (key_.size() < 200000) key_.push_back({"ipv6", ip_str(a, true), ip_str(out.data(), true)});
    }
    std::memcpy(a, hit->second.data(), 16);
}

// The network half of an IPv6 address (its first 64 bits), prefix-preserving.
const std::array<uint8_t, 8>& Sanitizer::net6(const uint8_t* a) {
    std::array<uint8_t, 8> net;
    std::memcpy(net.data(), a, 8);
    auto nh = v6_net_.find(net);
    if (nh == v6_net_.end()) {
        std::array<uint8_t, 8> stand_net{};
        bool link_local = a[0] == 0xfe && (a[1] & 0xc0) == 0x80;
        size_t fixed = link_local ? 64 : (a[0] & 0xfe) == 0xfc ? 7 : 3;  // fe80::/10, ULA fc00::/7, the rest by /3
        prefix_preserve("v6", 0, net.data(), stand_net.data(), fixed, 64);
        nh = v6_net_.emplace(net, stand_net).first;
    }
    return nh->second;
}

void Sanitizer::map_mac(uint8_t* m) {
    static const uint8_t zero[6] = {};
    if ((m[0] & 1) || std::memcmp(m, zero, 6) == 0) return;  // broadcast, multicast, unset
    std::array<uint8_t, 6> real;
    std::memcpy(real.data(), m, 6);
    auto hit = mac_.find(real);
    if (hit == mac_.end()) {
        std::array<uint8_t, 6> out;
        for (uint8_t tweak = 0;; ++tweak) {
            uint8_t msg[7];
            std::memcpy(msg, m, 6);
            msg[6] = tweak;
            uint32_t a = prf32("mac", msg, 7), b = prf32("mac2", msg, 7);
            out = {static_cast<uint8_t>(((a >> 24) & 0xfc) | 0x02), static_cast<uint8_t>(a >> 16),
                   static_cast<uint8_t>(a >> 8), static_cast<uint8_t>(a), static_cast<uint8_t>(b >> 8),
                   static_cast<uint8_t>(b)};  // locally administered, unicast
            if (!mac_used_.count(out) || tweak == 255) break;
        }
        mac_used_[out] = true;
        hit = mac_.emplace(real, out).first;
        if (key_.size() < 200000) key_.push_back({"mac", mac_str(m), mac_str(out.data())});
    }
    std::memcpy(m, hit->second.data(), 6);
}

void Sanitizer::cut(std::vector<uint8_t>& f, size_t end) {
    if (end < f.size()) {
        bytes_cut_ += f.size() - end;
        f.resize(end);
    }
}

uint64_t Sanitizer::time(uint64_t ts_us) {
    if (!opts_.shift_time) return ts_us;
    if (!have_first_) {
        first_ts_ = ts_us;
        have_first_ = true;
    }
    return ts_us >= first_ts_ ? kY2kUs + (ts_us - first_ts_) : kY2kUs - std::min(kY2kUs, first_ts_ - ts_us);
}

bool Sanitizer::frame(LinkType link, const uint8_t* p, size_t caplen, std::vector<uint8_t>& out) {
    out.assign(p, p + caplen);
    auto& f = out;
    switch (link) {
        case LinkType::Ethernet: {
            if (f.size() < 14) {  // not even a whole header: nothing in it is kept
                cut(f, 0);
                return true;
            }
            map_mac(f.data());
            map_mac(f.data() + 6);
            size_t off = 12;
            uint16_t type = be16(f, off);
            for (int tags = 0; tags < 4 && (type == 0x8100 || type == 0x88a8 || type == 0x9100); ++tags) {
                if (off + 6 > f.size()) {
                    cut(f, off);
                    return true;
                }
                off += 4;
                type = be16(f, off);
            }
            off += 2;
            if (type < 0x0600) {  // 802.3 length: LLC (spanning tree, CDP, NetBIOS)
                if (!opts_.keep_payload) cut(f, off);
                return true;
            }
            l3(type, f, off);
            return true;
        }
        case LinkType::Raw: case LinkType::Raw12: case LinkType::Raw14: case LinkType::Ipv4: case LinkType::Ipv6:
            if (f.empty()) return true;
            l3((f[0] >> 4) == 6 ? 0x86dd : (f[0] >> 4) == 4 ? 0x0800 : 0, f, 0);
            return true;
        case LinkType::Null: case LinkType::Loop: {
            if (f.size() < 4) {
                cut(f, 0);
                return true;
            }
            uint32_t le = static_cast<uint32_t>(f[0] | f[1] << 8 | f[2] << 16 | f[3] << 24);
            uint32_t be = static_cast<uint32_t>(f[0] << 24 | f[1] << 16 | f[2] << 8 | f[3]);
            auto type_of = [](uint32_t fam) -> uint16_t {
                return fam == 2 ? 0x0800 : (fam == 24 || fam == 28 || fam == 30) ? 0x86dd : 0;
            };
            uint16_t type = type_of(le) ? type_of(le) : type_of(be);
            l3(type, f, 4);
            return true;
        }
        case LinkType::LinuxSll: {
            if (f.size() < 16) {
                cut(f, 0);
                return true;
            }
            if (be16(f, 2) == 1 && be16(f, 4) == 6) map_mac(f.data() + 6);
            else std::fill(f.begin() + 6, f.begin() + 14, 0);  // another kind of link address: blanked
            l3(be16(f, 14), f, 16);
            return true;
        }
        case LinkType::LinuxSll2: {
            if (f.size() < 20) {
                cut(f, 0);
                return true;
            }
            if (be16(f, 8) == 1 && f[11] == 6) map_mac(f.data() + 12);
            else std::fill(f.begin() + 12, f.begin() + 20, 0);
            l3(be16(f, 0), f, 20);
            return true;
        }
        default:
            ++unsupported_;
            out.clear();
            return false;
    }
}

void Sanitizer::l3(uint16_t ethertype, std::vector<uint8_t>& f, size_t off) {
    if (ethertype == 0x0806) {
        arp(f, off);
        cut(f, off + 28);  // (and the frame's padding)
        return;
    }
    size_t end = f.size();
    if (ethertype == 0x0800) end = ipv4_packet(f, off);
    else if (ethertype == 0x86dd) end = ipv6_packet(f, off);
    else if (!opts_.keep_payload) end = off;  // another protocol (LLDP, PPPoE, MPLS …): its contents cut
    if (!opts_.keep_payload) cut(f, end);
}

void Sanitizer::arp(std::vector<uint8_t>& f, size_t off) {
    if (off + 28 <= f.size() && be16(f, off + 2) == 0x0800 && f[off + 4] == 6 && f[off + 5] == 4) {
        map_mac(f.data() + off + 8);
        map4(f.data() + off + 14);
        map_mac(f.data() + off + 18);
        map4(f.data() + off + 24);
    } else {
        cut(f, off);  // another kind of ARP: its addresses can't be told apart, so none are kept
    }
}

size_t Sanitizer::ipv4_packet(std::vector<uint8_t>& f, size_t off, int depth) {
    size_t ihl = off < f.size() ? static_cast<size_t>(f[off] & 15) * 4 : 0;
    if (off + 20 > f.size() || (f[off] >> 4) != 4 || ihl < 20 || off + ihl > f.size()) {
        cut(f, off);  // a broken or partial header: its addresses can't be found, so nothing of it is kept
        return off;
    }
    map4(f.data() + off + 12);
    map4(f.data() + off + 16);
    // Options that carry addresses (record route, timestamps, source routes) become no-ops.
    for (size_t i = off + 20; i < off + ihl;) {
        uint8_t type = f[i];
        if (type == 0) break;
        if (type == 1) {
            ++i;
            continue;
        }
        size_t len = i + 1 < off + ihl ? f[i + 1] : 0;
        if (len < 2 || i + len > off + ihl) {
            std::fill(f.begin() + static_cast<std::ptrdiff_t>(i), f.begin() + static_cast<std::ptrdiff_t>(off + ihl), 1);
            break;
        }
        if (type == 7 || type == 0x44 || type == 0x83 || type == 0x89)
            std::fill(f.begin() + static_cast<std::ptrdiff_t>(i), f.begin() + static_cast<std::ptrdiff_t>(i + len), 1);
        i += len;
    }
    put16(f, off + 10, 0);
    put16(f, off + 10, fold(sum16(f.data() + off, ihl)));
    size_t total = be16(f, off + 2);
    size_t ip_end = std::min(f.size(), off + std::max(total, ihl));
    bool whole = off + total <= f.size() && total >= ihl;
    if (be16(f, off + 6) & 0x1fff) return opts_.keep_payload ? f.size() : off + ihl;  // a later fragment: data only
    bool more = be16(f, off + 6) & 0x2000;
    return transport(f, off, false, f[off + 9], off + ihl, ip_end, whole && !more, depth);
}

size_t Sanitizer::ipv6_packet(std::vector<uint8_t>& f, size_t off, int depth) {
    if (off + 40 > f.size() || (f[off] >> 4) != 6) {
        cut(f, off);
        return off;
    }
    map6(f.data() + off + 8);
    map6(f.data() + off + 24);
    size_t plen = be16(f, off + 4);
    size_t ip_end = std::min(f.size(), off + 40 + plen);
    bool whole = plen && off + 40 + plen <= f.size();
    uint8_t next = f[off + 6];
    size_t pos = off + 40;
    for (int n = 0; n < 8; ++n) {
        if (next == 0 || next == 60 || next == 51) {  // hop-by-hop, destination options, AH
            if (pos + 2 > f.size()) return pos;
            size_t len = next == 51 ? (static_cast<size_t>(f[pos + 1]) + 2) * 4 : (static_cast<size_t>(f[pos + 1]) + 1) * 8;
            next = f[pos];
            pos += len;
            if (pos > f.size()) return f.size();
        } else if (next == 44) {  // fragment
            if (pos + 8 > f.size()) return pos;
            uint16_t frag = be16(f, pos + 2);
            next = f[pos];
            pos += 8;
            if (frag >> 3) return opts_.keep_payload ? f.size() : pos;
            whole = whole && !(frag & 1);
        } else if (next == 43) {  // routing: a list of addresses, cut away
            cut(f, pos);
            return pos;
        } else {
            break;
        }
    }
    return transport(f, off, true, next, pos, ip_end, whole, depth);
}

size_t Sanitizer::transport(std::vector<uint8_t>& f, size_t ip_off, bool v6, uint8_t proto, size_t off,
                            size_t ip_end, bool whole, int depth) {
    const bool keep = opts_.keep_payload;
    size_t hdr = proto == 6 ? 20 : (proto == 17 || proto == 1 || proto == 58) ? 8 : 0;
    if (!hdr) {
        if (!keep) return off;  // GRE, ESP, tunnels …: what they carry is cut
        // IP in IP and GRE: the inner packet's addresses too; anything else tunneled stays as it is.
        if (depth < 3 && proto == 4) ipv4_packet(f, off, depth + 1);
        else if (depth < 3 && proto == 41) ipv6_packet(f, off, depth + 1);
        else if (depth < 3 && proto == 47 && off + 4 <= f.size()) {
            uint16_t flags = be16(f, off), type = be16(f, off + 2);
            size_t inner = off + 4 + ((flags & 0x8000) ? 4 : 0) + ((flags & 0x2000) ? 4 : 0) + ((flags & 0x1000) ? 4 : 0);
            if ((flags & 0x07) == 0 && inner <= f.size() && type == 0x0800) ipv4_packet(f, inner, depth + 1);
            else if ((flags & 0x07) == 0 && inner <= f.size() && type == 0x86dd) ipv6_packet(f, inner, depth + 1);
        }
        return f.size();
    }
    if (off + hdr > f.size()) return f.size();  // a partial header: ports and flags, nothing carried
    if (proto == 6) hdr = std::max<size_t>(20, static_cast<size_t>(f[off + 12] >> 4) * 4);
    size_t hdr_end = std::min(f.size(), off + hdr);
    size_t csum = proto == 6 ? off + 16 : proto == 17 ? off + 6 : off + 2;
    if (proto == 1 && f[off] == 5) map4(f.data() + off + 4);  // ICMP redirect: the gateway's address
    const size_t done = keep ? f.size() : hdr_end;
    if (!keep && !(whole && ip_end <= hdr_end)) {
        // It covered contents that are gone (and a real one would hint at them). Zero means "none"
        // for UDP over IPv4; over IPv6 zero isn't allowed, so it's a constant there.
        put16(f, csum, v6 && proto == 17 ? 0xffff : 0);
        return done;
    }
    if (keep && proto == 1 && (f[off] == 3 || f[off] == 4 || f[off] == 5 || f[off] == 11 || f[off] == 12))
        icmp_inner(f, off + 8, ip_end, false);
    if (keep && proto == 58 && f[off] >= 1 && f[off] <= 4) icmp_inner(f, off + 8, ip_end, true);
    if (keep && proto == 58 && f[off] >= 133 && f[off] <= 137) ndp(f, off, ip_end, f[off]);
    put16(f, csum, 0);
    if (!whole || ip_end > f.size()) return done;  // (not all captured: no checksum can be made)
    uint32_t acc = 0;
    size_t len = ip_end - off;
    if (proto != 1) {  // the pseudo-header: the stand-in addresses
        if (v6) {
            acc = sum16(f.data() + ip_off + 8, 32);
            acc += static_cast<uint32_t>(len >> 16) + static_cast<uint32_t>(len & 0xffff) + proto;
        } else {
            acc = sum16(f.data() + ip_off + 12, 8);
            acc += static_cast<uint32_t>(len) + proto;
        }
    }
    uint16_t c = fold(sum16(f.data() + off, len, acc));
    if (proto == 17 && c == 0) c = 0xffff;
    put16(f, csum, c);
    return done;
}

// The packet an ICMP error quotes: its addresses too.
void Sanitizer::icmp_inner(std::vector<uint8_t>& f, size_t off, size_t end, bool v6) {
    end = std::min(end, f.size());
    if (v6) {
        if (off + 40 <= end && (f[off] >> 4) == 6) {
            map6(f.data() + off + 8);
            map6(f.data() + off + 24);
        }
        return;
    }
    if (off + 20 > end || (f[off] >> 4) != 4) return;
    size_t ihl = static_cast<size_t>(f[off] & 15) * 4;
    map4(f.data() + off + 12);
    map4(f.data() + off + 16);
    if (ihl >= 20 && off + ihl <= end) {
        put16(f, off + 10, 0);
        put16(f, off + 10, fold(sum16(f.data() + off, ihl)));
    }
}

// Neighbor Discovery: the target and its link-layer address, router prefixes, DNS servers.
void Sanitizer::ndp(std::vector<uint8_t>& f, size_t off, size_t end, uint8_t type) {
    end = std::min(end, f.size());
    size_t opts = off + (type == 133 ? 8 : type == 134 ? 16 : type == 137 ? 40 : 24);
    if ((type == 135 || type == 136 || type == 137) && off + 24 <= end) map6(f.data() + off + 8);
    if (type == 137 && off + 40 <= end) map6(f.data() + off + 24);
    auto map_net = [&](size_t at) {  // a prefix: only its network part
        if (f[at] != 0xff) std::memcpy(f.data() + at, net6(f.data() + at).data(), 8);
    };
    for (size_t i = opts; i + 2 <= end;) {
        size_t len = static_cast<size_t>(f[i + 1]) * 8;
        if (!len || i + len > end) break;
        uint8_t t = f[i];
        if ((t == 1 || t == 2) && len >= 8) map_mac(f.data() + i + 2);
        else if (t == 3 && len >= 32) map_net(i + 16);
        else if (t == 25)
            for (size_t a = i + 8; a + 16 <= i + len; a += 16) map6(f.data() + a);
        i += len;
    }
}

}  // namespace anta
