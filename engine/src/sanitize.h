// A share-safe copy of a capture: the same conversations, packet sizes and timing, with
// every address replaced by a stand-in and what the packets carried cut away, so it can
// be handed to someone else (a colleague, a vendor, a forum) without giving away which
// machines talked or what they said.
//
// Stand-ins are consistent within one copy (the same host is the same stand-in in every
// packet) and keep the network's shape: a private address stays private and in the same
// stand-in subnet as its neighbours (prefix-preserving, like Crypto-PAn), .0 and .255 stay
// network and broadcast, multicast, loopback and broadcast addresses are kept, and a
// MAC becomes a locally administered one. A fresh random key is drawn for every copy, so
// two copies can't be matched up, and nobody can work back from a stand-in without the
// address key, which is the user's to keep.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "packet.h"

namespace anta {

struct SanitizeOptions {
    bool keep_payload = false;  // keep what the packets carried: only the addresses change
    bool shift_time = false;    // move the capture to start at 2000-01-01 00:00:00 UTC
};

class Sanitizer {
public:
    explicit Sanitizer(SanitizeOptions opts);                  // a fresh random key
    Sanitizer(SanitizeOptions opts, const uint8_t key[32]);    // a given one (tests, fuzzing)

    // One frame rewritten into `out`. False if its link type can't be made share-safe
    // (802.11, PKTAP and the like): the frame is then left out of the copy.
    bool frame(LinkType link, const uint8_t* p, size_t caplen, std::vector<uint8_t>& out);
    uint64_t time(uint64_t ts_us);  // the frame's time in the copy

    struct KeyEntry {
        std::string kind;  // "ipv4", "ipv6", "mac"
        std::string real, stand_in;
    };
    // Every address replaced, in the order first seen: the user's key to the copy.
    const std::vector<KeyEntry>& key() const { return key_; }
    uint64_t bytes_cut() const { return bytes_cut_; }
    uint64_t frames_unsupported() const { return unsupported_; }

    // (The mappings, for tests.)
    std::array<uint8_t, 4> ipv4(const uint8_t a[4]);
    std::array<uint8_t, 16> ipv6(const uint8_t a[16]);
    std::array<uint8_t, 6> mac(const uint8_t m[6]);

private:
    bool prf_bit(const char* domain, uint32_t tweak, const uint8_t* bits, size_t nbits);
    uint32_t prf32(const char* domain, const uint8_t* data, size_t len);
    void prefix_preserve(const char* domain, uint32_t tweak, const uint8_t* in, uint8_t* out, size_t fixed,
                         size_t total);
    uint8_t last_octet(uint32_t net, uint8_t host);
    uint32_t feistel24(uint32_t v);

    void l3(uint16_t ethertype, std::vector<uint8_t>& f, size_t off);
    // Each returns where the copy of its packet ends (all of it when contents are kept).
    size_t ipv4_packet(std::vector<uint8_t>& f, size_t off, int depth = 0);
    size_t ipv6_packet(std::vector<uint8_t>& f, size_t off, int depth = 0);
    void arp(std::vector<uint8_t>& f, size_t off);
    // The transport header at `off` (proto), its checksum fixed or cleared; returns where the
    // copy ends (the end of the header unless contents are kept).
    size_t transport(std::vector<uint8_t>& f, size_t ip_off, bool v6, uint8_t proto, size_t off, size_t ip_end,
                     bool whole, int depth);
    void icmp_inner(std::vector<uint8_t>& f, size_t off, size_t end, bool v6);
    void ndp(std::vector<uint8_t>& f, size_t off, size_t end, uint8_t type);
    void map4(uint8_t* a);
    void map6(uint8_t* a);
    const std::array<uint8_t, 8>& net6(const uint8_t* a);
    void map_mac(uint8_t* m);
    void cut(std::vector<uint8_t>& f, size_t end);

    SanitizeOptions opts_;
    uint8_t key_bytes_[32];
    std::unordered_map<uint32_t, uint32_t> v4_, v4_net_;  // address / its first 24 bits -> stand-in
    std::map<std::array<uint8_t, 8>, std::array<uint8_t, 8>> v6_net_;  // /64 -> stand-in /64
    std::map<std::array<uint8_t, 16>, std::array<uint8_t, 16>> v6_;
    std::map<std::array<uint8_t, 6>, std::array<uint8_t, 6>> mac_;
    std::unordered_map<uint32_t, std::array<uint8_t, 32>> octets_;  // real /24 -> its host shuffle's round tables
    std::unordered_map<uint32_t, bool> v4_used_;                   // stand-in /24s handed out
    std::map<std::array<uint8_t, 6>, bool> mac_used_;
    std::vector<KeyEntry> key_;
    uint64_t bytes_cut_ = 0, unsupported_ = 0;
    uint64_t first_ts_ = 0;
    bool have_first_ = false;
};

}  // namespace anta
