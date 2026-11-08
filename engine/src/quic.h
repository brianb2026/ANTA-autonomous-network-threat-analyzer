// QUIC (RFC 9000/9001/9369) as far as a passive observer can follow it: packet
// headers, and the Initial packets, whose keys anyone can derive from the
// client's first Destination Connection ID. Those carry the TLS Client Hello,
// so the server name of a QUIC connection is visible just as it is over TCP.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <optional>
#include <utility>
#include <vector>

#include "proto.h"

namespace anta {

enum class QuicType : uint8_t { Initial, ZeroRtt, Handshake, Retry };

struct QuicLongHeader {
    uint32_t version = 0;
    QuicType type = QuicType::Initial;
    std::string dcid, scid;  // raw bytes
    size_t pn_offset = 0;    // offset of the (protected) packet number, from the packet start
    size_t length = 0;       // the whole packet: header, packet number and payload
};

// Reads the long header of the packet at p[0..avail). Version 0 (Version
// Negotiation) and unknown versions leave `type` meaningless; Retry has no
// packet number and runs to the end of the datagram.
bool quic_parse_long_header(const uint8_t* p, size_t avail, QuicLongHeader& h);
bool quic_known_version(uint32_t version);

struct QuicKeys {
    uint8_t key[16], iv[12], hp[16];
};
// One side's Initial keys, from the client's original Destination Connection ID.
bool quic_initial_keys(uint32_t version, const std::string& odcid, bool server, QuicKeys& k);

// Removes header protection and decrypts the Initial packet p[0..h.length).
// `largest` is the largest packet number seen in that direction (-1: none).
bool quic_open(const uint8_t* p, const QuicLongHeader& h, const QuicKeys& k, int64_t largest, uint64_t& pn,
               std::string& payload);

struct QuicFrames {
    std::vector<std::string> names;                            // Wireshark's frame names, in order
    std::vector<std::pair<uint64_t, std::string>> crypto;      // CRYPTO frames: (offset, data)
};
// The frames of a decrypted payload; parsing stops at anything malformed.
QuicFrames quic_frames(const std::string& payload);

// The TLS handshake bytes a CRYPTO stream carries, from pieces in any order.
class QuicCryptoStream {
public:
    void add(uint64_t offset, const std::string& data);
    // Bytes available from offset 0 without a gap.
    const std::string& head() const { return head_; }
    // Nothing received beyond the head is waiting for a gap to fill.
    bool contiguous() const { return pending_.empty(); }

private:
    static constexpr size_t kMax = 64 * 1024;
    std::vector<std::pair<uint64_t, std::string>> pending_;
    std::string head_;
};

// The Client Hello once a CRYPTO stream holds all of it (JA4 marked "q" for QUIC).
// `complete` says whether the message is all there, parsed or not.
std::optional<TlsClientHello> quic_client_hello(const std::string& crypto_head, bool& complete);

// Follows the client side of one connection far enough to read its Client Hello.
class QuicHelloReader {
public:
    // One UDP payload from the client. True once the hello is read (or given up on).
    bool on_client_datagram(const uint8_t* p, size_t len);
    std::optional<TlsClientHello> hello;

private:
    std::string odcid_;
    uint32_t version_ = 0;
    int64_t largest_ = -1;
    int datagrams_ = 0;
    QuicCryptoStream crypto_;
};

}  // namespace anta
