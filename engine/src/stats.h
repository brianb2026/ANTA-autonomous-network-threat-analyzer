// Capture statistics for the viewer's Statistics and Network Map views, in the
// spirit of Wireshark's Statistics menu: capture properties, protocol hierarchy,
// endpoints, conversations, I/O graph, packet lengths, expert information,
// DNS/HTTP/TLS summaries, and per-host evidence for labelling a network map.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace anta {

struct StatsQuery {
    std::vector<std::string> inputs;
    std::vector<uint64_t> bases;
    std::string bpf;
    std::string dfilter;                 // only frames matching this display filter
    std::vector<std::string> io_series;  // extra I/O graph series, one display filter each
    std::vector<std::string> counts;     // display filters counted over the whole capture (the protocol checks)
    double io_interval = 0;              // seconds per I/O bin; 0 picks one from the duration
    bool single_pass = false;
    size_t max_rows = 20000;             // per endpoint/conversation table
};

// Prints one JSON object ({"type":"stats", ...}) on stdout. Returns an exit code.
int run_stats(const StatsQuery& q);

}  // namespace anta

namespace anta {

struct FollowQuery {
    std::vector<std::string> inputs;
    std::vector<uint64_t> bases;
    bool udp = false;
    uint64_t stream = 0;           // tcp.stream / udp.stream index
    size_t max_bytes = 8u << 20;   // payload returned at most
    // Follow TLS Stream (decrypted application data) and Follow HTTP/2 Stream (one
    // stream's header blocks and body), with the user's TLS key log.
    enum Kind { Transport, Tls, Http2 } kind = Transport;
    uint32_t h2_stream = 0;
    std::string keylog;
};

// Wireshark's "Follow TCP/UDP/TLS/HTTP/2 Stream": the conversation's payload in order,
// as one JSON object ({"type":"follow", ...}). TCP data is put in sequence order
// with retransmitted bytes shown once. Returns an exit code.
int run_follow(const FollowQuery& q);

}  // namespace anta
