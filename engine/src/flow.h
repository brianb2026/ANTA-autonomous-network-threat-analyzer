// Session tracking keyed by 5-tuple, with per-direction TCP stream reassembly.
#pragma once

#include <cstdint>
#include <cstdio>
#include <climits>
#include <functional>
#include <map>
#include <tuple>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "hash.h"
#include "packet.h"
#include "logins.h"
#include "proto.h"
#include "ftpfiles.h"
#include "quic.h"
#include "object.h"
#include "smbfiles.h"
#include "http2.h"
#include "tlsstream.h"

namespace anta {

// Canonical (direction-independent) 5-tuple: endpoint A is always the smaller.
struct FlowKey {
    IpAddr a, b;
    uint16_t port_a = 0, port_b = 0;
    uint8_t proto = 0;

    bool operator==(const FlowKey& o) const {
        return proto == o.proto && port_a == o.port_a && port_b == o.port_b && a == o.a && b == o.b;
    }

    // Returns the key and whether the packet travels A -> B.
    static FlowKey from_packet(const PacketInfo& p, bool& a_to_b);
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const;
};

enum class Dir : uint8_t { ClientToServer = 0, ServerToClient = 1 };

// Reassembles one direction of a TCP connection into an ordered byte stream.
class TcpStream {
public:
    enum class SegmentKind { InOrder, OutOfOrder, Retransmission, PartialOverlap, Empty };

    using Sink = std::function<void(const uint8_t*, size_t)>;

    // Called for every segment in this direction. Delivers contiguous bytes to `sink`.
    // `pending_limit` caps buffered out-of-order bytes; past it the oldest hole is skipped.
    SegmentKind on_segment(uint32_t seq, uint8_t flags, const uint8_t* data, size_t len,
                           size_t pending_limit, const Sink& sink);
    // Skip any holes and deliver everything still buffered (used at flow close).
    void flush(const Sink& sink);

    uint64_t delivered() const { return delivered_; }
    size_t buffered() const { return pending_bytes_; }

    uint32_t retransmissions = 0;
    uint32_t out_of_order = 0;
    uint32_t gap_bytes = 0;        // bytes never seen (holes skipped)
    uint32_t zero_window = 0;      // segments advertising a zero receive window
    bool syn_seen = false;
    bool fin_seen = false;
    bool rst_seen = false;

private:
    void drain(const Sink& sink);
    void deliver(const uint8_t* data, size_t len, const Sink& sink);

    bool initialized_ = false;
    uint32_t next_seq_ = 0;        // next expected sequence number
    uint64_t delivered_ = 0;       // stream offset of next_seq_
    std::map<uint64_t, std::vector<uint8_t>> pending_;  // stream offset -> data
    size_t pending_bytes_ = 0;
};

struct PayloadEvent {
    uint64_t ts_us;
    uint32_t len;
    Dir dir;
};

// Fixed-size throughput histogram over a flow's lifetime. When a packet lands
// past the last bucket, adjacent buckets are merged and the width doubles, so
// memory stays constant and the full duration is always covered.
struct RateHistogram {
    static constexpr size_t kBuckets = 64;
    uint64_t bucket_us = 100'000;
    uint64_t out[kBuckets] = {0};
    uint64_t in[kBuckets] = {0};

    void add(uint64_t rel_us, uint32_t len, bool c2s) {
        while (rel_us / bucket_us >= kBuckets) {
            for (size_t i = 0; i < kBuckets / 2; ++i) {
                out[i] = out[2 * i] + out[2 * i + 1];
                in[i] = in[2 * i] + in[2 * i + 1];
            }
            for (size_t i = kBuckets / 2; i < kBuckets; ++i) out[i] = in[i] = 0;
            bucket_us *= 2;
        }
        size_t idx = static_cast<size_t>(rel_us / bucket_us);
        (c2s ? out : in)[idx] += len;
    }
};

// One HTTP response body (a "file"), hashed as it streams past, like Wireshark's
// File → Export Objects → HTTP list.
struct HttpFile {
    int status = 0;
    std::string content_type, content_encoding, filename;  // filename from Content-Disposition
    bool length_known = false;
    uint64_t declared_length = 0;
    uint64_t size = 0;       // body bytes seen (after removing chunked framing)
    std::string magic;       // the first bytes of the body
    std::string sha256;
    bool complete = false;   // every byte arrived, with no capture gaps
    uint64_t ts = 0;         // when the response started
    uint32_t response = 0;   // which response on the connection (pairs with the request of that number)
    uint64_t encoded_size = 0;  // bytes on the wire when sent compressed (size is then the decoded size)
    bool decoded = false;       // gzip/deflate body that was decompressed before hashing
};

// Walks the server side of an HTTP connection response by response.
struct HttpBodyTracker {
    enum Mode : uint8_t { Headers, Length, Chunked, UntilClose, Done } mode = Headers;
    HttpFile current;        // the body being read
    enum Chunk : uint8_t { Size, Data, DataEnd, Trailer } chunk = Size;
    std::string pending;     // header or chunk-size line being collected
    uint64_t remaining = 0;
    Sha256 hash;
    uint32_t gaps_at_start = 0;
    size_t responses = 0;
    std::vector<HttpFile> files;
    // gzip/deflate bodies are collected, then decompressed and hashed when complete.
    bool collect = false;
    std::string encoded;
    ObjectTarget* sink = nullptr;  // the body being read is the one to write out
};

// A TLS connection whose secrets the user supplied (--keylog): the application data
// inside it, which the HTTP parser and file extraction read the way they read plain HTTP.
struct TlsPlain {
    explicit TlsPlain(const TlsKeyLog* keylog) : dec(keylog) {}
    TlsStreamDecryptor dec;
    // What the decrypted bytes carry, from the first of them: 0 not known yet,
    // 1 HTTP/1.x, 2 HTTP/2, 3 something else. Bytes seen before it is known wait in held.
    uint8_t app = 0;
    std::string held[2];
    std::string req;              // HTTP/1.x: the client's decrypted bytes (its requests), bounded
    std::string resp;             // HTTP/1.x: the head of the server's, for the response line
    bool s2c_seen = false;        // the server's first decrypted bytes were looked at
    // After a capture hole: HTTP/1.x waits for the next message to begin (a request line,
    // a status line) before reading on.
    bool resync[2] = {false, false};
    uint32_t gaps[2] = {0, 0};
};

// HTTP/2 on a connection (inside decrypted TLS, or cleartext with prior knowledge): each
// stream's request, and its response body hashed as it streams past, like HTTP/1.x's.
struct H2Stream {
    int request = -1;        // its request's index in Flow::http
    bool response = false;   // response headers seen: the body is being read
    HttpBodyTracker body;
};
constexpr uint32_t kH2NoRequest = 0x40000000;  // file numbers for responses whose request wasn't read
struct H2State {
    explicit H2State(bool client_preface) : reader(client_preface) {}
    Http2Reader reader;
    std::map<uint32_t, H2Stream> streams;
    uint32_t responses = 0;  // bodies with no readable request are numbered from kH2NoRequest
    uint32_t gaps[2] = {0, 0};
};

struct DirStats {
    uint64_t packets = 0;
    uint64_t bytes = 0;          // wire bytes
    uint64_t payload_bytes = 0;  // L4 payload bytes (excluding retransmissions for TCP)
};

struct Flow {
    uint64_t id = 0;
    uint8_t proto = 0;
    IpAddr client_ip, server_ip;
    uint16_t client_port = 0, server_port = 0;
    bool client_is_a = true;     // maps FlowKey A/B onto client/server

    uint64_t first_ts = 0, last_ts = 0;
    uint64_t last_emit_ts = 0;
    bool dirty = false;          // new activity since the last emission
    bool closed = false;
    uint64_t closed_ts = 0;
    bool handshake_seen = false;
    // The handshake's timing at the capture point: SYN -> SYN/ACK is the round trip to the
    // server, SYN/ACK -> ACK the round trip to the client (the speed-of-light check).
    uint64_t syn_ts = 0, synack_ts = 0, hs_ack_ts = 0;
    uint32_t syn_seq = 0;
    // Each side's TCP timestamp clock (RFC 7323 TSval): the first and the latest reading with
    // the capture time it arrived, so its rate and starting point can be worked out.
    struct TsClock {
        uint64_t t0 = 0, t1 = 0;  // capture times, microseconds
        uint32_t v0 = 0, v1 = 0;  // TSval readings
        uint64_t n = 0;
    } ts_clock[2];

    DirStats stats[2];
    std::vector<PayloadEvent> events;  // capped
    RateHistogram rate;                // uncapped, coarse
    uint64_t events_dropped = 0;

    TcpStream tcp[2];
    // Head of each reassembled stream, kept only as long as a protocol parser
    // needs it. The per-direction limit is chosen once the protocol is known.
    std::string app_buf[2];
    size_t app_limit[2] = {SIZE_MAX, SIZE_MAX};  // SIZE_MAX = not yet classified
    double entropy[2] = {-1.0, -1.0};            // Shannon bits/byte of the stream head
    uint32_t entropy_sample[2] = {0, 0};
    size_t mem = 0;              // bytes this flow currently accounts for in the budget
    bool evicted = false;        // finished early to stay under the memory budget

    std::vector<DnsMessage> dns;
    std::vector<HttpRequest> http;
    std::optional<HttpResponse> http_response;
    std::optional<TlsClientHello> tls;
    std::optional<TlsServerHello> tls_server;
    std::unique_ptr<QuicHelloReader> quic;  // UDP 443 until its Client Hello is read
    bool quic_done = false;
    std::unique_ptr<DtlsHelloReader> dtls;  // a DTLS flow until both hellos are read
    bool dtls_done = false;
    std::unique_ptr<HttpBodyTracker> http_bodies;  // HTTP responses on the server side
    std::unique_ptr<TlsPlain> tls_plain;           // TLS the user holds the keys for
    std::unique_ptr<H2State> h2;                   // HTTP/2 (decrypted, or cleartext h2c)
    std::unique_ptr<SmbFileTracker> smb;          // files read and written over SMB2
    uint64_t smb_gaps[2] = {0, 0};
    std::unique_ptr<LoginTracker> logins;          // logins sent in clear text (usernames only)
    bool logins_decided = false;                   // whether the connection is one logins are read from
    std::unique_ptr<FtpControl> ftp_control;       // an FTP control connection (port 21)
    std::shared_ptr<FtpTransfer> ftp_transfer;     // an FTP data connection: what it carries
    std::unique_ptr<FtpDataSide[]> ftp_data;       // its two directions
    uint32_t null_flags = 0;                       // TCP segments with no flag set at all

    // The first bytes each side sent, and whether that was the true start of its
    // stream (its SYN was captured), so a protocol can be told apart from its port.
    std::string head[2];
    bool head_from_start[2] = {false, false};
    int8_t first_speaker = -1;   // 0 client, 1 server

    FILE* dump[2] = {nullptr, nullptr};
};

struct FlowTableOptions {
    uint64_t tcp_idle_us = 120'000'000;
    uint64_t udp_idle_us = 30'000'000;
    uint64_t close_linger_us = 2'000'000;    // absorb trailing ACKs after FIN/RST
    uint64_t update_interval_us = 30'000'000; // re-emit long-lived flows this often
    uint64_t half_open_idle_us = 30'000'000; // TCP flows that never completed a handshake
    size_t max_flows = 200'000;
    size_t max_events = 2'000;
    size_t app_buf_limit = 16 * 1024;
    size_t pending_limit = 2 * 1024 * 1024;  // per-direction out-of-order buffer cap
    size_t memory_budget = 512u << 20;       // all flow state; oldest flows are evicted past this
    std::string dump_dir;                    // write reassembled streams here if set
    ObjectTarget* object = nullptr;          // a file to write out as it streams past
    const TlsKeyLog* keylog = nullptr;       // the user's TLS secrets: their sessions are read decrypted
};

class FlowTable {
public:
    using EmitFn = std::function<void(const Flow&, bool final)>;

    FlowTable(FlowTableOptions opts, EmitFn emit) : opts_(std::move(opts)), emit_(std::move(emit)) {}
    ~FlowTable() { flush_all(); }

    void on_packet(const PacketInfo& p);
    // Expire idle/closed flows and emit periodic updates. `now_us` is packet time.
    void sweep(uint64_t now_us);
    void flush_all();

    size_t active() const { return flows_.size(); }
    uint64_t total_flows() const { return next_id_ - 1; }
    size_t memory() const { return total_mem_; }
    size_t peak_memory() const { return peak_mem_; }
    uint64_t evicted() const { return evicted_; }

private:
    Flow& lookup(const PacketInfo& p, bool& is_client_to_server, bool& created);
    void handle_tcp(Flow& f, const PacketInfo& p, Dir dir);
    void handle_udp(Flow& f, const PacketInfo& p, Dir dir);
    void on_stream_data(Flow& f, Dir dir, const uint8_t* data, size_t len);
    void tls_plain_data(Flow& f, Dir dir, const uint8_t* data, size_t len);
    void plain_app(Flow& f, Dir dir, const std::string& plain);
    void plain_gap(Flow& f, Dir dir);
    void h2_feed(Flow& f, Dir dir, const uint8_t* data, size_t len);
    void h2_finish(Flow& f);
    struct H2Events;  // the HTTP/2 reader's handler: requests and response bodies into the flow
    friend struct H2Events;
    void http_body_data(Flow& f, const uint8_t* data, size_t len);
    void http_body_bytes(HttpBodyTracker& t, const uint8_t* data, size_t len);
    void http_file_done(Flow& f, HttpBodyTracker& t, bool complete);
    void http_body_end(Flow& f, bool stream_closed);
    void parse_app(Flow& f, Dir dir);
    void record_event(Flow& f, const PacketInfo& p, Dir dir);
    void finish(Flow& f);
    void classify(Flow& f, Dir dir);
    void release_app_buf(Flow& f, Dir dir);
    void account(Flow& f);
    void evict_oldest(size_t count);

    FlowTableOptions opts_;
    EmitFn emit_;
    std::unordered_map<FlowKey, std::unique_ptr<Flow>, FlowKeyHash> flows_;
    uint64_t next_id_ = 1;
    uint64_t last_sweep_ = 0;
    size_t total_mem_ = 0;
    size_t peak_mem_ = 0;
    uint64_t evicted_ = 0;
    // Data connections FTP control connections announced: (address, port, from) -> transfer, when.
    std::map<std::tuple<IpAddr, uint16_t, IpAddr>, std::pair<std::shared_ptr<FtpTransfer>, uint64_t>> ftp_expect_;
};

}  // namespace anta
