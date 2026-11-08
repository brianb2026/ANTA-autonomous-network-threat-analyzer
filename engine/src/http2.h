// HTTP/2 (RFC 9113) as it streams past: frames read from each direction's ordered
// bytes, header blocks decoded with HPACK (RFC 7541), and what they carry handed to a
// handler — request and response headers per stream, and the body bytes of DATA frames
// (padding removed, never buffered whole). Used on HTTPS a key log decrypts and on
// cleartext HTTP/2 ("h2c" with prior knowledge).
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <utility>
#include <vector>

namespace anta {

using Http2Headers = std::vector<std::pair<std::string, std::string>>;

// How one header was coded (RFC 7541 §6), for display.
struct HpackRepr {
    enum Kind : uint8_t { Indexed, Incremental, WithoutIndexing, NeverIndexed } kind = Indexed;
    bool new_name = false;  // a literal whose name was spelled out rather than taken from the table
    uint32_t index = 0;     // the table index used (the field's, or its name's)
};

// HPACK decoding with the connection's dynamic table. One per direction: a header
// block can only be decoded after every earlier block from the same sender.
class Hpack {
public:
    // Decode one complete header block. false: malformed — the table may now be out of
    // step with the sender's, so nothing later from that side can be trusted.
    // `consumed` set: p is a fragment of a block (HEADERS then CONTINUATION frames); the
    // fields whole in it are decoded, and *consumed says where the unfinished one begins.
    bool decode(const uint8_t* p, size_t n, Http2Headers& out, std::vector<HpackRepr>* reprs = nullptr,
                std::vector<uint32_t>* size_updates = nullptr, size_t* consumed = nullptr);
    size_t table_bytes() const { return size_; }

private:
    bool lookup(uint64_t index, std::pair<std::string, std::string>& out) const;
    void insert(std::string name, std::string value);
    void evict();

    std::deque<std::pair<std::string, std::string>> dyn_;  // newest first
    size_t size_ = 0;     // RFC 7541 §4.1: name + value + 32 per entry
    size_t max_ = 4096;   // SETTINGS_HEADER_TABLE_SIZE default; the encoder may lower or restore it
};

// Decode a Huffman-coded HPACK string. false on an invalid code, EOS or bad padding.
bool hpack_huffman_decode(const uint8_t* p, size_t n, std::string& out);

const char* http2_frame_name(uint8_t type);  // "DATA", "HEADERS", … or nullptr
const char* http2_status_phrase(int status); // "OK", "Not Found", … or ""

class Http2Handler {
public:
    virtual ~Http2Handler() = default;
    // A complete header block. dir 0 = from the client, 1 = from the server. For a
    // PUSH_PROMISE (`push`), sid is the promised stream and the headers are its request.
    virtual void h2_headers(int dir, uint32_t sid, const Http2Headers& h, bool end_stream, bool push) = 0;
    virtual void h2_data(int dir, uint32_t sid, const uint8_t* p, size_t n) = 0;  // body bytes
    virtual void h2_end(int dir, uint32_t sid) = 0;                               // END_STREAM after DATA
    virtual void h2_reset(uint32_t sid) = 0;                                      // RST_STREAM
};

class Http2Reader {
public:
    static constexpr const char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    static constexpr size_t kPrefaceLen = 24;

    // `client_preface`: the client side begins with the connection preface.
    explicit Http2Reader(bool client_preface = true) { st_[0].preface = client_preface ? 0 : kPrefaceLen; }

    void feed(int dir, const uint8_t* p, size_t n, Http2Handler& h);
    bool broken(int dir) const { return st_[dir].broken; }
    void stop(int dir) { st_[dir].broken = true; }  // bytes were lost: that side's framing can't be found again
    uint64_t frames() const { return frames_; }
    size_t buffered() const;

private:
    struct Side {
        size_t preface = kPrefaceLen;  // client preface bytes matched so far (done at kPrefaceLen)
        uint8_t head[9];
        size_t head_got = 0;
        uint32_t len = 0, sid = 0;
        uint8_t type = 0, flags = 0;
        bool in_payload = false;
        size_t got = 0;                 // payload bytes consumed of this frame
        std::string payload;            // non-DATA payloads, whole
        // DATA: streamed. Padding length (if PADDED) comes first, then content, then padding.
        size_t data_pad = 0;
        bool data_pad_known = false;
        // A header block continued by CONTINUATION frames.
        std::string block;
        uint32_t block_sid = 0;
        bool block_open = false, block_end_stream = false, block_push = false;
        Hpack hpack;
        bool broken = false;
    };
    void frame_done(int dir, Side& s, Http2Handler& h);
    void header_block(int dir, Side& s, const uint8_t* p, size_t n, uint32_t sid, bool end_headers, bool end_stream,
                      bool push, Http2Handler& h);

    Side st_[2];
    uint64_t frames_ = 0;
};

}  // namespace anta
