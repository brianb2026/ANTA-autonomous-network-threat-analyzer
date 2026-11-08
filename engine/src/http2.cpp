#include "http2.h"

#include <algorithm>
#include <cstring>

namespace anta {

namespace {

struct HuffCode {
    uint32_t code;
    uint8_t len;
};
const HuffCode kHuff[257] = {
#include "hpack_huffman.inc"
};

// A binary trie over the Huffman codes, built once: node 0 is the root.
struct HuffTrie {
    struct Node {
        int16_t child[2] = {-1, -1};
        int16_t sym = -1;
    };
    std::vector<Node> nodes;
    HuffTrie() {
        nodes.reserve(520);
        nodes.emplace_back();
        for (int s = 0; s < 257; ++s) {
            size_t n = 0;
            for (int i = kHuff[s].len - 1; i >= 0; --i) {
                int bit = (kHuff[s].code >> i) & 1;
                if (nodes[n].child[bit] < 0) {
                    nodes[n].child[bit] = static_cast<int16_t>(nodes.size());
                    nodes.emplace_back();
                }
                n = static_cast<size_t>(nodes[n].child[bit]);
            }
            nodes[n].sym = static_cast<int16_t>(s);
        }
    }
};
const HuffTrie& trie() {
    static const HuffTrie t;
    return t;
}

const std::pair<const char*, const char*> kStatic[61] = {
    {":authority", ""}, {":method", "GET"}, {":method", "POST"}, {":path", "/"}, {":path", "/index.html"},
    {":scheme", "http"}, {":scheme", "https"}, {":status", "200"}, {":status", "204"}, {":status", "206"},
    {":status", "304"}, {":status", "400"}, {":status", "404"}, {":status", "500"}, {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"}, {"accept-language", ""}, {"accept-ranges", ""}, {"accept", ""},
    {"access-control-allow-origin", ""}, {"age", ""}, {"allow", ""}, {"authorization", ""}, {"cache-control", ""},
    {"content-disposition", ""}, {"content-encoding", ""}, {"content-language", ""}, {"content-length", ""},
    {"content-location", ""}, {"content-range", ""}, {"content-type", ""}, {"cookie", ""}, {"date", ""},
    {"etag", ""}, {"expect", ""}, {"expires", ""}, {"from", ""}, {"host", ""}, {"if-match", ""},
    {"if-modified-since", ""}, {"if-none-match", ""}, {"if-range", ""}, {"if-unmodified-since", ""},
    {"last-modified", ""}, {"link", ""}, {"location", ""}, {"max-forwards", ""}, {"proxy-authenticate", ""},
    {"proxy-authorization", ""}, {"range", ""}, {"referer", ""}, {"refresh", ""}, {"retry-after", ""},
    {"server", ""}, {"set-cookie", ""}, {"strict-transport-security", ""}, {"transfer-encoding", ""},
    {"user-agent", ""}, {"vary", ""}, {"via", ""}, {"www-authenticate", ""},
};

constexpr size_t kMaxString = 64 * 1024;     // one name or value
constexpr size_t kMaxHeaderList = 256 * 1024; // one decoded block
constexpr size_t kMaxHeaders = 512;
constexpr size_t kMaxTable = 1u << 20;        // a size update past this is not a real peer
constexpr size_t kMaxFrame = 1u << 20;        // non-DATA payloads are buffered whole, up to this
constexpr size_t kMaxBlock = 256 * 1024;      // a header block split over CONTINUATION frames

enum Read { kOk, kShort, kBad };  // read, ran out of bytes (more may follow), malformed

// RFC 7541 §5.1 integer with an N-bit prefix.
Read read_int(const uint8_t* p, size_t n, size_t& pos, int prefix, uint64_t& out) {
    if (pos >= n) return kShort;
    uint64_t mask = (1u << prefix) - 1;
    out = p[pos++] & mask;
    if (out < mask) return kOk;
    for (int shift = 0;; shift += 7) {
        if (shift > 28) return kBad;
        if (pos >= n) return kShort;
        uint8_t b = p[pos++];
        out += static_cast<uint64_t>(b & 0x7f) << shift;
        if (!(b & 0x80)) return kOk;
    }
}

Read read_string(const uint8_t* p, size_t n, size_t& pos, std::string& out) {
    if (pos >= n) return kShort;
    bool huff = p[pos] & 0x80;
    uint64_t len = 0;
    if (Read r = read_int(p, n, pos, 7, len); r != kOk) return r;
    if (len > kMaxString) return kBad;
    if (len > n - pos) return kShort;
    out.clear();
    bool ok = huff ? hpack_huffman_decode(p + pos, static_cast<size_t>(len), out)
                   : (out.assign(reinterpret_cast<const char*>(p + pos), static_cast<size_t>(len)), true);
    pos += static_cast<size_t>(len);
    return ok && out.size() <= kMaxString ? kOk : kBad;
}

}  // namespace

bool hpack_huffman_decode(const uint8_t* p, size_t n, std::string& out) {
    const auto& nodes = trie().nodes;
    size_t node = 0;
    int pending = 0;        // bits since the last whole symbol
    bool all_ones = true;   // …and whether they were all 1s (the only valid padding)
    for (size_t i = 0; i < n; ++i) {
        for (int b = 7; b >= 0; --b) {
            int bit = (p[i] >> b) & 1;
            int16_t next = nodes[node].child[bit];
            if (next < 0) return false;
            node = static_cast<size_t>(next);
            ++pending;
            all_ones = all_ones && bit;
            if (nodes[node].sym >= 0) {
                if (nodes[node].sym == 256) return false;  // EOS inside a string
                out.push_back(static_cast<char>(nodes[node].sym));
                if (out.size() > kMaxString) return false;
                node = 0;
                pending = 0;
                all_ones = true;
            }
        }
    }
    return pending < 8 && all_ones;  // RFC 7541 §5.2: at most 7 bits of EOS prefix
}

bool Hpack::lookup(uint64_t index, std::pair<std::string, std::string>& out) const {
    if (index == 0) return false;
    if (index <= 61) {
        out = {kStatic[index - 1].first, kStatic[index - 1].second};
        return true;
    }
    index -= 62;
    if (index >= dyn_.size()) return false;
    out = dyn_[static_cast<size_t>(index)];
    return true;
}

void Hpack::evict() {
    while (size_ > max_ && !dyn_.empty()) {
        size_ -= dyn_.back().first.size() + dyn_.back().second.size() + 32;
        dyn_.pop_back();
    }
}

void Hpack::insert(std::string name, std::string value) {
    size_t sz = name.size() + value.size() + 32;
    if (sz > max_) {  // larger than the whole table: it empties the table (RFC 7541 §4.4)
        dyn_.clear();
        size_ = 0;
        return;
    }
    size_ += sz;
    dyn_.emplace_front(std::move(name), std::move(value));
    evict();
}

bool Hpack::decode(const uint8_t* p, size_t n, Http2Headers& out, std::vector<HpackRepr>* reprs,
                   std::vector<uint32_t>* size_updates, size_t* consumed) {
    size_t pos = 0, total = 0;
    // A fragment (consumed != nullptr) may end inside a field: stop before it, and the
    // caller hands its bytes back with the next fragment. A whole block may not.
    auto fail = [&](Read r, size_t start) {
        if (r == kShort && consumed) {
            *consumed = start;
            return true;
        }
        return false;
    };
    while (pos < n) {
        size_t start = pos;
        uint8_t b = p[pos];
        std::pair<std::string, std::string> h;
        HpackRepr r;
        if (b & 0x80) {  // indexed field
            uint64_t idx = 0;
            if (Read e = read_int(p, n, pos, 7, idx); e != kOk) return fail(e, start);
            if (!lookup(idx, h)) return false;
            r.index = static_cast<uint32_t>(idx);
        } else if ((b & 0xe0) == 0x20) {  // dynamic table size update
            uint64_t sz = 0;
            if (Read e = read_int(p, n, pos, 5, sz); e != kOk) return fail(e, start);
            if (sz > kMaxTable) return false;
            max_ = static_cast<size_t>(sz);
            evict();
            if (size_updates) size_updates->push_back(static_cast<uint32_t>(sz));
            continue;
        } else {  // literal: with incremental indexing (01), without (0000) or never indexed (0001)
            bool incremental = (b & 0xc0) == 0x40;
            r.kind = incremental ? HpackRepr::Incremental : (b & 0xf0) == 0x10 ? HpackRepr::NeverIndexed
                                                                                 : HpackRepr::WithoutIndexing;
            uint64_t idx = 0;
            if (Read e = read_int(p, n, pos, incremental ? 6 : 4, idx); e != kOk) return fail(e, start);
            r.index = static_cast<uint32_t>(idx);
            r.new_name = idx == 0;
            if (idx) {
                std::pair<std::string, std::string> named;
                if (!lookup(idx, named)) return false;
                h.first = std::move(named.first);
            } else if (Read e = read_string(p, n, pos, h.first); e != kOk) {
                return fail(e, start);
            }
            if (Read e = read_string(p, n, pos, h.second); e != kOk) return fail(e, start);
            if (incremental) insert(h.first, h.second);
        }
        total += h.first.size() + h.second.size();
        if (out.size() >= kMaxHeaders || total > kMaxHeaderList) return false;
        out.push_back(std::move(h));
        if (reprs) reprs->push_back(r);
    }
    if (consumed) *consumed = n;
    return true;
}

const char* http2_frame_name(uint8_t type) {
    switch (type) {
        case 0: return "DATA";
        case 1: return "HEADERS";
        case 2: return "PRIORITY";
        case 3: return "RST_STREAM";
        case 4: return "SETTINGS";
        case 5: return "PUSH_PROMISE";
        case 6: return "PING";
        case 7: return "GOAWAY";
        case 8: return "WINDOW_UPDATE";
        case 9: return "CONTINUATION";
        case 0xa: return "ALTSVC";
        case 0xc: return "ORIGIN";
        case 0x10: return "PRIORITY_UPDATE";
        default: return nullptr;
    }
}

size_t Http2Reader::buffered() const {
    return st_[0].payload.capacity() + st_[1].payload.capacity() + st_[0].block.capacity() + st_[1].block.capacity() +
           st_[0].hpack.table_bytes() + st_[1].hpack.table_bytes();
}

void Http2Reader::feed(int dir, const uint8_t* p, size_t n, Http2Handler& h) {
    if (dir < 0 || dir > 1) return;
    Side& s = st_[dir];
    while (n && !s.broken) {
        if (s.preface < kPrefaceLen) {  // the client's connection preface
            size_t k = std::min(n, kPrefaceLen - s.preface);
            if (std::memcmp(p, kPreface + s.preface, k) != 0) {
                s.broken = true;
                return;
            }
            s.preface += k;
            p += k;
            n -= k;
            continue;
        }
        if (!s.in_payload) {
            size_t k = std::min(n, sizeof(s.head) - s.head_got);
            std::memcpy(s.head + s.head_got, p, k);
            s.head_got += k;
            p += k;
            n -= k;
            if (s.head_got < sizeof(s.head)) return;
            s.head_got = 0;
            s.len = (static_cast<uint32_t>(s.head[0]) << 16) | (s.head[1] << 8) | s.head[2];
            s.type = s.head[3];
            s.flags = s.head[4];
            s.sid = ((static_cast<uint32_t>(s.head[5]) << 24) | (s.head[6] << 16) | (s.head[7] << 8) | s.head[8]) &
                    0x7fffffffu;
            if ((s.type != 0 && s.len > kMaxFrame) || (s.block_open && s.type != 9)) {
                s.broken = true;  // a frame no peer sends, or a header block interrupted: framing is lost
                return;
            }
            s.in_payload = true;
            s.got = 0;
            s.payload.clear();
            s.data_pad = 0;
            s.data_pad_known = !(s.type == 0 && (s.flags & 0x8));
            if (s.len == 0) frame_done(dir, s, h);
            continue;
        }
        size_t k = std::min<size_t>(n, s.len - s.got);
        if (s.type == 0) {  // DATA: hand the content over as it arrives, without the padding
            if (!s.data_pad_known) {
                s.data_pad = p[0];
                s.data_pad_known = true;
                if (1 + s.data_pad > s.len) {
                    s.broken = true;
                    return;
                }
            }
            bool padded = s.flags & 0x8;
            size_t c0 = padded ? 1 : 0, c1 = s.len - (padded ? s.data_pad : 0);
            size_t a = std::max(s.got, c0), e = std::min(s.got + k, c1);
            if (a < e && s.sid) h.h2_data(dir, s.sid, p + (a - s.got), e - a);
        } else {
            s.payload.append(reinterpret_cast<const char*>(p), k);
        }
        s.got += k;
        p += k;
        n -= k;
        if (s.got == s.len) frame_done(dir, s, h);
    }
}

void Http2Reader::header_block(int dir, Side& s, const uint8_t* p, size_t n, uint32_t sid, bool end_headers,
                               bool end_stream, bool push, Http2Handler& h) {
    if (!end_headers) {  // CONTINUATION frames follow
        if (n > kMaxBlock) {
            s.broken = true;
            return;
        }
        s.block.assign(reinterpret_cast<const char*>(p), n);
        s.block_open = true;
        s.block_sid = sid;
        s.block_end_stream = end_stream;
        s.block_push = push;
        return;
    }
    Http2Headers hdrs;
    if (!s.hpack.decode(p, n, hdrs)) {
        s.broken = true;  // the dynamic table can't be trusted past a block it couldn't read
        return;
    }
    h.h2_headers(dir, sid, hdrs, end_stream, push);
}

void Http2Reader::frame_done(int dir, Side& s, Http2Handler& h) {
    s.in_payload = false;
    ++frames_;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(s.payload.data());
    size_t n = s.payload.size();
    switch (s.type) {
        case 0:  // DATA
            if ((s.flags & 0x1) && s.sid) h.h2_end(dir, s.sid);
            break;
        case 1:    // HEADERS
        case 5: {  // PUSH_PROMISE
            size_t off = 0, pad = 0;
            if (s.flags & 0x8) {
                if (!n) return void(s.broken = true);
                pad = p[0];
                off = 1;
            }
            uint32_t sid = s.sid;
            if (s.type == 1 && (s.flags & 0x20)) off += 5;  // priority: dependency + weight
            if (s.type == 5) {
                if (off + 4 > n) return void(s.broken = true);
                sid = ((static_cast<uint32_t>(p[off]) << 24) | (p[off + 1] << 16) | (p[off + 2] << 8) | p[off + 3]) &
                      0x7fffffffu;
                off += 4;
            }
            if (off + pad > n) return void(s.broken = true);
            header_block(dir, s, p + off, n - off - pad, sid, s.flags & 0x4, s.type == 1 && (s.flags & 0x1),
                         s.type == 5, h);
            break;
        }
        case 9:  // CONTINUATION
            if (!s.block_open || s.sid != s.block_sid || s.block.size() + n > kMaxBlock) return void(s.broken = true);
            s.block.append(reinterpret_cast<const char*>(p), n);
            if (s.flags & 0x4) {
                s.block_open = false;
                std::string block;
                block.swap(s.block);
                header_block(dir, s, reinterpret_cast<const uint8_t*>(block.data()), block.size(), s.block_sid, true,
                             s.block_end_stream, s.block_push, h);
            }
            break;
        case 3:  // RST_STREAM
            if (s.sid) h.h2_reset(s.sid);
            break;
        default:  // SETTINGS, PING, GOAWAY, WINDOW_UPDATE, PRIORITY, extensions: nothing to follow
            break;
    }
    if (s.payload.capacity() > 64 * 1024) std::string().swap(s.payload);
    else s.payload.clear();
}

}  // namespace anta
