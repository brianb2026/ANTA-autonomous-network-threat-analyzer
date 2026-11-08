#include "inflate.h"

#include <cstdint>
#include <cstring>

namespace anta {

namespace {

// Bits come least significant first; reading past the end fails the decode.
struct BitReader {
    const uint8_t* p;
    size_t n, pos = 0;
    uint32_t bitbuf = 0;
    int bitcnt = 0;
    bool overrun = false;

    uint32_t bits(int need) {
        while (bitcnt < need) {
            if (pos >= n) {
                overrun = true;
                return 0;
            }
            bitbuf |= static_cast<uint32_t>(p[pos++]) << bitcnt;
            bitcnt += 8;
        }
        uint32_t v = bitbuf & ((1u << need) - 1);
        bitbuf >>= need;
        bitcnt -= need;
        return v;
    }
    void align() {
        bitbuf = 0;
        bitcnt = 0;
    }
};

// Canonical Huffman code: how many codes of each length, and the symbols in code order.
struct Huffman {
    uint16_t count[16] = {};
    uint16_t symbol[320] = {};
};

// Returns false for an over-subscribed set of lengths. (Incomplete codes are
// allowed, as zlib allows them for a single distance code.)
bool build(Huffman& h, const uint8_t* lengths, int n) {
    std::memset(h.count, 0, sizeof h.count);
    for (int i = 0; i < n; ++i) h.count[lengths[i]]++;
    h.count[0] = 0;
    int left = 1;
    for (int len = 1; len < 16; ++len) {
        left <<= 1;
        left -= h.count[len];
        if (left < 0) return false;
    }
    uint16_t offs[16];
    offs[1] = 0;
    for (int len = 1; len < 15; ++len) offs[len + 1] = static_cast<uint16_t>(offs[len] + h.count[len]);
    for (int i = 0; i < n; ++i)
        if (lengths[i]) h.symbol[offs[lengths[i]]++] = static_cast<uint16_t>(i);
    return true;
}

int decode(BitReader& br, const Huffman& h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len < 16; ++len) {
        code |= static_cast<int>(br.bits(1));
        if (br.overrun) return -1;
        int count = h.count[len];
        if (code - count < first) return h.symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

const uint16_t kLenBase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                               31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
const uint8_t kLenExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
const uint16_t kDistBase[30] = {1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,    65,    97,    129,
                                193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
const uint8_t kDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

bool codes(BitReader& br, std::string& out, size_t max_out, const Huffman& lit, const Huffman& dist) {
    for (;;) {
        int sym = decode(br, lit);
        if (sym < 0) return false;
        if (sym < 256) {
            if (out.size() >= max_out) return false;
            out.push_back(static_cast<char>(sym));
            continue;
        }
        if (sym == 256) return true;
        sym -= 257;
        if (sym >= 29) return false;
        size_t len = kLenBase[sym] + br.bits(kLenExtra[sym]);
        int ds = decode(br, dist);
        if (ds < 0 || ds >= 30) return false;
        size_t d = kDistBase[ds] + br.bits(kDistExtra[ds]);
        if (br.overrun || d > out.size() || out.size() + len > max_out) return false;
        size_t from = out.size() - d;
        for (size_t i = 0; i < len; ++i) out.push_back(out[from + i]);  // may overlap itself
    }
}

struct FixedCodes {
    Huffman lit, dist;
    FixedCodes() {
        uint8_t l[288];
        for (int i = 0; i < 144; ++i) l[i] = 8;
        for (int i = 144; i < 256; ++i) l[i] = 9;
        for (int i = 256; i < 280; ++i) l[i] = 7;
        for (int i = 280; i < 288; ++i) l[i] = 8;
        build(lit, l, 288);
        uint8_t dl[30];
        for (auto& x : dl) x = 5;
        build(dist, dl, 30);
    }
};

bool inflate_raw(const uint8_t* data, size_t n, std::string& out, size_t max_out, size_t* used) {
    BitReader br{data, n};
    bool last = false;
    while (!last) {
        last = br.bits(1);
        uint32_t type = br.bits(2);
        if (br.overrun) return false;
        if (type == 0) {  // stored
            br.align();
            if (br.pos + 4 > n) return false;
            uint16_t len = static_cast<uint16_t>(data[br.pos] | (data[br.pos + 1] << 8));
            uint16_t nlen = static_cast<uint16_t>(data[br.pos + 2] | (data[br.pos + 3] << 8));
            br.pos += 4;
            if (len != static_cast<uint16_t>(~nlen) || br.pos + len > n || out.size() + len > max_out) return false;
            out.append(reinterpret_cast<const char*>(data + br.pos), len);
            br.pos += len;
        } else if (type == 1) {  // fixed codes
            static const FixedCodes fixed;  // built once, thread-safely
            if (!codes(br, out, max_out, fixed.lit, fixed.dist)) return false;
        } else if (type == 2) {  // dynamic codes
            int nlen = static_cast<int>(br.bits(5)) + 257, ndist = static_cast<int>(br.bits(5)) + 1;
            int ncode = static_cast<int>(br.bits(4)) + 4;
            if (br.overrun || nlen > 286 || ndist > 30) return false;
            static const uint8_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
            uint8_t lengths[320] = {};
            for (int i = 0; i < ncode; ++i) lengths[order[i]] = static_cast<uint8_t>(br.bits(3));
            Huffman lencode;
            if (br.overrun || !build(lencode, lengths, 19)) return false;
            int index = 0;
            std::memset(lengths, 0, sizeof lengths);
            while (index < nlen + ndist) {
                int sym = decode(br, lencode);
                if (sym < 0) return false;
                if (sym < 16) {
                    lengths[index++] = static_cast<uint8_t>(sym);
                    continue;
                }
                uint8_t len = 0;
                int repeat;
                if (sym == 16) {
                    if (!index) return false;
                    len = lengths[index - 1];
                    repeat = 3 + static_cast<int>(br.bits(2));
                } else if (sym == 17) {
                    repeat = 3 + static_cast<int>(br.bits(3));
                } else {
                    repeat = 11 + static_cast<int>(br.bits(7));
                }
                if (br.overrun || index + repeat > nlen + ndist) return false;
                while (repeat--) lengths[index++] = len;
            }
            if (!lengths[256]) return false;  // no end-of-block code
            Huffman lit, dist;
            if (!build(lit, lengths, nlen) || !build(dist, lengths + nlen, ndist)) return false;
            if (!codes(br, out, max_out, lit, dist)) return false;
        } else {
            return false;
        }
    }
    if (used) *used = br.pos;
    return true;
}

}  // namespace

bool http_decode_body(const std::string& in, const std::string& encoding, std::string& out, size_t max_out) {
    const auto* d = reinterpret_cast<const uint8_t*>(in.data());
    size_t n = in.size();
    out.clear();
    std::string enc;
    for (char c : encoding) enc.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
    if (enc == "gzip" || enc == "x-gzip") {
        if (n < 18 || d[0] != 0x1f || d[1] != 0x8b || d[2] != 8) return false;
        uint8_t flags = d[3];
        size_t pos = 10;
        if (flags & 4) {  // FEXTRA
            if (pos + 2 > n) return false;
            pos += 2 + (d[pos] | (d[pos + 1] << 8));
        }
        for (int field : {8, 16}) {  // FNAME, FCOMMENT: zero-terminated
            if (!(flags & field)) continue;
            while (pos < n && d[pos]) ++pos;
            ++pos;
        }
        if (flags & 2) pos += 2;  // FHCRC
        if (pos >= n) return false;
        return inflate_raw(d + pos, n - pos, out, max_out, nullptr);
    }
    if (enc == "deflate") {
        // Usually zlib-wrapped as the RFC says, but some servers send raw DEFLATE.
        bool zlib = n >= 2 && (d[0] & 0x0F) == 8 && ((d[0] << 8) | d[1]) % 31 == 0;
        if (zlib && inflate_raw(d + 2, n - 2, out, max_out, nullptr)) return true;
        out.clear();
        return inflate_raw(d, n, out, max_out, nullptr);
    }
    return false;
}

}  // namespace anta
