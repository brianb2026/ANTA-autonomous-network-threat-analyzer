#include "hash.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace anta {

namespace {

constexpr uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

constexpr uint32_t S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                            5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

inline uint32_t rotl(uint32_t x, uint32_t c) { return (x << c) | (x >> (32 - c)); }

}  // namespace

void md5(const uint8_t* data, size_t len, uint8_t digest[16]) {
    uint32_t h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476;

    std::vector<uint8_t> msg(data, data + len);
    uint64_t bit_len = static_cast<uint64_t>(msg.size()) * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0);
    for (int i = 0; i < 8; ++i) msg.push_back(static_cast<uint8_t>(bit_len >> (8 * i)));

    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32_t m[16];
        for (int i = 0; i < 16; ++i) {
            const uint8_t* p = &msg[chunk + i * 4];
            m[i] = p[0] | (p[1] << 8) | (p[2] << 16) | (static_cast<uint32_t>(p[3]) << 24);
        }
        uint32_t a = h0, b = h1, c = h2, d = h3;
        for (uint32_t i = 0; i < 64; ++i) {
            uint32_t f, g;
            if (i < 16) {
                f = (b & c) | (~b & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | (~d & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | ~d);
                g = (7 * i) % 16;
            }
            uint32_t tmp = d;
            d = c;
            c = b;
            b = b + rotl(a + f + K[i] + m[g], S[i]);
            a = tmp;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }

    int k = 0;
    for (uint32_t h : {h0, h1, h2, h3})
        for (int i = 0; i < 4; ++i) digest[k++] = static_cast<uint8_t>(h >> (8 * i));
}

std::string md5_hex(const std::string& input) {
    uint8_t d[16];
    md5(reinterpret_cast<const uint8_t*>(input.data()), input.size(), d);
    static const char* hex = "0123456789abcdef";
    std::string out;
    for (uint8_t byte : d) {
        out.push_back(hex[byte >> 4]);
        out.push_back(hex[byte & 0x0F]);
    }
    return out;
}

namespace {

constexpr uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t rotr(uint32_t x, uint32_t c) { return (x >> c) | (x << (32 - c)); }

}  // namespace

void Sha256::block(const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (static_cast<uint32_t>(p[i * 4]) << 24) | (p[i * 4 + 1] << 16) | (p[i * 4 + 2] << 8) | p[i * 4 + 3];
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], hh = h_[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + s1 + ch + K256[i] + w[i];
        uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += hh;
}

void Sha256::update(const uint8_t* data, size_t len) {
    total_ += len;
    if (buffered_) {
        size_t take = std::min(len, sizeof buf_ - buffered_);
        std::memcpy(buf_ + buffered_, data, take);
        buffered_ += take;
        data += take;
        len -= take;
        if (buffered_ < sizeof buf_) return;
        block(buf_);
        buffered_ = 0;
    }
    for (; len >= 64; data += 64, len -= 64) block(data);
    std::memcpy(buf_, data, len);
    buffered_ = len;
}

void Sha256::digest(uint8_t out[32]) const {
    Sha256 s = *this;  // finishing pads the state, so work on a copy
    uint64_t bit_len = s.total_ * 8;
    static const uint8_t pad[64] = {0x80};
    s.update(pad, 1 + ((119 - s.buffered_) % 64));
    uint8_t len_be[8];
    for (int i = 0; i < 8; ++i) len_be[i] = static_cast<uint8_t>(bit_len >> (8 * (7 - i)));
    s.update(len_be, 8);
    for (int w = 0; w < 8; ++w)
        for (int i = 0; i < 4; ++i) out[w * 4 + i] = static_cast<uint8_t>(s.h_[w] >> (8 * (3 - i)));
}

std::string Sha256::hex() const {
    uint8_t d[32];
    digest(d);
    static const char* hexd = "0123456789abcdef";
    std::string out;
    for (uint8_t byte : d) {
        out.push_back(hexd[byte >> 4]);
        out.push_back(hexd[byte & 0x0F]);
    }
    return out;
}

std::string sha256_hex(const std::string& input) {
    Sha256 s;
    s.update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
    return s.hex();
}

}  // namespace anta
