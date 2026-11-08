#include "crypto.h"

#include <cstring>
#include <optional>
#include <string>

#include "hash.h"

namespace anta {

void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t k[64] = {};
    if (key_len > 64) {
        Sha256 h;
        h.update(key, key_len);
        h.digest(k);
    } else {
        std::memcpy(k, key, key_len);
    }
    uint8_t pad[64];
    for (int i = 0; i < 64; ++i) pad[i] = k[i] ^ 0x36;
    Sha256 inner;
    inner.update(pad, 64);
    inner.update(data, len);
    uint8_t ih[32];
    inner.digest(ih);
    for (int i = 0; i < 64; ++i) pad[i] = k[i] ^ 0x5c;
    Sha256 outer;
    outer.update(pad, 64);
    outer.update(ih, 32);
    outer.digest(out);
}

void hkdf_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[32]) {
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

void hkdf_expand_label(const uint8_t secret[32], const char* label, uint8_t* out, size_t out_len) {
    std::string info;
    info.push_back(static_cast<char>(out_len >> 8));
    info.push_back(static_cast<char>(out_len & 0xFF));
    std::string full = std::string("tls13 ") + label;
    info.push_back(static_cast<char>(full.size()));
    info += full;
    info.push_back(0);  // empty context
    uint8_t t[32];
    size_t done = 0;
    std::string block;
    for (uint8_t n = 1; done < out_len; ++n) {
        std::string msg = block + info;
        msg.push_back(static_cast<char>(n));
        hmac_sha256(secret, 32, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), t);
        size_t take = out_len - done < 32 ? out_len - done : 32;
        std::memcpy(out + done, t, take);
        done += take;
        block.assign(reinterpret_cast<const char*>(t), 32);
    }
}

// ---------------------------------------------------------------- AES-128
namespace {

const uint8_t kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82,
    0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96,
    0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
    0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
    0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
    0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
    0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

inline uint8_t xtime(uint8_t x) { return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

}  // namespace

Aes128::Aes128(const uint8_t key[16]) {
    std::memcpy(rk_, key, 16);
    uint8_t rcon = 1;
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4] = {rk_[i - 4], rk_[i - 3], rk_[i - 2], rk_[i - 1]};
        if (i % 16 == 0) {
            uint8_t first = t[0];
            t[0] = kSbox[t[1]] ^ rcon;
            t[1] = kSbox[t[2]];
            t[2] = kSbox[t[3]];
            t[3] = kSbox[first];
            rcon = xtime(rcon);
        }
        for (int j = 0; j < 4; ++j) rk_[i + j] = rk_[i - 16 + j] ^ t[j];
    }
}

void Aes128::encrypt(const uint8_t in[16], uint8_t out[16]) const {
    uint8_t s[16];
    for (int i = 0; i < 16; ++i) s[i] = in[i] ^ rk_[i];
    for (int round = 1; round <= 10; ++round) {
        uint8_t t[16];
        for (int i = 0; i < 16; ++i) t[i] = kSbox[s[i]];
        // ShiftRows: the state is column-major, row r rotates left by r.
        for (int c = 0; c < 4; ++c)
            for (int r = 0; r < 4; ++r) s[c * 4 + r] = t[((c + r) % 4) * 4 + r];
        if (round != 10) {
            for (int c = 0; c < 4; ++c) {
                uint8_t* col = s + c * 4;
                uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3], all = a0 ^ a1 ^ a2 ^ a3;
                col[0] ^= all ^ xtime(a0 ^ a1);
                col[1] ^= all ^ xtime(a1 ^ a2);
                col[2] ^= all ^ xtime(a2 ^ a3);
                col[3] ^= all ^ xtime(a3 ^ a0);
            }
        }
        for (int i = 0; i < 16; ++i) s[i] ^= rk_[round * 16 + i];
    }
    std::memcpy(out, s, 16);
}

namespace {

// The inverse S-box, built from the forward one.
const uint8_t* inv_sbox() {
    static uint8_t inv[256];
    static bool built = [] {
        for (int i = 0; i < 256; ++i) inv[kSbox[i]] = static_cast<uint8_t>(i);
        return true;
    }();
    (void)built;
    return inv;
}

inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

// FIPS-197 §5.3, the inverse cipher, with the encryption key schedule `rk` of `rounds` rounds.
void aes_decrypt_block(const uint8_t* rk, int rounds, const uint8_t in[16], uint8_t out[16]) {
    const uint8_t* inv = inv_sbox();
    uint8_t s[16];
    for (int i = 0; i < 16; ++i) s[i] = in[i] ^ rk[rounds * 16 + i];
    for (int round = rounds - 1; round >= 0; --round) {
        uint8_t t[16];
        // InvShiftRows (row r rotates right by r), then InvSubBytes.
        for (int c = 0; c < 4; ++c)
            for (int r = 0; r < 4; ++r) t[c * 4 + r] = inv[s[((c - r + 4) % 4) * 4 + r]];
        for (int i = 0; i < 16; ++i) s[i] = t[i] ^ rk[round * 16 + i];
        if (round != 0) {
            for (int c = 0; c < 4; ++c) {
                uint8_t* col = s + c * 4;
                uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                col[0] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
                col[1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
                col[2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
                col[3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
            }
        }
    }
    std::memcpy(out, s, 16);
}

}  // namespace

void Aes128::decrypt(const uint8_t in[16], uint8_t out[16]) const { aes_decrypt_block(rk_, 10, in, out); }

// ---------------------------------------------------------------- GCM
namespace {

struct Block {
    uint64_t hi = 0, lo = 0;
};

Block load(const uint8_t* p) {
    Block b;
    for (int i = 0; i < 8; ++i) b.hi = (b.hi << 8) | p[i];
    for (int i = 8; i < 16; ++i) b.lo = (b.lo << 8) | p[i];
    return b;
}

void store(const Block& b, uint8_t* p) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(b.hi >> (56 - 8 * i));
    for (int i = 0; i < 8; ++i) p[8 + i] = static_cast<uint8_t>(b.lo >> (56 - 8 * i));
}

// Multiplication in GF(2^128) with GCM's bit order (SP 800-38D, Algorithm 1).
Block gf_mul(const Block& x, const Block& y) {
    Block z, v = y;
    for (int i = 0; i < 128; ++i) {
        uint64_t bit = i < 64 ? (x.hi >> (63 - i)) & 1 : (x.lo >> (127 - i)) & 1;
        if (bit) {
            z.hi ^= v.hi;
            z.lo ^= v.lo;
        }
        bool lsb = v.lo & 1;
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi >>= 1;
        if (lsb) v.hi ^= 0xe100000000000000ULL;
    }
    return z;
}

void ghash_update(Block& acc, const Block& h, const uint8_t* data, size_t len) {
    for (size_t off = 0; off < len; off += 16) {
        uint8_t blk[16] = {};
        std::memcpy(blk, data + off, len - off < 16 ? len - off : 16);
        Block b = load(blk);
        acc.hi ^= b.hi;
        acc.lo ^= b.lo;
        acc = gf_mul(acc, h);
    }
}

}  // namespace

void gcm_ghash(const uint8_t hkey[16], const uint8_t* aad, size_t aad_len, const uint8_t* ct, size_t ct_len,
               uint8_t out[16]) {
    Block h = load(hkey), acc;
    ghash_update(acc, h, aad, aad_len);
    ghash_update(acc, h, ct, ct_len);
    uint8_t lens[16];
    uint64_t abits = static_cast<uint64_t>(aad_len) * 8, cbits = static_cast<uint64_t>(ct_len) * 8;
    for (int i = 0; i < 8; ++i) {
        lens[i] = static_cast<uint8_t>(abits >> (56 - 8 * i));
        lens[8 + i] = static_cast<uint8_t>(cbits >> (56 - 8 * i));
    }
    ghash_update(acc, h, lens, 16);
    store(acc, out);
}

bool aes128_gcm_open(const uint8_t key[16], const uint8_t nonce[12], const uint8_t* aad, size_t aad_len,
                     const uint8_t* ct, size_t ct_len, const uint8_t tag[16], uint8_t* out) {
    Aes128 aes(key);
    uint8_t zero[16] = {}, hbytes[16];
    aes.encrypt(zero, hbytes);
    Block h = load(hbytes);
    Block acc;
    ghash_update(acc, h, aad, aad_len);
    ghash_update(acc, h, ct, ct_len);
    uint8_t lens[16];
    uint64_t abits = static_cast<uint64_t>(aad_len) * 8, cbits = static_cast<uint64_t>(ct_len) * 8;
    for (int i = 0; i < 8; ++i) {
        lens[i] = static_cast<uint8_t>(abits >> (56 - 8 * i));
        lens[8 + i] = static_cast<uint8_t>(cbits >> (56 - 8 * i));
    }
    ghash_update(acc, h, lens, 16);
    uint8_t counter[16];
    std::memcpy(counter, nonce, 12);
    counter[12] = counter[13] = counter[14] = 0;
    counter[15] = 1;
    uint8_t ek0[16], expect[16];
    aes.encrypt(counter, ek0);
    store(acc, expect);
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= static_cast<uint8_t>(expect[i] ^ ek0[i] ^ tag[i]);
    if (diff) return false;
    for (size_t off = 0; off < ct_len; off += 16) {
        for (int i = 15; i >= 12; --i)
            if (++counter[i]) break;
        uint8_t ks[16];
        aes.encrypt(counter, ks);
        size_t n = ct_len - off < 16 ? ct_len - off : 16;
        for (size_t i = 0; i < n; ++i) out[off + i] = ct[off + i] ^ ks[i];
    }
    return true;
}

// ---------------------------------------------------------------- SHA-512 / SHA-384
namespace {

const uint64_t kK512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

// One-shot SHA-512 family; `iv` picks SHA-512 or SHA-384, `out_len` the truncation.
void sha512_core(const uint8_t* data, size_t len, const uint64_t iv[8], uint8_t* out, size_t out_len) {
    uint64_t h[8];
    std::memcpy(h, iv, sizeof(uint64_t) * 8);
    std::string msg(reinterpret_cast<const char*>(data), len);
    uint64_t bits = static_cast<uint64_t>(len) * 8;  // messages here are far under 2^64 bits
    msg.push_back(static_cast<char>(0x80));
    while (msg.size() % 128 != 112) msg.push_back(0);
    for (int i = 0; i < 8; ++i) msg.push_back(0);  // high 64 bits of the length are 0
    for (int i = 7; i >= 0; --i) msg.push_back(static_cast<char>(bits >> (8 * i)));
    for (size_t off = 0; off < msg.size(); off += 128) {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(msg.data()) + off;
        uint64_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = 0;
            for (int j = 0; j < 8; ++j) w[i] = (w[i] << 8) | p[i * 8 + j];
        }
        for (int i = 16; i < 80; ++i) {
            uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint64_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 80; ++i) {
            uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t t1 = hh + S1 + ch + kK512[i] + w[i];
            uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    uint8_t full[64];
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 8; ++j) full[i * 8 + j] = static_cast<uint8_t>(h[i] >> (56 - 8 * j));
    std::memcpy(out, full, out_len);
}

const uint64_t kIv384[8] = {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
                            0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};

}  // namespace

void sha384(const uint8_t* data, size_t len, uint8_t out[48]) { sha512_core(data, len, kIv384, out, 48); }

void hmac_sha384(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[48]) {
    uint8_t k[128] = {};
    if (key_len > 128) sha384(key, key_len, k);
    else std::memcpy(k, key, key_len);
    uint8_t pad[128];
    for (int i = 0; i < 128; ++i) pad[i] = k[i] ^ 0x36;
    std::string inner(reinterpret_cast<char*>(pad), 128);
    inner.append(reinterpret_cast<const char*>(data), len);
    uint8_t ih[48];
    sha384(reinterpret_cast<const uint8_t*>(inner.data()), inner.size(), ih);
    for (int i = 0; i < 128; ++i) pad[i] = k[i] ^ 0x5c;
    std::string outer(reinterpret_cast<char*>(pad), 128);
    outer.append(reinterpret_cast<char*>(ih), 48);
    sha384(reinterpret_cast<const uint8_t*>(outer.data()), outer.size(), out);
}

void hkdf_expand_label_sha384(const uint8_t secret[48], const char* label, uint8_t* out, size_t out_len) {
    std::string info;
    info.push_back(static_cast<char>(out_len >> 8));
    info.push_back(static_cast<char>(out_len & 0xFF));
    std::string full = std::string("tls13 ") + label;
    info.push_back(static_cast<char>(full.size()));
    info += full;
    info.push_back(0);
    uint8_t t[48];
    size_t done = 0;
    std::string block;
    for (uint8_t n = 1; done < out_len; ++n) {
        std::string msg = block + info;
        msg.push_back(static_cast<char>(n));
        hmac_sha384(secret, 48, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), t);
        size_t take = out_len - done < 48 ? out_len - done : 48;
        std::memcpy(out + done, t, take);
        done += take;
        block.assign(reinterpret_cast<char*>(t), 48);
    }
}

// ---------------------------------------------------------------- AES-256
Aes256::Aes256(const uint8_t key[32]) {
    std::memcpy(rk_, key, 32);
    uint8_t rcon = 1;
    for (int i = 32; i < 240; i += 4) {
        uint8_t t[4] = {rk_[i - 4], rk_[i - 3], rk_[i - 2], rk_[i - 1]};
        if (i % 32 == 0) {
            uint8_t first = t[0];
            t[0] = kSbox[t[1]] ^ rcon;
            t[1] = kSbox[t[2]];
            t[2] = kSbox[t[3]];
            t[3] = kSbox[first];
            rcon = xtime(rcon);
        } else if (i % 32 == 16) {
            for (int j = 0; j < 4; ++j) t[j] = kSbox[t[j]];
        }
        for (int j = 0; j < 4; ++j) rk_[i + j] = rk_[i - 32 + j] ^ t[j];
    }
}

void Aes256::encrypt(const uint8_t in[16], uint8_t out[16]) const {
    uint8_t s[16];
    for (int i = 0; i < 16; ++i) s[i] = in[i] ^ rk_[i];
    for (int round = 1; round <= 14; ++round) {
        uint8_t t[16];
        for (int i = 0; i < 16; ++i) t[i] = kSbox[s[i]];
        for (int c = 0; c < 4; ++c)
            for (int r = 0; r < 4; ++r) s[c * 4 + r] = t[((c + r) % 4) * 4 + r];
        if (round != 14) {
            for (int c = 0; c < 4; ++c) {
                uint8_t* col = s + c * 4;
                uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3], all = a0 ^ a1 ^ a2 ^ a3;
                col[0] ^= all ^ xtime(a0 ^ a1);
                col[1] ^= all ^ xtime(a1 ^ a2);
                col[2] ^= all ^ xtime(a2 ^ a3);
                col[3] ^= all ^ xtime(a3 ^ a0);
            }
        }
        for (int i = 0; i < 16; ++i) s[i] ^= rk_[round * 16 + i];
    }
    std::memcpy(out, s, 16);
}

void Aes256::decrypt(const uint8_t in[16], uint8_t out[16]) const { aes_decrypt_block(rk_, 14, in, out); }

bool aes256_gcm_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad, size_t aad_len,
                     const uint8_t* ct, size_t ct_len, const uint8_t tag[16], uint8_t* out) {
    Aes256 aes(key);
    uint8_t zero[16] = {}, hbytes[16];
    aes.encrypt(zero, hbytes);
    Block h = load(hbytes);
    Block acc;
    ghash_update(acc, h, aad, aad_len);
    ghash_update(acc, h, ct, ct_len);
    uint8_t lens[16];
    uint64_t abits = static_cast<uint64_t>(aad_len) * 8, cbits = static_cast<uint64_t>(ct_len) * 8;
    for (int i = 0; i < 8; ++i) {
        lens[i] = static_cast<uint8_t>(abits >> (56 - 8 * i));
        lens[8 + i] = static_cast<uint8_t>(cbits >> (56 - 8 * i));
    }
    ghash_update(acc, h, lens, 16);
    uint8_t counter[16];
    std::memcpy(counter, nonce, 12);
    counter[12] = counter[13] = counter[14] = 0;
    counter[15] = 1;
    uint8_t ek0[16], expect[16];
    aes.encrypt(counter, ek0);
    store(acc, expect);
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= static_cast<uint8_t>(expect[i] ^ ek0[i] ^ tag[i]);
    if (diff) return false;
    for (size_t off = 0; off < ct_len; off += 16) {
        for (int i = 15; i >= 12; --i)
            if (++counter[i]) break;
        uint8_t ks[16];
        aes.encrypt(counter, ks);
        size_t n = ct_len - off < 16 ? ct_len - off : 16;
        for (size_t i = 0; i < n; ++i) out[off + i] = ct[off + i] ^ ks[i];
    }
    return true;
}

// ---------------------------------------------------------------- ChaCha20-Poly1305 (RFC 8439)
namespace {

inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t st[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (int i = 0; i < 8; ++i)
        st[4 + i] = key[4 * i] | (key[4 * i + 1] << 8) | (key[4 * i + 2] << 16) | (static_cast<uint32_t>(key[4 * i + 3]) << 24);
    st[12] = counter;
    for (int i = 0; i < 3; ++i)
        st[13 + i] = nonce[4 * i] | (nonce[4 * i + 1] << 8) | (nonce[4 * i + 2] << 16) | (static_cast<uint32_t>(nonce[4 * i + 3]) << 24);
    uint32_t x[16];
    std::memcpy(x, st, sizeof(st));
    auto qr = [&](int a, int b, int c, int d) {
        x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);
    };
    for (int i = 0; i < 10; ++i) {
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t v = x[i] + st[i];
        out[4 * i] = v & 0xFF; out[4 * i + 1] = (v >> 8) & 0xFF; out[4 * i + 2] = (v >> 16) & 0xFF; out[4 * i + 3] = (v >> 24) & 0xFF;
    }
}

// Poly1305 over 130-bit arithmetic in 26-bit limbs (RFC 8439 §2.5).
void poly1305(const uint8_t key[32], const uint8_t* msg, size_t len, uint8_t tag[16]) {
    uint32_t r0 = (key[0] | key[1] << 8 | key[2] << 16 | static_cast<uint32_t>(key[3]) << 24) & 0x3ffffff;
    uint32_t r1 = ((key[3] >> 2) | key[4] << 6 | key[5] << 14 | static_cast<uint32_t>(key[6]) << 22) & 0x3ffff03;
    uint32_t r2 = ((key[6] >> 4) | key[7] << 4 | key[8] << 12 | static_cast<uint32_t>(key[9]) << 20) & 0x3ffc0ff;
    uint32_t r3 = ((key[9] >> 6) | key[10] << 2 | key[11] << 10 | static_cast<uint32_t>(key[12]) << 18) & 0x3f03fff;
    uint32_t r4 = (key[13] | key[14] << 8 | static_cast<uint32_t>(key[15]) << 16) & 0x00fffff;
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    size_t off = 0;
    while (off < len) {
        uint8_t blk[17] = {};
        size_t n = len - off < 16 ? len - off : 16;
        std::memcpy(blk, msg + off, n);
        blk[n] = 1;  // the high 1 bit; for a full block this is 2^128, for a short one it pads the message
        uint32_t t0 = blk[0] | blk[1] << 8 | blk[2] << 16 | static_cast<uint32_t>(blk[3]) << 24;
        uint32_t t1 = blk[4] | blk[5] << 8 | blk[6] << 16 | static_cast<uint32_t>(blk[7]) << 24;
        uint32_t t2 = blk[8] | blk[9] << 8 | blk[10] << 16 | static_cast<uint32_t>(blk[11]) << 24;
        uint32_t t3 = blk[12] | blk[13] << 8 | blk[14] << 16 | static_cast<uint32_t>(blk[15]) << 24;
        h0 += t0 & 0x3ffffff;
        h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h4 += (t3 >> 8) | (static_cast<uint32_t>(blk[16]) << 24);
        uint64_t d0 = static_cast<uint64_t>(h0) * r0 + static_cast<uint64_t>(h1) * s4 + static_cast<uint64_t>(h2) * s3 + static_cast<uint64_t>(h3) * s2 + static_cast<uint64_t>(h4) * s1;
        uint64_t d1 = static_cast<uint64_t>(h0) * r1 + static_cast<uint64_t>(h1) * r0 + static_cast<uint64_t>(h2) * s4 + static_cast<uint64_t>(h3) * s3 + static_cast<uint64_t>(h4) * s2;
        uint64_t d2 = static_cast<uint64_t>(h0) * r2 + static_cast<uint64_t>(h1) * r1 + static_cast<uint64_t>(h2) * r0 + static_cast<uint64_t>(h3) * s4 + static_cast<uint64_t>(h4) * s3;
        uint64_t d3 = static_cast<uint64_t>(h0) * r3 + static_cast<uint64_t>(h1) * r2 + static_cast<uint64_t>(h2) * r1 + static_cast<uint64_t>(h3) * r0 + static_cast<uint64_t>(h4) * s4;
        uint64_t d4 = static_cast<uint64_t>(h0) * r4 + static_cast<uint64_t>(h1) * r3 + static_cast<uint64_t>(h2) * r2 + static_cast<uint64_t>(h3) * r1 + static_cast<uint64_t>(h4) * r0;
        uint64_t c = 0;
        c = d0 >> 26; h0 = d0 & 0x3ffffff; d1 += c;
        c = d1 >> 26; h1 = d1 & 0x3ffffff; d2 += c;
        c = d2 >> 26; h2 = d2 & 0x3ffffff; d3 += c;
        c = d3 >> 26; h3 = d3 & 0x3ffffff; d4 += c;
        c = d4 >> 26; h4 = static_cast<uint32_t>(d4 & 0x3ffffff); h0 += static_cast<uint32_t>(c) * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        off += n;
    }
    // Full carry, then subtract p = 2^130-5 if h >= p.
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    uint32_t g0 = h0 + 5, g1 = h1, g2 = h2, g3 = h3, g4 = h4;
    c = g0 >> 26; g0 &= 0x3ffffff; g1 += c;
    c = g1 >> 26; g1 &= 0x3ffffff; g2 += c;
    c = g2 >> 26; g2 &= 0x3ffffff; g3 += c;
    c = g3 >> 26; g3 &= 0x3ffffff; g4 += c - (1u << 26);
    uint32_t mask = (g4 >> 31) - 1;  // all-ones if g4 didn't borrow (h >= p)
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    uint32_t nmask = ~mask;
    h0 = (h0 & nmask) | g0; h1 = (h1 & nmask) | g1; h2 = (h2 & nmask) | g2; h3 = (h3 & nmask) | g3; h4 = (h4 & nmask) | g4;
    uint64_t f0 = (static_cast<uint64_t>(h0) | static_cast<uint64_t>(h1) << 26) & 0xffffffff;
    uint64_t f1 = ((static_cast<uint64_t>(h1) >> 6) | static_cast<uint64_t>(h2) << 20) & 0xffffffff;
    uint64_t f2 = ((static_cast<uint64_t>(h2) >> 12) | static_cast<uint64_t>(h3) << 14) & 0xffffffff;
    uint64_t f3 = ((static_cast<uint64_t>(h3) >> 18) | static_cast<uint64_t>(h4) << 8) & 0xffffffff;
    uint64_t s[4];
    for (int i = 0; i < 4; ++i)
        s[i] = key[16 + 4 * i] | key[17 + 4 * i] << 8 | key[18 + 4 * i] << 16 | static_cast<uint64_t>(key[19 + 4 * i]) << 24;
    uint64_t acc = f0 + s[0]; tag[0] = acc; tag[1] = acc >> 8; tag[2] = acc >> 16; tag[3] = acc >> 24;
    acc = f1 + s[1] + (acc >> 32); tag[4] = acc; tag[5] = acc >> 8; tag[6] = acc >> 16; tag[7] = acc >> 24;
    acc = f2 + s[2] + (acc >> 32); tag[8] = acc; tag[9] = acc >> 8; tag[10] = acc >> 16; tag[11] = acc >> 24;
    acc = f3 + s[3] + (acc >> 32); tag[12] = acc; tag[13] = acc >> 8; tag[14] = acc >> 16; tag[15] = acc >> 24;
}

}  // namespace

bool chacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad, size_t aad_len,
                            const uint8_t* ct, size_t ct_len, const uint8_t tag[16], uint8_t* out) {
    uint8_t poly_key[64];
    chacha20_block(key, 0, nonce, poly_key);  // counter 0 gives the one-time Poly1305 key
    // MAC input: aad || pad16 || ciphertext || pad16 || len(aad) || len(ct).
    std::string mac;
    mac.append(reinterpret_cast<const char*>(aad), aad_len);
    mac.resize((mac.size() + 15) & ~size_t{15}, '\0');
    mac.append(reinterpret_cast<const char*>(ct), ct_len);
    mac.resize((mac.size() + 15) & ~size_t{15}, '\0');
    for (int i = 0; i < 8; ++i) mac.push_back(static_cast<char>(static_cast<uint64_t>(aad_len) >> (8 * i)));
    for (int i = 0; i < 8; ++i) mac.push_back(static_cast<char>(static_cast<uint64_t>(ct_len) >> (8 * i)));
    uint8_t expect[16];
    poly1305(poly_key, reinterpret_cast<const uint8_t*>(mac.data()), mac.size(), expect);
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= static_cast<uint8_t>(expect[i] ^ tag[i]);
    if (diff) return false;
    for (size_t off = 0; off < ct_len; off += 64) {
        uint8_t ks[64];
        chacha20_block(key, 1 + static_cast<uint32_t>(off / 64), nonce, ks);  // counter starts at 1 for the data
        size_t n = ct_len - off < 64 ? ct_len - off : 64;
        for (size_t i = 0; i < n; ++i) out[off + i] = ct[off + i] ^ ks[i];
    }
    return true;
}

// ---------------------------------------------------------------- TLS 1.2 PRF (RFC 5246 §5)
void tls12_prf(const uint8_t* secret, size_t secret_len, const char* label, const uint8_t* seed, size_t seed_len,
               uint8_t* out, size_t out_len, bool sha384) {
    std::string ls(label);
    ls.append(reinterpret_cast<const char*>(seed), seed_len);
    const uint8_t* ls_p = reinterpret_cast<const uint8_t*>(ls.data());
    size_t hl = sha384 ? 48 : 32;
    auto H = [&](const uint8_t* k, size_t kl, const uint8_t* d, size_t dl, uint8_t* o) {
        if (sha384) hmac_sha384(k, kl, d, dl, o);
        else hmac_sha256(k, kl, d, dl, o);
    };
    uint8_t a[48];
    H(secret, secret_len, ls_p, ls.size(), a);  // A(1) = HMAC(secret, label+seed)
    size_t done = 0;
    while (done < out_len) {
        std::string in(reinterpret_cast<char*>(a), hl);
        in += ls;
        uint8_t block[48];
        H(secret, secret_len, reinterpret_cast<const uint8_t*>(in.data()), in.size(), block);
        size_t take = out_len - done < hl ? out_len - done : hl;
        std::memcpy(out + done, block, take);
        done += take;
        H(secret, secret_len, a, hl, a);  // A(i+1) = HMAC(secret, A(i))
    }
}

// ---------------------------------------------------------------- SHA-1 (FIPS 180-4)
void sha1(const uint8_t* data, size_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    auto rotl = [](uint32_t x, int n) { return (x << n) | (x >> (32 - n)); };
    auto block = [&](const uint8_t* p) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = (static_cast<uint32_t>(p[4 * i]) << 24) | (p[4 * i + 1] << 16) | (p[4 * i + 2] << 8) | p[4 * i + 3];
        for (int i = 16; i < 80; ++i) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) f = (b & c) | (~b & d), k = 0x5A827999;
            else if (i < 40) f = b ^ c ^ d, k = 0x6ED9EBA1;
            else if (i < 60) f = (b & c) | (b & d) | (c & d), k = 0x8F1BBCDC;
            else f = b ^ c ^ d, k = 0xCA62C1D6;
            uint32_t t = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    };
    size_t full = len / 64 * 64;
    for (size_t off = 0; off < full; off += 64) block(data + off);
    uint8_t tail[128] = {};
    size_t rest = len - full;
    std::memcpy(tail, data + full, rest);
    tail[rest] = 0x80;
    size_t tl = rest + 1 + 8 <= 64 ? 64 : 128;
    uint64_t bits = static_cast<uint64_t>(len) * 8;
    for (int i = 0; i < 8; ++i) tail[tl - 1 - i] = static_cast<uint8_t>(bits >> (8 * i));
    for (size_t off = 0; off < tl; off += 64) block(tail + off);
    for (int i = 0; i < 5; ++i)
        for (int j = 0; j < 4; ++j) out[4 * i + j] = static_cast<uint8_t>(h[i] >> (24 - 8 * j));
}

namespace {
// HMAC (RFC 2104) over a 64-byte-block hash.
template <size_t N, typename Hash>
void hmac64(Hash hash, const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[N]) {
    uint8_t k[64] = {};
    if (key_len > 64) hash(key, key_len, k);
    else std::memcpy(k, key, key_len);
    std::string msg(64, '\0');
    for (int i = 0; i < 64; ++i) msg[i] = static_cast<char>(k[i] ^ 0x36);
    msg.append(reinterpret_cast<const char*>(data), len);
    uint8_t ih[N];
    hash(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), ih);
    std::string outer(64, '\0');
    for (int i = 0; i < 64; ++i) outer[i] = static_cast<char>(k[i] ^ 0x5c);
    outer.append(reinterpret_cast<const char*>(ih), N);
    hash(reinterpret_cast<const uint8_t*>(outer.data()), outer.size(), out);
}
}  // namespace

void hmac_sha1(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[20]) {
    hmac64<20>(sha1, key, key_len, data, len, out);
}

void hmac_md5(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[16]) {
    hmac64<16>(md5, key, key_len, data, len, out);
}

// ---------------------------------------------------------------- TLS 1.0/1.1 PRF (RFC 2246 §5)
namespace {
template <size_t N, typename Mac>
void p_hash(Mac mac, const uint8_t* secret, size_t secret_len, const std::string& ls, uint8_t* out, size_t out_len) {
    uint8_t a[N];
    mac(secret, secret_len, reinterpret_cast<const uint8_t*>(ls.data()), ls.size(), a);  // A(1)
    for (size_t done = 0; done < out_len;) {
        std::string in(reinterpret_cast<char*>(a), N);
        in += ls;
        uint8_t block[N];
        mac(secret, secret_len, reinterpret_cast<const uint8_t*>(in.data()), in.size(), block);
        for (size_t i = 0; i < N && done < out_len; ++i) out[done++] ^= block[i];
        mac(secret, secret_len, a, N, a);  // A(i+1)
    }
}
}  // namespace

void tls10_prf(const uint8_t* secret, size_t secret_len, const char* label, const uint8_t* seed, size_t seed_len,
               uint8_t* out, size_t out_len) {
    std::string ls(label);
    ls.append(reinterpret_cast<const char*>(seed), seed_len);
    size_t half = (secret_len + 1) / 2;  // the halves overlap by a byte when the length is odd
    std::memset(out, 0, out_len);
    p_hash<16>(hmac_md5, secret, half, ls, out, out_len);
    p_hash<20>(hmac_sha1, secret + secret_len - half, half, ls, out, out_len);
}

// ---------------------------------------------------------------- AES-CBC and AES-CCM
bool aes_cbc_decrypt(const uint8_t* key, size_t key_len, const uint8_t iv[16], const uint8_t* in, size_t len,
                     uint8_t* out) {
    if (len % 16 || (key_len != 16 && key_len != 32)) return false;
    std::optional<Aes128> a128;
    std::optional<Aes256> a256;
    if (key_len == 16) a128.emplace(key);
    else a256.emplace(key);
    uint8_t prev[16];
    std::memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        uint8_t blk[16], cur[16];
        std::memcpy(cur, in + off, 16);  // (in and out may be the same buffer)
        if (a128) a128->decrypt(cur, blk);
        else a256->decrypt(cur, blk);
        for (int i = 0; i < 16; ++i) out[off + i] = blk[i] ^ prev[i];
        std::memcpy(prev, cur, 16);
    }
    return true;
}

bool aes_ccm_open(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* aad,
                  size_t aad_len, const uint8_t* ct, size_t ct_len, const uint8_t* tag, size_t tag_len, uint8_t* out) {
    if ((key_len != 16 && key_len != 32) || nonce_len < 7 || nonce_len > 13 || tag_len < 4 || tag_len > 16 ||
        tag_len % 2 || aad_len >= 0xFF00)
        return false;
    size_t L = 15 - nonce_len;  // bytes of the length field and the counter
    if (L < 8 && (static_cast<uint64_t>(ct_len) >> (8 * L)) != 0) return false;
    std::optional<Aes128> a128;
    std::optional<Aes256> a256;
    if (key_len == 16) a128.emplace(key);
    else a256.emplace(key);
    auto enc = [&](const uint8_t* in, uint8_t* o) {
        if (a128) a128->encrypt(in, o);
        else a256->encrypt(in, o);
    };
    auto counter = [&](uint64_t i, uint8_t a[16]) {  // A_i = flags(L-1) || nonce || i
        a[0] = static_cast<uint8_t>(L - 1);
        std::memcpy(a + 1, nonce, nonce_len);
        for (size_t k = 0; k < L; ++k) a[15 - k] = static_cast<uint8_t>(i >> (8 * k));
    };
    uint8_t a[16], s[16];
    for (size_t off = 0, i = 1; off < ct_len; off += 16, ++i) {  // CTR from counter 1
        counter(i, a);
        enc(a, s);
        size_t n = ct_len - off < 16 ? ct_len - off : 16;
        for (size_t k = 0; k < n; ++k) out[off + k] = ct[off + k] ^ s[k];
    }
    // CBC-MAC over B0, the encoded AAD and the plaintext, each padded to whole blocks.
    uint8_t x[16], b[16];
    b[0] = static_cast<uint8_t>((aad_len ? 64 : 0) | (((tag_len - 2) / 2) << 3) | (L - 1));
    std::memcpy(b + 1, nonce, nonce_len);
    for (size_t k = 0; k < L; ++k) b[15 - k] = static_cast<uint8_t>(static_cast<uint64_t>(ct_len) >> (8 * k));
    enc(b, x);
    auto absorb = [&](const uint8_t* p, size_t n) {
        for (size_t off = 0; off < n; off += 16) {
            size_t m = n - off < 16 ? n - off : 16;
            for (size_t k = 0; k < m; ++k) x[k] ^= p[off + k];
            enc(x, x);
        }
    };
    if (aad_len) {
        std::string enc_aad;
        enc_aad.push_back(static_cast<char>(aad_len >> 8));
        enc_aad.push_back(static_cast<char>(aad_len & 0xFF));
        enc_aad.append(reinterpret_cast<const char*>(aad), aad_len);
        absorb(reinterpret_cast<const uint8_t*>(enc_aad.data()), enc_aad.size());
    }
    absorb(out, ct_len);
    counter(0, a);
    enc(a, s);
    uint8_t diff = 0;
    for (size_t k = 0; k < tag_len; ++k) diff |= static_cast<uint8_t>((x[k] ^ s[k]) ^ tag[k]);
    return diff == 0;
}

}  // namespace anta
