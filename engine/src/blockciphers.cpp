#include "blockciphers.h"

#include <cstring>

namespace anta {

namespace {
#include "cipher_tables.inc"

inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline uint8_t rotl8(uint8_t x, int n) { return static_cast<uint8_t>((x << n) | (x >> (8 - n))); }
inline uint64_t be64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}
inline void put64(uint64_t v, uint8_t* p) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (56 - 8 * i));
}
inline uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}
inline void put32(uint32_t v, uint8_t* p) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(v >> (24 - 8 * i));
}

// A 128-bit value as two 64-bit halves, and its circular rotation.
struct U128 { uint64_t hi, lo; };
U128 rotl128(U128 x, int n) {
    n &= 127;
    if (n >= 64) {
        uint64_t t = x.hi;
        x.hi = x.lo;
        x.lo = t;
        n -= 64;
    }
    if (!n) return x;
    return {(x.hi << n) | (x.lo >> (64 - n)), (x.lo << n) | (x.hi >> (64 - n))};
}
U128 load128(const uint8_t* p) { return {be64(p), be64(p + 8)}; }
void store128(U128 x, uint8_t* p) {
    put64(x.hi, p);
    put64(x.lo, p + 8);
}

// ------------------------------------------------------------------ Camellia (RFC 3713)
uint8_t cam_sbox(int which, uint8_t x) {
    switch (which) {
        case 1: return kCamelliaSbox1[x];
        case 2: return rotl8(kCamelliaSbox1[x], 1);
        case 3: return rotl8(kCamelliaSbox1[x], 7);
        default: return kCamelliaSbox1[rotl8(x, 1)];
    }
}

uint64_t cam_f(uint64_t in, uint64_t ke) {
    uint64_t x = in ^ ke;
    uint8_t t[8];
    static const int kBox[8] = {1, 2, 3, 4, 2, 3, 4, 1};
    for (int i = 0; i < 8; ++i) t[i] = cam_sbox(kBox[i], static_cast<uint8_t>(x >> (56 - 8 * i)));
    uint8_t y[8];
    y[0] = t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
    y[1] = t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
    y[2] = t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
    y[3] = t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
    y[4] = t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
    y[5] = t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
    y[6] = t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
    y[7] = t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
    uint64_t out = 0;
    for (int i = 0; i < 8; ++i) out = (out << 8) | y[i];
    return out;
}

uint64_t cam_fl(uint64_t in, uint64_t ke) {
    uint32_t x1 = static_cast<uint32_t>(in >> 32), x2 = static_cast<uint32_t>(in);
    uint32_t k1 = static_cast<uint32_t>(ke >> 32), k2 = static_cast<uint32_t>(ke);
    x2 ^= rotl32(x1 & k1, 1);
    x1 ^= (x2 | k2);
    return (static_cast<uint64_t>(x1) << 32) | x2;
}

uint64_t cam_flinv(uint64_t in, uint64_t ke) {
    uint32_t y1 = static_cast<uint32_t>(in >> 32), y2 = static_cast<uint32_t>(in);
    uint32_t k1 = static_cast<uint32_t>(ke >> 32), k2 = static_cast<uint32_t>(ke);
    y1 ^= (y2 | k2);
    y2 ^= rotl32(y1 & k1, 1);
    return (static_cast<uint64_t>(y1) << 32) | y2;
}

// ------------------------------------------------------------------ ARIA (RFC 5794)
void aria_sl(const uint8_t* x, uint8_t* y, bool type2) {
    const uint8_t* const boxes1[4] = {kAriaSb1, kAriaSb2, kAriaSb3, kAriaSb4};
    const uint8_t* const boxes2[4] = {kAriaSb3, kAriaSb4, kAriaSb1, kAriaSb2};
    for (int i = 0; i < 16; ++i) y[i] = (type2 ? boxes2 : boxes1)[i % 4][x[i]];
}

void aria_a(const uint8_t* x, uint8_t* y) {
    y[0] = x[3] ^ x[4] ^ x[6] ^ x[8] ^ x[9] ^ x[13] ^ x[14];
    y[1] = x[2] ^ x[5] ^ x[7] ^ x[8] ^ x[9] ^ x[12] ^ x[15];
    y[2] = x[1] ^ x[4] ^ x[6] ^ x[10] ^ x[11] ^ x[12] ^ x[15];
    y[3] = x[0] ^ x[5] ^ x[7] ^ x[10] ^ x[11] ^ x[13] ^ x[14];
    y[4] = x[0] ^ x[2] ^ x[5] ^ x[8] ^ x[11] ^ x[14] ^ x[15];
    y[5] = x[1] ^ x[3] ^ x[4] ^ x[9] ^ x[10] ^ x[14] ^ x[15];
    y[6] = x[0] ^ x[2] ^ x[7] ^ x[9] ^ x[10] ^ x[12] ^ x[13];
    y[7] = x[1] ^ x[3] ^ x[6] ^ x[8] ^ x[11] ^ x[12] ^ x[13];
    y[8] = x[0] ^ x[1] ^ x[4] ^ x[7] ^ x[10] ^ x[13] ^ x[15];
    y[9] = x[0] ^ x[1] ^ x[5] ^ x[6] ^ x[11] ^ x[12] ^ x[14];
    y[10] = x[2] ^ x[3] ^ x[5] ^ x[6] ^ x[8] ^ x[13] ^ x[15];
    y[11] = x[2] ^ x[3] ^ x[4] ^ x[7] ^ x[9] ^ x[12] ^ x[14];
    y[12] = x[1] ^ x[2] ^ x[6] ^ x[7] ^ x[9] ^ x[11] ^ x[12];
    y[13] = x[0] ^ x[3] ^ x[6] ^ x[7] ^ x[8] ^ x[10] ^ x[13];
    y[14] = x[0] ^ x[3] ^ x[4] ^ x[5] ^ x[9] ^ x[11] ^ x[14];
    y[15] = x[1] ^ x[2] ^ x[4] ^ x[5] ^ x[8] ^ x[10] ^ x[15];
}

// FO (type 1) or FE (type 2): A(SL(D ^ RK)).
void aria_round(const uint8_t* d, const uint8_t* rk, uint8_t* out, bool even) {
    uint8_t t[16], s[16];
    for (int i = 0; i < 16; ++i) t[i] = d[i] ^ rk[i];
    aria_sl(t, s, even);
    aria_a(s, out);
}

// ------------------------------------------------------------------ SEED (RFC 4269)
struct SeedTables {
    uint32_t ss[4][256];
    SeedTables() {
        const uint32_t m0 = 0xFC, m1 = 0xF3, m2 = 0xCF, m3 = 0x3F;
        for (int x = 0; x < 256; ++x) {
            uint32_t a = kSeedS0[x], b = kSeedS1[x];
            ss[0][x] = ((a & m3) << 24) | ((a & m2) << 16) | ((a & m1) << 8) | (a & m0);
            ss[1][x] = ((b & m0) << 24) | ((b & m3) << 16) | ((b & m2) << 8) | (b & m1);
            ss[2][x] = ((a & m1) << 24) | ((a & m0) << 16) | ((a & m3) << 8) | (a & m2);
            ss[3][x] = ((b & m2) << 24) | ((b & m1) << 16) | ((b & m0) << 8) | (b & m3);
        }
    }
};
const SeedTables& seed_tables() {
    static const SeedTables t;
    return t;
}

uint32_t seed_g(uint32_t x) {
    const auto& t = seed_tables();
    return t.ss[0][x & 0xFF] ^ t.ss[1][(x >> 8) & 0xFF] ^ t.ss[2][(x >> 16) & 0xFF] ^ t.ss[3][x >> 24];
}

// ------------------------------------------------------------------ DES (FIPS 46-3)
// Bit i (1-based, from the most significant) of a `width`-bit value.
inline uint64_t bit(uint64_t v, int i, int width) { return (v >> (width - i)) & 1; }

uint64_t permute(uint64_t in, int in_width, const uint8_t* table, int out_width) {
    uint64_t out = 0;
    for (int i = 0; i < out_width; ++i) out = (out << 1) | bit(in, table[i], in_width);
    return out;
}

void des_schedule(const uint8_t* key, uint64_t sub[16]) {
    uint64_t cd = permute(be64(key), 64, kDesPc1, 56);
    uint32_t c = static_cast<uint32_t>(cd >> 28) & 0x0FFFFFFF, d = static_cast<uint32_t>(cd) & 0x0FFFFFFF;
    for (int r = 0; r < 16; ++r) {
        for (int s = 0; s < kDesShifts[r]; ++s) {
            c = ((c << 1) | (c >> 27)) & 0x0FFFFFFF;
            d = ((d << 1) | (d >> 27)) & 0x0FFFFFFF;
        }
        sub[r] = permute((static_cast<uint64_t>(c) << 28) | d, 56, kDesPc2, 48);
    }
}

uint32_t des_f(uint32_t r, uint64_t k) {
    uint64_t x = permute(r, 32, kDesE, 48) ^ k;
    uint32_t out = 0;
    for (int i = 0; i < 8; ++i) {
        uint32_t six = static_cast<uint32_t>(x >> (42 - 6 * i)) & 0x3F;
        uint32_t row = ((six >> 4) & 2) | (six & 1), col = (six >> 1) & 0xF;
        out = (out << 4) | kDesS[i * 64 + row * 16 + col];
    }
    return static_cast<uint32_t>(permute(out, 32, kDesP, 32));
}

uint64_t des_block(uint64_t in, const uint64_t sub[16], bool decrypt) {
    uint64_t x = permute(in, 64, kDesIp, 64);
    uint32_t l = static_cast<uint32_t>(x >> 32), r = static_cast<uint32_t>(x);
    for (int i = 0; i < 16; ++i) {
        uint32_t t = r;
        r = l ^ des_f(r, sub[decrypt ? 15 - i : i]);
        l = t;
    }
    return permute((static_cast<uint64_t>(r) << 32) | l, 64, kDesFp, 64);
}
}  // namespace

// ------------------------------------------------------------------ the key schedules

BlockCipher::BlockCipher(BlockAlg alg, const uint8_t* key, size_t key_len) : alg_(alg) {
    switch (alg) {
        case BlockAlg::Aes:
            if (key_len == 16) aes128_.emplace(key);
            else if (key_len == 32) aes256_.emplace(key);
            else return;
            break;
        case BlockAlg::Camellia: {
            if (key_len != 16 && key_len != 24 && key_len != 32) return;
            U128 kl = load128(key), kr{0, 0};
            if (key_len == 24) kr = {be64(key + 16), ~be64(key + 16)};
            if (key_len == 32) kr = load128(key + 16);
            uint64_t d1 = kl.hi ^ kr.hi, d2 = kl.lo ^ kr.lo;
            d2 ^= cam_f(d1, kCamelliaSigma[0]);
            d1 ^= cam_f(d2, kCamelliaSigma[1]);
            d1 ^= kl.hi;
            d2 ^= kl.lo;
            d2 ^= cam_f(d1, kCamelliaSigma[2]);
            d1 ^= cam_f(d2, kCamelliaSigma[3]);
            U128 ka{d1, d2};
            d1 = ka.hi ^ kr.hi;
            d2 = ka.lo ^ kr.lo;
            d2 ^= cam_f(d1, kCamelliaSigma[4]);
            d1 ^= cam_f(d2, kCamelliaSigma[5]);
            U128 kb{d1, d2};
            uint64_t* kw = cam_kw_[0];
            uint64_t* k = cam_k_[0];
            uint64_t* ke = cam_ke_[0];
            auto pair = [](U128 v, int n, uint64_t& a, uint64_t& b) {
                U128 r = rotl128(v, n);
                a = r.hi;
                b = r.lo;
            };
            if (key_len == 16) {
                rounds_ = 18;
                pair(kl, 0, kw[0], kw[1]);
                pair(ka, 0, k[0], k[1]);
                pair(kl, 15, k[2], k[3]);
                pair(ka, 15, k[4], k[5]);
                pair(ka, 30, ke[0], ke[1]);
                pair(kl, 45, k[6], k[7]);
                k[8] = rotl128(ka, 45).hi;
                k[9] = rotl128(kl, 60).lo;
                pair(ka, 60, k[10], k[11]);
                pair(kl, 77, ke[2], ke[3]);
                pair(kl, 94, k[12], k[13]);
                pair(ka, 94, k[14], k[15]);
                pair(kl, 111, k[16], k[17]);
                pair(ka, 111, kw[2], kw[3]);
            } else {
                rounds_ = 24;
                pair(kl, 0, kw[0], kw[1]);
                pair(kb, 0, k[0], k[1]);
                pair(kr, 15, k[2], k[3]);
                pair(ka, 15, k[4], k[5]);
                pair(kr, 30, ke[0], ke[1]);
                pair(kb, 30, k[6], k[7]);
                pair(kl, 45, k[8], k[9]);
                pair(ka, 45, k[10], k[11]);
                pair(kl, 60, ke[2], ke[3]);
                pair(kr, 60, k[12], k[13]);
                pair(kb, 60, k[14], k[15]);
                pair(kl, 77, k[16], k[17]);
                pair(ka, 77, ke[4], ke[5]);
                pair(kr, 94, k[18], k[19]);
                pair(ka, 94, k[20], k[21]);
                pair(kl, 111, k[22], k[23]);
                pair(kb, 111, kw[2], kw[3]);
            }
            // Decryption: the same procedure with the subkeys in reverse (RFC 3713 §2.3.3).
            int nke = rounds_ == 18 ? 4 : 6;
            cam_kw_[1][0] = kw[2];
            cam_kw_[1][1] = kw[3];
            cam_kw_[1][2] = kw[0];
            cam_kw_[1][3] = kw[1];
            for (int i = 0; i < rounds_; ++i) cam_k_[1][i] = k[rounds_ - 1 - i];
            for (int i = 0; i < nke; ++i) cam_ke_[1][i] = ke[nke - 1 - i];
            break;
        }
        case BlockAlg::Aria: {
            if (key_len != 16 && key_len != 24 && key_len != 32) return;
            rounds_ = key_len == 16 ? 12 : key_len == 24 ? 14 : 16;
            uint8_t kl[16], kr[16] = {};
            std::memcpy(kl, key, 16);
            std::memcpy(kr, key + 16, key_len - 16);
            int first = key_len == 16 ? 0 : key_len == 24 ? 1 : 2;  // CK1 = C1, C2 or C3
            const uint8_t* ck[3] = {kAriaC + 16 * first, kAriaC + 16 * ((first + 1) % 3), kAriaC + 16 * ((first + 2) % 3)};
            uint8_t w0[16], w1[16], w2[16], w3[16], t[16];
            std::memcpy(w0, kl, 16);
            aria_round(w0, ck[0], t, false);
            for (int i = 0; i < 16; ++i) w1[i] = t[i] ^ kr[i];
            aria_round(w1, ck[1], t, true);
            for (int i = 0; i < 16; ++i) w2[i] = t[i] ^ w0[i];
            aria_round(w2, ck[2], t, false);
            for (int i = 0; i < 16; ++i) w3[i] = t[i] ^ w1[i];
            U128 w[4] = {load128(w0), load128(w1), load128(w2), load128(w3)};
            // ek1..ek17: W(i) ^ (W(i+1) rotated), the rotations 19 right, 31 right, 61 left,
            // 31 left and 19 left, four keys each (RFC 5794 §2.2).
            static const int kRot[5] = {128 - 19, 128 - 31, 61, 31, 19};
            for (int n = 0; n < 17; ++n) {
                int a = n % 4, b = (n + 1) % 4;
                U128 r = rotl128(w[b], kRot[n / 4]), v;
                if (a == 3) {  // ek4, ek8, …: (W0 rotated) ^ W3
                    r = rotl128(w[0], kRot[n / 4]);
                    v = {r.hi ^ w[3].hi, r.lo ^ w[3].lo};
                } else {
                    v = {w[a].hi ^ r.hi, w[a].lo ^ r.lo};
                }
                store128(v, aria_rk_[0][n]);
            }
            // Decryption keys: dk1 = ek(n+1), dk(i) = A(ek(n+2-i)), dk(n+1) = ek1.
            std::memcpy(aria_rk_[1][0], aria_rk_[0][rounds_], 16);
            for (int i = 1; i < rounds_; ++i) aria_a(aria_rk_[0][rounds_ - i], aria_rk_[1][i]);
            std::memcpy(aria_rk_[1][rounds_], aria_rk_[0][0], 16);
            break;
        }
        case BlockAlg::Seed: {
            if (key_len != 16) return;
            uint32_t k0 = be32(key), k1 = be32(key + 4), k2 = be32(key + 8), k3 = be32(key + 12);
            for (int i = 0; i < 16; ++i) {
                seed_k_[0][2 * i] = seed_g(k0 + k2 - kSeedKc[i]);
                seed_k_[0][2 * i + 1] = seed_g(k1 - k3 + kSeedKc[i]);
                if (i % 2 == 0) {  // odd rounds (1-based): (Key0 || Key1) >>> 8
                    uint32_t t = k0;
                    k0 = (k0 >> 8) | (k1 << 24);
                    k1 = (k1 >> 8) | (t << 24);
                } else {  // even rounds: (Key2 || Key3) <<< 8
                    uint32_t t = k2;
                    k2 = (k2 << 8) | (k3 >> 24);
                    k3 = (k3 << 8) | (t >> 24);
                }
            }
            for (int i = 0; i < 16; ++i) {
                seed_k_[1][2 * i] = seed_k_[0][2 * (15 - i)];
                seed_k_[1][2 * i + 1] = seed_k_[0][2 * (15 - i) + 1];
            }
            break;
        }
        case BlockAlg::Des3:
            if (key_len != 24) return;
            for (int i = 0; i < 3; ++i) des_schedule(key + 8 * i, des_k_[i]);
            break;
    }
    valid_ = true;
}

// ------------------------------------------------------------------ the block functions

void BlockCipher::camellia(const uint64_t* kw, const uint64_t* k, const uint64_t* ke, const uint8_t* in,
                           uint8_t* out) const {
    uint64_t d1 = be64(in) ^ kw[0], d2 = be64(in + 8) ^ kw[1];
    for (int r = 0; r < rounds_; ++r) {
        if (r % 2 == 0) d2 ^= cam_f(d1, k[r]);
        else d1 ^= cam_f(d2, k[r]);
        if (r % 6 == 5 && r + 1 < rounds_) {  // FL and FLINV after every six rounds but the last
            d1 = cam_fl(d1, ke[(r / 6) * 2]);
            d2 = cam_flinv(d2, ke[(r / 6) * 2 + 1]);
        }
    }
    d2 ^= kw[2];
    d1 ^= kw[3];
    put64(d2, out);
    put64(d1, out + 8);
}

void BlockCipher::aria(const uint8_t (*rk)[16], const uint8_t* in, uint8_t* out) const {
    uint8_t p[16], t[16];
    std::memcpy(p, in, 16);
    for (int i = 0; i < rounds_ - 1; ++i) {
        aria_round(p, rk[i], t, i % 2 == 1);  // rounds 1, 3, … odd (FO); 2, 4, … even (FE)
        std::memcpy(p, t, 16);
    }
    for (int i = 0; i < 16; ++i) t[i] = p[i] ^ rk[rounds_ - 1][i];
    aria_sl(t, p, true);
    for (int i = 0; i < 16; ++i) out[i] = p[i] ^ rk[rounds_][i];
}

void BlockCipher::seed(const uint32_t* k, const uint8_t* in, uint8_t* out) const {
    uint32_t l0 = be32(in), l1 = be32(in + 4), r0 = be32(in + 8), r1 = be32(in + 12);
    for (int i = 0; i < 16; ++i) {
        uint32_t a = r0 ^ k[2 * i], b = r1 ^ k[2 * i + 1];
        uint32_t c = seed_g(a ^ b), d = seed_g(c + a), f1 = seed_g(d + c), f0 = f1 + d;
        if (i < 15) {
            uint32_t t0 = r0, t1 = r1;
            r0 = l0 ^ f0;
            r1 = l1 ^ f1;
            l0 = t0;
            l1 = t1;
        } else {
            l0 ^= f0;
            l1 ^= f1;
        }
    }
    put32(l0, out);
    put32(l1, out + 4);
    put32(r0, out + 8);
    put32(r1, out + 12);
}

void BlockCipher::encrypt(const uint8_t* in, uint8_t* out) const {
    switch (alg_) {
        case BlockAlg::Aes:
            if (aes128_) aes128_->encrypt(in, out);
            else aes256_->encrypt(in, out);
            break;
        case BlockAlg::Camellia: camellia(cam_kw_[0], cam_k_[0], cam_ke_[0], in, out); break;
        case BlockAlg::Aria: aria(aria_rk_[0], in, out); break;
        case BlockAlg::Seed: seed(seed_k_[0], in, out); break;
        case BlockAlg::Des3: {  // encrypt, decrypt, encrypt
            uint64_t x = des_block(be64(in), des_k_[0], false);
            x = des_block(x, des_k_[1], true);
            put64(des_block(x, des_k_[2], false), out);
            break;
        }
    }
}

void BlockCipher::decrypt(const uint8_t* in, uint8_t* out) const {
    switch (alg_) {
        case BlockAlg::Aes:
            if (aes128_) aes128_->decrypt(in, out);
            else aes256_->decrypt(in, out);
            break;
        case BlockAlg::Camellia: camellia(cam_kw_[1], cam_k_[1], cam_ke_[1], in, out); break;
        case BlockAlg::Aria: aria(aria_rk_[1], in, out); break;
        case BlockAlg::Seed: seed(seed_k_[1], in, out); break;
        case BlockAlg::Des3: {
            uint64_t x = des_block(be64(in), des_k_[2], true);
            x = des_block(x, des_k_[1], false);
            put64(des_block(x, des_k_[0], true), out);
            break;
        }
    }
}

// ------------------------------------------------------------------ modes

bool block_cbc_decrypt(const BlockCipher& c, const uint8_t* iv, const uint8_t* in, size_t len, uint8_t* out) {
    size_t bs = c.block_size();
    if (!c.valid() || len % bs) return false;
    uint8_t prev[16], cur[16], blk[16];
    std::memcpy(prev, iv, bs);
    for (size_t off = 0; off < len; off += bs) {
        std::memcpy(cur, in + off, bs);  // (in and out may be the same buffer)
        c.decrypt(cur, blk);
        for (size_t i = 0; i < bs; ++i) out[off + i] = blk[i] ^ prev[i];
        std::memcpy(prev, cur, bs);
    }
    return true;
}

bool block_gcm_open(const BlockCipher& c, const uint8_t nonce[12], const uint8_t* aad, size_t aad_len,
                    const uint8_t* ct, size_t ct_len, const uint8_t tag[16], uint8_t* out) {
    if (!c.valid() || c.block_size() != 16) return false;
    uint8_t zero[16] = {}, h[16], s[16];
    c.encrypt(zero, h);
    gcm_ghash(h, aad, aad_len, ct, ct_len, s);
    uint8_t counter[16];
    std::memcpy(counter, nonce, 12);
    counter[12] = counter[13] = counter[14] = 0;
    counter[15] = 1;
    uint8_t ek0[16];
    c.encrypt(counter, ek0);
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= static_cast<uint8_t>(s[i] ^ ek0[i] ^ tag[i]);
    if (diff) return false;
    for (size_t off = 0; off < ct_len; off += 16) {
        for (int i = 15; i >= 12; --i)
            if (++counter[i]) break;
        uint8_t ks[16];
        c.encrypt(counter, ks);
        size_t n = ct_len - off < 16 ? ct_len - off : 16;
        for (size_t i = 0; i < n; ++i) out[off + i] = ct[off + i] ^ ks[i];
    }
    return true;
}

Rc4::Rc4(const uint8_t* key, size_t key_len) {
    for (int i = 0; i < 256; ++i) s_[i] = static_cast<uint8_t>(i);
    uint8_t j = 0;
    for (int i = 0; i < 256; ++i) {
        j = static_cast<uint8_t>(j + s_[i] + key[i % key_len]);
        uint8_t t = s_[i];
        s_[i] = s_[j];
        s_[j] = t;
    }
}

void Rc4::crypt(const uint8_t* in, uint8_t* out, size_t n) {
    for (size_t k = 0; k < n; ++k) {
        i_ = static_cast<uint8_t>(i_ + 1);
        j_ = static_cast<uint8_t>(j_ + s_[i_]);
        uint8_t t = s_[i_];
        s_[i_] = s_[j_];
        s_[j_] = t;
        out[k] = in[k] ^ s_[static_cast<uint8_t>(s_[i_] + s_[j_])];
    }
}

}  // namespace anta
