#include "tlsdecrypt.h"

#include <cstring>
#include <string>

#include "crypto.h"
#include "hash.h"

namespace anta {

// TLS 1.3 cipher suites (RFC 8446 §B.4).
constexpr uint16_t kAes128GcmSha256 = 0x1301;
constexpr uint16_t kAes256GcmSha384 = 0x1302;
constexpr uint16_t kChaCha20Sha256 = 0x1303;
constexpr uint16_t kAes128Ccm8Sha256 = 0x1305;  // (0x1304 is TLS_AES_128_CCM_SHA256)

bool tls13_cipher_supported(uint16_t cipher) { return cipher >= kAes128GcmSha256 && cipher <= kAes128Ccm8Sha256; }

TlsRecordKeys tls13_record_keys(const uint8_t* secret, size_t secret_len, uint16_t cipher) {
    TlsRecordKeys k;
    k.cipher = cipher;
    bool sha384 = cipher == kAes256GcmSha384;
    if (!tls13_cipher_supported(cipher) || secret_len != (sha384 ? 48u : 32u))
        return k;
    k.key_len = cipher == kAes256GcmSha384 || cipher == kChaCha20Sha256 ? 32 : 16;
    k.tag_len = cipher == kAes128Ccm8Sha256 ? 8 : 16;
    if (sha384) {
        hkdf_expand_label_sha384(secret, "key", k.key, k.key_len);
        hkdf_expand_label_sha384(secret, "iv", k.iv, 12);
    } else {
        hkdf_expand_label(secret, "key", k.key, k.key_len);
        hkdf_expand_label(secret, "iv", k.iv, 12);
    }
    std::memcpy(k.secret, secret, secret_len);
    k.secret_len = secret_len;
    k.valid = true;
    return k;
}

TlsRecordKeys tls13_next_keys(const TlsRecordKeys& k) {
    if (!k.valid)
        return k;
    uint8_t next[48];
    if (k.secret_len == 48)
        hkdf_expand_label_sha384(k.secret, "traffic upd", next, 48);
    else
        hkdf_expand_label(k.secret, "traffic upd", next, 32);
    return tls13_record_keys(next, k.secret_len, k.cipher);
}

long tls13_open(const TlsRecordKeys& k, uint64_t seq, const uint8_t aad[5],
                const uint8_t* body, size_t body_len, uint8_t* out) {
    if (!k.valid || body_len < k.tag_len)
        return -1;
    size_t ct_len = body_len - k.tag_len;
    const uint8_t* tag = body + ct_len;
    uint8_t nonce[12];
    std::memcpy(nonce, k.iv, 12);
    for (int i = 0; i < 8; ++i)  // nonce = iv XOR seq (right-aligned), RFC 8446 §5.3
        nonce[11 - i] ^= static_cast<uint8_t>(seq >> (8 * i));
    bool ok = false;
    if (k.cipher == kAes128GcmSha256)
        ok = aes128_gcm_open(k.key, nonce, aad, 5, body, ct_len, tag, out);
    else if (k.cipher == kAes256GcmSha384)
        ok = aes256_gcm_open(k.key, nonce, aad, 5, body, ct_len, tag, out);
    else if (k.cipher == kChaCha20Sha256)
        ok = chacha20_poly1305_open(k.key, nonce, aad, 5, body, ct_len, tag, out);
    else
        ok = aes_ccm_open(k.key, 16, nonce, 12, aad, 5, body, ct_len, tag, k.tag_len, out);
    return ok ? static_cast<long>(ct_len) : -1;
}

// --- SSL 3.0 - TLS 1.2 ---
namespace {
enum MacHash : uint8_t { NoMac, Md5, Sha1, Sha256, Sha384 };
// What a suite needs: its record protection and cipher, key size, MAC, AEAD tag, and
// whether the TLS 1.2 PRF is SHA-384 (else SHA-256).
struct Suite12 {
    Tls12Keys::Mode mode;
    BlockAlg alg;
    size_t key_len;
    MacHash mac;
    size_t tag_len;
    bool prf384;
};
using M = Tls12Keys;
constexpr BlockAlg kAes = BlockAlg::Aes, kCam = BlockAlg::Camellia, kAria = BlockAlg::Aria, kSeed = BlockAlg::Seed,
                   kDes3 = BlockAlg::Des3;

Suite12 tls12_suite(uint16_t c) {
    // ARIA (RFC 6209) and Camellia GCM (RFC 6367): even codes 128-bit/SHA-256, odd 256-bit/SHA-384.
    if ((c >= 0xC03C && c <= 0xC04F) || (c >= 0xC064 && c <= 0xC069) || c == 0xC070 || c == 0xC071)
        return c % 2 ? Suite12{M::Cbc, kAria, 32, Sha384, 0, true} : Suite12{M::Cbc, kAria, 16, Sha256, 0, false};
    if ((c >= 0xC050 && c <= 0xC063) || (c >= 0xC06A && c <= 0xC06F))
        return c % 2 ? Suite12{M::Gcm, kAria, 32, NoMac, 16, true} : Suite12{M::Gcm, kAria, 16, NoMac, 16, false};
    if (c >= 0xC07A && c <= 0xC093)
        return c % 2 ? Suite12{M::Gcm, kCam, 32, NoMac, 16, true} : Suite12{M::Gcm, kCam, 16, NoMac, 16, false};
    // Camellia CBC with SHA-256/SHA-384 for ECDHE, ECDH and PSK (RFC 6367).
    if (c >= 0xC072 && c <= 0xC079)
        return c % 2 ? Suite12{M::Cbc, kCam, 32, Sha384, 0, true} : Suite12{M::Cbc, kCam, 16, Sha256, 0, false};
    if (c >= 0xC094 && c <= 0xC09B)
        return c % 2 ? Suite12{M::Cbc, kCam, 32, Sha384, 0, true} : Suite12{M::Cbc, kCam, 16, Sha256, 0, false};
    switch (c) {
        // AES-GCM (RFC 5288, 5289, 5487)
        case 0x009C: case 0x009E: case 0x00A0: case 0x00A2: case 0x00A4: case 0x00A8: case 0x00AA: case 0x00AC:
        case 0xC02B: case 0xC02D: case 0xC02F: case 0xC031:
            return {M::Gcm, kAes, 16, NoMac, 16, false};
        case 0x009D: case 0x009F: case 0x00A1: case 0x00A3: case 0x00A5: case 0x00A9: case 0x00AB: case 0x00AD:
        case 0xC02C: case 0xC02E: case 0xC030: case 0xC032:
            return {M::Gcm, kAes, 32, NoMac, 16, true};
        // ChaCha20-Poly1305 (RFC 7905)
        case 0xCCA8: case 0xCCA9: case 0xCCAA: case 0xCCAB: case 0xCCAC: case 0xCCAD: case 0xCCAE:
            return {M::ChaCha, kAes, 32, NoMac, 16, false};
        // AES-CCM and CCM_8 (RFC 6655, 7251)
        case 0xC09C: case 0xC09E: case 0xC0A4: case 0xC0A6: case 0xC0AC: return {M::Ccm, kAes, 16, NoMac, 16, false};
        case 0xC09D: case 0xC09F: case 0xC0A5: case 0xC0A7: case 0xC0AD: return {M::Ccm, kAes, 32, NoMac, 16, false};
        case 0xC0A0: case 0xC0A2: case 0xC0A8: case 0xC0AA: case 0xC0AE: return {M::Ccm, kAes, 16, NoMac, 8, false};
        case 0xC0A1: case 0xC0A3: case 0xC0A9: case 0xC0AB: case 0xC0AF: return {M::Ccm, kAes, 32, NoMac, 8, false};
        // AES-CBC with HMAC-SHA1 (RFC 3268, 4279, 4492, 5489)
        case 0x002F: case 0x0030: case 0x0031: case 0x0032: case 0x0033: case 0x0034: case 0x008C: case 0x0090:
        case 0x0094: case 0xC004: case 0xC009: case 0xC00E: case 0xC013: case 0xC018: case 0xC035:
            return {M::Cbc, kAes, 16, Sha1, 0, false};
        case 0x0035: case 0x0036: case 0x0037: case 0x0038: case 0x0039: case 0x003A: case 0x008D: case 0x0091:
        case 0x0095: case 0xC005: case 0xC00A: case 0xC00F: case 0xC014: case 0xC019: case 0xC036:
            return {M::Cbc, kAes, 32, Sha1, 0, false};
        // AES-CBC with HMAC-SHA256 / SHA384 (RFC 5246, 5289, 5487, 5489)
        case 0x003C: case 0x003E: case 0x003F: case 0x0040: case 0x0067: case 0x006C: case 0x00AE: case 0x00B2:
        case 0x00B6: case 0xC023: case 0xC025: case 0xC027: case 0xC029: case 0xC037:
            return {M::Cbc, kAes, 16, Sha256, 0, false};
        case 0x003D: case 0x0068: case 0x0069: case 0x006A: case 0x006B: case 0x006D:
            return {M::Cbc, kAes, 32, Sha256, 0, false};
        case 0x00AF: case 0x00B3: case 0x00B7: case 0xC024: case 0xC026: case 0xC028: case 0xC02A: case 0xC038:
            return {M::Cbc, kAes, 32, Sha384, 0, true};
        // Camellia CBC (RFC 4132, 5932)
        case 0x0041: case 0x0042: case 0x0043: case 0x0044: case 0x0045: case 0x0046:
            return {M::Cbc, kCam, 16, Sha1, 0, false};
        case 0x0084: case 0x0085: case 0x0086: case 0x0087: case 0x0088: case 0x0089:
            return {M::Cbc, kCam, 32, Sha1, 0, false};
        case 0x00BA: case 0x00BB: case 0x00BC: case 0x00BD: case 0x00BE: case 0x00BF:
            return {M::Cbc, kCam, 16, Sha256, 0, false};
        case 0x00C0: case 0x00C1: case 0x00C2: case 0x00C3: case 0x00C4: case 0x00C5:
            return {M::Cbc, kCam, 32, Sha256, 0, false};
        // SEED (RFC 4162)
        case 0x0096: case 0x0097: case 0x0098: case 0x0099: case 0x009A: case 0x009B:
            return {M::Cbc, kSeed, 16, Sha1, 0, false};
        // Triple DES (RFC 5246 and its families)
        case 0x000A: case 0x000D: case 0x0010: case 0x0013: case 0x0016: case 0x001B: case 0x008B: case 0x008F:
        case 0x0093: case 0xC003: case 0xC008: case 0xC00D: case 0xC012: case 0xC017: case 0xC034:
            return {M::Cbc, kDes3, 24, Sha1, 0, false};
        // RC4 (128-bit keys)
        case 0x0004: case 0x0018: return {M::Stream, kAes, 16, Md5, 0, false};
        case 0x0005: case 0x008A: case 0x008E: case 0x0092: case 0xC002: case 0xC007: case 0xC00C: case 0xC011:
        case 0xC016: case 0xC033:
            return {M::Stream, kAes, 16, Sha1, 0, false};
        // NULL encryption: the MAC alone
        case 0x0001: return {M::Null, kAes, 0, Md5, 0, false};
        case 0x0002: case 0x002C: case 0x002D: case 0x002E: case 0xC001: case 0xC006: case 0xC00B: case 0xC010:
        case 0xC015: case 0xC039:
            return {M::Null, kAes, 0, Sha1, 0, false};
        case 0x003B: case 0x00B0: case 0x00B4: case 0x00B8: case 0xC03A:
            return {M::Null, kAes, 0, Sha256, 0, false};
        case 0x00B1: case 0x00B5: case 0x00B9: case 0xC03B:
            return {M::Null, kAes, 0, Sha384, 0, true};
        default: return {M::Gcm, kAes, 0, NoMac, 0, false};
    }
}

bool suite_known(const Suite12& s) { return s.key_len != 0 || s.mode == M::Null; }
size_t mac_size(MacHash h) { return h == Md5 ? 16 : h == Sha1 ? 20 : h == Sha256 ? 32 : h == Sha384 ? 48 : 0; }

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    class Sha256 h;  // (the class: MacHash has a Sha256 too)
    h.update(data, len);
    h.digest(out);
}

void hmac(size_t mac_len, const uint8_t* key, const uint8_t* data, size_t len, uint8_t* out) {
    if (mac_len == 16) hmac_md5(key, 16, data, len, out);
    else if (mac_len == 20) hmac_sha1(key, 20, data, len, out);
    else if (mac_len == 32) hmac_sha256(key, 32, data, len, out);
    else hmac_sha384(key, 48, data, len, out);
}

// The MAC input header: seq_num(8) || type(1) || version(2) || length(2) (SSL 3.0: no version).
std::string mac_header(uint64_t seq, uint8_t type, uint16_t version, size_t len, bool ssl3) {
    std::string h;
    for (int i = 7; i >= 0; --i) h.push_back(static_cast<char>(seq >> (8 * i)));
    h.push_back(static_cast<char>(type));
    if (!ssl3) {
        h.push_back(static_cast<char>(version >> 8));
        h.push_back(static_cast<char>(version & 0xFF));
    }
    h.push_back(static_cast<char>(len >> 8));
    h.push_back(static_cast<char>(len & 0xFF));
    return h;
}

// SSL 3.0's MAC (RFC 6101 §5.2.3.1): hash(secret + pad_2 + hash(secret + pad_1 + header + data)).
void ssl3_mac(size_t mac_len, const uint8_t* secret, const std::string& header, const uint8_t* data, size_t len,
              uint8_t* out) {
    size_t pad = mac_len == 16 ? 48 : 40;
    auto hash = [&](const std::string& m, uint8_t* o) {
        if (mac_len == 16) md5(reinterpret_cast<const uint8_t*>(m.data()), m.size(), o);
        else sha1(reinterpret_cast<const uint8_t*>(m.data()), m.size(), o);
    };
    std::string inner(reinterpret_cast<const char*>(secret), mac_len);
    inner.append(pad, '\x36');
    inner += header;
    inner.append(reinterpret_cast<const char*>(data), len);
    uint8_t ih[20];
    hash(inner, ih);
    std::string outer(reinterpret_cast<const char*>(secret), mac_len);
    outer.append(pad, '\x5c');
    outer.append(reinterpret_cast<const char*>(ih), mac_len);
    hash(outer, out);
}

bool mac_ok(const Tls12Keys& k, const uint8_t* key, uint64_t seq, uint8_t type, uint16_t version,
            const uint8_t* data, size_t len, const uint8_t* expect) {
    bool ssl3 = k.version == 0x0300;
    std::string hdr = mac_header(seq, type, version, len, ssl3);
    uint8_t got[48];
    if (ssl3) {
        ssl3_mac(k.mac_len, key, hdr, data, len, got);
    } else {
        std::string m = hdr;
        m.append(reinterpret_cast<const char*>(data), len);
        hmac(k.mac_len, key, reinterpret_cast<const uint8_t*>(m.data()), m.size(), got);
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < k.mac_len; ++i) diff |= static_cast<uint8_t>(got[i] ^ expect[i]);
    return diff == 0;
}

// SSL 3.0's key derivation (RFC 6101 §6.2): MD5(secret + SHA1("A" + secret + a + b)) +
// MD5(secret + SHA1("BB" + secret + a + b)) + … until `need` bytes.
void ssl3_derive(const uint8_t* secret, size_t secret_len, const uint8_t* a, const uint8_t* b, uint8_t* out,
                 size_t need) {
    for (size_t done = 0, i = 0; done < need; ++i) {
        std::string inner(i + 1, static_cast<char>('A' + i));
        inner.append(reinterpret_cast<const char*>(secret), secret_len);
        inner.append(reinterpret_cast<const char*>(a), 32);
        inner.append(reinterpret_cast<const char*>(b), 32);
        uint8_t sh[20];
        sha1(reinterpret_cast<const uint8_t*>(inner.data()), inner.size(), sh);
        std::string outer(reinterpret_cast<const char*>(secret), secret_len);
        outer.append(reinterpret_cast<const char*>(sh), 20);
        uint8_t mh[16];
        md5(reinterpret_cast<const uint8_t*>(outer.data()), outer.size(), mh);
        for (size_t j = 0; j < 16 && done < need; ++j) out[done++] = mh[j];
    }
}

long cbc_open(const Tls12Keys& k, bool server, uint64_t seq, uint8_t type, uint16_t version,
              const uint8_t* record, size_t record_len, uint8_t* out) {
    const uint8_t* key = server ? k.server_key : k.client_key;
    const uint8_t* mac_key = server ? k.server_mac : k.client_mac;
    bool explicit_iv = k.version >= 0x0302;
    size_t ml = k.mac_len, bs = k.block;
    // encrypt-then-MAC: IV || CBC(content || padding) || MAC(seq, header, IV || CBC(...)).
    // MAC-then-encrypt: IV || CBC(content || MAC || padding).
    size_t enc_len = k.etm ? (record_len >= ml ? record_len - ml : 0) : record_len;
    size_t iv_len = explicit_iv ? bs : 0;
    if (enc_len < iv_len + bs || (enc_len - iv_len) % bs)
        return -1;
    if (k.etm && !mac_ok(k, mac_key, seq, type, version, record, enc_len, record + enc_len))
        return -1;
    const uint8_t* iv = explicit_iv ? record : (server ? k.server_iv : k.client_iv);
    size_t ct_len = enc_len - iv_len;
    BlockCipher c(k.alg, key, k.key_len);
    if (!block_cbc_decrypt(c, iv, record + iv_len, ct_len, out))
        return -1;
    size_t pad = out[ct_len - 1];
    size_t trailer = pad + 1 + (k.etm ? 0 : ml);
    if (trailer > ct_len)
        return -1;
    if (k.version == 0x0300) {  // SSL 3.0: the padding bytes are arbitrary, but less than a block
        if (pad >= bs) return -1;
    } else {
        for (size_t i = ct_len - 1 - pad; i < ct_len - 1; ++i)  // TLS padding: every byte holds its length
            if (out[i] != pad)
                return -1;
    }
    size_t content = ct_len - trailer;
    if (!k.etm && !mac_ok(k, mac_key, seq, type, version, out, content, out + content))
        return -1;
    return static_cast<long>(content);
}
}  // namespace

bool tls12_cipher_supported(uint16_t cipher) { return suite_known(tls12_suite(cipher)); }

bool tls_master_secret(const uint8_t* premaster, size_t premaster_len, const uint8_t client_random[32],
                       const uint8_t server_random[32], uint16_t cipher, uint16_t version, bool ems,
                       const std::string& transcript, uint8_t master[48]) {
    Suite12 s = tls12_suite(cipher);
    if (!suite_known(s) || !premaster_len || version < 0x0300 || version > 0x0303)
        return false;
    if (version == 0x0300) {
        ssl3_derive(premaster, premaster_len, client_random, server_random, master, 48);
        return true;
    }
    const uint8_t* t = reinterpret_cast<const uint8_t*>(transcript.data());
    uint8_t seed[64], hash[48];
    size_t seed_len;
    if (ems) {  // RFC 7627: the session hash of the handshake so far
        if (version == 0x0303 && s.prf384) {
            sha384(t, transcript.size(), hash);
            seed_len = 48;
        } else if (version == 0x0303) {
            sha256(t, transcript.size(), hash);
            seed_len = 32;
        } else {  // TLS 1.0/1.1: MD5 || SHA-1
            md5(t, transcript.size(), hash);
            sha1(t, transcript.size(), hash + 16);
            seed_len = 36;
        }
        std::memcpy(seed, hash, seed_len);
    } else {
        std::memcpy(seed, client_random, 32);
        std::memcpy(seed + 32, server_random, 32);
        seed_len = 64;
    }
    const char* label = ems ? "extended master secret" : "master secret";
    if (version == 0x0303)
        tls12_prf(premaster, premaster_len, label, seed, seed_len, master, 48, s.prf384);
    else
        tls10_prf(premaster, premaster_len, label, seed, seed_len, master, 48);
    return true;
}

Tls12Keys tls12_keys(const uint8_t master[48], const uint8_t client_random[32], const uint8_t server_random[32],
                     uint16_t cipher, uint16_t version, bool etm) {
    Tls12Keys k;
    Suite12 s = tls12_suite(cipher);
    bool legacy_ok = s.mode == M::Cbc || s.mode == M::Stream || s.mode == M::Null;
    if (!suite_known(s) || version < 0x0300 || version > 0x0303 || (!legacy_ok && version != 0x0303))
        return k;
    k.cipher = cipher;
    k.version = version;
    k.mode = s.mode;
    k.alg = s.alg;
    k.key_len = s.key_len;
    k.block = s.alg == kDes3 ? 8 : 16;
    k.tag_len = s.tag_len ? s.tag_len : 16;
    k.mac_len = mac_size(s.mac);
    k.etm = etm && s.mode == M::Cbc && version != 0x0300;
    // Implicit IVs: AEAD's fixed part, and the first IV of SSL 3.0 and TLS 1.0 CBC.
    k.fixed_iv_len = s.mode == M::ChaCha ? 12
                   : s.mode == M::Cbc    ? (version <= 0x0301 ? k.block : 0)
                   : s.mode == M::Gcm || s.mode == M::Ccm ? 4 : 0;
    uint8_t seed[64];
    std::memcpy(seed, server_random, 32);  // "key expansion" seed = server_random || client_random
    std::memcpy(seed + 32, client_random, 32);
    // key_block: client MAC key, server MAC key, client key, server key, client IV, server IV.
    uint8_t kb[2 * 48 + 2 * 32 + 2 * 16];
    size_t need = 2 * k.mac_len + 2 * k.key_len + 2 * k.fixed_iv_len;
    if (version == 0x0303)
        tls12_prf(master, 48, "key expansion", seed, 64, kb, need, s.prf384);
    else if (version == 0x0300)
        ssl3_derive(master, 48, server_random, client_random, kb, need);
    else
        tls10_prf(master, 48, "key expansion", seed, 64, kb, need);
    size_t p = 0;
    std::memcpy(k.client_mac, kb + p, k.mac_len); p += k.mac_len;
    std::memcpy(k.server_mac, kb + p, k.mac_len); p += k.mac_len;
    std::memcpy(k.client_key, kb + p, k.key_len); p += k.key_len;
    std::memcpy(k.server_key, kb + p, k.key_len); p += k.key_len;
    std::memcpy(k.client_iv, kb + p, k.fixed_iv_len); p += k.fixed_iv_len;
    std::memcpy(k.server_iv, kb + p, k.fixed_iv_len);
    if (s.mode == M::Stream) {
        k.client_rc4 = Rc4(k.client_key, k.key_len);
        k.server_rc4 = Rc4(k.server_key, k.key_len);
    }
    k.valid = true;
    return k;
}

long tls12_open(Tls12Keys& k, bool server, uint64_t seq, uint8_t content_type, uint16_t version,
                const uint8_t* record, size_t record_len, uint8_t* out) {
    if (!k.valid)
        return -1;
    if (k.mode == M::Cbc)
        return cbc_open(k, server, seq, content_type, version, record, record_len, out);
    if (k.mode == M::Stream || k.mode == M::Null) {  // content || MAC, RC4 over both
        if (record_len < k.mac_len) return -1;
        Rc4 stream = server ? k.server_rc4 : k.client_rc4;  // (moved on only if the MAC checks)
        if (k.mode == M::Stream) stream.crypt(record, out, record_len);
        else std::memcpy(out, record, record_len);
        size_t content = record_len - k.mac_len;
        if (!mac_ok(k, server ? k.server_mac : k.client_mac, seq, content_type, version, out, content, out + content))
            return -1;
        if (k.mode == M::Stream) (server ? k.server_rc4 : k.client_rc4) = stream;
        return static_cast<long>(content);
    }
    const uint8_t* key = server ? k.server_key : k.client_key;
    const uint8_t* fixed = server ? k.server_iv : k.client_iv;
    uint8_t nonce[12];
    size_t ct_off, ct_len;
    if (k.mode == M::ChaCha) {  // RFC 7905: nonce = (00000000 || seq) XOR the 12-byte write IV
        if (record_len < 16) return -1;
        uint8_t padded[12] = {};
        for (int i = 0; i < 8; ++i) padded[11 - i] = static_cast<uint8_t>(seq >> (8 * i));
        for (int i = 0; i < 12; ++i) nonce[i] = fixed[i] ^ padded[i];
        ct_off = 0;
        ct_len = record_len - 16;
    } else {  // GCM and CCM: record = explicit_nonce(8) || ciphertext || tag; nonce = fixed(4) || explicit(8)
        if (record_len < 8 + k.tag_len) return -1;
        std::memcpy(nonce, fixed, 4);
        std::memcpy(nonce + 4, record, 8);
        ct_off = 8;
        ct_len = record_len - 8 - k.tag_len;
    }
    std::string aad = mac_header(seq, content_type, version, ct_len, false);
    const uint8_t* ad = reinterpret_cast<const uint8_t*>(aad.data());
    const uint8_t* ct = record + ct_off;
    const uint8_t* tag = ct + ct_len;
    bool ok;
    if (k.mode == M::ChaCha)
        ok = chacha20_poly1305_open(key, nonce, ad, 13, ct, ct_len, tag, out);
    else if (k.mode == M::Ccm)
        ok = aes_ccm_open(key, k.key_len, nonce, 12, ad, 13, ct, ct_len, tag, k.tag_len, out);
    else if (k.alg != kAes)
        ok = block_gcm_open(BlockCipher(k.alg, key, k.key_len), nonce, ad, 13, ct, ct_len, tag, out);
    else if (k.key_len == 16)
        ok = aes128_gcm_open(key, nonce, ad, 13, ct, ct_len, tag, out);
    else
        ok = aes256_gcm_open(key, nonce, ad, 13, ct, ct_len, tag, out);
    return ok ? static_cast<long>(ct_len) : -1;
}

void tls12_chain_iv(Tls12Keys& k, bool server, const uint8_t* record, size_t record_len) {
    if (!k.valid || k.mode != M::Cbc || k.version > 0x0301)
        return;
    size_t enc_len = k.etm ? (record_len >= k.mac_len ? record_len - k.mac_len : 0) : record_len;
    if (enc_len < k.block || enc_len % k.block)
        return;
    std::memcpy(server ? k.server_iv : k.client_iv, record + enc_len - k.block, k.block);
}

}  // namespace anta
