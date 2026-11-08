// The few primitives QUIC Initial packets need (RFC 9001 §5): HKDF-SHA256 and
// AES-128-GCM. Initial keys come from the connection ID on the wire, so this is
// decoding, not breaking anything: it is what Wireshark does to show them.
#pragma once

#include <cstddef>
#include <cstdint>

namespace anta {

void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[32]);
void hkdf_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[32]);
// TLS 1.3 HKDF-Expand-Label with an empty context (RFC 8446 §7.1), out_len <= 255.
void hkdf_expand_label(const uint8_t secret[32], const char* label, uint8_t* out, size_t out_len);

class Aes128 {
public:
    explicit Aes128(const uint8_t key[16]);
    void encrypt(const uint8_t in[16], uint8_t out[16]) const;
    void decrypt(const uint8_t in[16], uint8_t out[16]) const;  // the inverse cipher (CBC)

private:
    uint8_t rk_[176];
};

// GCM's GHASH (NIST SP 800-38D) over the AAD and ciphertext with their lengths, under
// the hash key H (the cipher's encryption of the zero block). For GCM over other ciphers.
void gcm_ghash(const uint8_t hkey[16], const uint8_t* aad, size_t aad_len, const uint8_t* ct, size_t ct_len,
               uint8_t out[16]);

// AES-128-GCM decryption (NIST SP 800-38D) with a 12-byte nonce and a 16-byte
// tag. Writes ct_len bytes to `out` and returns false if the tag doesn't match.
bool aes128_gcm_open(const uint8_t key[16], const uint8_t nonce[12], const uint8_t* aad, size_t aad_len,
                     const uint8_t* ct, size_t ct_len, const uint8_t tag[16], uint8_t* out);

// --- The rest the stronger TLS cipher suites need (SHA-384, AES-256, ChaCha20). ---

// One-shot SHA-384 (FIPS 180-4) and its HMAC.
void sha384(const uint8_t* data, size_t len, uint8_t out[48]);
void hmac_sha384(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[48]);

// TLS 1.3 HKDF-Expand-Label with a 48-byte (SHA-384) secret and an empty context.
void hkdf_expand_label_sha384(const uint8_t secret[48], const char* label, uint8_t* out, size_t out_len);

class Aes256 {
public:
    explicit Aes256(const uint8_t key[32]);
    void encrypt(const uint8_t in[16], uint8_t out[16]) const;
    void decrypt(const uint8_t in[16], uint8_t out[16]) const;

private:
    uint8_t rk_[240];
};

// AES-256-GCM decryption, same contract as aes128_gcm_open.
bool aes256_gcm_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad, size_t aad_len,
                     const uint8_t* ct, size_t ct_len, const uint8_t tag[16], uint8_t* out);

// ChaCha20-Poly1305 decryption (RFC 8439): 12-byte nonce, 16-byte tag.
bool chacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad, size_t aad_len,
                            const uint8_t* ct, size_t ct_len, const uint8_t tag[16], uint8_t* out);

// TLS 1.2 PRF (RFC 5246 §5): out = P_hash(secret, label || seed). sha384 selects the hash.
void tls12_prf(const uint8_t* secret, size_t secret_len, const char* label, const uint8_t* seed, size_t seed_len,
               uint8_t* out, size_t out_len, bool sha384);

// --- What the older TLS suites need: SHA-1 and MD5 MACs, the TLS 1.0/1.1 PRF, AES-CBC
// (TLS 1.0-1.2 CBC suites) and AES-CCM. ---

void sha1(const uint8_t* data, size_t len, uint8_t out[20]);
void hmac_sha1(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[20]);
void hmac_md5(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[16]);

// TLS 1.0/1.1 PRF (RFC 2246 §5): P_MD5 over the secret's first half XOR P_SHA1 over its second.
void tls10_prf(const uint8_t* secret, size_t secret_len, const char* label, const uint8_t* seed, size_t seed_len,
               uint8_t* out, size_t out_len);

// AES-CBC decryption (key_len 16 or 32) of `len` bytes, a multiple of 16.
bool aes_cbc_decrypt(const uint8_t* key, size_t key_len, const uint8_t iv[16], const uint8_t* in, size_t len,
                     uint8_t* out);

// AES-CCM decryption (NIST SP 800-38C, RFC 3610), key_len 16 or 32, a 7-13 byte nonce and
// a tag_len-byte tag (8 or 16 in TLS). Writes ct_len bytes; false if the tag doesn't match.
bool aes_ccm_open(const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* aad,
                  size_t aad_len, const uint8_t* ct, size_t ct_len, const uint8_t* tag, size_t tag_len, uint8_t* out);

}  // namespace anta
