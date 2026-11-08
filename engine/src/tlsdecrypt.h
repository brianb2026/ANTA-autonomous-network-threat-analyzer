// TLS record decryption from secrets a user supplied in a key log (see tlskeys.h).
// This is the same thing Wireshark does with tls.keylog_file: it reads traffic the
// capture's owner already holds the keys for. It never breaks or recovers a key: every
// secret comes from the key log (a master secret may be computed from the premaster
// secret the log gives, as the protocol defines).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "blockciphers.h"

namespace anta {

// Per-direction record keys derived from a TLS 1.3 traffic secret and the suite. The
// secret is kept: a KeyUpdate derives the next one from it.
struct TlsRecordKeys {
    uint16_t cipher = 0;
    uint8_t key[32] = {};
    size_t key_len = 0;
    uint8_t iv[12] = {};
    size_t tag_len = 16;  // 8 for TLS_AES_128_CCM_8_SHA256
    uint8_t secret[48] = {};
    size_t secret_len = 0;
    bool valid = false;
};

// Supported TLS 1.3 cipher suites: all five of RFC 8446 §B.4 (others return invalid
// keys / -1 from open).
bool tls13_cipher_supported(uint16_t cipher);

// Record keys from a TLS 1.3 traffic secret (len = the suite's hash size) and suite.
TlsRecordKeys tls13_record_keys(const uint8_t* secret, size_t secret_len, uint16_t cipher);

// The keys after a KeyUpdate (RFC 8446 §7.2): the next traffic secret, derived from the
// current one. The sender's record counter starts again at 0.
TlsRecordKeys tls13_next_keys(const TlsRecordKeys& k);

// Open one TLS 1.3 record. `aad` is the 5-byte record header, `body` is the record
// contents (ciphertext followed by the tag), `seq` the per-direction record counter.
// Writes the plaintext to `out` (needs body_len bytes) and returns its length, or -1 on
// an authentication failure or unsupported suite. The plaintext's last non-zero byte is
// the real content type (TLS 1.3 inner type); the caller strips it.
long tls13_open(const TlsRecordKeys& k, uint64_t seq, const uint8_t aad[5],
                const uint8_t* body, size_t body_len, uint8_t* out);

// --- SSL 3.0 and TLS 1.0, 1.1 and 1.2 (RFC 6101, 2246, 4346, 5246): the AEAD suites (AES,
// ARIA and Camellia in GCM, AES-CCM, ChaCha20-Poly1305), the CBC suites (AES, Camellia,
// ARIA, SEED, Triple DES) with SHA-1, SHA-256 or SHA-384 MACs, MAC-then-encrypt or
// encrypt-then-MAC (RFC 7366), RC4, and the NULL (MAC only) suites. ---

struct Tls12Keys {
    enum Mode : uint8_t { Gcm, ChaCha, Ccm, Cbc, Stream, Null };
    uint16_t cipher = 0;
    uint16_t version = 0x0303;  // 0x0300 SSL 3.0, 0x0301 TLS 1.0, 0x0302 TLS 1.1, 0x0303 TLS 1.2
    Mode mode = Gcm;
    BlockAlg alg = BlockAlg::Aes;
    uint8_t client_key[32] = {}, server_key[32] = {};
    size_t key_len = 0;
    size_t block = 16;  // the block cipher's block (8 for Triple DES)
    // AEAD: the implicit (fixed) IV, 4 bytes (GCM, CCM) or 12 (ChaCha20). CBC in SSL 3.0 and
    // TLS 1.0: the next record's IV, the last ciphertext block of the one before
    // (tls12_chain_iv moves it on); TLS 1.1 and later carry an explicit IV per record.
    uint8_t client_iv[16] = {}, server_iv[16] = {};
    size_t fixed_iv_len = 0;
    size_t tag_len = 16;  // AEAD tag: 8 for the CCM_8 suites
    uint8_t client_mac[48] = {}, server_mac[48] = {};
    size_t mac_len = 0;   // CBC, RC4, NULL: 16 (MD5), 20 (SHA-1), 32 (SHA-256) or 48 (SHA-384)
    bool etm = false;     // CBC: encrypt-then-MAC was negotiated
    Rc4 client_rc4, server_rc4;  // RC4: each direction's keystream, moved on by each record
    bool valid = false;
};

bool tls12_cipher_supported(uint16_t cipher);

// Derive both directions' record keys from the master secret (RFC 5246 §6.3; TLS 1.0
// and 1.1 use their own PRF, SSL 3.0 its MD5/SHA-1 construction). `version` is the
// negotiated version, `etm` whether the server accepted encrypt-then-MAC (CBC only).
Tls12Keys tls12_keys(const uint8_t master[48], const uint8_t client_random[32], const uint8_t server_random[32],
                     uint16_t cipher, uint16_t version = 0x0303, bool etm = false);

// The master secret from a premaster secret (a key log's RSA or PMS_CLIENT_RANDOM line).
// With the extended master secret (RFC 7627), `transcript` holds the handshake messages up
// to and including the Client Key Exchange; otherwise the randoms are used. False if the
// suite isn't known.
bool tls_master_secret(const uint8_t* premaster, size_t premaster_len, const uint8_t client_random[32],
                       const uint8_t server_random[32], uint16_t cipher, uint16_t version, bool ems,
                       const std::string& transcript, uint8_t master[48]);

// Open one protected record. `server` picks the writer's keys, `seq` is the record
// sequence number for that direction (starts at 0 at the first record after that side's
// ChangeCipherSpec). `record`/`record_len` is the full encrypted record payload;
// `content_type` and `version` come from its header. Returns the plaintext length
// (written to `out`, which needs record_len bytes), or -1 if it doesn't authenticate. An
// RC4 keystream moves on only when the record authenticates.
long tls12_open(Tls12Keys& k, bool server, uint64_t seq, uint8_t content_type, uint16_t version,
                const uint8_t* record, size_t record_len, uint8_t* out);

// After each protected record of a direction, opened or not: SSL 3.0 and TLS 1.0 CBC chain
// the IV from it (nothing to do for the other modes).
void tls12_chain_iv(Tls12Keys& k, bool server, const uint8_t* record, size_t record_len);

}  // namespace anta
