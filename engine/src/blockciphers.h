// The ciphers of older TLS suites, beside AES (crypto.h): Camellia (RFC 3713), ARIA
// (RFC 5794), SEED (RFC 4269), Triple DES (FIPS 46-3) and RC4, with CBC and GCM over
// any of the block ciphers. They decrypt only records whose keys the user supplied in a
// key log, as Wireshark does with tls.keylog_file.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "crypto.h"

namespace anta {

enum class BlockAlg : uint8_t { Aes, Camellia, Aria, Seed, Des3 };

class BlockCipher {
public:
    // key_len: AES 16 or 32; Camellia and ARIA 16, 24 or 32; SEED 16; Triple DES 24.
    BlockCipher(BlockAlg alg, const uint8_t* key, size_t key_len);
    bool valid() const { return valid_; }
    size_t block_size() const { return alg_ == BlockAlg::Des3 ? 8 : 16; }
    void encrypt(const uint8_t* in, uint8_t* out) const;
    void decrypt(const uint8_t* in, uint8_t* out) const;

private:
    void camellia(const uint64_t* kw, const uint64_t* k, const uint64_t* ke, const uint8_t* in, uint8_t* out) const;
    void aria(const uint8_t (*rk)[16], const uint8_t* in, uint8_t* out) const;
    void seed(const uint32_t* k, const uint8_t* in, uint8_t* out) const;

    BlockAlg alg_;
    bool valid_ = false;
    std::optional<Aes128> aes128_;
    std::optional<Aes256> aes256_;
    int rounds_ = 0;  // Camellia 18 or 24; ARIA 12, 14 or 16
    uint64_t cam_kw_[2][4] = {}, cam_k_[2][24] = {}, cam_ke_[2][6] = {};  // [0] encryption, [1] decryption
    uint8_t aria_rk_[2][17][16] = {};
    uint32_t seed_k_[2][32] = {};
    uint64_t des_k_[3][16] = {};  // the three DES keys' 48-bit round keys
};

// CBC decryption of whole blocks; false if len isn't a multiple of the block size.
bool block_cbc_decrypt(const BlockCipher& c, const uint8_t* iv, const uint8_t* in, size_t len, uint8_t* out);

// GCM decryption (NIST SP 800-38D) over a 16-byte block cipher: 12-byte nonce, 16-byte tag.
bool block_gcm_open(const BlockCipher& c, const uint8_t nonce[12], const uint8_t* aad, size_t aad_len,
                    const uint8_t* ct, size_t ct_len, const uint8_t tag[16], uint8_t* out);

// RC4: a keystream that runs on across a direction's records.
class Rc4 {
public:
    Rc4() = default;
    Rc4(const uint8_t* key, size_t key_len);
    void crypt(const uint8_t* in, uint8_t* out, size_t n);

private:
    uint8_t s_[256] = {};
    uint8_t i_ = 0, j_ = 0;
};

}  // namespace anta
