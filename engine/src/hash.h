// Minimal MD5 (RFC 1321) and SHA-256 (FIPS 180-4): JA3/JA4 fingerprints and the
// hashes of files seen in traffic (identifiers to look up, not a security boundary).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace anta {

// Incremental SHA-256, for hashing files as they stream past.
class Sha256 {
public:
    void update(const uint8_t* data, size_t len);
    std::string hex() const;  // the digest of everything so far
    void digest(uint8_t out[32]) const;
    uint64_t size() const { return total_; }

private:
    void block(const uint8_t* p);
    uint32_t h_[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t buf_[64] = {};
    size_t buffered_ = 0;
    uint64_t total_ = 0;
};

void md5(const uint8_t* data, size_t len, uint8_t digest[16]);
std::string md5_hex(const std::string& input);
std::string sha256_hex(const std::string& input);

}  // namespace anta
