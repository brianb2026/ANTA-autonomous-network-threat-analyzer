// A TLS key log (the NSS "SSLKEYLOGFILE" format browsers and curl write when
// SSLKEYLOGFILE is set). It holds the per-session secrets that let a capture's
// owner read their own TLS traffic — exactly what Wireshark's tls.keylog_file
// does. No keys are derived or broken here: the secrets come from a file the
// user supplies, so only traffic they already hold the keys for can be read.
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace anta {

// One session's secrets, each keyed by the ClientHello random (32 bytes). A log
// may carry only some of these; length is the hash size (32 for SHA-256 suites,
// 48 for SHA-384), or 48 for the TLS 1.2 master secret.
struct TlsSecrets {
    enum Which { ClientHandshake, ServerHandshake, ClientApp, ServerApp, Master, ClientEarly, kCount };
    uint8_t secret[kCount][48] = {};
    uint8_t len[kCount] = {};
    std::string premaster;  // PMS_CLIENT_RANDOM: the premaster secret (any length; DH ones are long)
    bool has(Which w) const { return len[w] != 0; }
};

class TlsKeyLog {
public:
    // Load (or add to) the log from a file. Returns the number of secrets read.
    // Safe to call with a missing or malformed file: bad lines are skipped. The file is
    // remembered: a browser keeps appending to its SSLKEYLOGFILE, and later lookups
    // read what it added (as Wireshark re-reads tls.keylog_file).
    size_t load(const std::string& path);
    bool empty() const { return sessions_.empty() && rsa_.empty() && path_.empty(); }
    size_t size() const { return sessions_.size(); }

    // The secrets for a ClientHello random (raw 32 bytes), or nullptr. A miss reads
    // what was appended to the file since (at most once a second).
    const TlsSecrets* find(const uint8_t client_random[32]) const;

    // The premaster secret of an RSA key exchange, from an `RSA` line: keyed by the first 8
    // bytes of the encrypted premaster the Client Key Exchange carries. Empty if unknown.
    std::string find_rsa(const uint8_t encrypted_premaster[8]) const;

private:
    size_t read_from(uint64_t offset) const;
    size_t parse_line(const std::string& line) const;

    mutable std::unordered_map<std::string, TlsSecrets> sessions_;  // key: 32 raw random bytes
    mutable std::unordered_map<std::string, std::string> rsa_;       // 8 bytes of ciphertext -> premaster
    std::string path_;
    mutable uint64_t offset_ = 0;  // bytes of the file read so far (whole lines)
    mutable std::chrono::steady_clock::time_point next_refresh_{};
};

}  // namespace anta
