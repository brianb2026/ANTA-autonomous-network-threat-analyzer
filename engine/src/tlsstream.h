// Decrypts a TLS connection as its bytes stream past, for the analysis path: the
// raw reassembled stream of each direction goes in, the application data inside it
// comes out, so the HTTP parser, file extraction and detectors can read HTTPS the
// way they read plain HTTP. It needs the session's secrets from a key log the user
// supplied (see tlskeys.h); without them nothing is decrypted.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "tlsdecrypt.h"
#include "tlskeys.h"

namespace anta {

class TlsStreamDecryptor {
public:
    explicit TlsStreamDecryptor(const TlsKeyLog* keylog) : keylog_(keylog) {}

    // In-order bytes from one direction (0 = client to server, 1 = server to client).
    // Decrypted application data from that direction is appended to `out`.
    void feed(int dir, const uint8_t* data, size_t len, std::string& out);

    // Bytes of this direction were never captured: its record framing is lost. The
    // decryptor hunts for the next record and finds its number again by trying the
    // ones that could have been lost; until then nothing comes out.
    void gap(int dir, uint64_t lost_bytes);
    // A gap was crossed since the last call: what comes out next doesn't continue what
    // came before (the application layer should look for a new message).
    bool take_discontinuity(int dir) {
        bool d = discontinuity_[dir];
        discontinuity_[dir] = false;
        return d;
    }

    bool decrypting() const { return records_ > 0; }  // at least one record opened
    uint64_t records() const { return records_; }
    uint16_t version() const { return version_; }      // negotiated (0x0303, 0x0304), 0 until known
    uint16_t cipher() const { return cipher_; }
    const std::string& alpn() const { return alpn_; }  // "h2", "http/1.1", or ""
    size_t buffered() const { return buf_[0].size() + buf_[1].size() + hs_[0].size() + hs_[1].size(); }

private:
    void record(int dir, uint8_t ct, uint16_t ver, const uint8_t* rec, size_t rlen, std::string& out);
    // `renegotiation`: messages read under the record keys; their hellos start a new session.
    void handshake(int dir, const uint8_t* p, size_t n, bool renegotiation = false);
    bool lookup();
    bool open13(int dir, const uint8_t* rec, size_t rlen, std::string& out);
    bool open_early(const uint8_t* rec, size_t rlen, std::string& out);
    bool open12(int dir, uint8_t ct, uint16_t ver, const uint8_t* body, size_t blen, std::string& out);
    bool hunt(int dir, std::string& out);

    const TlsKeyLog* keylog_;
    std::string buf_[2];  // a record split across calls
    std::string hs_[2];   // a plaintext handshake message split across records
    bool dead_[2] = {};   // that direction stopped looking like TLS
    // Records that went by unread (no keys yet, or lost in a gap): how far ahead of the
    // counter the next readable record may be.
    uint32_t unread_[2] = {};
    bool hunting_[2] = {};       // after a gap: looking for where a record starts
    bool discontinuity_[2] = {};
    uint8_t cr_[32] = {}, sr_[32] = {};
    bool cr_set_ = false, sr_set_ = false;
    uint16_t version_ = 0, cipher_ = 0;
    bool etm_ = false;  // CBC suites: encrypt-then-MAC
    // The master secret, from the key log or from the premaster secret it gives (RSA or
    // PMS_CLIENT_RANDOM lines) over the handshake transcript (extended master secret).
    bool ems_ = false;
    std::string transcript_;  // Client Hello … Client Key Exchange
    bool transcript_done_ = false;
    uint8_t rsa_enc8_[8] = {};
    bool rsa_enc_set_ = false;
    uint8_t master_[48] = {};
    bool master_set_ = false;
    bool master();
    std::string alpn_;
    const TlsSecrets* secrets_ = nullptr;
    // TLS 1.3: application-traffic keys per direction (handshake records don't open with
    // them); a Key Update moves its sender to the next ones.
    TlsRecordKeys app_[2];
    bool app_ready_[2] = {};
    uint64_t app_seq_[2] = {};
    // TLS 1.3 early data: the client's records under its early-traffic keys, when its
    // Client Hello offered them, up to its End of Early Data.
    bool early_offered_ = false, early_done_ = false;
    TlsRecordKeys early_;
    uint64_t early_seq_ = 0;
    // TLS 1.2 and earlier: records are protected from each side's ChangeCipherSpec on,
    // under the key block it switched to (a renegotiation moves each side in turn).
    bool enc12_[2] = {};
    uint64_t seq12_[2] = {};
    Tls12Keys k12_[2];
    bool k12_ready_[2] = {};
    uint64_t records_ = 0;
};

}  // namespace anta
