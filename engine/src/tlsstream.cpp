#include "tlsstream.h"

#include <algorithm>
#include <cstring>

#include "proto.h"

namespace anta {

namespace {
constexpr size_t kMaxRecordBody = 16384 + 2048;  // TLSCiphertext.length limit (RFC 8446 §5.2)
constexpr size_t kMaxHandshake = 64 * 1024;      // a hello (with its extensions) is far smaller
constexpr size_t kMinRecordBody = 9;             // an inner type and the shortest tag (CCM_8's)
inline uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

// Whether a Client Hello's body (after the 4-byte message header) carries an extension.
bool client_hello_has_ext(const uint8_t* p, size_t n, uint16_t want) {
    size_t pos = 2 + 32;  // legacy version, random
    if (pos + 1 > n) return false;
    pos += 1 + p[pos];  // session id
    if (pos + 2 > n) return false;
    pos += 2 + be16(p + pos);  // cipher suites
    if (pos + 1 > n) return false;
    pos += 1 + p[pos];  // compression methods
    if (pos + 2 > n) return false;
    size_t end = std::min(n, pos + 2 + be16(p + pos));
    for (pos += 2; pos + 4 <= end; pos += 4 + be16(p + pos + 2))
        if (be16(p + pos) == want) return true;
    return false;
}
}  // namespace

namespace {
constexpr uint32_t kMaxUnread = 1024;  // records searched ahead for the counter
}  // namespace

void TlsStreamDecryptor::gap(int dir, uint64_t lost_bytes) {
    if (dir < 0 || dir > 1) return;
    buf_[dir].clear();
    hs_[dir].clear();
    dead_[dir] = false;
    hunting_[dir] = true;
    discontinuity_[dir] = true;
    // A record is at least 22 bytes (header, inner type, tag): at most this many were lost.
    uint64_t lost = lost_bytes / 22 + 2;
    unread_[dir] = static_cast<uint32_t>(std::min<uint64_t>(kMaxUnread, unread_[dir] + lost));
}

// After a gap: the next place a record opens with the keys, at a record number within
// reach of the counter. Consumes buf_ up to it; false if more bytes are needed.
bool TlsStreamDecryptor::hunt(int dir, std::string& out) {
    std::string& b = buf_[dir];
    bool tls13 = version_ == 0x0304;
    if (tls13 ? !lookup() : !master()) {  // without the keys nothing can tell a record from the middle of one
        if (b.size() > 4) b.erase(0, b.size() - 4);
        return false;
    }
    for (size_t i = 0; i + 5 <= b.size(); ++i) {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(b.data()) + i;
        uint8_t ct = p[0];
        uint16_t ver = be16(p + 1);
        size_t rlen = be16(p + 3);
        if (ver < 0x0300 || ver > 0x0303 || rlen < kMinRecordBody || rlen > kMaxRecordBody ||
            (tls13 ? ct != 23 : (ct < 20 || ct > 24)))
            continue;
        if (b.size() - i < 5 + rlen) {  // a candidate not whole yet: wait for it
            b.erase(0, i);
            return false;
        }
        // TLS 1.0 CBC: a record's IV is the last ciphertext block before it (ahead of the
        // MAC with encrypt-then-MAC), which is in the buffer when the record before is.
        Tls12Keys& k = k12_[dir];
        if (!tls13 && k12_ready_[dir] && k.mode == Tls12Keys::Cbc && k.version == 0x0301) {
            size_t back = 16 + (k.etm ? k.mac_len : 0);
            if (i >= back) std::memcpy(dir == 1 ? k.server_iv : k.client_iv, p - back, 16);
        }
        uint64_t seq12 = seq12_[dir];
        bool ok = tls13 ? open13(dir, p, rlen, out) : (enc12_[dir] && open12(dir, ct, ver, p + 5, rlen, out));
        if (!ok) seq12_[dir] = seq12;  // a false start leaves the counter where it was
        if (ok) {
            hunting_[dir] = false;
            b.erase(0, i + 5 + rlen);
            return true;
        }
    }
    if (b.size() > 4) b.erase(0, b.size() - 4);  // keep a header's worth that may continue
    return false;
}

void TlsStreamDecryptor::feed(int dir, const uint8_t* data, size_t len, std::string& out) {
    if (dir < 0 || dir > 1 || dead_[dir])
        return;
    std::string& b = buf_[dir];
    b.append(reinterpret_cast<const char*>(data), len);
    if (hunting_[dir] && !hunt(dir, out))
        return;
    size_t pos = 0;
    while (b.size() - pos >= 5) {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(b.data()) + pos;
        uint8_t ct = p[0];
        uint16_t ver = be16(p + 1);
        size_t rlen = be16(p + 3);
        if (ct < 20 || ct > 24 || (ver >> 8) != 3 || rlen > kMaxRecordBody) {
            dead_[dir] = true;  // not (or no longer) a TLS record stream: stop reading it
            b.clear();
            return;
        }
        if (b.size() - pos < 5 + rlen)
            break;
        record(dir, ct, ver, p, rlen, out);
        pos += 5 + rlen;
    }
    b.erase(0, pos);
}

void TlsStreamDecryptor::record(int dir, uint8_t ct, uint16_t ver, const uint8_t* rec, size_t rlen, std::string& out) {
    bool tls13 = version_ == 0x0304;
    if (ct == 20) {  // ChangeCipherSpec: TLS 1.2 protects what follows from this side
        // (TLS 1.3's compatibility CCS can come before the Server Hello, with early data:
        // only a session known to be TLS 1.2 or earlier switches.)
        if (version_ && !tls13) {
            enc12_[dir] = true;
            seq12_[dir] = 0;
            k12_ready_[dir] = false;
        }
        return;
    }
    if (!tls13 && enc12_[dir]) {
        open12(dir, ct, ver, rec + 5, rlen, out);
        return;
    }
    if (ct == 22) {
        handshake(dir, rec + 5, rlen);
        return;
    }
    if (ct == 23 && dir == 0 && early_offered_ && !early_done_ && open_early(rec, rlen, out))
        return;
    if (ct == 23 && tls13)
        open13(dir, rec, rlen, out);
}

void TlsStreamDecryptor::handshake(int dir, const uint8_t* p, size_t n, bool renegotiation) {
    std::string& h = hs_[dir];
    if (h.size() + n > kMaxHandshake) {
        h.clear();
        return;
    }
    h.append(reinterpret_cast<const char*>(p), n);
    size_t pos = 0;
    while (h.size() - pos >= 4) {
        const uint8_t* m = reinterpret_cast<const uint8_t*>(h.data()) + pos;
        size_t mlen = (static_cast<size_t>(m[1]) << 16) | (m[2] << 8) | m[3];
        if (h.size() - pos < 4 + mlen)
            break;
        uint8_t t = m[0];
        if (t == 1) {  // a handshake starts (a renegotiation's too): its own transcript and master
            transcript_.clear();
            transcript_done_ = false;
            master_set_ = false;
            rsa_enc_set_ = false;
        }
        if (!transcript_done_ && t != 0 && transcript_.size() + 4 + mlen <= (1u << 20))
            transcript_.append(reinterpret_cast<const char*>(m), 4 + mlen);
        if (t == 16 && !transcript_done_) {  // Client Key Exchange: the end of what the master hashes
            transcript_done_ = true;
            if (mlen >= 10 && be16(m + 4) == mlen - 2) {  // RSA: length, then the ciphertext
                std::memcpy(rsa_enc8_, m + 6, 8);
                rsa_enc_set_ = true;
            } else if (mlen >= 8) {  // SSL 3.0
                std::memcpy(rsa_enc8_, m + 4, 8);
                rsa_enc_set_ = true;
            }
        }
        // The random follows the 2-byte legacy version: type(1) + length(3) + version(2).
        if (t == 1 && mlen >= 34 && (!cr_set_ || renegotiation)) {
            std::memcpy(cr_, m + 6, 32);
            cr_set_ = true;
            secrets_ = nullptr;  // a renegotiation's secrets are under its own random
            if (!renegotiation) early_offered_ = client_hello_has_ext(m + 4, mlen, 0x002a);
        } else if (t == 2 && mlen >= 34 && (!sr_set_ || renegotiation)) {
            std::memcpy(sr_, m + 6, 32);
            sr_set_ = true;
            std::string rec("\x16\x03\x03", 3);
            rec.push_back(static_cast<char>(((4 + mlen) >> 8) & 0xFF));
            rec.push_back(static_cast<char>((4 + mlen) & 0xFF));
            rec.append(reinterpret_cast<const char*>(m), 4 + mlen);
            if (auto sh = parse_tls_server_hello(rec)) {
                version_ = sh->version;
                cipher_ = sh->cipher;
                etm_ = sh->etm;
                ems_ = sh->ems;
                if (!renegotiation) alpn_ = sh->alpn;
            }
        }
        pos += 4 + mlen;
    }
    h.erase(0, pos);
}

// Looked up until found: a browser writes a session's secrets to its key log as the
// handshake ends, which can be a moment after its first records were captured.
bool TlsStreamDecryptor::lookup() {
    if (!secrets_ && cr_set_ && keylog_)
        secrets_ = keylog_->find(cr_);  // (the log throttles re-reading its file)
    return secrets_ != nullptr;
}

bool TlsStreamDecryptor::master() {
    if (master_set_) return true;
    if (lookup() && secrets_->has(TlsSecrets::Master)) {
        std::memcpy(master_, secrets_->secret[TlsSecrets::Master], 48);
        return master_set_ = true;
    }
    if (!keylog_ || !transcript_done_ || !sr_set_) return false;
    std::string pms = secrets_ ? secrets_->premaster : std::string();
    if (pms.empty() && rsa_enc_set_) pms = keylog_->find_rsa(rsa_enc8_);
    master_set_ = !pms.empty() && tls_master_secret(reinterpret_cast<const uint8_t*>(pms.data()), pms.size(), cr_, sr_,
                                                    cipher_, version_, ems_, transcript_, master_);
    return master_set_;
}

bool TlsStreamDecryptor::open_early(const uint8_t* rec, size_t rlen, std::string& out) {
    if (rlen < kMinRecordBody || !lookup())
        return false;  // (the secrets may still be on their way into the key log)
    if (!secrets_->has(TlsSecrets::ClientEarly)) {
        early_done_ = true;
        return false;
    }
    std::string plain(rlen, '\0');
    uint8_t* pp = reinterpret_cast<uint8_t*>(&plain[0]);
    long n = -1;
    if (early_.valid) {
        n = tls13_open(early_, early_seq_, rec, rec + 5, rlen, pp);
    } else {  // the resumed session's suite, before the Server Hello names it: the one whose tag checks
        const uint8_t* secret = secrets_->secret[TlsSecrets::ClientEarly];
        size_t sl = secrets_->len[TlsSecrets::ClientEarly];
        for (uint16_t cs = 0x1301; cs <= 0x1305 && n < 0; ++cs) {
            TlsRecordKeys k = tls13_record_keys(secret, sl, cs);
            if (k.valid && (n = tls13_open(k, 0, rec, rec + 5, rlen, pp)) >= 0) early_ = k;
        }
    }
    if (n < 0) {
        early_done_ = true;  // the server turned the early data down, or it is over
        return false;
    }
    ++early_seq_;
    ++records_;
    size_t pn = static_cast<size_t>(n);
    while (pn && plain[pn - 1] == '\0') --pn;
    if (!pn) return true;
    uint8_t inner = static_cast<uint8_t>(plain[pn - 1]);
    if (inner == 23)
        out.append(plain.data(), pn - 1);
    else if (inner == 22 && plain[0] == 5)
        early_done_ = true;  // End of Early Data
    return true;
}

bool TlsStreamDecryptor::open13(int dir, const uint8_t* rec, size_t rlen, std::string& out) {
    if (!lookup() || !tls13_cipher_supported(cipher_)) {
        if (unread_[dir] < kMaxUnread) ++unread_[dir];  // read later, once the keys are known
        return false;
    }
    if (!app_ready_[dir]) {
        auto which = dir == 0 ? TlsSecrets::ClientApp : TlsSecrets::ServerApp;
        if (!secrets_->has(which))
            return false;
        app_[dir] = tls13_record_keys(secrets_->secret[which], secrets_->len[which], cipher_);
        app_ready_[dir] = app_[dir].valid;
        if (!app_ready_[dir])
            return false;
    }
    std::string plain(rlen, '\0');
    uint8_t* pp = reinterpret_cast<uint8_t*>(&plain[0]);
    long n = tls13_open(app_[dir], app_seq_[dir], rec, rec + 5, rlen, pp);
    // Records went by unread (keys that came late, or a gap): the counter is somewhere
    // ahead; the record that opens says where.
    for (uint32_t k = 1; n < 0 && k <= unread_[dir]; ++k) {
        n = tls13_open(app_[dir], app_seq_[dir] + k, rec, rec + 5, rlen, pp);
        if (n >= 0) app_seq_[dir] += k;
    }
    if (n < 0)
        return false;  // a handshake record under the handshake keys: not application data
    unread_[dir] = 0;
    ++app_seq_[dir];
    ++records_;
    size_t pn = static_cast<size_t>(n);
    while (pn && plain[pn - 1] == '\0')  // TLS 1.3 padding
        --pn;
    if (!pn)
        return true;
    uint8_t inner = static_cast<uint8_t>(plain[pn - 1]);
    if (inner == 23) {  // application data
        out.append(plain.data(), pn - 1);
    } else if (inner == 22) {  // New Session Ticket, or a Key Update: the sender's next keys
        bool update = false;
        for (size_t m = 0; m + 4 <= pn - 1; m += 4 + ((static_cast<size_t>(pp[m + 1]) << 16) | (pp[m + 2] << 8) | pp[m + 3]))
            if (pp[m] == 24) update = true;
        if (update) {
            app_[dir] = tls13_next_keys(app_[dir]);
            app_seq_[dir] = 0;
        }
    }
    return true;
}

bool TlsStreamDecryptor::open12(int dir, uint8_t ct, uint16_t ver, const uint8_t* body, size_t blen, std::string& out) {
    uint64_t seq = seq12_[dir]++;  // every protected record takes a sequence number
    if (!k12_ready_[dir]) {  // this side's first record after its ChangeCipherSpec
        if (!sr_set_ || !tls12_cipher_supported(cipher_) || !master())
            return false;
        k12_[dir] = tls12_keys(master_, cr_, sr_, cipher_, version_, etm_);
        k12_ready_[dir] = k12_[dir].valid;
        if (!k12_ready_[dir])
            return false;
    }
    Tls12Keys& k = k12_[dir];
    std::string plain(blen, '\0');
    uint8_t* pp = reinterpret_cast<uint8_t*>(&plain[0]);
    long n = tls12_open(k, dir == 1, seq, ct, ver, body, blen, pp);
    for (uint32_t r = 1; n < 0 && r <= unread_[dir]; ++r) {  // after a gap: records were lost
        n = tls12_open(k, dir == 1, seq + r, ct, ver, body, blen, pp);
        if (n >= 0) seq12_[dir] = seq + r + 1;
    }
    tls12_chain_iv(k, dir == 1, body, blen);  // (TLS 1.0 CBC: the next record's IV)
    if (n < 0)
        return false;
    unread_[dir] = 0;
    ++records_;
    if (ct == 23) {
        out.append(plain.data(), static_cast<size_t>(n));
    } else if (ct == 22) {  // the Finished, or a renegotiation: its hellos name the new keys
        handshake(dir, pp, static_cast<size_t>(n), true);
    } else if (ct == 20) {  // a renegotiation's ChangeCipherSpec: this side's new keys follow
        k12_ready_[dir] = false;
        seq12_[dir] = 0;
    }
    return true;
}

}  // namespace anta
