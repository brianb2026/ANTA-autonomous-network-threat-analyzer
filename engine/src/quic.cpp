#include "quic.h"

#include <algorithm>
#include <cstring>

#include "crypto.h"

namespace anta {

namespace {

constexpr uint32_t kV1 = 0x00000001, kV2 = 0x6b3343cf;

bool varint(const uint8_t* p, size_t avail, size_t& pos, uint64_t& v) {
    if (pos >= avail) return false;
    size_t n = size_t(1) << (p[pos] >> 6);
    if (pos + n > avail) return false;
    v = p[pos] & 0x3F;
    for (size_t i = 1; i < n; ++i) v = (v << 8) | p[pos + i];
    pos += n;
    return true;
}

bool is_draft(uint32_t v) { return v >= 0xff00001d && v <= 0xff000022; }  // drafts 29-34

}  // namespace

bool quic_known_version(uint32_t v) { return v == kV1 || v == kV2 || is_draft(v); }

bool quic_parse_long_header(const uint8_t* p, size_t avail, QuicLongHeader& h) {
    if (avail < 7 || !(p[0] & 0x80)) return false;
    h.version = (static_cast<uint32_t>(p[1]) << 24) | (p[2] << 16) | (p[3] << 8) | p[4];
    size_t pos = 5;
    uint8_t dl = p[pos++];
    if (dl > 20 || pos + dl + 1 > avail) return false;
    h.dcid.assign(reinterpret_cast<const char*>(p + pos), dl);
    pos += dl;
    uint8_t sl = p[pos++];
    if (sl > 20 || pos + sl > avail) return false;
    h.scid.assign(reinterpret_cast<const char*>(p + pos), sl);
    pos += sl;
    if (h.version == 0) {  // Version Negotiation: the supported versions follow
        h.length = avail;
        return true;
    }
    uint8_t t = (p[0] >> 4) & 3;
    if (h.version == kV2) t = (t + 3) & 3;  // v2 numbers the types Retry, Initial, 0-RTT, Handshake
    h.type = static_cast<QuicType>(t);
    if (h.type == QuicType::Retry) {
        h.pn_offset = pos;
        h.length = avail;
        return true;
    }
    if (h.type == QuicType::Initial) {
        uint64_t tl = 0;
        if (!varint(p, avail, pos, tl) || tl > avail - pos) return false;
        pos += static_cast<size_t>(tl);
    }
    uint64_t len = 0;
    if (!varint(p, avail, pos, len) || len > avail - pos || len < 1) return false;
    h.pn_offset = pos;
    h.length = pos + static_cast<size_t>(len);
    return true;
}

bool quic_initial_keys(uint32_t version, const std::string& odcid, bool server, QuicKeys& k) {
    static const uint8_t salt_v1[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
    static const uint8_t salt_v2[20] = {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
                                        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};
    static const uint8_t salt_d29[20] = {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
                                         0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99};
    const uint8_t* salt = version == kV1 ? salt_v1 : version == kV2 ? salt_v2 : is_draft(version) ? salt_d29 : nullptr;
    if (!salt) return false;
    uint8_t initial[32], secret[32];
    hkdf_extract(salt, 20, reinterpret_cast<const uint8_t*>(odcid.data()), odcid.size(), initial);
    hkdf_expand_label(initial, server ? "server in" : "client in", secret, 32);
    bool v2 = version == kV2;
    hkdf_expand_label(secret, v2 ? "quicv2 key" : "quic key", k.key, 16);
    hkdf_expand_label(secret, v2 ? "quicv2 iv" : "quic iv", k.iv, 12);
    hkdf_expand_label(secret, v2 ? "quicv2 hp" : "quic hp", k.hp, 16);
    return true;
}

bool quic_open(const uint8_t* p, const QuicLongHeader& h, const QuicKeys& k, int64_t largest, uint64_t& pn,
               std::string& payload) {
    // Header protection: the sample starts 4 bytes after the packet number's start.
    if (h.pn_offset + 4 + 16 > h.length) return false;
    uint8_t mask[16];
    Aes128(k.hp).encrypt(p + h.pn_offset + 4, mask);
    std::string header(reinterpret_cast<const char*>(p), h.pn_offset + 4);
    header[0] = static_cast<char>(static_cast<uint8_t>(header[0]) ^ (mask[0] & 0x0F));
    size_t pn_len = (static_cast<uint8_t>(header[0]) & 3) + 1;
    uint64_t truncated = 0;
    for (size_t i = 0; i < pn_len; ++i) {
        uint8_t b = static_cast<uint8_t>(header[h.pn_offset + i]) ^ mask[1 + i];
        header[h.pn_offset + i] = static_cast<char>(b);
        truncated = (truncated << 8) | b;
    }
    header.resize(h.pn_offset + pn_len);
    // The full packet number nearest the next expected one (RFC 9000 §A.3).
    uint64_t expected = static_cast<uint64_t>(largest + 1);
    uint64_t win = uint64_t(1) << (pn_len * 8), hwin = win / 2;
    uint64_t candidate = (expected & ~(win - 1)) | truncated;
    if (candidate + hwin <= expected && candidate < (uint64_t(1) << 62) - win) candidate += win;
    else if (candidate > expected + hwin && candidate >= win) candidate -= win;
    pn = candidate;
    size_t ct_off = h.pn_offset + pn_len;
    if (h.length < ct_off + 16) return false;
    size_t ct_len = h.length - ct_off - 16;
    uint8_t nonce[12];
    std::memcpy(nonce, k.iv, 12);
    for (int i = 0; i < 8; ++i) nonce[11 - i] ^= static_cast<uint8_t>(pn >> (8 * i));
    payload.resize(ct_len);
    return aes128_gcm_open(k.key, nonce, reinterpret_cast<const uint8_t*>(header.data()), header.size(),
                           p + ct_off, ct_len, p + ct_off + ct_len, reinterpret_cast<uint8_t*>(&payload[0]));
}

QuicFrames quic_frames(const std::string& payload) {
    QuicFrames out;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(payload.data());
    size_t n = payload.size(), pos = 0;
    while (pos < n) {
        uint64_t type = 0;
        if (!varint(p, n, pos, type)) break;
        uint64_t a = 0, b = 0, c = 0;
        if (type == 0x00) {  // PADDING: a run of zero bytes is one frame
            while (pos < n && p[pos] == 0) ++pos;
            out.names.push_back("PADDING");
        } else if (type == 0x01) {
            out.names.push_back("PING");
        } else if (type == 0x02 || type == 0x03) {
            uint64_t count = 0;
            if (!varint(p, n, pos, a) || !varint(p, n, pos, b) || !varint(p, n, pos, count) || !varint(p, n, pos, c))
                break;
            bool ok = true;
            for (uint64_t i = 0; i < count && ok; ++i) ok = varint(p, n, pos, a) && varint(p, n, pos, b);
            for (int i = 0; type == 0x03 && i < 3 && ok; ++i) ok = varint(p, n, pos, a);
            if (!ok) break;
            out.names.push_back("ACK");
        } else if (type == 0x06) {
            if (!varint(p, n, pos, a) || !varint(p, n, pos, b) || b > n - pos) break;
            out.crypto.emplace_back(a, payload.substr(pos, static_cast<size_t>(b)));
            pos += static_cast<size_t>(b);
            out.names.push_back("CRYPTO");
        } else if (type == 0x1c || type == 0x1d) {
            if (!varint(p, n, pos, a) || (type == 0x1c && !varint(p, n, pos, b)) || !varint(p, n, pos, c) ||
                c > n - pos)
                break;
            pos += static_cast<size_t>(c);
            out.names.push_back(type == 0x1c ? "CONNECTION_CLOSE (Transport)" : "CONNECTION_CLOSE (Application)");
        } else {
            break;  // not allowed in Initial packets
        }
    }
    return out;
}

void QuicCryptoStream::add(uint64_t offset, const std::string& data) {
    if (offset >= kMax || data.empty()) return;
    pending_.emplace_back(offset, data.substr(0, static_cast<size_t>(std::min<uint64_t>(data.size(), kMax - offset))));
    for (bool grew = true; grew;) {
        grew = false;
        for (auto it = pending_.begin(); it != pending_.end();) {
            uint64_t end = it->first + it->second.size();
            if (it->first <= head_.size()) {
                if (end > head_.size()) {
                    head_ += it->second.substr(static_cast<size_t>(head_.size() - it->first));
                    grew = true;
                }
                it = pending_.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (pending_.size() > 256) pending_.erase(pending_.begin());
}

std::optional<TlsClientHello> quic_client_hello(const std::string& hs, bool& complete) {
    complete = false;
    if (hs.size() < 4 || hs[0] != 1) return std::nullopt;
    size_t mlen = (static_cast<size_t>(static_cast<uint8_t>(hs[1])) << 16) |
                  (static_cast<size_t>(static_cast<uint8_t>(hs[2])) << 8) | static_cast<uint8_t>(hs[3]);
    if (hs.size() < 4 + mlen) return std::nullopt;
    complete = true;
    if (mlen + 4 > 0xFFFF) return std::nullopt;
    std::string rec("\x16\x03\x01", 3);  // as a TLS record, for the TLS parser
    rec.push_back(static_cast<char>(((mlen + 4) >> 8) & 0xFF));
    rec.push_back(static_cast<char>((mlen + 4) & 0xFF));
    rec.append(hs, 0, mlen + 4);
    auto ch = parse_tls_client_hello(rec);
    if (ch && !ch->ja4.empty()) ch->ja4[0] = 'q';
    return ch;
}

bool QuicHelloReader::on_client_datagram(const uint8_t* p, size_t len) {
    if (++datagrams_ > 16) return true;  // no hello in the first packets: not QUIC, or not from the start
    for (size_t pos = 0; pos < len;) {
        QuicLongHeader h;
        if (!(p[pos] & 0x80) || !quic_parse_long_header(p + pos, len - pos, h) || h.version == 0) break;
        if (!quic_known_version(h.version)) return true;
        if (h.type == QuicType::Initial) {
            if (odcid_.empty()) {
                if (h.dcid.empty()) return true;
                odcid_ = h.dcid;
                version_ = h.version;
            }
            QuicKeys k;
            uint64_t pn = 0;
            std::string payload;
            if (quic_initial_keys(version_, odcid_, false, k) && quic_open(p + pos, h, k, largest_, pn, payload)) {
                if (static_cast<int64_t>(pn) > largest_) largest_ = static_cast<int64_t>(pn);
                for (const auto& c : quic_frames(payload).crypto) crypto_.add(c.first, c.second);
                bool complete = false;
                hello = quic_client_hello(crypto_.head(), complete);
                if (complete) return true;
            }
        }
        if (h.length == 0) break;
        pos += h.length;
    }
    return false;
}

}  // namespace anta
