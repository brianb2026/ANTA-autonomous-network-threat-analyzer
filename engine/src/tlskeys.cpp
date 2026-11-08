#include "tlskeys.h"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>

namespace anta {

namespace {

// Lowercase-hex to bytes; returns false (and leaves out partial) on any non-hex
// nibble or odd length. Caps at `max` bytes.
bool unhex(const std::string& s, uint8_t* out, size_t max, size_t& n) {
    if (s.empty() || s.size() % 2 || s.size() / 2 > max)
        return false;
    n = s.size() / 2;
    for (size_t i = 0; i < n; ++i) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(s[2 * i]), lo = nib(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

// The log label -> which secret it holds (the ones that decrypt records). Exporter
// secrets aren't used for reading any records.
bool label_to_which(const std::string& label, TlsSecrets::Which& w) {
    if (label == "CLIENT_EARLY_TRAFFIC_SECRET") w = TlsSecrets::ClientEarly;  // TLS 1.3 0-RTT data
    else if (label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET") w = TlsSecrets::ClientHandshake;
    else if (label == "SERVER_HANDSHAKE_TRAFFIC_SECRET") w = TlsSecrets::ServerHandshake;
    else if (label == "CLIENT_TRAFFIC_SECRET_0") w = TlsSecrets::ClientApp;
    else if (label == "SERVER_TRAFFIC_SECRET_0") w = TlsSecrets::ServerApp;
    else if (label == "CLIENT_RANDOM") w = TlsSecrets::Master;  // TLS 1.2 master secret
    else return false;
    return true;
}

}  // namespace

size_t TlsKeyLog::parse_line(const std::string& line) const {
    if (line.size() > 4096)
        return 0;  // a real line is ~200 chars; ignore anything absurd
    // Fields: LABEL <client_random hex> <secret hex>
    size_t a = line.find(' ');
    if (a == std::string::npos || line[0] == '#')
        return 0;
    size_t b = line.find(' ', a + 1);
    if (b == std::string::npos)
        return 0;
    std::string label = line.substr(0, a);
    std::string rnd_hex = line.substr(a + 1, b - a - 1);
    std::string sec_hex = line.substr(b + 1);
    while (!sec_hex.empty() && (sec_hex.back() == '\r' || sec_hex.back() == ' '))
        sec_hex.pop_back();
    if (label == "RSA") {  // RSA <first 8 bytes of the encrypted premaster> <premaster>
        uint8_t enc[8], pms[48];
        size_t enc_len = 0, pms_len = 0;
        if (!unhex(rnd_hex, enc, 8, enc_len) || enc_len != 8 || !unhex(sec_hex, pms, 48, pms_len) || pms_len != 48)
            return 0;
        if (rsa_.size() >= 200'000) return 0;
        rsa_[std::string(reinterpret_cast<char*>(enc), 8)] = std::string(reinterpret_cast<char*>(pms), 48);
        return 1;
    }
    bool premaster = label == "PMS_CLIENT_RANDOM";
    TlsSecrets::Which which = TlsSecrets::Master;
    if (!premaster && !label_to_which(label, which))
        return 0;
    uint8_t rnd[32];
    size_t rnd_len = 0;
    if (!unhex(rnd_hex, rnd, 32, rnd_len) || rnd_len != 32)
        return 0;
    if (premaster) {  // a (EC)DH premaster can be long: up to 1024 bytes (an 8192-bit group)
        uint8_t pms[1024];
        size_t pms_len = 0;
        if (!unhex(sec_hex, pms, sizeof pms, pms_len) || pms_len == 0)
            return 0;
        std::string key(reinterpret_cast<char*>(rnd), 32);
        if (sessions_.size() >= 200'000 && !sessions_.count(key)) return 0;
        sessions_[key].premaster.assign(reinterpret_cast<char*>(pms), pms_len);
        return 1;
    }
    uint8_t sec[48];
    size_t sec_len = 0;
    if (!unhex(sec_hex, sec, 48, sec_len) || sec_len == 0)
        return 0;
    std::string key(reinterpret_cast<char*>(rnd), 32);
    if (sessions_.size() >= 200'000 && !sessions_.count(key))  // bound memory against a huge or hostile file
        return 0;
    // (Adding to the map leaves pointers to existing entries valid: lookups may hold them.)
    TlsSecrets& s = sessions_[key];
    std::memcpy(s.secret[which], sec, sec_len);
    s.len[which] = static_cast<uint8_t>(sec_len);
    return 1;
}

// Whole lines from `offset` on; a last line still being written is left for next time.
size_t TlsKeyLog::read_from(uint64_t offset) const {
    std::ifstream in(path_, std::ios::binary);
    if (!in)
        return 0;
    in.seekg(0, std::ios::end);
    auto end = static_cast<uint64_t>(in.tellg());
    if (end < offset)
        offset = 0;  // replaced or truncated: read it again from the start
    if (end - offset > (256u << 20))
        return 0;  // not a key log any browser writes
    in.seekg(static_cast<std::streamoff>(offset));
    std::string chunk(static_cast<size_t>(end - offset), '\0');
    in.read(&chunk[0], static_cast<std::streamsize>(chunk.size()));
    chunk.resize(static_cast<size_t>(in.gcount()));
    size_t added = 0, pos = 0;
    for (size_t nl; (nl = chunk.find('\n', pos)) != std::string::npos; pos = nl + 1)
        added += parse_line(chunk.substr(pos, nl - pos));
    offset_ = offset + pos;
    return added;
}

size_t TlsKeyLog::load(const std::string& path) {
    path_ = path;
    offset_ = 0;
    size_t added = read_from(0);
    std::ifstream in(path, std::ios::binary);  // a last line without its newline counts in a file loaded once
    if (in) {
        in.seekg(static_cast<std::streamoff>(offset_));
        std::string tail((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (!tail.empty() && tail.find('\n') == std::string::npos) added += parse_line(tail);
    }
    return added;
}

std::string TlsKeyLog::find_rsa(const uint8_t encrypted_premaster[8]) const {
    std::string key(reinterpret_cast<const char*>(encrypted_premaster), 8);
    auto it = rsa_.find(key);
    if (it == rsa_.end() && !path_.empty()) {  // (appended since? at most once a second, as find)
        auto now = std::chrono::steady_clock::now();
        if (now >= next_refresh_) {
            next_refresh_ = now + std::chrono::seconds(1);
            read_from(offset_);
            it = rsa_.find(key);
        }
    }
    return it == rsa_.end() ? std::string() : it->second;
}

const TlsSecrets* TlsKeyLog::find(const uint8_t client_random[32]) const {
    std::string key(reinterpret_cast<const char*>(client_random), 32);
    auto it = sessions_.find(key);
    if (it != sessions_.end()) return &it->second;
    auto now = std::chrono::steady_clock::now();
    if (path_.empty() || now < next_refresh_) return nullptr;
    next_refresh_ = now + std::chrono::seconds(1);
    if (!read_from(offset_)) return nullptr;
    it = sessions_.find(key);
    return it == sessions_.end() ? nullptr : &it->second;
}

}  // namespace anta
