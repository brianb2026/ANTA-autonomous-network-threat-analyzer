#include "smbfiles.h"

#include <algorithm>
#include <cstring>

namespace anta {

namespace {

constexpr size_t kMaxMessage = 16u << 20;   // an NBSS message larger than this is skipped
constexpr size_t kMaxPending = 16u << 20;   // out-of-order data held per file before hashing gives up
constexpr size_t kMaxOpen = 256;
constexpr size_t kMaxFiles = 64;
constexpr size_t kMagic = 16;

uint16_t le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t le32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | (static_cast<uint32_t>(p[3]) << 24); }
uint64_t le64(const uint8_t* p) { return le32(p) | (static_cast<uint64_t>(le32(p + 4)) << 32); }

std::string utf16(const uint8_t* p, size_t n) {
    std::string out;
    for (size_t i = 0; i + 1 < n && out.size() < 4096; i += 2) {
        uint32_t c = le16(p + i);
        if (c == 0) break;
        if (c >= 0xD800 && c < 0xE000) {  // a surrogate pair, or U+FFFD for a stray half
            uint32_t lo = c < 0xDC00 && i + 3 < n ? le16(p + i + 2) : 0;
            if (lo >= 0xDC00 && lo < 0xE000) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            } else {
                c = 0xFFFD;
            }
        }
        if (c < 0x80) {
            out.push_back(static_cast<char>(c < 0x20 ? '.' : c));
        } else if (c < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else if (c < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (c >> 12)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (c >> 18)));
            out.push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return out;
}

}  // namespace

void SmbFileTracker::on_gap(bool from_client) {
    int d = from_client ? 0 : 1;
    lost_[d] = true;
    std::string().swap(buf_[d]);
}

void SmbFileTracker::on_data(bool from_client, const uint8_t* data, size_t len, uint64_t ts) {
    int d = from_client ? 0 : 1;
    if (lost_[d] || encrypted_) return;
    std::string& b = buf_[d];
    b.append(reinterpret_cast<const char*>(data), len);
    size_t pos = 0;
    while (b.size() - pos >= 4) {
        const uint8_t* h = reinterpret_cast<const uint8_t*>(b.data()) + pos;
        size_t mlen = (static_cast<size_t>(h[1]) << 16) | (h[2] << 8) | h[3];
        if (h[0] != 0x00 && (h[0] < 0x81 || h[0] > 0x85)) {  // not NBSS framing: lost sync
            lost_[d] = true;
            std::string().swap(b);
            return;
        }
        if (mlen > kMaxMessage) {
            lost_[d] = true;
            std::string().swap(b);
            return;
        }
        if (b.size() - pos < 4 + mlen) break;
        if (h[0] == 0x00 && mlen >= 64) message(from_client, h + 4, mlen, ts);
        pos += 4 + mlen;
    }
    b.erase(0, pos);
}

void SmbFileTracker::message(bool from_client, const uint8_t* p, size_t n, uint64_t ts) {
    if (p[0] == 0xFD && p[1] == 'S' && p[2] == 'M' && p[3] == 'B') {  // SMB3 encryption: nothing to follow
        encrypted_ = true;
        return;
    }
    for (size_t pos = 0, hops = 0; pos + 64 <= n && hops < 64; ++hops) {
        const uint8_t* h = p + pos;
        if (h[0] != 0xFE || h[1] != 'S' || h[2] != 'M' || h[3] != 'B') return;
        uint32_t next = le32(h + 20);
        size_t len = next && next <= n - pos ? next : n - pos;
        const uint8_t* end = h + len;
        const uint8_t* body = h + 64;
        uint32_t status = le32(h + 8), flags = le32(h + 16);
        uint16_t cmd = le16(h + 12);
        bool resp = flags & 1;
        std::string sess(reinterpret_cast<const char*>(h + 40), 8);
        std::string tree_key = sess + std::string(reinterpret_cast<const char*>(h + 36), 4);
        std::string req_key = sess + std::string(reinterpret_cast<const char*>(h + 24), 8);
        auto have = [&](const uint8_t* at, size_t k) { return at >= h && at + k <= end; };
        auto fid_at = [&](const uint8_t* at) { return std::string(reinterpret_cast<const char*>(at), 16); };
        if (from_client && !resp) {
            Request r;
            r.cmd = cmd;
            r.tree_key = tree_key;
            switch (cmd) {
                case 3:  // Tree Connect: the share
                    if (have(body, 8) && have(h + le16(body + 4), le16(body + 6)))
                        r.name = utf16(h + le16(body + 4), le16(body + 6));
                    break;
                case 5:  // Create: the file's name
                    if (have(body, 56) && have(h + le16(body + 44), le16(body + 46)))
                        r.name = utf16(h + le16(body + 44), le16(body + 46));
                    break;
                case 6:  // Close
                    if (have(body, 24)) r.fid = fid_at(body + 8);
                    break;
                case 8:  // Read: which part of which file
                    if (have(body, 32)) {
                        r.offset = le64(body + 8);
                        r.fid = fid_at(body + 16);
                    }
                    break;
                case 9: {  // Write: the data is right here
                    if (!have(body, 32)) break;
                    uint64_t off = le64(body + 8);
                    std::string fid = fid_at(body + 16);
                    const uint8_t* data = h + le16(body + 2);
                    size_t dlen = le32(body + 4);
                    auto it = open_.find(sess + fid);
                    if (it != open_.end() && data >= h && data <= end) {
                        it->second.written = true;
                        add_data(it->second, off, data, std::min<size_t>(dlen, static_cast<size_t>(end - data)), ts);
                    }
                    break;
                }
                default: break;
            }
            if (cmd == 3 || cmd == 5 || cmd == 6 || cmd == 8) {
                if (requests_.size() > 4096) requests_.clear();
                requests_[req_key] = r;
            }
        } else if (!from_client && resp) {
            auto it = requests_.find(req_key);
            if (it != requests_.end() && it->second.cmd == cmd) {
                Request r = std::move(it->second);
                requests_.erase(it);
                switch (cmd) {
                    case 3:
                        if (!status && have(body, 4)) trees_[tree_key] = {r.name, body[2]};
                        break;
                    case 5: {  // Create response: the handle, and the file's size
                        if (status || !have(body, 80)) break;
                        auto t = trees_.find(r.tree_key);
                        if (t == trees_.end() || t->second.second != 1) break;  // disk shares only, not pipes
                        if (le32(body + 56) & 0x10) break;                     // a directory
                        if (open_.size() >= kMaxOpen) break;
                        Open o;
                        o.name = r.name;
                        o.share = t->second.first;
                        o.end_of_file = le64(body + 48);
                        o.seq = next_seq_++;
                        if (target_ && target_->n == o.seq) target_->found = true;
                        open_[sess + fid_at(body + 64)] = std::move(o);
                        break;
                    }
                    case 6:
                        if (!status) close(sess + r.fid);
                        break;
                    case 8: {  // Read response: data for the requested part
                        if ((status && status != 0x80000005) || !have(body, 16)) break;
                        auto o = open_.find(sess + r.fid);
                        const uint8_t* data = h + body[2];
                        size_t dlen = le32(body + 4);
                        if (o != open_.end() && data >= h && data <= end)
                            add_data(o->second, r.offset, data, std::min<size_t>(dlen, static_cast<size_t>(end - data)), ts);
                        break;
                    }
                    default: break;
                }
            }
        }
        if (!next) break;
        pos += next;
    }
}

void SmbFileTracker::add_data(Open& o, uint64_t off, const uint8_t* p, size_t n, uint64_t ts) {
    if (!n) return;
    if (!o.data_seen) o.ts = ts;
    o.data_seen = true;
    o.max_end = std::max<uint64_t>(o.max_end, off + n);
    if (off < kMagic && o.magic.size() < kMagic && off <= o.magic.size()) {
        size_t skip = static_cast<size_t>(o.magic.size() - off);
        if (skip < n) o.magic.append(reinterpret_cast<const char*>(p + skip), std::min(n - skip, kMagic - o.magic.size()));
    }
    if (o.broken || off + n <= o.hashed) return;
    if (off > o.hashed) {  // ahead of what's hashed: hold it
        if (o.pending_bytes + n > kMaxPending) {
            o.broken = true;
            o.pending.clear();
            o.pending_bytes = 0;
            return;
        }
        auto& slot = o.pending[off];
        if (slot.size() < n) {
            o.pending_bytes += n - slot.size();
            slot.assign(reinterpret_cast<const char*>(p), n);
        }
        return;
    }
    ObjectTarget* out = target_ && target_->n == o.seq ? target_ : nullptr;
    size_t skip = static_cast<size_t>(o.hashed - off);
    o.hash.update(p + skip, n - skip);
    if (out) out->write(p + skip, n - skip);
    o.hashed += n - skip;
    while (!o.pending.empty() && o.pending.begin()->first <= o.hashed) {
        auto first = o.pending.begin();
        uint64_t at = first->first;
        const std::string& chunk = first->second;
        if (at + chunk.size() > o.hashed) {
            size_t s = static_cast<size_t>(o.hashed - at);
            o.hash.update(reinterpret_cast<const uint8_t*>(chunk.data()) + s, chunk.size() - s);
            if (out) out->write(chunk.data() + s, chunk.size() - s);
            o.hashed = at + chunk.size();
        }
        o.pending_bytes -= chunk.size();
        o.pending.erase(first);
    }
}

void SmbFileTracker::close(const std::string& key) {
    auto it = open_.find(key);
    if (it == open_.end()) return;
    Open& o = it->second;
    if (o.data_seen && files_.size() < kMaxFiles) {
        SmbFile f;
        f.name = o.name;
        f.share = o.share;
        f.written = o.written;
        f.size = o.max_end;
        f.end_of_file = o.end_of_file;
        f.magic = o.magic;
        f.ts = o.ts;
        f.seq = o.seq;
        bool contiguous = !o.broken && o.pending.empty() && o.hashed == o.max_end;
        if (contiguous) f.sha256 = o.hash.hex();
        // A read is whole when it reached the end the server announced; a write when nothing is missing.
        f.complete = contiguous && (o.written || o.end_of_file == 0 || o.max_end >= o.end_of_file);
        files_.push_back(std::move(f));
    }
    open_.erase(it);
}

void SmbFileTracker::finish() {
    std::vector<std::string> keys;
    for (const auto& kv : open_) keys.push_back(kv.first);
    for (const auto& k : keys) close(k);
}

}  // namespace anta
