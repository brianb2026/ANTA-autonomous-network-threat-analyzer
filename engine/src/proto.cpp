#include "proto.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#include "hash.h"
#include "platform.h"

namespace anta {

namespace {

// Bounds-checked big-endian reader. Any overrun latches `ok = false` and
// returns zeros, so parsers can read straight through and check once.
class Reader {
public:
    Reader(const uint8_t* data, size_t len) : data_(data), len_(len) {}

    bool ok() const { return ok_; }
    size_t pos() const { return pos_; }
    size_t remaining() const { return ok_ ? len_ - pos_ : 0; }

    uint8_t u8() {
        if (!need(1)) return 0;
        return data_[pos_++];
    }
    uint16_t u16() {
        if (!need(2)) return 0;
        uint16_t v = static_cast<uint16_t>((data_[pos_] << 8) | data_[pos_ + 1]);
        pos_ += 2;
        return v;
    }
    uint32_t u24() {
        if (!need(3)) return 0;
        uint32_t v = (data_[pos_] << 16) | (data_[pos_ + 1] << 8) | data_[pos_ + 2];
        pos_ += 3;
        return v;
    }
    uint32_t u32() {
        uint32_t hi = u16();
        return (hi << 16) | u16();
    }
    const uint8_t* bytes(size_t n) {
        if (!need(n)) return nullptr;
        const uint8_t* p = data_ + pos_;
        pos_ += n;
        return p;
    }
    void skip(size_t n) { bytes(n); }
    Reader sub(size_t n) {
        const uint8_t* p = bytes(n);
        return p ? Reader(p, n) : Reader(nullptr, 0, false);
    }

private:
    Reader(const uint8_t* data, size_t len, bool ok) : data_(data), len_(len), ok_(ok) {}
    bool need(size_t n) {
        if (!ok_ || len_ - pos_ < n) {
            ok_ = false;
            return false;
        }
        return true;
    }
    const uint8_t* data_;
    size_t len_;
    size_t pos_ = 0;
    bool ok_ = true;
};

// ---------------------------------------------------------------- DNS

}  // namespace

// Decode a (possibly compressed) domain name starting at `off`. Returns the
// offset just past the name in the original position (not following pointers).
bool read_dns_name(const uint8_t* msg, size_t len, size_t off, std::string& name, size_t& next) {
    name.clear();
    bool jumped = false;
    int hops = 0;
    size_t cur = off;
    while (true) {
        if (cur >= len) return false;
        uint8_t label_len = msg[cur];
        if ((label_len & 0xC0) == 0xC0) {
            if (cur + 1 >= len || ++hops > 16) return false;  // loop guard
            size_t ptr = static_cast<size_t>(((label_len & 0x3F) << 8) | msg[cur + 1]);
            if (!jumped) next = cur + 2;
            jumped = true;
            cur = ptr;
            continue;
        }
        if (label_len & 0xC0) return false;  // reserved label types
        if (label_len == 0) {
            if (!jumped) next = cur + 1;
            return true;
        }
        if (cur + 1 + label_len > len || name.size() + label_len > 255) return false;
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(msg + cur + 1), label_len);
        cur += 1 + label_len;
    }
}

namespace {

std::string render_rdata(const uint8_t* msg, size_t len, uint16_t type, size_t off, uint16_t rdlen) {
    char buf[64];
    if (type == 1 && rdlen == 4) {
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", msg[off], msg[off + 1], msg[off + 2], msg[off + 3]);
        return buf;
    }
    if (type == 28 && rdlen == 16) {  // canonical RFC 5952 text, matching how flows print addresses
        char text[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, msg + off, text, sizeof(text));
        return text;
    }
    if (type == 5 || type == 12 || type == 2) {  // CNAME, PTR, NS
        std::string name;
        size_t next = 0;
        if (read_dns_name(msg, len, off, name, next)) return name;
    }
    return {};
}

// ---------------------------------------------------------------- HTTP

const char* kHttpMethods[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ",
                              "PATCH ", "CONNECT ", "TRACE "};

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t\r");
    return s.substr(b, e - b + 1);
}

// Split a header block into (lowercased name, value) pairs; returns the first line.
std::string parse_header_block(const std::string& block,
                               std::vector<std::pair<std::string, std::string>>& headers) {
    size_t line_end = block.find("\r\n");
    std::string first = block.substr(0, line_end);
    size_t pos = line_end == std::string::npos ? block.size() : line_end + 2;
    while (pos < block.size()) {
        size_t end = block.find("\r\n", pos);
        if (end == std::string::npos) end = block.size();
        std::string line = block.substr(pos, end - pos);
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            headers.emplace_back(lower(trim(line.substr(0, colon))), trim(line.substr(colon + 1)));
        }
        pos = end + 2;
    }
    return first;
}

// ---------------------------------------------------------------- TLS

bool is_grease(uint16_t v) { return (v & 0x0F0F) == 0x0A0A && (v >> 8) == (v & 0xFF); }

// Concatenate handshake-record payloads from the start of a TLS stream until a
// whole handshake message of `want_type` is available.
bool collect_handshake(const std::string& buf, uint8_t want_type, std::string& hs) {
    const auto* data = reinterpret_cast<const uint8_t*>(buf.data());
    size_t pos = 0;
    hs.clear();
    while (pos + 5 <= buf.size()) {
        uint8_t content_type = data[pos];
        uint16_t rec_len = static_cast<uint16_t>((data[pos + 3] << 8) | data[pos + 4]);
        if (content_type != 22) break;  // not a handshake record
        if (pos + 5 + rec_len > buf.size()) {
            hs.append(buf, pos + 5, std::string::npos);  // partial record: take what we have
            break;
        }
        hs.append(buf, pos + 5, rec_len);
        pos += 5 + rec_len;
        if (hs.size() >= 4) {
            uint32_t msg_len = (static_cast<uint8_t>(hs[1]) << 16) | (static_cast<uint8_t>(hs[2]) << 8) |
                               static_cast<uint8_t>(hs[3]);
            if (hs.size() >= 4 + msg_len) break;
        }
    }
    if (hs.size() < 4 || static_cast<uint8_t>(hs[0]) != want_type) return false;
    uint32_t msg_len = (static_cast<uint8_t>(hs[1]) << 16) | (static_cast<uint8_t>(hs[2]) << 8) |
                       static_cast<uint8_t>(hs[3]);
    return hs.size() >= 4 + msg_len;
}

std::string join_dec(const std::vector<uint16_t>& v) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += '-';
        out += std::to_string(v[i]);
    }
    return out;
}

std::string join_hex(const std::vector<uint16_t>& v) {
    std::string out;
    char buf[8];
    for (size_t i = 0; i < v.size(); ++i) {
        std::snprintf(buf, sizeof(buf), "%s%04x", i ? "," : "", v[i]);
        out += buf;
    }
    return out;
}

std::string ja4_version(uint16_t v) {
    switch (v) {
        case 0x0304: return "13";
        case 0x0303: return "12";
        case 0x0302: return "11";
        case 0x0301: return "10";
        case 0x0300: return "s3";
        case 0xfeff: return "d1";  // DTLS 1.0
        case 0xfefd: return "d2";  // DTLS 1.2
        case 0xfefc: return "d3";  // DTLS 1.3
        default: return "00";
    }
}

std::string ja4_alpn(const std::vector<std::string>& alpn) {
    if (alpn.empty() || alpn[0].empty()) return "00";
    const std::string& a = alpn[0];
    unsigned char f = static_cast<unsigned char>(a.front());
    unsigned char l = static_cast<unsigned char>(a.back());
    if (std::isalnum(f) && std::isalnum(l)) return std::string{static_cast<char>(f), static_cast<char>(l)};
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%02x%02x", f, l);
    return std::string{buf[0], buf[3]};
}

}  // namespace

// ------------------------------------------------------------------ DNS

std::optional<DnsMessage> parse_dns(const uint8_t* data, size_t len) {
    if (len < 12) return std::nullopt;
    Reader r(data, len);
    DnsMessage m;
    m.txid = r.u16();
    uint16_t flags = r.u16();
    uint16_t qdcount = r.u16();
    uint16_t ancount = r.u16();
    r.u16();  // nscount
    r.u16();  // arcount
    m.is_response = (flags & 0x8000) != 0;
    m.rcode = flags & 0x000F;
    if ((flags >> 11 & 0xF) > 2 || qdcount == 0 || qdcount > 4) return std::nullopt;  // opcode sanity

    size_t off = 12;
    size_t next = 0;
    if (!read_dns_name(data, len, off, m.qname, next) || next + 4 > len) return std::nullopt;
    m.qtype = static_cast<uint16_t>((data[next] << 8) | data[next + 1]);
    off = next + 4;
    for (uint16_t q = 1; q < qdcount; ++q) {  // skip any extra questions
        std::string ignored;
        if (!read_dns_name(data, len, off, ignored, next) || next + 4 > len) return m;
        off = next + 4;
    }

    m.answer_count = ancount;
    for (uint16_t i = 0; i < ancount && i < 32; ++i) {
        std::string rrname;
        if (!read_dns_name(data, len, off, rrname, next) || next + 10 > len) break;
        uint16_t type = static_cast<uint16_t>((data[next] << 8) | data[next + 1]);
        uint16_t rdlen = static_cast<uint16_t>((data[next + 8] << 8) | data[next + 9]);
        size_t rdata = next + 10;
        if (rdata + rdlen > len) break;
        if (type == 16) {
            m.txt_bytes += rdlen;
        } else {
            std::string rendered = render_rdata(data, len, type, rdata, rdlen);
            if (!rendered.empty() && m.answers.size() < 8) m.answers.push_back(rendered);
        }
        off = rdata + rdlen;
    }
    return m;
}

// ------------------------------------------------------------------ HTTP

bool looks_like_http_request(const std::string& buf) {
    for (const char* m : kHttpMethods) {
        size_t n = std::strlen(m);
        if (buf.size() >= n && buf.compare(0, n, m) == 0) return true;
    }
    return false;
}

std::vector<HttpRequest> parse_http_requests(const std::string& buf, size_t max_requests) {
    std::vector<HttpRequest> out;
    size_t pos = 0;
    while (out.size() < max_requests && pos < buf.size()) {
        size_t end = buf.find("\r\n\r\n", pos);
        if (end == std::string::npos) break;
        std::string block = buf.substr(pos, end - pos);
        if (!looks_like_http_request(block)) break;

        std::vector<std::pair<std::string, std::string>> headers;
        std::string first = parse_header_block(block, headers);
        HttpRequest req;
        size_t sp1 = first.find(' ');
        size_t sp2 = first.rfind(' ');
        req.method = first.substr(0, sp1);
        if (sp2 > sp1) req.uri = first.substr(sp1 + 1, sp2 - sp1 - 1);
        if (req.uri.size() > 512) req.uri.resize(512);
        for (auto& [name, value] : headers) {
            if (name == "host") req.host = value;
            else if (name == "user-agent") req.user_agent = value;
            else if (name == "content-type") req.content_type = value;
            else if (name == "content-length") req.content_length = std::strtoull(value.c_str(), nullptr, 10);
        }
        out.push_back(req);
        // Skip a declared request body so pipelined requests stay aligned.
        pos = end + 4 + static_cast<size_t>(std::min<uint64_t>(req.content_length, buf.size()));
    }
    return out;
}

std::optional<HttpResponse> parse_http_response(const std::string& buf) {
    if (buf.compare(0, 5, "HTTP/") != 0) return std::nullopt;
    size_t end = buf.find("\r\n\r\n");
    std::string block = buf.substr(0, end == std::string::npos ? std::min<size_t>(buf.size(), 4096) : end);
    std::vector<std::pair<std::string, std::string>> headers;
    std::string first = parse_header_block(block, headers);
    HttpResponse resp;
    size_t sp = first.find(' ');
    if (sp != std::string::npos) resp.status = std::atoi(first.c_str() + sp + 1);
    for (auto& [name, value] : headers) {
        if (name == "server") resp.server = value;
        else if (name == "content-type") resp.content_type = value;
        else if (name == "x-powered-by") resp.powered_by = value.substr(0, 128);
    }
    return resp;
}

// ------------------------------------------------------------------ TLS

bool looks_like_tls(const std::string& buf) {
    return buf.size() >= 3 && static_cast<uint8_t>(buf[0]) == 22 && static_cast<uint8_t>(buf[1]) == 3 &&
           static_cast<uint8_t>(buf[2]) <= 4;
}

std::optional<TlsClientHello> parse_tls_client_hello(const std::string& buf, bool dtls) {
    std::string hs;
    if (!looks_like_tls(buf) || !collect_handshake(buf, 1, hs)) return std::nullopt;

    Reader r(reinterpret_cast<const uint8_t*>(hs.data()), hs.size());
    r.u8();   // handshake type
    r.u24();  // length
    TlsClientHello ch;
    ch.version = r.u16();
    r.skip(32);              // random
    r.skip(r.u8());          // session id
    if (dtls) r.skip(r.u8());  // cookie

    std::vector<uint16_t> ciphers;
    Reader cs = r.sub(r.u16());
    while (cs.ok() && cs.remaining() >= 2) {
        uint16_t c = cs.u16();
        if (!is_grease(c)) ciphers.push_back(c);
    }
    r.skip(r.u8());          // compression methods
    if (!r.ok()) return std::nullopt;

    std::vector<uint16_t> extensions, curves, sig_algs;
    std::vector<uint16_t> point_formats;
    uint16_t best_version = 0;
    if (r.remaining() >= 2) {
        Reader exts = r.sub(r.u16());
        while (exts.ok() && exts.remaining() >= 4) {
            uint16_t type = exts.u16();
            Reader body = exts.sub(exts.u16());
            if (!exts.ok()) break;
            if (is_grease(type)) continue;
            extensions.push_back(type);
            switch (type) {
                case 0x0000: {  // server_name
                    Reader list = body.sub(body.u16());
                    while (list.ok() && list.remaining() >= 3) {
                        uint8_t name_type = list.u8();
                        uint16_t n = list.u16();
                        const uint8_t* p = list.bytes(n);
                        if (p && name_type == 0) {
                            ch.sni.assign(reinterpret_cast<const char*>(p), n);
                            break;
                        }
                    }
                    break;
                }
                case 0x000a: {  // supported_groups
                    Reader list = body.sub(body.u16());
                    while (list.ok() && list.remaining() >= 2) {
                        uint16_t g = list.u16();
                        if (!is_grease(g)) curves.push_back(g);
                    }
                    break;
                }
                case 0x000b: {  // ec_point_formats
                    Reader list = body.sub(body.u8());
                    while (list.ok() && list.remaining() >= 1) point_formats.push_back(list.u8());
                    break;
                }
                case 0x000d: {  // signature_algorithms
                    Reader list = body.sub(body.u16());
                    while (list.ok() && list.remaining() >= 2) {
                        uint16_t s = list.u16();
                        if (!is_grease(s)) sig_algs.push_back(s);
                    }
                    break;
                }
                case 0x0010: {  // ALPN
                    Reader list = body.sub(body.u16());
                    while (list.ok() && list.remaining() >= 1) {
                        uint8_t n = list.u8();
                        const uint8_t* p = list.bytes(n);
                        if (p) ch.alpn.emplace_back(reinterpret_cast<const char*>(p), n);
                    }
                    break;
                }
                case 0x002b: {  // supported_versions
                    Reader list = body.sub(body.u8());
                    while (list.ok() && list.remaining() >= 2) {
                        uint16_t v = list.u16();
                        if (!is_grease(v) && v > best_version) best_version = v;  // (DTLS too, as FoxIO's JA4 does)
                    }
                    break;
                }
                default:
                    break;
            }
        }
    }

    // JA3: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    ch.ja3 = std::to_string(ch.version) + "," + join_dec(ciphers) + "," + join_dec(extensions) + "," +
             join_dec(curves) + "," + join_dec(point_formats);
    ch.ja3_hash = md5_hex(ch.ja3);

    // JA4 (FoxIO spec): <t><ver><d|i><#ciphers><#exts><alpn>_<sha(ciphers)>_<sha(exts_sigalgs)>
    char counts[8];
    std::snprintf(counts, sizeof(counts), "%02zu%02zu", std::min<size_t>(ciphers.size(), 99),
                  std::min<size_t>(extensions.size(), 99));
    std::string ja4_a = std::string(dtls ? "d" : "t") + ja4_version(best_version ? best_version : ch.version) +
                        (ch.sni.empty() ? "i" : "d") + counts + ja4_alpn(ch.alpn);

    std::vector<uint16_t> sorted_ciphers = ciphers;
    std::sort(sorted_ciphers.begin(), sorted_ciphers.end());
    std::string ja4_b = sorted_ciphers.empty() ? "000000000000" : sha256_hex(join_hex(sorted_ciphers)).substr(0, 12);

    std::vector<uint16_t> sorted_exts;
    for (uint16_t e : extensions)
        if (e != 0x0000 && e != 0x0010) sorted_exts.push_back(e);
    std::sort(sorted_exts.begin(), sorted_exts.end());
    std::string c_input = join_hex(sorted_exts);
    if (!sig_algs.empty()) c_input += "_" + join_hex(sig_algs);
    std::string ja4_c = sorted_exts.empty() ? "000000000000" : sha256_hex(c_input).substr(0, 12);

    ch.ja4 = ja4_a + "_" + ja4_b + "_" + ja4_c;
    return ch;
}

std::optional<TlsServerHello> parse_tls_server_hello(const std::string& buf, bool dtls) {
    std::string hs;
    if (!looks_like_tls(buf) || !collect_handshake(buf, 2, hs)) return std::nullopt;
    Reader r(reinterpret_cast<const uint8_t*>(hs.data()), hs.size());
    r.u8();
    r.u24();
    TlsServerHello sh;
    sh.version = sh.legacy_version = r.u16();
    r.skip(32);
    r.skip(r.u8());
    sh.cipher = r.u16();
    r.u8();  // compression
    if (!r.ok()) return std::nullopt;
    std::vector<uint16_t> extensions;  // in the order the server sent them
    if (r.remaining() >= 2) {
        Reader exts = r.sub(r.u16());
        while (exts.ok() && exts.remaining() >= 4) {
            uint16_t type = exts.u16();
            Reader body = exts.sub(exts.u16());
            if (!exts.ok()) break;
            if (!is_grease(type)) extensions.push_back(type);
            if (type == 0x002b && body.remaining() >= 2) sh.version = body.u16();
            if (type == 0x0016) sh.etm = true;
            if (type == 0x0017) sh.ems = true;
            if (type == 0x0010 && body.remaining() >= 3) {  // ALPN: a list holding the chosen protocol
                Reader list = body.sub(body.u16());
                uint8_t n = list.u8();
                const uint8_t* p = list.bytes(n);
                if (p) sh.alpn.assign(reinterpret_cast<const char*>(p), n);
            }
        }
    }
    // JA3S: SSLVersion,Cipher,Extensions
    sh.ja3s = std::to_string(sh.legacy_version) + "," + std::to_string(sh.cipher) + "," + join_dec(extensions);
    sh.ja3s_hash = md5_hex(sh.ja3s);
    // JA4S: <t><version><#extensions><alpn>_<cipher>_<sha256(extensions, in order)>
    char a[16];
    std::snprintf(a, sizeof a, "%02zu", std::min<size_t>(extensions.size(), 99));
    char cipher[8];
    std::snprintf(cipher, sizeof cipher, "%04x", sh.cipher);
    std::vector<std::string> alpn;
    if (!sh.alpn.empty()) alpn.push_back(sh.alpn);
    sh.ja4s = std::string(dtls ? "d" : "t") + ja4_version(sh.version) + a + ja4_alpn(alpn) + "_" + cipher + "_" +
              (extensions.empty() ? "000000000000" : sha256_hex(join_hex(extensions)).substr(0, 12));
    return sh;
}

// ------------------------------------------------------------------ DTLS

bool DtlsHelloReader::on_datagram(const uint8_t* p, size_t len, bool from_client) {
    if (++datagrams_ > 64) return true;  // the hellos come first
    auto u16 = [&](size_t o) { return static_cast<uint32_t>((p[o] << 8) | p[o + 1]); };
    auto u24 = [&](size_t o) { return (static_cast<uint32_t>(p[o]) << 16) | u16(o + 1); };
    for (size_t pos = 0; pos + 13 <= len;) {
        uint8_t ct = p[pos];
        uint32_t ver = u16(pos + 1), epoch = u16(pos + 3), rlen = u16(pos + 11);
        if (ct < 20 || ct > 26 || (ver != 0xfeff && ver != 0xfefd && ver != 0x0100)) {
            return datagrams_ == 1 && pos == 0;  // a first datagram that isn't DTLS: give up
        }
        size_t body = pos + 13, end = std::min(len, body + rlen);
        if (ct == 22 && epoch == 0) {
            for (size_t o = body; o + 12 <= end;) {
                uint8_t t = p[o];
                uint32_t length = u24(o + 1), foff = u24(o + 6), flen = u24(o + 9);
                if (o + 12 + flen > end) break;
                if ((t == 1 && from_client) || (t == 2 && !from_client)) fragment(t - 1, p + o + 12, length, foff, flen);
                o += 12 + flen;
            }
        }
        pos = body + rlen;
    }
    return hello.has_value() && server_hello.has_value();
}

void DtlsHelloReader::fragment(int which, const uint8_t* f, uint32_t length, uint32_t offset, uint32_t flen) {
    Message& m = msg_[which];
    if ((which == 0 ? hello.has_value() : server_hello.has_value()) || length > 65000 ||  // (one TLS record)
        static_cast<uint64_t>(offset) + flen > length)
        return;
    if (m.length != length) {  // a new message (or the first)
        m = Message();
        m.length = length;
        m.data.assign(length, '\0');
    }
    std::memcpy(&m.data[offset], f, flen);
    m.have.emplace_back(offset, offset + flen);
    std::sort(m.have.begin(), m.have.end());
    uint32_t covered = 0;
    for (const auto& [a, b] : m.have) {
        if (a > covered) return;
        covered = std::max(covered, b);
    }
    if (covered < length) return;
    // As a TLS handshake record: type, length, then the body.
    std::string rec("\x16\x03\x03", 3);
    size_t mlen = 4 + static_cast<size_t>(length);
    rec.push_back(static_cast<char>((mlen >> 8) & 0xFF));
    rec.push_back(static_cast<char>(mlen & 0xFF));
    rec.push_back(static_cast<char>(which + 1));
    rec.push_back(static_cast<char>((length >> 16) & 0xFF));
    rec.push_back(static_cast<char>((length >> 8) & 0xFF));
    rec.push_back(static_cast<char>(length & 0xFF));
    rec += m.data;
    if (which == 0) hello = parse_tls_client_hello(rec, true);
    else server_hello = parse_tls_server_hello(rec, true);
    m = Message();
}

}  // namespace anta
