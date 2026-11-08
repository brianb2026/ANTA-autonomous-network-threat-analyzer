#include "logins.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace anta {

namespace {

constexpr size_t kMaxLine = 4096;
constexpr size_t kMaxLogins = 16;
constexpr uint64_t kTextLimit = 256 * 1024;        // logins come early in a text protocol's session
constexpr uint64_t kHttpLimit = 16 * 1024 * 1024;  // HTTP sends credentials with any request
constexpr size_t kMaxForm = 8192;

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string upper(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

bool starts_with(const std::string& s, const char* prefix) { return s.compare(0, std::strlen(prefix), prefix) == 0; }

std::string base64_decode(const std::string& in) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=' || std::isspace(static_cast<unsigned char>(c))) continue;
        size_t v = chars.find(c);
        if (v == std::string::npos) return {};
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

// A printable account name (control characters dropped), at most 128 characters.
std::string clean_user(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (static_cast<unsigned char>(c) >= 0x20 && c != 0x7f) out.push_back(c);
        if (out.size() >= 128) break;
    }
    return out;
}

// The first word of `s` and the rest after it.
std::pair<std::string, std::string> split_word(const std::string& s) {
    size_t sp = s.find(' ');
    if (sp == std::string::npos) return {s, ""};
    size_t rest = s.find_first_not_of(' ', sp);
    return {s.substr(0, sp), rest == std::string::npos ? "" : s.substr(rest)};
}

// IMAP's first argument: a quoted string or an atom.
std::string imap_arg(const std::string& s) {
    if (s.empty()) return {};
    if (s[0] == '"') {
        std::string out;
        for (size_t i = 1; i < s.size(); ++i) {
            if (s[i] == '\\' && i + 1 < s.size()) out.push_back(s[++i]);
            else if (s[i] == '"') break;
            else out.push_back(s[i]);
        }
        return out;
    }
    if (s[0] == '{') return {};  // a literal: the name follows on its own line
    return split_word(s).first;
}

std::string url_decode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '+') out.push_back(' ');
        else if (s[i] == '%' && i + 2 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
                 std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
            out.push_back(static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16)));
            i += 2;
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

// A BER element at the start of `b`: its tag, the offset of its contents and their length.
bool ber(const std::string& b, size_t at, uint8_t& tag, size_t& off, size_t& len) {
    if (at + 2 > b.size()) return false;
    tag = static_cast<uint8_t>(b[at]);
    size_t l = static_cast<uint8_t>(b[at + 1]);
    off = at + 2;
    if (l & 0x80) {
        size_t n = l & 0x7f;
        if (n == 0 || n > 4 || off + n > b.size()) return false;
        l = 0;
        for (size_t i = 0; i < n; ++i) l = (l << 8) | static_cast<uint8_t>(b[off + i]);
        off += n;
    }
    len = l;
    return off + len <= b.size();
}

uint32_t ber_int(const std::string& b, size_t off, size_t len) {
    uint32_t v = 0;
    for (size_t i = 0; i < len && i < 4; ++i) v = (v << 8) | static_cast<uint8_t>(b[off + i]);
    return v;
}

}  // namespace

const char* LoginTracker::proto_for_port(uint16_t port) {
    switch (port) {
        case 21: return "FTP";
        case 23: return "Telnet";
        case 25: case 587: case 2525: return "SMTP";
        case 110: return "POP";
        case 143: return "IMAP";
        case 389: case 3268: return "LDAP";
        default: return nullptr;
    }
}

size_t LoginTracker::add(CleartextLogin l) {
    // The same account the same way again (HTTP Basic sends it with every request): one entry.
    for (size_t i = 0; i < logins.size(); ++i)
        if (logins[i].method == l.method && logins[i].user == l.user) return i;
    if (logins.size() >= kMaxLogins) return logins.size() - 1;
    l.proto = proto_;
    logins.push_back(std::move(l));
    return logins.size() - 1;
}

void LoginTracker::answer(int8_t accepted) {
    if (awaiting_ >= 0 && static_cast<size_t>(awaiting_) < logins.size()) {
        // Once accepted, a later refusal of a repeat doesn't undo it.
        if (logins[awaiting_].accepted != 1) logins[awaiting_].accepted = accepted;
    }
    awaiting_ = -1;
}

void LoginTracker::data(bool from_client, const uint8_t* p, size_t n, uint64_t ts) {
    int d = from_client ? 0 : 1;
    uint64_t limit = proto_ == "HTTP" ? kHttpLimit : kTextLimit;
    if (seen_[d] >= limit || !n) return;
    n = static_cast<size_t>(std::min<uint64_t>(n, limit - seen_[d]));
    seen_[d] += n;
    if (proto_ == "Telnet") return telnet(from_client, p, n, ts);
    if (proto_ == "LDAP") {
        if (ber_[d].size() + n <= 65536) ber_[d].append(reinterpret_cast<const char*>(p), n);
        return ldap(from_client, ts);
    }
    for (size_t i = 0; i < n; ++i) {
        if (from_client && http_body_left_) {  // an HTTP request's body: read raw, not as lines
            size_t take = std::min(http_body_left_, n - i);
            if (http_form_ && http_body_.size() < kMaxForm)
                http_body_.append(reinterpret_cast<const char*>(p + i), std::min(take, kMaxForm - http_body_.size()));
            http_body_left_ -= take;
            i += take - 1;
            if (!http_body_left_ && http_form_) {
                http_form(http_body_, ts);
                http_body_.clear();
                http_form_ = false;
            }
            continue;
        }
        char c = static_cast<char>(p[i]);
        std::string& line = line_[d];
        if (c == '\n') {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!overlong_[d]) {
                if (from_client) client_line(line, ts);
                else server_line(line);
            }
            line.clear();  // (a password on this line goes with it)
            overlong_[d] = false;
        } else if (line.size() < kMaxLine) {
            line.push_back(c);
        } else {
            overlong_[d] = true;
        }
    }
}

void LoginTracker::client_line(const std::string& line, uint64_t ts) {
    if (proto_ == "HTTP") return http_client_line(line, ts);
    // The continuation of an AUTH / AUTHENTICATE exchange: base64 lines ("*" cancels).
    if (expect_ != Expect::Nothing) {
        Expect e = expect_;
        expect_ = Expect::Nothing;
        if (line == "*") return;
        if (e == Expect::AuthPlain) {
            std::string dec = base64_decode(line);
            size_t a = dec.find('\0'), b = a == std::string::npos ? std::string::npos : dec.find('\0', a + 1);
            std::string user = b == std::string::npos ? "" : dec.substr(a + 1, b - a - 1);
            if (user.empty() && a != std::string::npos) user = dec.substr(0, a);
            CleartextLogin l;
            l.method = "AUTH PLAIN";
            l.user = clean_user(user);
            l.ts = ts;
            awaiting_ = static_cast<long>(add(l));
        } else if (e == Expect::AuthLoginUser) {
            pending_user_ = clean_user(base64_decode(line));
            expect_ = Expect::AuthLoginPass;
        } else {
            CleartextLogin l;
            l.method = "AUTH LOGIN";
            l.user = pending_user_;
            l.ts = ts;
            awaiting_ = static_cast<long>(add(l));
        }
        return;
    }
    std::string tag;
    std::string rest = line;
    if (proto_ == "IMAP") {
        auto [t, r] = split_word(line);
        tag = t;
        rest = r;
    }
    auto [word, arg] = split_word(rest);
    std::string cmd = upper(word);
    if ((proto_ == "FTP" || proto_ == "POP") && cmd == "USER") {
        pending_user_ = clean_user(arg);
    } else if ((proto_ == "FTP" || proto_ == "POP") && cmd == "PASS") {
        CleartextLogin l;
        l.method = "USER/PASS";
        l.user = pending_user_;
        std::string u = lower(pending_user_);
        l.anonymous = proto_ == "FTP" && (u == "anonymous" || u == "ftp");
        l.ts = ts;
        awaiting_ = static_cast<long>(add(l));
    } else if (proto_ == "IMAP" && cmd == "LOGIN") {
        CleartextLogin l;
        l.method = "LOGIN";
        l.user = clean_user(imap_arg(arg));
        l.ts = ts;
        imap_tag_ = tag;
        awaiting_ = static_cast<long>(add(l));
    } else if ((cmd == "AUTH" && (proto_ == "SMTP" || proto_ == "POP")) || (cmd == "AUTHENTICATE" && proto_ == "IMAP")) {
        auto [mech, initial] = split_word(arg);
        mech = upper(mech);
        imap_tag_ = tag;
        if (mech == "PLAIN") {
            expect_ = Expect::AuthPlain;
            if (!initial.empty() && initial != "=") client_line(initial, ts);
        } else if (mech == "LOGIN") {
            expect_ = Expect::AuthLoginUser;
            if (!initial.empty()) client_line(initial, ts);
        }
        // (CRAM-MD5, GSSAPI, NTLM, XOAUTH2 … don't send the password itself)
    }
}

void LoginTracker::server_line(const std::string& line) {
    if (proto_ == "HTTP") {
        if (!starts_with(line, "HTTP/1.") || line.size() < 12) return;
        int code = std::atoi(line.c_str() + 9);
        if (code < 100 || code >= 200) {  // (1xx are interim: the final answer follows)
            if (!http_requests_.empty()) {
                long idx = http_requests_.front();
                http_requests_.erase(http_requests_.begin());
                if (idx >= 0 && static_cast<size_t>(idx) < logins.size()) {
                    auto& l = logins[idx];
                    int8_t v = code == 401 || code == 403 ? 0 : (l.method == "Basic" && code < 400 ? 1 : -1);
                    if (l.accepted != 1) l.accepted = v;
                }
            }
        }
        return;
    }
    if (awaiting_ < 0) return;
    if (proto_ == "FTP") {
        if (starts_with(line, "230")) answer(1);
        else if (starts_with(line, "530") || starts_with(line, "5")) answer(0);
    } else if (proto_ == "POP") {
        if (starts_with(line, "+OK")) answer(1);
        else if (starts_with(line, "-ERR")) answer(0);
    } else if (proto_ == "IMAP") {
        if (imap_tag_.empty() || !starts_with(line, (imap_tag_ + " ").c_str())) return;
        std::string status = upper(split_word(line.substr(imap_tag_.size() + 1)).first);
        if (status == "OK") answer(1);
        else if (status == "NO" || status == "BAD") answer(0);
    } else if (proto_ == "SMTP") {
        if (starts_with(line, "235")) answer(1);
        else if (starts_with(line, "5")) answer(0);
    }
}

void LoginTracker::http_client_line(const std::string& line, uint64_t ts) {
    if (!http_headers_) {
        static const char* kMethods[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "PROPFIND ", "CONNECT "};
        if (line.find(" HTTP/1.") == std::string::npos ||
            std::none_of(std::begin(kMethods), std::end(kMethods), [&](const char* m) { return starts_with(line, m); }))
            return;
        http_headers_ = true;
        http_form_ = false;
        http_length_ = 0;
        http_body_left_ = 0;
        http_requests_.push_back(-1);
        if (http_requests_.size() > 256) http_requests_.erase(http_requests_.begin());
        return;
    }
    if (line.empty()) {  // end of the headers: a body may follow
        http_headers_ = false;
        http_body_left_ = http_length_;
        http_length_ = 0;
        if (!http_body_left_) http_form_ = false;
        return;
    }
    size_t colon = line.find(':');
    if (colon == std::string::npos) return;
    std::string name = lower(line.substr(0, colon));
    std::string value = line.substr(colon + 1);
    value.erase(0, value.find_first_not_of(" \t"));
    if (name == "authorization" || name == "proxy-authorization") {
        auto [scheme, cred] = split_word(value);
        if (lower(scheme) == "basic") {
            std::string dec = base64_decode(cred);
            size_t c = dec.find(':');
            CleartextLogin l;
            l.method = name == "authorization" ? "Basic" : "Basic (proxy)";
            l.user = clean_user(c == std::string::npos ? dec : dec.substr(0, c));
            l.ts = ts;
            long idx = static_cast<long>(add(l));
            if (!http_requests_.empty()) http_requests_.back() = idx;
        }
    } else if (name == "content-type") {
        http_form_ = lower(value).find("application/x-www-form-urlencoded") != std::string::npos;
    } else if (name == "content-length") {
        long long len = std::atoll(value.c_str());
        http_length_ = len > 0 ? static_cast<size_t>(std::min<long long>(len, 1 << 20)) : 0;
    }
}

void LoginTracker::http_form(const std::string& body, uint64_t ts) {
    static const char* kPassword[] = {"password", "passwd", "pass", "pwd", "pw", "pswd", "passwort", "j_password",
                                      "login_password", "user_password", "userpassword"};
    static const char* kUser[] = {"username", "user", "login", "email", "uname", "user_name", "userid", "j_username",
                                  "log", "login_name", "account"};
    bool has_password = false;
    std::string user;
    size_t pos = 0;
    while (pos <= body.size()) {
        size_t amp = body.find('&', pos);
        if (amp == std::string::npos) amp = body.size();
        std::string pair = body.substr(pos, amp - pos);
        size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            std::string key = lower(url_decode(pair.substr(0, eq)));
            bool value_given = eq + 1 < pair.size();
            if (value_given && (std::any_of(std::begin(kPassword), std::end(kPassword), [&](const char* k) { return key == k; }) ||
                                key.find("password") != std::string::npos))
                has_password = true;  // (its value is never kept)
            else if (user.empty() && std::any_of(std::begin(kUser), std::end(kUser), [&](const char* k) { return key == k; }))
                user = url_decode(pair.substr(eq + 1));
        }
        pos = amp + 1;
    }
    if (!has_password) return;
    CleartextLogin l;
    l.method = "form";
    l.user = clean_user(user);
    l.ts = ts;
    long idx = static_cast<long>(add(l));
    if (!http_requests_.empty()) http_requests_.back() = idx;
}

void LoginTracker::ldap(bool from_client, uint64_t ts) {
    std::string& b = ber_[from_client ? 0 : 1];
    for (;;) {
        uint8_t tag;
        size_t off, len;
        if (b.empty()) return;
        if (static_cast<uint8_t>(b[0]) != 0x30) {  // (not plain LDAP: SASL-wrapped or TLS after StartTLS)
            b.clear();
            seen_[from_client ? 0 : 1] = kTextLimit;
            return;
        }
        if (!ber(b, 0, tag, off, len)) return;  // the rest of the message is still to come
        size_t end = off + len;
        uint8_t t2, t3;
        size_t o2, l2, o3, l3;
        if (ber(b, off, t2, o2, l2) && t2 == 0x02 && ber(b, o2 + l2, t3, o3, l3)) {
            uint32_t id = ber_int(b, o2, l2);
            if (from_client && t3 == 0x60) {  // BindRequest: version, name, authentication
                uint8_t tv, tn, ta;
                size_t ov, lv, on, ln, oa, la;
                if (ber(b, o3, tv, ov, lv) && ber(b, ov + lv, tn, on, ln) && tn == 0x04 &&
                    ber(b, on + ln, ta, oa, la) && ta == 0x80 && la > 0) {  // simple, with a password
                    CleartextLogin l;
                    l.method = "simple bind";
                    l.user = clean_user(b.substr(on, ln));
                    l.anonymous = ln == 0;
                    l.ts = ts;
                    ldap_binds_[id] = static_cast<long>(add(l));
                }
            } else if (!from_client && t3 == 0x61) {  // BindResponse: resultCode first
                uint8_t tr;
                size_t orc, lr;
                auto it = ldap_binds_.find(id);
                if (it != ldap_binds_.end() && ber(b, o3, tr, orc, lr) && tr == 0x0a && it->second >= 0 &&
                    static_cast<size_t>(it->second) < logins.size()) {
                    logins[it->second].accepted = ber_int(b, orc, lr) == 0 ? 1 : 0;
                    ldap_binds_.erase(it);
                }
            }
        }
        b.erase(0, end);
    }
}

void LoginTracker::telnet(bool from_client, const uint8_t* p, size_t n, uint64_t ts) {
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = p[i];
        // Skip the option negotiation (IAC sequences) on either side.
        if (telnet_iac_ == 0xFF) {  // subnegotiation: until IAC SE
            if (c == 0xFF && i + 1 < n && p[i + 1] == 0xF0) { ++i; telnet_iac_ = 0; }
            continue;
        }
        if (telnet_iac_) {
            if (telnet_iac_ == 2 && c == 0xFA) { telnet_iac_ = 0xFF; continue; }
            if (telnet_iac_ == 2 && c >= 0xFB && c <= 0xFE) { telnet_iac_ = 1; continue; }
            telnet_iac_ = 0;
            if (c != 0xFF) continue;  // (IAC IAC is a literal 0xFF)
        } else if (c == 0xFF) {
            telnet_iac_ = 2;
            continue;
        }
        if (!from_client) {
            telnet_tail_.push_back(static_cast<char>(std::tolower(c)));
            if (telnet_tail_.size() > 64) telnet_tail_.erase(0, telnet_tail_.size() - 64);
            auto ends = [&](const char* s) {
                std::string t = telnet_tail_;
                while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) t.pop_back();
                size_t k = std::strlen(s);
                return t.size() >= k && t.compare(t.size() - k, k, s) == 0;
            };
            if (ends("login:") || ends("username:") || ends("user name:")) telnet_ask_ = 1;
            else if (ends("password:")) telnet_ask_ = 2;
            if (awaiting_ >= 0) {
                if (telnet_tail_.find("incorrect") != std::string::npos || telnet_tail_.find("failed") != std::string::npos ||
                    telnet_tail_.find("denied") != std::string::npos || telnet_tail_.find("invalid") != std::string::npos)
                    answer(0);
                else if (telnet_tail_.find("last login") != std::string::npos || telnet_tail_.find("welcome") != std::string::npos)
                    answer(1);
            }
            continue;
        }
        std::string& line = line_[0];
        if (c == '\r' || c == '\n' || c == 0) {
            if (!line.empty() || telnet_ask_ == 2) {
                if (telnet_ask_ == 1) {
                    pending_user_ = clean_user(line);
                } else if (telnet_ask_ == 2) {
                    CleartextLogin l;
                    l.method = "login prompt";
                    l.user = pending_user_;
                    l.ts = ts;
                    awaiting_ = static_cast<long>(add(l));
                    telnet_tail_.clear();
                }
                telnet_ask_ = 0;
            }
            line.clear();  // (the password typed goes with it)
        } else if (c == 0x08 || c == 0x7F) {
            if (!line.empty()) line.pop_back();
        } else if (c >= 0x20 && line.size() < 256) {
            line.push_back(static_cast<char>(c));
        }
    }
}

void LoginTracker::snmp(const uint8_t* p, size_t n, uint64_t ts) {
    if (!logins.empty() || n < 8) return;
    std::string b(reinterpret_cast<const char*>(p), std::min<size_t>(n, 512));
    uint8_t tag;
    size_t off, len;
    if (b.empty() || static_cast<uint8_t>(b[0]) != 0x30) return;
    // (the message may be cut short at 512 bytes: only its start is needed)
    size_t o = (static_cast<uint8_t>(b[1]) & 0x80) ? 2 + (static_cast<uint8_t>(b[1]) & 0x7f) : 2;
    uint8_t tv, tc;
    size_t ov, lv, oc, lc;
    (void)tag; (void)off; (void)len;
    if (!ber(b, o, tv, ov, lv) || tv != 0x02 || lv != 1) return;
    uint32_t version = static_cast<uint8_t>(b[ov]);
    if (version > 1) return;  // v1 and v2c carry a community; v3 doesn't
    if (!ber(b, ov + lv, tc, oc, lc) || tc != 0x04 || lc == 0) return;
    std::string community = b.substr(oc, lc);
    CleartextLogin l;
    l.method = "community";
    l.default_secret = community == "public" || community == "private";
    l.ts = ts;
    add(l);  // (the community itself is never kept)
}

}  // namespace anta
