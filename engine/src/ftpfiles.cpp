#include "ftpfiles.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace anta {

namespace {

constexpr size_t kMaxLine = 4096;
constexpr size_t kMaxCommands = 64;

std::string upper(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

// "h1,h2,h3,h4,p1,p2" (PORT, and inside a 227 reply) -> address and port.
bool parse_hostport(const std::string& s, IpAddr& ip, uint16_t& port) {
    unsigned v[6];
    size_t start = s.find_first_of("0123456789");
    if (start == std::string::npos) return false;
    if (std::sscanf(s.c_str() + start, "%u,%u,%u,%u,%u,%u", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return false;
    for (unsigned x : v)
        if (x > 255) return false;
    ip = IpAddr();
    ip.family = 4;
    for (int i = 0; i < 4; ++i) ip.bytes[i] = static_cast<uint8_t>(v[i]);
    port = static_cast<uint16_t>(v[4] * 256 + v[5]);
    return port != 0;
}

// "|1|10.0.0.5|5282|" (EPRT) or "(|||5282|)" (229): the port, and the address if present.
bool parse_extended(const std::string& s, IpAddr& ip, bool& has_ip, uint16_t& port) {
    size_t a = s.find('|');
    if (a == std::string::npos) return false;
    char d = '|';
    std::vector<std::string> parts;
    size_t pos = a + 1;
    for (int i = 0; i < 3; ++i) {
        size_t e = s.find(d, pos);
        if (e == std::string::npos) return false;
        parts.push_back(s.substr(pos, e - pos));
        pos = e + 1;
    }
    unsigned long p = std::strtoul(parts[2].c_str(), nullptr, 10);
    if (p == 0 || p > 65535) return false;
    port = static_cast<uint16_t>(p);
    has_ip = false;
    if (parts[0] == "1" && !parts[1].empty()) {
        unsigned b[4];
        if (std::sscanf(parts[1].c_str(), "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]) == 4 && b[0] < 256 &&
            b[1] < 256 && b[2] < 256 && b[3] < 256) {
            ip = IpAddr();
            ip.family = 4;
            for (int i = 0; i < 4; ++i) ip.bytes[i] = static_cast<uint8_t>(b[i]);
            has_ip = true;
        }
    }
    return true;
}

}  // namespace

void FtpDataSide::add(const uint8_t* p, size_t n) {
    hash.update(p, n);
    bytes += n;
    if (head.size() < kKeep) head.append(reinterpret_cast<const char*>(p), std::min(n, kKeep - head.size()));
}

FtpControl::FtpControl(const IpAddr& client, uint16_t client_port, const IpAddr& server, uint16_t server_port)
    : client_(client), server_(server) {
    desc_ = client.str() + ":" + std::to_string(client_port) + " -> " + server.str() + ":" + std::to_string(server_port);
}

void FtpControl::on_data(bool from_client, const uint8_t* p, size_t n, std::vector<FtpExpect>& expect) {
    std::string& b = buf_[from_client ? 0 : 1];
    for (size_t i = 0; i < n; ++i) {
        char c = static_cast<char>(p[i]);
        if (c == '\n') {
            if (!b.empty() && b.back() == '\r') b.pop_back();
            line(from_client, b, expect);
            b.clear();
        } else if (b.size() < kMaxLine) {
            b.push_back(c);
        }
    }
}

std::shared_ptr<FtpTransfer> FtpControl::next() {
    if (!current_) {
        current_ = std::make_shared<FtpTransfer>();
        current_->user = user;
        current_->control = desc_;
        current_->tls_refused = tls_refused;
    }
    return current_;
}

void FtpControl::announce(const IpAddr* announced, uint16_t port, bool active, std::vector<FtpExpect>& expect) {
    current_.reset();  // a new PORT/PASV starts the next transfer
    auto t = next();
    t->active = active;
    // Active: the server connects to the client; passive: the client to the server.
    // The connection's real address is expected as well as the announced one (NAT).
    const IpAddr& own = active ? client_ : server_;
    const IpAddr& peer = active ? server_ : client_;
    expect.push_back({own, port, peer, t});
    if (announced && !(*announced == own)) expect.push_back({*announced, port, peer, t});
}

void FtpControl::line(bool from_client, const std::string& text, std::vector<FtpExpect>& expect) {
    if (from_client) {
        size_t sp = text.find(' ');
        std::string cmd = upper(text.substr(0, sp));
        std::string arg = sp == std::string::npos ? "" : text.substr(sp + 1);
        if (cmd.empty() || cmd.size() > 8) return;
        if (commands.size() < kMaxCommands) commands.push_back(cmd == "PASS" ? "PASS ***" : text.substr(0, 512));
        if (cmd == "USER") {
            user = arg.substr(0, 256);
        } else if (cmd == "AUTH" && upper(arg).rfind("TLS", 0) == 0) {
            auth_tls_asked_ = true;
        } else if (cmd == "PORT") {
            IpAddr ip;
            uint16_t port = 0;
            if (parse_hostport(arg, ip, port)) announce(&ip, port, true, expect);
        } else if (cmd == "EPRT") {
            IpAddr ip;
            bool has_ip = false;
            uint16_t port = 0;
            if (parse_extended(arg, ip, has_ip, port)) announce(has_ip ? &ip : nullptr, port, true, expect);
        } else if (cmd == "STOR" || cmd == "APPE" || cmd == "STOU" || cmd == "RETR" || cmd == "LIST" ||
                   cmd == "NLST" || cmd == "MLSD") {
            auto t = next();
            if (t->command.empty()) {
                t->command = cmd;
                t->name = arg.substr(0, 1024);
                t->user = user;
                t->tls_refused = tls_refused;
            }
        }
        return;
    }
    if (text.size() < 3 || !std::isdigit(static_cast<unsigned char>(text[0]))) return;
    int code = std::atoi(text.substr(0, 3).c_str());
    bool last = text.size() == 3 || text[3] == ' ';  // the final line of a multi-line reply
    if (code == 227) {
        IpAddr ip;
        uint16_t port = 0;
        size_t open = text.find('(');
        if (parse_hostport(open == std::string::npos ? text.substr(4) : text.substr(open + 1), ip, port))
            announce(&ip, port, false, expect);
    } else if (code == 229) {
        IpAddr ip;
        bool has_ip = false;
        uint16_t port = 0;
        if (parse_extended(text, ip, has_ip, port)) announce(has_ip ? &ip : nullptr, port, false, expect);
    } else if (last && auth_tls_asked_) {
        tls_refused = code >= 400;  // the reply to AUTH TLS; a 234 means what follows is encrypted
        auth_tls_asked_ = false;
    } else if (last && current_ && !current_->command.empty() && (code == 226 || code == 250 || code >= 425)) {
        current_->reply = text.substr(0, 256);  // the transfer's outcome
        current_.reset();
    }
}

}  // namespace anta
