// Logins sent in clear text, like Wireshark's Tools > Credentials: which protocol, which
// account, and whether the server accepted it. Never the password: it is read only to
// know that one was sent, and dropped at once. What it is for: knowing which passwords
// crossed the network readable by anyone on the path, so they can be changed and the
// service moved to its encrypted form.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace anta {

struct CleartextLogin {
    std::string proto;         // FTP, POP, IMAP, SMTP, HTTP, LDAP, Telnet, SNMP
    std::string method;        // USER/PASS, AUTH PLAIN, AUTH LOGIN, LOGIN, Basic, form, simple bind, login prompt, community
    std::string user;          // the account name ("" when it isn't sent or can't be read)
    int8_t accepted = -1;      // 1 accepted, 0 refused, -1 not known
    bool anonymous = false;    // FTP's anonymous account, an LDAP bind with no name
    bool default_secret = false;  // SNMP's well-known "public" or "private" community
    uint64_t ts = 0;           // microseconds
};

class LoginTracker {
public:
    // The protocol a TCP connection to `port` speaks, if it is one logins are read from.
    static const char* proto_for_port(uint16_t port);
    explicit LoginTracker(std::string proto) : proto_(std::move(proto)) {}

    // One piece of a direction's reassembled stream, in order.
    void data(bool from_client, const uint8_t* p, size_t n, uint64_t ts_us);
    // An SNMP v1/v2c message (UDP): its community string, if it has one.
    void snmp(const uint8_t* p, size_t n, uint64_t ts_us);

    const std::string& proto() const { return proto_; }
    std::vector<CleartextLogin> logins;

private:
    void client_line(const std::string& line, uint64_t ts);
    void server_line(const std::string& line);
    void http_client_line(const std::string& line, uint64_t ts);
    void http_form(const std::string& body, uint64_t ts);
    void telnet(bool from_client, const uint8_t* p, size_t n, uint64_t ts);
    void ldap(bool from_client, uint64_t ts);
    size_t add(CleartextLogin l);
    void answer(int8_t accepted);

    std::string proto_;
    std::string line_[2];        // the unfinished line of each direction
    bool overlong_[2] = {false, false};
    uint64_t seen_[2] = {0, 0};  // bytes read per direction (reading stops after a while)
    enum class Expect : uint8_t { Nothing, AuthPlain, AuthLoginUser, AuthLoginPass };
    Expect expect_ = Expect::Nothing;
    std::string pending_user_;
    long awaiting_ = -1;         // the login waiting for the server's answer
    std::string imap_tag_;       // the tag of IMAP's LOGIN / AUTHENTICATE
    // HTTP: requests in order (a response answers the oldest), the form body being read.
    std::vector<long> http_requests_;
    bool http_headers_ = false, http_form_ = false;
    size_t http_length_ = 0;     // the request's Content-Length, until its headers end
    size_t http_body_left_ = 0;
    std::string http_body_;
    // LDAP: the client's and server's BER bytes; a bind's message ID names its login.
    std::string ber_[2];
    std::map<uint32_t, long> ldap_binds_;
    // Telnet: the server's latest text, whether it asked for a name or a password.
    std::string telnet_tail_;
    uint8_t telnet_ask_ = 0;     // 1 name, 2 password
    uint8_t telnet_iac_ = 0;     // inside an IAC sequence (bytes left to skip; 0xFF: subnegotiation)
};

}  // namespace anta
