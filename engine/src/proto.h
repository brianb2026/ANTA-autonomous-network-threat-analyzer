// Application-layer metadata extraction: DNS, HTTP/1.x, TLS ClientHello (JA3/JA4).
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace anta {

struct DnsMessage {
    uint16_t txid = 0;
    bool is_response = false;
    uint8_t rcode = 0;
    std::string qname;
    uint16_t qtype = 0;
    std::vector<std::string> answers;  // A/AAAA/CNAME/PTR rendered as text
    uint32_t txt_bytes = 0;            // total TXT RDATA bytes in the answer section
    uint16_t answer_count = 0;
};

struct HttpRequest {
    std::string method;
    std::string uri;
    std::string host;
    std::string user_agent;
    std::string content_type;
    uint64_t content_length = 0;
};

struct HttpResponse {
    int status = 0;
    std::string server;
    std::string content_type;
    std::string powered_by;  // X-Powered-By (PHP/7.4.3, Express): software and version
};

struct TlsClientHello {
    uint16_t version = 0;         // legacy_version from the handshake
    std::string sni;
    std::vector<std::string> alpn;
    std::string ja3;              // the full JA3 string
    std::string ja3_hash;         // md5(ja3)
    std::string ja4;              // JA4 (TCP variant)
};

struct TlsServerHello {
    uint16_t version = 0;         // negotiated version (supported_versions wins)
    uint16_t legacy_version = 0;  // the version field of the ServerHello itself
    uint16_t cipher = 0;
    std::string alpn;             // the protocol the server chose
    bool etm = false;             // encrypt-then-MAC accepted (RFC 7366: CBC records MAC their ciphertext)
    bool ems = false;             // extended master secret (RFC 7627: the master hashes the handshake)
    // The server's fingerprints: JA3S (Salesforce) and JA4S (FoxIO). Together with the
    // client's JA3/JA4 they identify a client/server pair (a C2 framework's defaults)
    // without decrypting anything.
    std::string ja3s, ja3s_hash, ja4s;
};

// Decode a (possibly compressed) DNS name at `off`; `next` is set past it (pointers not followed).
bool read_dns_name(const uint8_t* msg, size_t len, size_t off, std::string& name, size_t& next);

// DNS wire message (UDP payload, or one TCP message with the length prefix stripped).
std::optional<DnsMessage> parse_dns(const uint8_t* data, size_t len);

// Parse every complete HTTP/1.x request header block in `buf`.
std::vector<HttpRequest> parse_http_requests(const std::string& buf, size_t max_requests);
std::optional<HttpResponse> parse_http_response(const std::string& buf);

// `buf` is the start of the client->server byte stream. `dtls`: the hello came over DTLS
// (its handshake message, wrapped in a TLS record): the Client Hello carries a cookie, and
// JA4/JA4S start with "d" and name DTLS versions (d1, d2, d3).
std::optional<TlsClientHello> parse_tls_client_hello(const std::string& buf, bool dtls = false);
std::optional<TlsServerHello> parse_tls_server_hello(const std::string& buf, bool dtls = false);

bool looks_like_http_request(const std::string& buf);
bool looks_like_tls(const std::string& buf);

// The Client and Server Hello of a DTLS session (RFC 6347), read from its datagrams: the
// plaintext handshake records of epoch 0, each hello reassembled from its fragments. Like
// the TLS hellos they give the server name and the JA3/JA4 fingerprints (JA4 "d").
class DtlsHelloReader {
public:
    // One UDP payload. True once both hellos are read, or the flow isn't DTLS.
    bool on_datagram(const uint8_t* p, size_t len, bool from_client);
    std::optional<TlsClientHello> hello;
    std::optional<TlsServerHello> server_hello;

private:
    struct Message {
        uint32_t length = 0;
        std::string data;
        std::vector<std::pair<uint32_t, uint32_t>> have;  // byte ranges received
    };
    void fragment(int which, const uint8_t* f, uint32_t length, uint32_t offset, uint32_t flen);
    Message msg_[2];  // the Client Hello, the Server Hello
    int datagrams_ = 0;
};

}  // namespace anta
