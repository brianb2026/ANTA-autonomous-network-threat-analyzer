// Which application a flow carries, from the first bytes each side sent rather
// than from its port (deep packet inspection): SSH on port 80 is SSH, a web server
// on port 53 is HTTP. Signatures only look at the start of each direction, so they
// cost nothing per packet and never need the rest of the stream.
#pragma once

#include <cstdint>
#include <string>

namespace anta {

struct AppId {
    const char* name = "";   // short id: "ssh", "tls", "http", ... ("" when nothing matched)
    const char* label = "";  // how people write it: "SSH", "TLS", "HTTP"
};

// client/server: the first bytes the client and the server sent (up to kDpiHead).
AppId identify_app(uint8_t proto, const std::string& client, const std::string& server);

// The application normally found on a server port ("" when the port has no usual one).
const char* app_for_port(uint8_t proto, uint16_t port);

// True when `app` on `port` is what the port is for, or a known compatible variant
// (TLS on a port whose service upgrades to TLS, HTTP on a proxy port...).
bool app_fits_port(uint8_t proto, uint16_t port, const char* app);

constexpr size_t kDpiHead = 64;

}  // namespace anta
