#include "dpi.h"

#include <cctype>
#include <cstring>

namespace anta {

namespace {

const uint8_t* bytes(const std::string& s) { return reinterpret_cast<const uint8_t*>(s.data()); }

bool starts(const std::string& s, const char* prefix) {
    size_t n = std::strlen(prefix);
    return s.size() >= n && s.compare(0, n, prefix) == 0;
}

bool starts_ci(const std::string& s, const char* prefix) {
    size_t n = std::strlen(prefix);
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; ++i)
        if (std::tolower(static_cast<unsigned char>(s[i])) != std::tolower(static_cast<unsigned char>(prefix[i]))) return false;
    return true;
}

bool contains_ci(const std::string& s, const char* needle) {
    std::string low = s;
    for (auto& c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return low.find(needle) != std::string::npos;
}

// An HTTP/1.x request line: METHOD SP target.
bool http_request(const std::string& s) {
    static const char* methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ",
                                    "PROPFIND ", "PROPPATCH ", "MKCOL ", "COPY ", "MOVE ", "LOCK ", "UNLOCK ",
                                    "REPORT ", "SEARCH ", "SUBSCRIBE ", "MKCALENDAR "};
    for (const char* m : methods) {
        if (!starts(s, m)) continue;
        size_t n = std::strlen(m);
        return s.size() > n && (s[n] == '/' || s[n] == '*' || starts_ci(s.substr(n), "http"));
    }
    return false;
}

bool tls_record(const std::string& s, uint8_t handshake_type) {
    const uint8_t* p = bytes(s);
    return s.size() >= 6 && p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x04 && p[5] == handshake_type;
}

AppId tcp_app(const std::string& c, const std::string& s) {
    const uint8_t* cp = bytes(c);
    const uint8_t* sp = bytes(s);
    // Encrypted transports first: they say what they are in their first record.
    if (tls_record(c, 0x01) || tls_record(s, 0x02)) return {"tls", "TLS"};
    if (c.size() >= 4 && (cp[0] & 0x80) && cp[2] == 0x01 && (cp[3] == 0x03 || cp[3] == 0x00 || cp[3] == 0x02))
        return {"tls", "SSLv2"};
    if (starts(c, "SSH-") || starts(s, "SSH-")) return {"ssh", "SSH"};
    // Web.
    if (starts(c, "CONNECT ")) return {"http-proxy", "HTTP proxy (CONNECT)"};
    if (http_request(c)) return {"http", "HTTP"};
    if (starts(s, "HTTP/1.") || starts(s, "HTTP/2")) return {"http", "HTTP"};
    if (starts(c, "PRI * HTTP/2.0")) return {"http2", "HTTP/2 (cleartext)"};
    if (starts(c, "OPTIONS rtsp://") || starts(c, "DESCRIBE rtsp://") || starts(s, "RTSP/1.0")) return {"rtsp", "RTSP"};
    if (starts(c, "INVITE sip:") || starts(c, "REGISTER sip:") || starts(c, "OPTIONS sip:") || starts(s, "SIP/2.0 "))
        return {"sip", "SIP"};
    // Windows and remote access.
    if (c.size() >= 8 && cp[0] == 0x00 && (cp[5] == 'S' && cp[6] == 'M' && cp[7] == 'B') &&
        (cp[4] == 0xfe || cp[4] == 0xff || cp[4] == 0xfd))
        return {"smb", "SMB"};
    if (c.size() >= 6 && cp[0] == 0x03 && cp[1] == 0x00 && cp[5] == 0xe0) return {"rdp", "RDP"};
    if (starts(s, "RFB 00")) return {"vnc", "VNC"};
    if (c.size() >= 3 && cp[0] == 0x05 && cp[1] == 0x00 && cp[2] == 0x0b) return {"dcerpc", "DCE/RPC"};
    if (c.size() >= 2 && cp[0] == 0xff && cp[1] >= 0xfb && cp[1] <= 0xfe) return {"telnet", "Telnet"};
    if (s.size() >= 2 && sp[0] == 0xff && sp[1] >= 0xfb && sp[1] <= 0xfe) return {"telnet", "Telnet"};
    // Proxies and tunnels.
    if (c.size() >= 3 && cp[0] == 0x05 && cp[1] >= 1 && cp[1] <= 9 && s.size() >= 2 && sp[0] == 0x05 &&
        (sp[1] == 0x00 || sp[1] == 0x01 || sp[1] == 0x02 || sp[1] == 0xff))
        return {"socks", "SOCKS5"};
    if (c.size() >= 9 && cp[0] == 0x04 && (cp[1] == 0x01 || cp[1] == 0x02) && s.size() >= 2 && sp[0] == 0x00 &&
        sp[1] >= 0x5a && sp[1] <= 0x5d)
        return {"socks", "SOCKS4"};
    if (c.size() >= 3 && ((cp[2] >> 3) == 7 || (cp[2] >> 3) == 10) && (static_cast<size_t>(cp[0]) << 8 | cp[1]) >= 14 &&
        (static_cast<size_t>(cp[0]) << 8 | cp[1]) <= 1600 && s.size() >= 3 && ((sp[2] >> 3) == 8))
        return {"openvpn", "OpenVPN"};
    if (c.size() >= 20 && cp[0] == 0x13 && std::memcmp(cp + 1, "BitTorrent protocol", 19) == 0)
        return {"bittorrent", "BitTorrent"};
    // Mail and file transfer: the server speaks first.
    if (starts(s, "+OK")) return {"pop3", "POP3"};
    if (starts(s, "* OK") || starts(s, "* PREAUTH")) return {"imap", "IMAP"};
    if (s.size() >= 4 && starts(s, "220") && (s[3] == ' ' || s[3] == '-')) {
        // The client's first command says it best; else the greeting's own first line (a later
        // reply such as FTP's "331 Send email" must not make it mail).
        if (starts_ci(c, "EHLO") || starts_ci(c, "HELO")) return {"smtp", "SMTP"};
        if (starts_ci(c, "USER") || starts_ci(c, "AUTH TLS") || starts_ci(c, "FEAT") || starts_ci(c, "OPTS"))
            return {"ftp", "FTP"};
        const std::string banner = s.substr(0, s.find('\n'));
        if (contains_ci(banner, "smtp")) return {"smtp", "SMTP"};
        if (contains_ci(banner, "ftp")) return {"ftp", "FTP"};
        if (contains_ci(banner, "mail")) return {"smtp", "SMTP"};
        return {"ftp-or-smtp", "FTP or SMTP"};
    }
    // Databases.
    if (s.size() >= 6 && sp[3] == 0x00 && sp[4] == 0x0a && std::isdigit(sp[5]) &&
        (static_cast<size_t>(sp[0]) | static_cast<size_t>(sp[1]) << 8 | static_cast<size_t>(sp[2]) << 16) < 1024)
        return {"mysql", "MySQL"};
    if (c.size() >= 8 && cp[4] == 0x00 && cp[5] == 0x03 && cp[6] == 0x00 && cp[7] == 0x00) return {"postgresql", "PostgreSQL"};
    if (c.size() >= 8 && cp[0] == 0 && cp[1] == 0 && cp[2] == 0 && cp[3] == 8 && cp[4] == 0x04 && cp[5] == 0xd2 &&
        cp[6] == 0x16 && cp[7] == 0x2f)
        return {"postgresql", "PostgreSQL"};
    if (c.size() >= 8 && cp[0] == 0x12 && cp[1] == 0x01 && cp[2] == 0x00) return {"mssql", "Microsoft SQL (TDS)"};
    if (c.size() >= 16 && cp[8] == 0 && cp[9] == 0 && cp[10] == 0 && cp[11] == 0 &&
        ((cp[12] == 0xdd && cp[13] == 0x07) || (cp[12] == 0xd4 && cp[13] == 0x07)) && cp[14] == 0 && cp[15] == 0)
        return {"mongodb", "MongoDB"};
    if (c.size() >= 4 && cp[0] == '*' && std::isdigit(cp[1]) && (starts(c.substr(2), "\r\n$") || starts(c.substr(3), "\r\n$")))
        return {"redis", "Redis"};
    // Messaging, chat, IoT.
    if (c.size() >= 10 && cp[0] == 0x10 &&
        (std::memcmp(cp + 2, "\x00\x04MQTT", 6) == 0 || std::memcmp(cp + 3, "\x00\x04MQTT", 6) == 0 ||
         std::memcmp(cp + 2, "\x00\x06MQIsdp", 8) == 0))
        return {"mqtt", "MQTT"};
    if (starts(c, "NICK ") || starts(c, "CAP LS") || (starts(c, "USER ") && !starts(s, "220")) ||
        (s.size() > 2 && sp[0] == ':' && contains_ci(s, " notice ")))
        return {"irc", "IRC"};
    if ((starts(c, "<?xml") || starts(c, "<stream:stream")) && contains_ci(c, "stream")) return {"xmpp", "XMPP"};
    // Directory and authentication.
    if (c.size() >= 8 && cp[0] == 0x30) {  // LDAPMessage: SEQUENCE { messageID INTEGER, protocolOp }
        size_t i = 2 + ((cp[1] & 0x80) ? (cp[1] & 0x7f) : 0);
        if (i + 2 < c.size() && cp[i] == 0x02 && cp[i + 1] >= 1 && cp[i + 1] <= 4 && i + 2 + cp[i + 1] < c.size()) {
            uint8_t op = cp[i + 2 + cp[i + 1]];
            if (op == 0x60 || op == 0x63 || op == 0x77 || op == 0x42) return {"ldap", "LDAP"};
        }
    }
    if (c.size() >= 6 && cp[0] == 0 && (cp[4] == 0x6a || cp[4] == 0x6c) && (cp[5] == 0x81 || cp[5] == 0x82))
        return {"kerberos", "Kerberos"};
    // DNS over TCP: a 2-byte length, then a plausible header with one question.
    if (c.size() >= 14) {
        size_t len = static_cast<size_t>(cp[0]) << 8 | cp[1];
        uint16_t flags = static_cast<uint16_t>(cp[4] << 8 | cp[5]);
        uint16_t qd = static_cast<uint16_t>(cp[6] << 8 | cp[7]);
        if (len >= 17 && len < 2048 && !(flags & 0x8000) && ((flags >> 11) & 0xF) == 0 && qd == 1 && cp[8] == 0 &&
            cp[9] == 0)
            return {"dns", "DNS"};
    }
    return {};
}

AppId udp_app(const std::string& c, const std::string& s) {
    const uint8_t* cp = bytes(c);
    const uint8_t* sp = bytes(s);
    if (c.size() >= 5 && (cp[0] & 0xc0) == 0xc0) {
        uint32_t v = static_cast<uint32_t>(cp[1]) << 24 | static_cast<uint32_t>(cp[2]) << 16 |
                     static_cast<uint32_t>(cp[3]) << 8 | cp[4];
        if (v == 0x00000001 || v == 0x6b3343cf || (v & 0xffffff00) == 0xff000000 || v == 0)
            return {"quic", "QUIC"};
    }
    if (c.size() >= 3 && cp[0] == 0x16 && cp[1] == 0xfe && (cp[2] == 0xfd || cp[2] == 0xff)) return {"dtls", "DTLS"};
    if (c.size() >= 8 && cp[4] == 0x21 && cp[5] == 0x12 && cp[6] == 0xa4 && cp[7] == 0x42 && cp[0] < 0x40)
        return {"stun", "STUN"};
    if (c.size() >= 4 && cp[0] >= 1 && cp[0] <= 4 && cp[1] == 0 && cp[2] == 0 && cp[3] == 0) return {"wireguard", "WireGuard"};
    // OpenVPN: the client's hard reset (opcode 7 or 10) answered by the server's (opcode 8).
    // Both are needed: a DNS ID can start with the same byte, and its answer echoes it.
    if (c.size() >= 14 && ((cp[0] >> 3) == 7 || (cp[0] >> 3) == 10) && s.size() >= 14 && (sp[0] >> 3) == 8)
        return {"openvpn", "OpenVPN"};
    if (starts(c, "M-SEARCH * HTTP/1.1") || starts(c, "NOTIFY * HTTP/1.1")) return {"ssdp", "SSDP"};
    if (starts(c, "INVITE sip:") || starts(c, "REGISTER sip:") || starts(c, "OPTIONS sip:") || starts(c, "SIP/2.0 "))
        return {"sip", "SIP"};
    if (c.size() >= 4 && cp[0] == '<' && std::isdigit(cp[1])) {
        size_t i = 1;
        while (i < c.size() && i < 5 && std::isdigit(cp[i])) ++i;
        if (i < c.size() && cp[i] == '>') return {"syslog", "syslog"};
    }
    if (c.size() >= 7 && cp[0] == 0x30 && cp[2] == 0x02 && cp[3] == 0x01 && cp[4] <= 3 && cp[5] == 0x04)
        return {"snmp", "SNMP"};
    if (c.size() >= 4 && cp[0] == 0 && (cp[1] == 1 || cp[1] == 2) && std::isprint(cp[2])) {
        // TFTP read/write request: opcode, file name, NUL, mode.
        size_t nul = c.find('\0', 2);
        if (nul != std::string::npos && (contains_ci(c.substr(nul), "octet") || contains_ci(c.substr(nul), "netascii")))
            return {"tftp", "TFTP"};
    }
    if (c.size() >= 12) {  // DNS: one question, a standard query
        uint16_t flags = static_cast<uint16_t>(cp[2] << 8 | cp[3]);
        uint16_t qd = static_cast<uint16_t>(cp[4] << 8 | cp[5]);
        if (!(flags & 0x8000) && ((flags >> 11) & 0xF) == 0 && qd == 1 && cp[6] == 0 && cp[7] == 0 && (flags & 0x0070) == 0)
            return {"dns", "DNS"};
    }
    return {};
}

struct PortApp {
    uint16_t port;
    const char* app;
};
const PortApp kTcpPorts[] = {
    {21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"}, {53, "dns"}, {80, "http"}, {88, "kerberos"},
    {110, "pop3"}, {135, "dcerpc"}, {139, "smb"}, {143, "imap"}, {389, "ldap"}, {443, "tls"}, {445, "smb"},
    {465, "tls"}, {554, "rtsp"}, {587, "smtp"}, {636, "tls"}, {853, "tls"}, {993, "tls"}, {995, "tls"},
    {1080, "socks"}, {1194, "openvpn"}, {1433, "mssql"}, {3268, "ldap"}, {5985, "http"}, {5986, "tls"}, {1883, "mqtt"}, {3306, "mysql"}, {3389, "rdp"},
    {5060, "sip"}, {5222, "xmpp"}, {5432, "postgresql"}, {5900, "vnc"}, {6379, "redis"}, {6667, "irc"},
    {8080, "http"}, {8443, "tls"}, {27017, "mongodb"},
};
const PortApp kUdpPorts[] = {
    {53, "dns"}, {67, "dhcp"}, {68, "dhcp"}, {69, "tftp"}, {88, "kerberos"}, {123, "ntp"}, {137, "netbios-ns"},
    {138, "netbios-dgm"}, {161, "snmp"}, {162, "snmp"}, {389, "cldap"}, {443, "quic"}, {500, "isakmp"},
    {514, "syslog"}, {546, "dhcpv6"}, {547, "dhcpv6"}, {1194, "openvpn"}, {1812, "radius"}, {1900, "ssdp"},
    {3478, "stun"}, {4500, "ipsec-nat-t"}, {5060, "sip"}, {5353, "dns"}, {5355, "dns"}, {51820, "wireguard"},
};

}  // namespace

AppId identify_app(uint8_t proto, const std::string& client, const std::string& server) {
    if (proto == 6) return tcp_app(client, server);
    if (proto == 17) return udp_app(client, server);
    return {};
}

const char* app_for_port(uint8_t proto, uint16_t port) {
    if (proto == 6) {
        for (const auto& p : kTcpPorts)
            if (p.port == port) return p.app;
    } else if (proto == 17) {
        for (const auto& p : kUdpPorts)
            if (p.port == port) return p.app;
    }
    return "";
}

bool app_fits_port(uint8_t proto, uint16_t port, const char* app) {
    const char* expected = app_for_port(proto, port);
    if (!*expected || !*app) return true;  // nothing to compare against
    if (std::strcmp(expected, app) == 0) return true;
    // Compatible pairings: a service that upgrades to TLS, mail that STARTTLSes, web
    // proxies, HTTP/2 cleartext on a web port, TLS-wrapped web on alternate ports.
    auto is = [&](const char* a, const char* b) { return std::strcmp(expected, a) == 0 && std::strcmp(app, b) == 0; };
    return is("http", "http-proxy") || is("http", "http2") || is("ftp", "ftp-or-smtp") || is("smtp", "ftp-or-smtp") ||
           is("smtp", "tls") || is("imap", "tls") || is("pop3", "tls") || is("ldap", "tls") || is("xmpp", "tls") ||
           is("ftp", "tls") || is("mssql", "tls") || is("postgresql", "tls") || is("mysql", "tls") ||
           is("rdp", "tls") || is("socks", "http-proxy") || is("sip", "tls") || is("tls", "http2") ||
           is("netbios-ns", "dns") || is("cldap", "dns");  // NetBIOS names use the DNS message format
}

}  // namespace anta
