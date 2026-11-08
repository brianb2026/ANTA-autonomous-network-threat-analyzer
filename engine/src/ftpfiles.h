// FTP: what a control connection asks for, and the files its data connections
// carry (Wireshark's File > Export Objects > FTP-DATA). A data connection is
// matched to the port PORT/EPRT/PASV/EPSV announced, on the control connection's
// own addresses as well as the announced one, so a server behind NAT (announcing
// an address that isn't the one on the wire) still has its transfers followed.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "hash.h"
#include "packet.h"

namespace anta {

// One transfer, shared by the control connection that set it up and the data
// connection that carries it.
struct FtpTransfer {
    std::string command;   // STOR, APPE, STOU, RETR, LIST, NLST, MLSD
    std::string name;      // the command's argument (a file); empty for a plain LIST
    std::string user;      // USER on the control connection
    std::string control;   // "client_ip:port -> server_ip:port"
    std::string reply;     // the server's final word on it (226 ..., 426 ...)
    bool active = false;   // the server opened the data connection (PORT/EPRT)
    bool tls_refused = false;  // AUTH TLS was refused on the control connection first
    bool upload() const { return command == "STOR" || command == "APPE" || command == "STOU"; }
};

// One direction of a data connection: hashed as it streams past, its start kept.
struct FtpDataSide {
    static constexpr size_t kKeep = 64 * 1024;  // a small text file is kept whole
    Sha256 hash;
    uint64_t bytes = 0;
    std::string head;
    void add(const uint8_t* p, size_t n);
};

// A data connection the control connection told the other side to expect: to ip:port,
// from `peer` (the control connection's other end), as Wireshark's FTP conversations.
struct FtpExpect {
    IpAddr ip;
    uint16_t port = 0;
    IpAddr peer;
    std::shared_ptr<FtpTransfer> transfer;
};

class FtpControl {
public:
    FtpControl(const IpAddr& client, uint16_t client_port, const IpAddr& server, uint16_t server_port);
    // Reassembled control text, either direction. Data connections announced on
    // the way are appended to `expect`.
    void on_data(bool from_client, const uint8_t* p, size_t n, std::vector<FtpExpect>& expect);

    std::string user;
    bool tls_refused = false;              // AUTH TLS was asked for and refused: everything in clear
    std::vector<std::string> commands;     // what the client sent (PASS hidden), capped

private:
    void line(bool from_client, const std::string& text, std::vector<FtpExpect>& expect);
    std::shared_ptr<FtpTransfer> next();   // the transfer the next data connection carries
    void announce(const IpAddr* announced, uint16_t port, bool active, std::vector<FtpExpect>& expect);

    IpAddr client_, server_;
    std::string desc_;
    std::string buf_[2];
    std::shared_ptr<FtpTransfer> current_;
    bool auth_tls_asked_ = false;
};

}  // namespace anta
