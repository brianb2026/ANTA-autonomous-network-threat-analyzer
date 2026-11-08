// Files copied over SMB2/SMB3, as Wireshark's Export Objects > SMB lists them:
// what a client read from or wrote to a share, reassembled from Read and Write
// data and hashed (SHA-256), so a program copied between hosts is as visible as
// one downloaded over HTTP. Encrypted SMB3 can't be followed.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "hash.h"
#include "object.h"

namespace anta {

struct SmbFile {
    std::string name;        // the path within the share
    std::string share;       // \\server\share
    bool written = false;    // the client wrote it (an upload), rather than read it
    uint64_t size = 0;       // bytes seen: the highest offset reached
    uint64_t end_of_file = 0;  // the file's size per the server when it was opened (0: unknown)
    std::string magic;       // its first bytes
    std::string sha256;      // of bytes 0..size, when all of them were seen
    bool complete = false;   // every byte of the file was seen
    uint64_t ts = 0;         // first data, microseconds
    uint64_t seq = 0;        // which open on the connection this was (names it for export)
};

class SmbFileTracker {
public:
    // Reassembled stream data, either direction.
    void on_data(bool from_client, const uint8_t* data, size_t len, uint64_t ts_us);
    // A hole in one direction's stream: its message framing is lost.
    void on_gap(bool from_client);
    // The connection ended: files still open are reported as they stand.
    void finish();
    const std::vector<SmbFile>& files() const { return files_; }
    // Write out the file of open number target->n as its bytes are hashed.
    void set_target(ObjectTarget* target) { target_ = target; }
    bool encrypted() const { return encrypted_; }

private:
    struct Open {
        std::string name, share;
        uint64_t end_of_file = 0, max_end = 0, hashed = 0, ts = 0, seq = 0;
        bool written = false, data_seen = false, broken = false;
        std::string magic;
        Sha256 hash;
        std::map<uint64_t, std::string> pending;  // data beyond what's hashed, by offset
        size_t pending_bytes = 0;
    };
    struct Request {
        uint16_t cmd = 0;
        std::string name, fid;
        std::string tree_key;
        uint64_t offset = 0;
    };
    void message(bool from_client, const uint8_t* p, size_t n, uint64_t ts);
    void add_data(Open& o, uint64_t offset, const uint8_t* p, size_t n, uint64_t ts);
    void close(const std::string& fid);

    std::string buf_[2];
    bool lost_[2] = {false, false};
    bool encrypted_ = false;
    std::map<std::string, Request> requests_;   // session + message ID
    std::map<std::string, std::pair<std::string, uint8_t>> trees_;  // session + tree ID -> path, share type
    std::map<std::string, Open> open_;          // session + file ID
    std::vector<SmbFile> files_;
    ObjectTarget* target_ = nullptr;
    uint64_t next_seq_ = 0;
};

}  // namespace anta
