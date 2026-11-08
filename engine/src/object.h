// A transferred file written out while a capture is read (Export Objects).
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace anta {

// One transferred file to write out while the capture is read (Export Objects):
// object `n` of flow `flow_id` ('h' the HTTP response of that number, 's' the SMB
// open of that number, 'f' direction n of an FTP data connection). Exactly the
// bytes that are hashed are written, so the copy's SHA-256 is the listed one.
struct ObjectTarget {
    uint64_t flow_id = 0;
    char kind = 0;
    uint64_t n = 0;
    std::FILE* out = nullptr;
    uint64_t written = 0;
    bool found = false;
    void write(const void* p, size_t len) {
        if (len && std::fwrite(p, 1, len, out) == len) written += len;
    }
};

}  // namespace anta
