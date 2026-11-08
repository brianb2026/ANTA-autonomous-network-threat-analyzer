// DEFLATE decompression (RFC 1951) with the gzip (RFC 1952) and zlib (RFC 1950)
// wrappers, for HTTP bodies sent with Content-Encoding: gzip / deflate, so a
// file's hash is the hash of the file, as in Wireshark's Export Objects.
#pragma once

#include <cstddef>
#include <string>

namespace anta {

// Decodes `in` according to an HTTP Content-Encoding ("gzip", "x-gzip" or
// "deflate"). Fails on corrupt input or when the output would pass `max_out`
// bytes (a decompression bomb can't run away with memory).
bool http_decode_body(const std::string& in, const std::string& encoding, std::string& out, size_t max_out);

}  // namespace anta
