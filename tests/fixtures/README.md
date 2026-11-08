# Test fixtures

`h2_curl.pcap` is real HTTP/2-over-TLS traffic recorded on loopback: curl 8.7.1
(nghttp2's HPACK encoder) fetching four files in parallel from a small local test
server, through a relay that recorded the exact bytes. `h2_curl.keys` is the TLS key
log the server's OpenSSL wrote for that one throwaway session (self-signed
certificate, loopback only), and `h2_curl.json` the SHA-256 of each file the server
sent. Nothing in them comes from a real network.

`tls_suites/` holds real TLS sessions between OpenSSL 3's own `s_client` and `s_server`
on loopback, recorded through the same kind of relay by `python -m anta.tools.tls_record
tests/fixtures/tls_suites` (set `OPENSSL` to an OpenSSL 3 `openssl` if the one on PATH
is LibreSSL). Each `NAME.pcap` comes with the key log its client wrote, `NAME.keys`, for
that one throwaway session (self-signed certificate, loopback only): CBC suites in TLS
1.0, 1.1 and 1.2 with and without encrypt-then-MAC, AES-CCM and CCM_8 in TLS 1.2 and
1.3, TLS 1.3 key updates from both sides, TLS 1.2 renegotiation started by either side,
and TLS 1.3 early data on a resumed session. Nothing in them comes from a real network.

`dtls/` holds real DTLS sessions between OpenSSL 3's `s_client` and `s_server` on
loopback, recorded through a UDP relay by `python -m anta.tools.tls_record tests/fixtures/dtls
dtls12_ecdhe_gcm dtls12_aes128_sha_mtu dtls10_aes256_sha dtls12_chacha20`: DTLS 1.2 and 1.0,
with the server's flight cut into fragments (one with a 500-byte MTU), a Hello Verify
Request cookie exchange, a few lines of application data each way and close_notify. They
have no key logs: DTLS is dissected, not decrypted. Nothing in them comes from a real network.
