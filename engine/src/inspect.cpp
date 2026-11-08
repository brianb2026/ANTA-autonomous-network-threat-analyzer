#include "inspect.h"

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <unordered_map>

#include "crypto.h"
#include "flow.h"
#include "platform.h"
#include "dfilter.h"
#include "proto.h"
#include "quic.h"
#include "http2.h"
#include "inflate.h"
#include "tlsdecrypt.h"
#include "tlskeys.h"

namespace anta {

namespace {

#if defined(__GNUC__) || defined(__clang__)
#define ANTA_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#define ANTA_PRINTF(a, b)
#endif

std::string fmt(const char* f, ...) ANTA_PRINTF(1, 2);
std::string fmt(const char* f, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, f);
    std::vsnprintf(buf, sizeof(buf), f, ap);
    va_end(ap);
    return buf;
}

// Bounds-checked big-endian access to the captured bytes.
struct Bytes {
    const uint8_t* p;
    size_t n;
    bool have(size_t off, size_t len) const { return off <= n && len <= n - off; }
    uint8_t u8(size_t off) const { return p[off]; }
    uint16_t u16(size_t off) const { return static_cast<uint16_t>((p[off] << 8) | p[off + 1]); }
    uint32_t u32(size_t off) const {
        return (static_cast<uint32_t>(p[off]) << 24) | (p[off + 1] << 16) | (p[off + 2] << 8) | p[off + 3];
    }
    uint16_t le16(size_t off) const { return static_cast<uint16_t>(p[off] | (p[off + 1] << 8)); }
    uint32_t le32(size_t off) const {
        return p[off] | (p[off + 1] << 8) | (p[off + 2] << 16) | (static_cast<uint32_t>(p[off + 3]) << 24);
    }
    uint64_t le64(size_t off) const { return le32(off) | (static_cast<uint64_t>(le32(off + 4)) << 32); }
};

std::string mac_raw(const uint8_t* m) {
    return fmt("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// Vendor short names for MAC addresses (Wireshark-style "Vendor_xx:xx:xx").
#include "oui_data.inc"

// Windows protocol numbers and their names (NT status codes, FSCTLs, SMB2
// information levels, DCE/RPC interfaces and operations).
struct NameEntry {
    uint32_t code;
    const char* name;
};
struct RpcInterface {
    const char* uuid;
    uint16_t ver;
    const char* ctx_name;     // in bind context lists
    const char* proto;        // the Protocol column
    const char* filter;       // its display-filter name, e.g. "samr"
    const char* opnum_field;  // e.g. "samr.opnum"
    const NameEntry* ops;
    size_t n_ops;
};
#include "names_data.inc"

const char* lookup_name(const NameEntry* t, size_t n, uint32_t code) {
    const NameEntry* end = t + n;
    const NameEntry* it = std::lower_bound(t, end, code, [](const NameEntry& e, uint32_t c) { return e.code < c; });
    return it != end && it->code == code ? it->name : nullptr;
}
template <size_t N>
const char* lookup_name(const NameEntry (&t)[N], uint32_t code) {
    return lookup_name(t, N, code);
}
const RpcInterface* rpc_interface(const std::string& uuid, uint16_t major) {
    for (const auto& i : kRpcInterfaces)
        if (i.ver == major && uuid == i.uuid) return &i;
    return nullptr;
}
std::string nt_status_name(uint32_t status) {
    const char* n = lookup_name(kNtStatus, status);
    return n ? n : fmt("Unknown (0x%08X)", status);
}

const char* oui_vendor(const uint8_t* m) {
    uint32_t prefix = (static_cast<uint32_t>(m[0]) << 16) | (m[1] << 8) | m[2];
    const uint32_t* end = kOuiTable + sizeof(kOuiTable) / sizeof(kOuiTable[0]);
    const uint32_t* it = std::lower_bound(kOuiTable, end, prefix << 8);
    if (it == end || (*it >> 8) != prefix) return nullptr;
    return kOuiNames[*it & 0xFF];
}

std::string mac_name(const uint8_t* m) {
    static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (std::memcmp(m, bcast, 6) == 0) return "Broadcast";
    if (m[0] == 0x01 && m[1] == 0x00 && m[2] == 0x5e) return fmt("IPv4mcast_%02x:%02x:%02x", m[3], m[4], m[5]);
    if (m[0] == 0x33 && m[1] == 0x33) return fmt("IPv6mcast_%02x:%02x:%02x:%02x", m[2], m[3], m[4], m[5]);
    if (const char* v = oui_vendor(m)) return fmt("%s_%02x:%02x:%02x", v, m[3], m[4], m[5]);
    return mac_raw(m);
}

std::string ipv4s(const uint8_t* a) { return fmt("%u.%u.%u.%u", a[0], a[1], a[2], a[3]); }

std::string ipv6s(const uint8_t* a) {
    char buf[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, a, buf, sizeof(buf));
    return buf;
}

// One text line, non-printables shown as '.', stopping at CR/LF.
std::string text_line(const uint8_t* p, size_t n, size_t max = 400) {
    std::string s;
    for (size_t i = 0; i < n && s.size() < max; ++i) {
        unsigned char c = p[i];
        if (c == '\r' || c == '\n') break;
        s.push_back(c >= 0x20 && c < 0x7f ? static_cast<char>(c) : '.');
    }
    return s;
}

bool starts_with(const uint8_t* p, size_t n, const char* s) {
    size_t k = std::strlen(s);
    return n >= k && std::memcmp(p, s, k) == 0;
}

const char* ethertype_name(uint16_t t) {
    switch (t) {
        case 0x0800: return "IPv4";
        case 0x86DD: return "IPv6";
        case 0x0806: return "ARP";
        case 0x8100: return "802.1Q";
        case 0x88A8: return "802.1ad";
        case 0x88CC: return "LLDP";
        case 0x888E: return "EAPOL";
        case 0x8863: return "PPPoED";
        case 0x8864: return "PPPoES";
        case 0x88F7: return "PTPv2";
        case 0x8809: return "Slow";
        case 0x893A: return "IEEE1905";
        case 0x0842: return "WOL";
        case 0x8035: return "RARP";
        case 0x8847: return "MPLS";
        case 0x8848: return "MPLS";
        case 0x9000: return "LOOP";
        case 0x88E5: return "MACsec";
        case 0x22F0: return "AVTP";
        default: return nullptr;
    }
}

std::string ip_proto_name(uint8_t p) {
    switch (p) {
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 4: return "IPIP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 41: return "IPv6";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 58: return "ICMPv6";
        case 88: return "EIGRP";
        case 89: return "OSPF";
        case 103: return "PIMv2";
        case 112: return "VRRP";
        case 132: return "SCTP";
        default: return fmt("IP proto %u", p);
    }
}

const char* dns_type_name(uint16_t t) {
    switch (t) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 13: return "HINFO";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 35: return "NAPTR";
        case 41: return "OPT";
        case 43: return "DS";
        case 46: return "RRSIG";
        case 47: return "NSEC";
        case 48: return "DNSKEY";
        case 64: return "SVCB";
        case 65: return "HTTPS";
        case 255: return "ANY";
        case 257: return "CAA";
        default: return nullptr;
    }
}

std::string dns_type(uint16_t t) {
    const char* n = dns_type_name(t);
    return n ? n : fmt("Unknown (%u)", t);
}

}  // namespace

// ------------------------------------------------------------- state

struct InspectorState {
    // A message (PDU) that spans TCP segments, reassembled by sequence number
    // (Wireshark's tcp_multisegment_pdu plus its fragment list).
    struct Fragment {
        uint32_t off, len;
    };
    struct Msp {
        uint32_t seq = 0, nxtpdu = 0;  // relative sequence numbers
        uint64_t first_frame = 0, last_frame = 0;
        bool entire_segment = false;   // "one more segment": take whatever the next segment carries
        bool from_start = false;       // began at the first payload byte of first_frame
        bool multi = false;            // another frame has added data
        bool phantom = false;          // pass 2 only: Wireshark's second pass never has this one
        bool defragmented = false;
        bool tot_known = false;
        uint32_t tot_len = 0;
        uint64_t reassembled_in = 0;
        std::vector<Fragment> frags;   // sorted by offset
        std::vector<uint64_t> frames;
        std::string data;              // the first kMspKeep bytes
    };
    struct Unacked {
        uint32_t seq, nextseq;
        uint64_t frame = 0, ts = 0;
        bool retrans = false;  // a retransmitted copy (Karn: its ACK is ambiguous)
    };
    struct Dir {
        bool base_set = false;
        uint32_t base = 0;
        // Sequence analysis on raw numbers; 0 means "not seen yet", as in Wireshark.
        uint32_t nextseq = 0;
        uint64_t nextseqtime = 0;
        uint32_t maxseqtobeacked = 0;
        uint32_t lastack = 0;
        uint64_t lastacktime = 0;
        uint64_t lastnondupack = 0;
        uint32_t dupacknum = 0;
        uint32_t lastacklen = 0;
        uint32_t window = 0xFFFFFFFFu;  // as sent (unscaled)
        uint16_t mss = 0;               // MSS this side announced in its SYN (0: SYN not seen)
        int win_scale = -1;             // -1 unknown, -2 not in use, else the shift
        bool is_first_ack = false;
        uint32_t lastsegmentflags = 0;
        std::deque<Unacked> segments;   // sent and not yet acknowledged, newest first
        int num_sack = 0;
        uint32_t sack_le[4] = {}, sack_re[4] = {};
        // Reassembly, on relative sequence numbers.
        uint32_t maxnextseq = 0;
        std::map<uint32_t, Msp> msps;
        bool until_fin = false;
        uint64_t fin_frame = 0;
        // SSH
        bool ssh_banner_done = false;
        uint64_t ssh_banner_frame = 0;
        bool ssh_newkeys = false;
        uint64_t ssh_newkeys_frame = 0;
        size_t ssh_newkeys_offset = 0;
        std::string ssh_kex;
        // TLS
        uint64_t tls_ccs_frame = 0;
        bool hs_pending = false;
        uint8_t hs_type = 0;
        uint32_t hs_remaining = 0;
    };
    struct Conv {
        Dir dir[2];
        int client = -1;          // direction index of the connection initiator
        uint16_t server_port = 0;
        uint64_t syn_time = 0;    // most recent SYN
        uint64_t first_rtt = 0;   // SYN to the first pure ACK
        bool fin_or_rst = false;
        int8_t first_fin_dir = -1;  // which side sent the first FIN (the active close)
        uint8_t app = 0;          // conversation dissector, once a heuristic matched
        uint8_t ssh_version = 0;  // from the banner: 1 or 2
        uint16_t tls_version = 0;
        bool tls_resumed = false;   // a Server Hello not (yet) followed by the server's certificate
        int8_t tls_server_dir = -1;
        // TLS decryption (only when a key log is loaded): the ClientHello random keys
        // the secrets, the negotiated suite picks the cipher, and each direction keeps
        // its derived application-record keys and record counter.
        uint8_t tls_client_random[32] = {};
        uint8_t tls_server_random[32] = {};
        bool tls_cr_set = false, tls_sr_set = false;
        uint16_t tls_cipher = 0;
        bool tls_dec_looked_up = false;
        const TlsSecrets* tls_secrets = nullptr;
        bool tls_app_ready[2] = {};
        TlsRecordKeys tls_app[2];
        uint64_t tls_app_seq[2] = {};
        // TLS 1.3 handshake records (Encrypted Extensions … Finished), when the key log also
        // holds the *_HANDSHAKE_TRAFFIC_SECRETs (browsers and curl write them): a side's
        // handshake keys are used until its Finished. The extensions name the ALPN protocol.
        bool tls_hs_ready[2] = {};
        bool tls_hs_done[2] = {};
        TlsRecordKeys tls_hs[2];
        uint64_t tls_hs_seq[2] = {};
        std::string tls_hs_buf[2];  // a decrypted handshake message continued in the next record
        std::string tls_alpn;
        uint8_t tls_proto = 0;      // what decrypted application data carries: 0 not known yet, 2 HTTP/2
        // HTTP/2 (decrypted, or cleartext h2c): per side, the HPACK state, a header block
        // awaiting CONTINUATION, a frame continued in the next TLS record, and how far the
        // side's stream has been dissected (TCP may hand the same bytes over twice).
        struct H2Side {
            Hpack hpack;
            bool hpack_broken = false;
            std::string block;                // undecoded bytes of a header block CONTINUATION goes on with
            uint32_t block_sid = 0;           // the stream its headers belong to (a promised one for PUSH_PROMISE)
            uint32_t block_frame_sid = 0;     // the stream its frames are on (what CONTINUATION carries)
            uint8_t block_type = 0;
            bool block_open = false;
            std::string pend;                 // TLS: the start of a frame the next record completes
            std::vector<uint64_t> pend_frames;
            uint64_t stream_pos = 0;          // TLS: plaintext bytes of this side so far
            uint64_t pos_done = 0;            // stream offset below which every frame was dissected
            struct Decoded {
                Http2Headers headers;
                std::vector<HpackRepr> reprs;
                std::vector<uint32_t> updates;
            };
            std::map<uint64_t, Decoded> cache;  // h2c: header fragments decoded, by stream offset
        };
        H2Side h2[2];
        int8_t h2_client = -1;  // which side is the client (sent the preface, or the TLS client)
        struct H2Stream {
            bool has_method = false, has_path = false, has_authority = false, has_scheme = false;
            std::string method, path, authority, scheme;
            uint64_t req_frame = 0, req_ts = 0;
            uint64_t resp_frame = 0;          // the latest response HEADERS (with :status) so far
            std::string ctype[2], cenc[2];    // per side: the media type of the body it sends
            std::string body[2];
            std::string follow_body[2];       // Follow HTTP/2 Stream: body bytes not shown yet
        };
        std::map<uint32_t, H2Stream> h2_streams;
        // TLS 1.2 and earlier: a direction's records are encrypted after its
        // ChangeCipherSpec, with its own record counter. Each direction keeps the key block
        // it switched to: a renegotiation moves the two sides to new keys one at a time.
        bool tls12_enc[2] = {};
        uint64_t tls12_seq[2] = {};
        Tls12Keys tls12[2];
        bool tls12_ready[2] = {};
        bool tls_etm = false;  // CBC suites: the server accepted encrypt-then-MAC
        // A key log with only the premaster secret (RSA or PMS_CLIENT_RANDOM lines): the
        // master secret is computed from it, over the handshake transcript when the
        // extended master secret (RFC 7627) was negotiated.
        bool tls_ems = false;
        std::string tls_transcript;          // Client Hello … Client Key Exchange
        bool tls_transcript_done = false;
        uint8_t tls_rsa_enc8[8] = {};        // the encrypted premaster's first 8 bytes
        bool tls_rsa_enc_set = false;
        uint8_t tls_master[48] = {};
        bool tls_master_set = false;
        // TLS 1.3 early data: offered by the Client Hello, read under its own keys until
        // the End of Early Data.
        int8_t tls_client_dir = -1;
        bool tls_early_offered = false, tls_early_done = false;
        TlsRecordKeys tls_early;
        uint64_t tls_early_seq = 0;
        // Decrypted HTTP messages spanning TLS records: the bytes so far, how many the
        // message needs (0: unknown, parse again), and the frames that carried them.
        std::string tls_http_pend[2];
        size_t tls_http_need[2] = {};
        std::vector<uint64_t> tls_http_frames[2];
        bool http_seen = false;
        std::string http_method;  // method of the last request (HEAD responses have no body)
        // Request/response pairs, newest last. Like Wireshark, a response takes the latest
        // request if that has no (final) response yet, and otherwise stands alone.
        struct HttpPair {
            uint64_t req_frame = 0, req_ts = 0, res_frame = 0;
            std::string uri, full_uri;
            uint32_t ann = UINT32_MAX;  // its copy in the first pass's annotations
            uint64_t key = 0;           // the message that made it (frame, offset): a re-dissection reuses it
        };
        std::deque<HttpPair> http_pairs;
        // LDAP: a SASL bind's mechanism, the frame its wrapped traffic starts at, StartTLS
        uint8_t ldap_sasl = 0;    // 1: GSS-API (GSS-SPNEGO, GSSAPI), 2: another mechanism
        uint64_t ldap_sasl_from = 0, ldap_tls_from = 0;
        bool ldap_starttls = false;
        // Databases: MySQL's request/response state, a PostgreSQL TLS request, TLS inside TDS
        uint8_t mysql_state = 0;
        bool mysql_binary = false;  // the result set answers Execute Statement (binary rows)
        bool pgsql_ssl_requested = false;
        bool tds_tls = false;
        bool tds_more[2] = {false, false};  // a TDS message continues in this direction's next packet
        uint64_t stream = ~0ULL;  // tcp.stream index, in order of first appearance
    };
    struct FtpPending {
        std::string mode, ip;
        uint16_t port = 0;
    };
    struct FtpData {
        std::string mode, cmd;
    };
    struct EchoRequest {
        uint64_t frame = 0;
        bool answered = false;
    };
    struct DnsTransaction {   // Wireshark's dns_transaction_t
        uint64_t req_frame = 0, rep_frame = 0, req_ts = 0;
    };
    struct Fragments {
        std::string data;  // reassembled IP payload
        std::vector<std::pair<uint32_t, uint32_t>> pieces;
        uint32_t total = 0;  // known once the last fragment arrives
        std::vector<uint64_t> frames;
        uint8_t proto = 0;
        std::string header;  // first fragment's IP header
    };

    std::unordered_map<FlowKey, Conv, FlowKeyHash> convs;
    std::unordered_map<FlowKey, FtpPending, FlowKeyHash> ftp_pending;  // per control connection
    std::unordered_map<std::string, FtpData> ftp_data;                  // "ip|port|peer" -> data channel
    std::unordered_map<std::string, EchoRequest> echo;                  // echo key -> request
    std::unordered_map<std::string, Fragments> frags;                   // "src|dst|id|proto"
    std::unordered_map<FlowKey, uint64_t, FlowKeyHash> udp_streams;     // udp.stream indexes
    // DNS transactions per conversation, by transaction ID (the latest one wins).
    std::unordered_map<FlowKey, std::unordered_map<uint16_t, DnsTransaction>, FlowKeyHash> dns;
    struct QuicConn {
        uint32_t version = 0;
        std::string odcid;               // the client's first Destination Connection ID: the Initial keys
        bool client_a_to_b = true;       // which way the client's packets travel
        int cid_len[2] = {-1, -1};       // connection ID length each side chose (client, server)
        int64_t largest[2] = {-1, -1};   // largest Initial packet number (client, server)
        bool short_tried[2] = {false, false};  // a 1-RTT packet Wireshark tried (and failed) to decrypt
        QuicCryptoStream crypto;         // the client's Initial CRYPTO stream: its Client Hello
        QuicCryptoStream server_crypto;  // the server's: its Server Hello
        bool hello_done = false, server_hello_done = false;
    };
    std::unordered_map<FlowKey, QuicConn, FlowKeyHash> quic;
    // DTLS over UDP (Wireshark's SslSession for the conversation): the session's version
    // and the handshake fragments, reassembled per direction, epoch and message_seq.
    struct DtlsFragment {
        struct Piece {
            uint32_t offset = 0;
            std::string data;
            uint64_t frame = 0;
        };
        std::vector<Piece> pieces;     // in the order they came
        uint32_t length = 0;           // the message length the first fragment gave (0: not yet)
        bool defragmented = false;
        std::string data;              // the message, once defragmented
    };
    struct DtlsConn {
        bool started = false;
        uint16_t version = 0;          // the session's version (0: not settled)
        std::map<uint64_t, DtlsFragment> frags;
        size_t frag_bytes = 0;
    };
    std::unordered_map<FlowKey, DtlsConn, FlowKeyHash> dtls;
    std::unordered_map<size_t, uint32_t> ldap_results;  // search entries per conversation (Wireshark counts them all)
    // SMB2: trees and open files by session, and what each request asked for (by message ID)
    struct SmbTree {
        std::string path;
        uint8_t type = 0;  // 1 disk, 2 named pipe, 3 printer
    };
    struct SmbRequest {
        uint16_t cmd = 0;
        std::string name, pattern;  // Create's file name, Tree Connect's path; Find's pattern
        std::string fid;            // the file the request used
        uint8_t cls = 0, level = 0;
    };
    std::unordered_map<std::string, SmbTree> smb_trees;        // session + tree ID
    std::unordered_map<std::string, std::string> smb_files;    // session + file ID -> name
    std::unordered_map<std::string, SmbRequest> smb_requests;  // conversation + message ID
    // DCE/RPC: bound presentation contexts and outstanding calls, per connection (and SMB pipe)
    struct RpcBinding {
        std::string uuid;
        uint16_t major = 0, minor = 0;
        bool ndr64 = false;  // the transfer syntax offered with it
    };
    struct RpcConv {
        std::unordered_map<uint16_t, RpcBinding> ctx;
        std::unordered_map<uint32_t, std::pair<uint16_t, uint16_t>> calls;  // call ID -> (context, opnum)
        std::unordered_map<uint64_t, std::vector<uint64_t>> frags;         // call ID + type -> fragment frames
    };
    std::unordered_map<std::string, RpcConv> rpc;
    uint64_t next_tcp_stream = 0, next_udp_stream = 0;
    size_t msp_bytes = 0;                                                // reassembly buffers held
    uint64_t first_ts = 0, prev_ts = 0;
    bool first_ts_set = false, prev_ts_set = false;
    InspectorAnnotations* record = nullptr;
    const InspectorAnnotations* use = nullptr;
    const TlsKeyLog* keylog = nullptr;  // TLS secrets the user supplied, for decryption
    FollowTap* tap = nullptr;           // Follow TLS / HTTP/2 Stream: what is decrypted and decoded

    Conv& conv(const FlowKey& k) {
        if (convs.size() > 500'000) {  // bound memory on huge captures
            convs.clear();
            msp_bytes = 0;
        }
        return convs[k];
    }
};

namespace {

class Decoder {
public:
    Decoder(InspectorState& st, const uint8_t* data, size_t caplen, uint64_t frame, uint64_t ts_us, bool full)
        : st_(st), b_{data, caplen}, frame_(frame), ts_(ts_us), full_(full) {}

    void want_fields(FrameFields* f) { ff_ = f; }
    void set_wire_len(size_t n) { wire_len_ = n; }

    DecodedFrame run(LinkType link) {
        link_layer(link, 0, 0);
        if (full_ && d_.info.empty() && d_.malformed) d_.info = "[Malformed Packet]";
        return std::move(d_);
    }

private:
    // ----------------------------------------------------------- helpers
    Layer& layer(const char* name, size_t off, size_t len) {
        if (!full_) return dummy_;
        Layer l;
        l.name = name;
        if (!virtual_) {  // reassembled data has no place in this frame's bytes
            l.offset = static_cast<uint32_t>(std::min(off, b_.n));
            l.length = static_cast<uint32_t>(std::min(len, b_.n - l.offset));
        }
        d_.layers.push_back(std::move(l));
        return d_.layers.back();
    }
    void field(Layer& l, const std::string& name, const std::string& value, size_t off, size_t len) {
        if (!full_) return;
        size_t o = virtual_ ? 0 : std::min(off, b_.n);
        size_t n = virtual_ ? 0 : std::min(len, b_.n - o);
        l.fields.push_back({name, value, static_cast<uint32_t>(o), static_cast<uint32_t>(n)});
    }
// Lazy so observe() (full_ == false) never pays for string formatting.
#define FIELD(l, name, value, off, len)             \
    do {                                            \
        if (full_) field(l, name, value, off, len); \
    } while (0)
#define INFO(value)                   \
    do {                              \
        if (full_) d_.info = (value); \
    } while (0)

    void truncated() { d_.malformed = true; }

    // Display-filter fields (Wireshark names), recorded when a caller asks for them.
#define FF(call)                                 \
    do {                                         \
        if (ff_ && !frozen_) ff_->call;          \
    } while (0)
    void fproto(const char* name, size_t off, size_t len) {
        if (!ff_ || frozen_) return;
        bool v = virtual_ || ff_virtual_;
        ff_->proto(name, v ? 0 : off, v ? 0 : std::min(len, b_.n - std::min(off, b_.n)));
    }

    // An expert-info item. Like Wireshark, any expert item makes the frame match _ws.expert.
    void expert(const char* name) {
        if (!ff_ || frozen_) return;
        ff_->proto(name, 0, 0);
        if (!ff_->has_proto("_ws.expert")) ff_->proto("_ws.expert", 0, 0);
    }
    // One whose summary varies: also handed to the statistics.
    void expert(const char* name, int severity, const char* group, const char* protocol, std::string summary) {
        expert(name);
        // Wireshark files every item of its "Malformed" group under _ws.malformed too.
        if (ff_ && !frozen_ && std::strcmp(group, "Malformed") == 0 && !ff_->has_proto("_ws.malformed"))
            ff_->proto("_ws.malformed", 0, 0);
        if (d_.notes.size() < 64) d_.notes.push_back({severity, group, protocol, std::move(summary)});
    }

    // The Info column, with Wireshark's semantics: text before the fence is kept
    // when a higher layer sets or clears the column.
    void col_set(const std::string& s) {
        if (!full_ || frozen_) return;
        col_.resize(std::min(fence_, col_.size()));
        col_ += s;
    }
    void col_clear() {
        if (full_ && !frozen_) col_.resize(std::min(fence_, col_.size()));
    }
    void col_append(const std::string& s) {
        if (full_ && !frozen_) col_ += s;
    }
    void col_append_sep(const std::string& s, const char* sep = ", ") {
        if (!full_ || frozen_) return;
        if (!col_.empty()) col_ += sep;
        col_ += s;
    }
    void col_prepend(const std::string& s) {
        if (!full_ || frozen_) return;
        col_.insert(0, s);
        if (fence_ > 0) fence_ += s.size();
    }
    void col_prepend_fence(const std::string& s) {
        if (!full_ || frozen_) return;
        col_.insert(0, s);
        fence_ += s.size();
    }
    void col_set_fence() {
        if (!frozen_) fence_ = col_.size();
    }
    void set_proto(const std::string& p) {
        if (proto_writable_ && !frozen_) d_.protocol = p;
    }

    // ------------------------------------------------------- link layer
    void link_layer(LinkType link, size_t off, int depth) {
        if (depth > 4) return truncated();
        switch (link) {
            case LinkType::Ethernet: return ethernet(off, depth);
            case LinkType::Null:
            case LinkType::Loop: {
                if (!b_.have(off, 4)) return truncated();
                Layer& l = layer("Null/Loopback", off, 4);
                FIELD(l, "Family", fmt("%u", link == LinkType::Loop ? b_.u32(off) : b_.le32(off)), off, 4);
                return l3(0, off + 4, depth);
            }
            case LinkType::Raw:
            case LinkType::Raw12:
            case LinkType::Raw14:
            case LinkType::Ipv4:
            case LinkType::Ipv6: return l3(0, off, depth);
            case LinkType::LinuxSll: return sll(off, depth);
            case LinkType::LinuxSll2: return sll2(off, depth);
            case LinkType::Ppp:
            case LinkType::PppHdlc: return ppp(off, depth);
            case LinkType::CiscoHdlc: {
                if (!b_.have(off, 4)) return truncated();
                Layer& l = layer("Cisco HDLC", off, 4);
                uint16_t type = b_.u16(off + 2);
                FIELD(l, "Protocol", fmt("0x%04x", type), off + 2, 2);
                return l3(type, off + 4, depth);
            }
            case LinkType::Ieee80211: return ieee80211(off, depth);
            case LinkType::Radiotap: {
                if (!b_.have(off, 4)) return truncated();
                size_t len = b_.le16(off + 2);
                if (len < 8 || !b_.have(off, len)) return truncated();
                Layer& l = layer("Radiotap Header v0", off, len);
                fproto("radiotap", off, len);
                FIELD(l, "Header length", fmt("%zu", len), off + 2, 2);
                return ieee80211(off + len, depth);
            }
            case LinkType::Ppi: {
                if (!b_.have(off, 8)) return truncated();
                size_t len = b_.le16(off + 2);
                auto inner = static_cast<LinkType>(b_.le32(off + 4));
                if (len < 8 || !b_.have(off, len) || inner == LinkType::Ppi) return truncated();
                Layer& l = layer("PPI version 0", off, len);
                FIELD(l, "Header length", fmt("%zu", len), off + 2, 2);
                FIELD(l, "DLT", fmt("%d", static_cast<int>(inner)), off + 4, 4);
                return link_layer(inner, off + len, depth + 1);
            }
            case LinkType::Pktap:
            case LinkType::User2: return pktap(off, depth);
            case LinkType::Nflog: return nflog(off, depth);
        }
        d_.protocol = fmt("DLT %d", static_cast<int>(link));
        INFO(fmt("Unsupported link-layer type %d", static_cast<int>(link)));
        layer("Frame data", off, b_.n - std::min(off, b_.n));
    }

    void ethernet(size_t off, int depth) {
        if (!b_.have(off, 14)) return truncated();
        Layer& l = layer("Ethernet II", off, 14);
        d_.dst = mac_name(b_.p + off);
        d_.src = mac_name(b_.p + off + 6);
        if (ff_) {
            fproto("eth", off, b_.n - off);
            FF(mac("eth.dst", b_.p + off));
            FF(mac("eth.src", b_.p + off + 6));
            FF(mac("eth.addr", b_.p + off));
            FF(mac("eth.addr", b_.p + off + 6));
            FF(boolean("eth.dst.ig", b_.u8(off) & 1));
            FF(uint("eth.type", b_.u16(off + 12)));
            if (const char* v = oui_vendor(b_.p + off + 6)) FF(string("eth.src.oui_resolved", v));
            if (const char* v = oui_vendor(b_.p + off)) FF(string("eth.dst.oui_resolved", v));
        }
        if (full_) {
            std::string draw = mac_raw(b_.p + off), sraw = mac_raw(b_.p + off + 6);
            field(l, "Destination", d_.dst == draw ? draw : d_.dst + " (" + draw + ")", off, 6);
            field(l, "Source", d_.src == sraw ? sraw : d_.src + " (" + sraw + ")", off + 6, 6);
        }
        uint16_t type = b_.u16(off + 12);
        const char* tn = ethertype_name(type);
        FIELD(l, type <= 1500 ? "Length" : "Type",
              type <= 1500 ? fmt("%u", type) : tn ? fmt("%s (0x%04x)", tn, type) : fmt("0x%04x", type), off + 12, 2);
        d_.protocol = "Ethernet";
        size_t pos = off + 14;
        for (int i = 0; i < 3 && (type == 0x8100 || type == 0x88A8 || type == 0x9100); ++i) {
            if (!b_.have(pos, 4)) return truncated();
            Layer& v = layer(type == 0x8100 ? "802.1Q Virtual LAN" : "802.1ad Service VLAN", pos, 4);
            uint16_t tci = b_.u16(pos);
            fproto("vlan", pos, 4);
            FF(uint("vlan.id", tci & 0x0FFF));
            FF(uint("vlan.priority", tci >> 13));
            FIELD(v, "Priority", fmt("%u", tci >> 13), pos, 2);
            FIELD(v, "DEI", fmt("%u", (tci >> 12) & 1), pos, 2);
            FIELD(v, "ID", fmt("%u", tci & 0x0FFF), pos, 2);
            type = b_.u16(pos + 2);
            const char* inner = ethertype_name(type);
            FIELD(v, "Type", inner ? fmt("%s (0x%04x)", inner, type) : fmt("0x%04x", type), pos + 2, 2);
            pos += 4;
        }
        if (type <= 1500) return llc(pos, depth);
        ethertype_payload(type, pos, depth);
    }

    void llc(size_t off, int depth) {
        if (!b_.have(off, 3)) return truncated();
        uint8_t dsap = b_.u8(off), ssap = b_.u8(off + 1);
        if (dsap == 0xAA && ssap == 0xAA && b_.have(off, 8)) {
            Layer& l = layer("Logical-Link Control (SNAP)", off, 8);
            fproto("llc", off, 8);
            uint16_t type = b_.u16(off + 6);
            FIELD(l, "Type", fmt("0x%04x", type), off + 6, 2);
            return ethertype_payload(type, off + 8, depth);
        }
        Layer& l = layer("Logical-Link Control", off, 3);
        fproto("llc", off, 3);
        FIELD(l, "DSAP", fmt("0x%02x", dsap), off, 1);
        FIELD(l, "SSAP", fmt("0x%02x", ssap), off + 1, 1);
        if (dsap == 0x42 && ssap == 0x42) {
            d_.protocol = "STP";
            INFO("Spanning Tree Protocol BPDU");
            fproto("stp", off + 3, b_.n - std::min(off + 3, b_.n));
            if (b_.have(off + 3, 4)) FF(uint("stp.type", b_.u8(off + 6)));
            layer("Spanning Tree Protocol", off + 3, b_.n - std::min(off + 3, b_.n));
        } else {
            d_.protocol = "LLC";
            INFO(fmt("DSAP 0x%02x SSAP 0x%02x", dsap, ssap));
        }
    }

    void ethertype_payload(uint16_t type, size_t off, int depth) {
        if (type == 0x8847 || type == 0x8848) {
            for (int i = 0; i < 8; ++i) {
                if (!b_.have(off, 4)) return truncated();
                Layer& l = layer("MultiProtocol Label Switching Header", off, 4);
                uint32_t v = b_.u32(off);
                fproto("mpls", off, 4);
                FF(uint("mpls.label", v >> 12));
                FIELD(l, "Label", fmt("%u", v >> 12), off, 3);
                FIELD(l, "TTL", fmt("%u", v & 0xFF), off + 3, 1);
                off += 4;
                if (v & 0x100) return l3(0, off, depth);
            }
            return truncated();
        }
        if (type == 0x8864) {
            if (!b_.have(off, 8)) return truncated();
            Layer& l = layer("PPP-over-Ethernet Session", off, 6);
            fproto("pppoes", off, 6);
            FIELD(l, "Session ID", fmt("0x%04x", b_.u16(off + 2)), off + 2, 2);
            return ppp(off + 6, depth);
        }
        l3(type, off, depth);
    }

    static std::string sll_packet_type(unsigned t) {
        switch (t) {
            case 0: return "Unicast to us (0)";
            case 1: return "Broadcast (1)";
            case 2: return "Multicast (2)";
            case 3: return "Unicast to another host (3)";
            case 4: return "Sent by us (4)";
            default: return fmt("%u", t);
        }
    }

    void sll_source(Layer& l, size_t off, size_t alen) {
        if (alen == 6) {
            d_.src = mac_name(b_.p + off);  // cooked captures carry no destination address
            FIELD(l, "Source", d_.src, off, 6);
            FF(mac("sll.src.eth", b_.p + off));
            if (const char* v = oui_vendor(b_.p + off)) FF(string("sll.src.oui_resolved", v));
        } else if (alen > 0 && alen <= 8) {
            std::string hex;
            for (size_t i = 0; i < alen; ++i) hex += fmt(i ? ":%02x" : "%02x", b_.u8(off + i));
            d_.src = hex;
            FIELD(l, "Source", hex, off, alen);
        }
    }

    void sll(size_t off, int depth) {
        if (!b_.have(off, 16)) return truncated();
        Layer& l = layer("Linux cooked capture v1", off, 16);
        fproto("sll", off, 16);
        uint16_t ptype = b_.u16(off), alen = b_.u16(off + 4), type = b_.u16(off + 14);
        FIELD(l, "Packet type", sll_packet_type(ptype), off, 2);
        FIELD(l, "Link-layer address type", fmt("%u", b_.u16(off + 2)), off + 2, 2);
        sll_source(l, off + 6, alen);
        FIELD(l, "Protocol", fmt("0x%04x", type), off + 14, 2);
        l3(type, off + 16, depth);
    }

    void sll2(size_t off, int depth) {
        if (!b_.have(off, 20)) return truncated();
        Layer& l = layer("Linux cooked capture v2", off, 20);
        fproto("sll", off, 20);
        uint16_t type = b_.u16(off);
        const char* tn = ethertype_name(type);
        FIELD(l, "Protocol", tn ? fmt("%s (0x%04x)", tn, type) : fmt("0x%04x", type), off, 2);
        FIELD(l, "Interface index", fmt("%u", b_.u32(off + 4)), off + 4, 4);
        FIELD(l, "Link-layer address type", fmt("%u", b_.u16(off + 8)), off + 8, 2);
        FIELD(l, "Packet type", sll_packet_type(b_.u8(off + 10)), off + 10, 1);
        sll_source(l, off + 12, b_.u8(off + 11));
        l3(type, off + 20, depth);
    }

    void ppp(size_t off, int depth) {
        size_t start = off;
        if (b_.have(off, 2) && b_.u8(off) == 0xFF && b_.u8(off + 1) == 0x03) off += 2;
        if (!b_.have(off, 1)) return truncated();
        uint16_t proto;
        if (b_.u8(off) & 1) {
            proto = b_.u8(off);
            off += 1;
        } else {
            if (!b_.have(off, 2)) return truncated();
            proto = b_.u16(off);
            off += 2;
        }
        Layer& l = layer("Point-to-Point Protocol", start, off - start);
        fproto("ppp", start, off - start);
        FIELD(l, "Protocol", fmt("0x%04x", proto), start, off - start);
        if (proto == 0x0021) return ipv4(off, depth);
        if (proto == 0x0057) return ipv6(off, depth);
        d_.protocol = proto == 0xC021 ? "PPP LCP" : proto == 0x8021 ? "PPP IPCP" : proto == 0xC023 ? "PPP PAP"
                    : proto == 0xC223 ? "PPP CHAP" : "PPP";
        INFO(fmt("PPP protocol 0x%04x", proto));
    }

    void ieee80211(size_t off, int depth) {
        if (!b_.have(off, 10)) return truncated();
        uint16_t fc = b_.le16(off);
        uint8_t type = (fc >> 2) & 0x3, subtype = (fc >> 4) & 0xF, flags = fc >> 8;
        d_.protocol = "802.11";
        static const char* mgmt[] = {"Association Request", "Association Response", "Reassociation Request",
                                     "Reassociation Response", "Probe Request", "Probe Response",
                                     "Timing Advertisement", "Reserved", "Beacon frame", "ATIM", "Disassociate",
                                     "Authentication", "Deauthentication", "Action", "Action No Ack", "Reserved"};
        static const char* ctrl[] = {"Reserved", "Reserved", "Trigger", "TACK", "Beamforming Report Poll",
                                     "VHT NDP Announcement", "Control Frame Extension", "Control Wrapper",
                                     "802.11 Block Ack Req", "802.11 Block Ack", "Power-Save poll",
                                     "Request-to-send", "Clear-to-send", "Acknowledgement", "CF-End",
                                     "CF-End + CF-Ack"};
        size_t hlen = type == 1 ? (subtype == 12 || subtype == 13 ? 10 : 16) : 24;
        if (type == 2) {
            if ((flags & 0x03) == 0x03) hlen += 6;
            if (subtype & 0x8) hlen += 2 + ((flags & 0x80) ? 4 : 0);
        }
        Layer& l = layer("IEEE 802.11", off, hlen);
        fproto("wlan", off, hlen);
        FIELD(l, "Frame control", fmt("0x%04x (type %u, subtype %u)", fc, type, subtype), off, 2);
        d_.dst = mac_name(b_.p + off + 4);
        FIELD(l, "Receiver address", d_.dst, off + 4, 6);
        if (type != 1 && b_.have(off, 16)) {
            d_.src = mac_name(b_.p + off + 10);
            FIELD(l, "Transmitter address", d_.src, off + 10, 6);
        }
        if (type == 0) {
            std::string name = mgmt[subtype];
            if ((subtype == 8 || subtype == 5 || subtype == 4) && b_.have(off, 24)) {
                size_t ie = off + 24 + (subtype == 4 ? 0 : 12);
                if (b_.have(ie, 2) && b_.u8(ie) == 0 && b_.have(ie + 2, b_.u8(ie + 1))) {
                    std::string ssid = text_line(b_.p + ie + 2, b_.u8(ie + 1), 32);
                    name += ssid.empty() ? ", SSID=Broadcast" : ", SSID=\"" + ssid + "\"";
                    FIELD(l, "SSID", ssid, ie + 2, b_.u8(ie + 1));
                }
            }
            INFO(name);
            return;
        }
        if (type == 1) {
            INFO(ctrl[subtype]);
            return;
        }
        if (type != 2) {
            INFO("Extension frame");
            return;
        }
        bool qos = subtype & 0x8;
        if (flags & 0x40) {
            INFO(std::string(qos ? "QoS Data" : "Data") + ", encrypted");
            if (b_.have(off, hlen)) layer("Encrypted data", off + hlen, b_.n - std::min(b_.n, off + hlen));
            return;
        }
        if (subtype & 0x4) {
            INFO(qos ? "QoS Null function (No data)" : "Null function (No data)");
            return;
        }
        size_t pos = off + hlen;
        if (!b_.have(pos, 8)) return truncated();
        if (b_.u8(pos) == 0xAA && b_.u8(pos + 1) == 0xAA) {
            Layer& s = layer("Logical-Link Control (SNAP)", pos, 8);
            uint16_t et = b_.u16(pos + 6);
            FIELD(s, "Type", fmt("0x%04x", et), pos + 6, 2);
            return ethertype_payload(et, pos + 8, depth);
        }
        INFO(qos ? "QoS Data" : "Data");
    }

    void pktap(size_t off, int depth) {
        if (!b_.have(off, 12)) return truncated();
        size_t len = b_.le32(off);
        auto inner = static_cast<LinkType>(b_.le32(off + 8));
        if (len < 12 || !b_.have(off, len) || inner == LinkType::Pktap || inner == LinkType::User2) return truncated();
        Layer& l = layer("PKTAP", off, len);
        FIELD(l, "Header length", fmt("%zu", len), off, 4);
        FIELD(l, "DLT", fmt("%d", static_cast<int>(inner)), off + 8, 4);
        if (len >= 36) FIELD(l, "Interface", text_line(b_.p + off + 12, 24, 24), off + 12, 24);
        if (len >= 73 && full_) {
            int32_t pid = static_cast<int32_t>(b_.le32(off + 52));
            std::string comm;
            for (size_t i = 0; i < 17 && b_.u8(off + 56 + i); ++i) {
                unsigned char ch = b_.u8(off + 56 + i);
                comm.push_back(ch >= 0x20 && ch < 0x7f ? static_cast<char>(ch) : '.');
            }
            field(l, "Process", fmt("%s (%d)", comm.c_str(), pid), off + 52, 21);
        }
        link_layer(inner, off + len, depth + 1);
    }

    void nflog(size_t off, int depth) {
        if (!b_.have(off, 4)) return truncated();
        Layer& l = layer("Linux Netfilter NFLOG", off, 4);
        fproto("nflog", off, 4);
        uint8_t fam = b_.u8(off);
        FIELD(l, "Family", fam == 2 ? "IPv4" : fam == 10 ? "IPv6" : fmt("%u", fam), off, 1);
        size_t pos = off + 4;
        while (b_.have(pos, 4)) {
            size_t tlv_len = b_.le16(pos);
            uint16_t type = b_.le16(pos + 2);
            if (tlv_len < 4 || !b_.have(pos, tlv_len)) return truncated();
            if (type == 10 && full_ && !d_.layers.empty())
                field(d_.layers.back(), "Prefix", text_line(b_.p + pos + 4, tlv_len - 4), pos + 4, tlv_len - 4);
            if (type == 9) {
                Bytes saved = b_;
                b_.n = std::min(b_.n, pos + tlv_len);
                l3(0, pos + 4, depth);
                b_ = saved;
                return;
            }
            pos += (tlv_len + 3) & ~static_cast<size_t>(3);
        }
        d_.protocol = "NFLOG";
        INFO("NFLOG (no payload)");
    }

    // ------------------------------------------------------------ L3
    void l3(uint16_t type, size_t off, int depth) {
        if (type == 0) {
            if (!b_.have(off, 1)) return truncated();
            uint8_t v = b_.u8(off) >> 4;
            if (v == 4) return ipv4(off, depth);
            if (v == 6) return ipv6(off, depth);
            layer("Data", off, b_.n - off);
            return;
        }
        if (type == 0x0800) return ipv4(off, depth);
        if (type == 0x86DD) return ipv6(off, depth);
        if (type == 0x0806) return arp(off);
        if (type == 0x88CC) return lldp(off);
        const char* tn = ethertype_name(type);
        d_.protocol = tn ? tn : fmt("0x%04x", type);
        INFO(tn ? fmt("%s frame", tn) : fmt("Ethernet II, type 0x%04x", type));
        if (b_.n > off) layer("Data", off, b_.n - off);
    }

    void arp(size_t off) {
        d_.protocol = "ARP";
        if (!b_.have(off, 8)) return truncated();
        uint8_t hlen = b_.u8(off + 4), plen = b_.u8(off + 5);
        uint16_t op = b_.u16(off + 6);
        if (hlen != 6 || plen != 4 || !b_.have(off, 28)) {
            layer("Address Resolution Protocol", off, b_.n - off);
            fproto("arp", off, b_.n - off);
            FF(uint("arp.opcode", op));
            INFO(fmt("ARP opcode %u", op));
            return;
        }
        if (!full_) return;
        Layer& l = layer("Address Resolution Protocol", off, 28);
        fproto("arp", off, 28);
        FF(uint("arp.opcode", op));
        FF(mac("arp.src.hw_mac", b_.p + off + 8));
        FF(ipv4("arp.src.proto_ipv4", b_.p + off + 14));
        FF(mac("arp.dst.hw_mac", b_.p + off + 18));
        FF(ipv4("arp.dst.proto_ipv4", b_.p + off + 24));
        std::string sha = mac_raw(b_.p + off + 8), spa = ipv4s(b_.p + off + 14);
        std::string tha = mac_raw(b_.p + off + 18), tpa = ipv4s(b_.p + off + 24);
        field(l, "Opcode", op == 1 ? "request (1)" : op == 2 ? "reply (2)" : fmt("%u", op), off + 6, 2);
        field(l, "Sender MAC address", sha, off + 8, 6);
        field(l, "Sender IP address", spa, off + 14, 4);
        field(l, "Target MAC address", tha, off + 18, 6);
        field(l, "Target IP address", tpa, off + 24, 4);
        bool zero_tha = tha == "00:00:00:00:00:00";
        if (op == 1 && spa == tpa && zero_tha) d_.info = fmt("ARP Announcement for %s", spa.c_str());
        else if (op == 1 && spa == "0.0.0.0") d_.info = fmt("Who has %s? (ARP Probe)", tpa.c_str());
        else if (spa == tpa) d_.info = fmt("Gratuitous ARP for %s (%s)", spa.c_str(), op == 1 ? "Request" : "Reply");
        else if (op == 1) d_.info = fmt("Who has %s? Tell %s", tpa.c_str(), spa.c_str());
        else if (op == 2) d_.info = fmt("%s is at %s", spa.c_str(), sha.c_str());
        else d_.info = fmt("ARP opcode %u", op);
    }

    void lldp(size_t off) {
        d_.protocol = "LLDP";
        if (!full_) return;
        Layer& l = layer("Link Layer Discovery Protocol", off, b_.n - std::min(off, b_.n));
        fproto("lldp", off, b_.n - std::min(off, b_.n));
        std::string chassis, port, name;
        size_t pos = off;
        for (int i = 0; i < 32 && b_.have(pos, 2); ++i) {
            uint16_t h = b_.u16(pos);
            uint16_t type = h >> 9, len = h & 0x1FF;
            if (type == 0 || !b_.have(pos + 2, len)) break;
            const uint8_t* v = b_.p + pos + 2;
            if (type == 1 && len > 1) chassis = len == 7 ? mac_raw(v + 1) : text_line(v + 1, len - 1, 64);
            if (type == 2 && len > 1) port = text_line(v + 1, len - 1, 64);
            if (type == 5) name = text_line(v, len, 64);
            pos += 2 + len;
        }
        field(l, "Chassis", chassis, off, 0);
        field(l, "Port", port, off, 0);
        if (!name.empty()) field(l, "System name", name, off, 0);
        d_.info = fmt("Name=%s Port=%s", name.empty() ? chassis.c_str() : name.c_str(), port.c_str());
    }

    void ipv4(size_t off, int depth) {
        d_.protocol = "IPv4";
        if (!b_.have(off, 20)) {  // truncated header: still show what addresses survived
            if (b_.have(off, 16)) d_.src = ipv4s(b_.p + off + 12);
            if (b_.have(off, 20)) d_.dst = ipv4s(b_.p + off + 16);
            if (ff_ && b_.have(off, 1) && (b_.u8(off) >> 4) == 4) {
                fproto("ip", off, b_.n - off);
                size_t reported = std::max(wire_len_, b_.n);
                reported = reported > off ? reported - off : 0;
                if (b_.have(off, 4) && b_.u16(off + 2) > reported && !in_error_)
                    expert("ip.bogus_ip_length", 3, "Protocol", "IPv4",
                           fmt("IPv4 total length exceeds packet length (%zu bytes)", reported));
                FF(uint("ip.version", 4));
                FF(uint("ip.hdr_len", (b_.u8(off) & 0x0Fu) * 4u));
                if (b_.have(off, 2)) FF(uint("ip.dsfield.dscp", b_.u8(off + 1) >> 2));
                if (b_.have(off, 4)) FF(uint("ip.len", b_.u16(off + 2)));
                if (b_.have(off, 6)) FF(uint("ip.id", b_.u16(off + 4)));
                if (b_.have(off, 8)) {
                    uint16_t fr = b_.u16(off + 6);
                    FF(boolean("ip.flags.rb", fr & 0x8000));
                    FF(boolean("ip.flags.df", fr & 0x4000));
                    FF(boolean("ip.flags.mf", fr & 0x2000));
                    FF(uint("ip.frag_offset", (fr & 0x1FFFu) * 8u));
                }
                if (b_.have(off, 9)) FF(uint("ip.ttl", b_.u8(off + 8)));
                if (b_.have(off, 10)) FF(uint("ip.proto", b_.u8(off + 9)));
                if (b_.have(off, 16)) {
                    FF(ipv4("ip.src", b_.p + off + 12));
                    FF(ipv4("ip.addr", b_.p + off + 12));
                }
            }
            return truncated();
        }
        if ((b_.u8(off) >> 4) != 4) return truncated();
        size_t ihl = static_cast<size_t>(b_.u8(off) & 0x0F) * 4;
        if (ihl < 20 || !b_.have(off, ihl)) return truncated();
        uint16_t total = b_.u16(off + 2), frag = b_.u16(off + 6);
        uint8_t proto = b_.u8(off + 9);
        {
            size_t reported = std::max(wire_len_, b_.n);
            reported = reported > off ? reported - off : 0;
            if (total && total > reported && !in_error_)
                expert("ip.bogus_ip_length", 3, "Protocol", "IPv4",
                       fmt("IPv4 total length exceeds packet length (%zu bytes)", reported));
        }
        Layer& l = layer("Internet Protocol Version 4", off, ihl);
        src_ip_ = IpAddr();
        dst_ip_ = IpAddr();
        src_ip_.family = dst_ip_.family = 4;
        std::memcpy(src_ip_.bytes.data(), b_.p + off + 12, 4);
        std::memcpy(dst_ip_.bytes.data(), b_.p + off + 16, 4);
        d_.src = ipv4s(b_.p + off + 12);
        d_.dst = ipv4s(b_.p + off + 16);
        ttl_ = b_.u8(off + 8);
        if (ff_) {
            fproto("ip", off, (total >= ihl && total != 0) ? total : b_.n - off);
            FF(uint("ip.version", 4));
            FF(uint("ip.hdr_len", ihl));
            FF(uint("ip.dsfield.dscp", b_.u8(off + 1) >> 2));
            FF(uint("ip.len", total));
            FF(uint("ip.id", b_.u16(off + 4)));
            FF(boolean("ip.flags.rb", frag & 0x8000));
            FF(boolean("ip.flags.df", frag & 0x4000));
            FF(boolean("ip.flags.mf", frag & 0x2000));
            FF(uint("ip.frag_offset", (frag & 0x1FFFu) * 8u));
            FF(uint("ip.ttl", ttl_));
            // Wireshark's TTL notes: the Local Network Control Block (224.0.0.0/24) expects
            // TTL 1 (255 for VRRP, GLBP and mDNS); elsewhere, a TTL under 5 on a unicast or
            // broadcast packet is noted, except for PIM and OSPF.
            const uint8_t* da = b_.p + off + 16;
            if (da[0] == 224 && da[1] == 0 && da[2] == 0) {
                unsigned want = (da[3] == 18 || da[3] == 102 || da[3] == 251) ? 255 : 1;
                if (ttl_ != want && proto != 103) expert("ip.ttl.lncb");
            } else if ((da[0] & 0xF0) != 0xE0 && ttl_ < 5 && proto != 103 && proto != 89) {
                expert("ip.ttl.too_small");
            }
            FF(uint("ip.proto", proto));
            FF(ipv4("ip.src", b_.p + off + 12));
            FF(ipv4("ip.dst", b_.p + off + 16));
            FF(ipv4("ip.addr", b_.p + off + 12));
            FF(ipv4("ip.addr", b_.p + off + 16));
        }
        if (full_) {
            field(l, "Version", "4", off, 1);
            field(l, "Header length", fmt("%zu bytes", ihl), off, 1);
            field(l, "Differentiated services", fmt("0x%02x", b_.u8(off + 1)), off + 1, 1);
            field(l, "Total length", fmt("%u", total), off + 2, 2);
            field(l, "Identification", fmt("0x%04x (%u)", b_.u16(off + 4), b_.u16(off + 4)), off + 4, 2);
            std::string flags = (frag & 0x4000) ? "Don't fragment" : "";
            if (frag & 0x2000) flags += flags.empty() ? "More fragments" : ", More fragments";
            field(l, "Flags", fmt("0x%x", frag >> 13) + (flags.empty() ? "" : ", " + flags), off + 6, 2);
            field(l, "Fragment offset", fmt("%u", (frag & 0x1FFF) * 8), off + 6, 2);
            field(l, "Time to live", fmt("%u", ttl_), off + 8, 1);
            field(l, "Protocol", fmt("%s (%u)", ip_proto_name(proto).c_str(), proto), off + 9, 1);
            field(l, "Header checksum", fmt("0x%04x", b_.u16(off + 10)), off + 10, 2);
            field(l, "Source address", d_.src, off + 12, 4);
            field(l, "Destination address", d_.dst, off + 16, 4);
        }
        size_t end = (total >= ihl && total != 0) ? std::min(b_.n, off + total) : b_.n;  // drop link padding
        if ((frag & 0x2000) || (frag & 0x1FFF)) return ipv4_fragment(off, ihl, end, frag, proto, depth);
        l4_reported_ = total >= ihl && total != 0 ? total - ihl : 0;
        l4(proto, off + ihl, end, depth);
    }

    // Collect IPv4 fragments; the frame that completes a datagram decodes it whole.
    void ipv4_fragment(size_t off, size_t ihl, size_t end, uint16_t frag, uint8_t proto, int depth) {
        uint32_t foff = (frag & 0x1FFF) * 8u;
        bool more = frag & 0x2000;
        uint16_t id = b_.u16(off + 4);
        std::string key = d_.src + "|" + d_.dst + "|" + std::to_string(id) + "|" + std::to_string(proto);
        if (st_.frags.size() > 1000) st_.frags.clear();
        auto& fr = st_.frags[key];
        fr.proto = proto;
        size_t plen = end > off + ihl ? end - off - ihl : 0;
        if (foff == 0) fr.header.assign(reinterpret_cast<const char*>(b_.p + off), ihl);
        if (foff + plen <= 65535) {
            if (fr.data.size() < foff + plen) fr.data.resize(foff + plen);
            std::memcpy(&fr.data[foff], b_.p + off + ihl, plen);
            fr.pieces.emplace_back(foff, static_cast<uint32_t>(foff + plen));
        }
        fr.frames.push_back(frame_);
        if (!more) fr.total = static_cast<uint32_t>(foff + plen);
        // Complete once the pieces cover [0, total).
        bool complete = false;
        if (fr.total && !fr.header.empty()) {
            auto pieces = fr.pieces;
            std::sort(pieces.begin(), pieces.end());
            uint32_t covered = 0;
            for (auto& pc : pieces) {
                if (pc.first > covered) break;
                covered = std::max(covered, pc.second);
            }
            complete = covered >= fr.total;
        }
        if (!complete) {
            std::string info = fmt("Fragmented IP protocol (proto=%s %u, off=%u, ID=%04x)", ip_proto_name(proto).c_str(),
                                   proto, foff, id);
            if (st_.use) {
                auto it = st_.use->fragment_in.find(frame_);
                if (it != st_.use->fragment_in.end()) info += fmt(" [Reassembled in #%llu]", static_cast<unsigned long long>(it->second));
            }
            INFO(info);
            if (plen) {
                layer("Fragment data", off + ihl, plen);
                fproto("data", off + ihl, plen);
            }
            return;
        }
        if (st_.record)
            for (uint64_t f : fr.frames)
                if (f != frame_) st_.record->fragment_in[f] = frame_;
        // Decode the reassembled datagram from a synthesized, unfragmented copy.
        std::string whole = fr.header;
        whole += fr.data.substr(0, fr.total);
        size_t total_len = whole.size();
        whole[2] = static_cast<char>(total_len >> 8);
        whole[3] = static_cast<char>(total_len & 0xFF);
        whole[6] = 0;
        whole[7] = 0;
        size_t nfrags = fr.frames.size(), header_len = fr.header.size();
        st_.frags.erase(key);  // `fr` is gone from here on
        Decoder sub(st_, reinterpret_cast<const uint8_t*>(whole.data()), whole.size(), frame_, ts_, full_);
        sub.ff_ = ff_;
        sub.ff_virtual_ = true;
        FrameFields::Mark before = ff_ ? ff_->mark() : FrameFields::Mark{0, 0};
        sub.ipv4(0, depth + 1);
        if (ff_) {  // the rebuilt header repeats this frame's IP fields: drop the copies
            auto& fs = ff_->fields;
            fs.erase(std::remove_if(fs.begin() + static_cast<std::ptrdiff_t>(before.fields), fs.end(),
                                    [](const FrameFields::Field& f) { return std::strncmp(f.name, "ip.", 3) == 0; }),
                     fs.end());
            auto& ps = ff_->protos;
            ps.erase(std::remove_if(ps.begin() + static_cast<std::ptrdiff_t>(before.protos), ps.end(),
                                    [](const FrameFields::Proto& pr) {
                                        return std::strcmp(pr.name, "ip") == 0 || std::strncmp(pr.name, "ip.", 3) == 0;
                                    }),
                     ps.end());
        }
        d_.protocol = sub.d_.protocol;
        d_.exceeds_mss = d_.exceeds_mss || sub.d_.exceeds_mss;
        for (auto& note : sub.d_.notes)
            if (note.protocol != "IPv4" && d_.notes.size() < 64) d_.notes.push_back(std::move(note));
        if (full_) {
            d_.info = sub.d_.info;
            layer("Reassembled IPv4 datagram", off + ihl, plen)
                .fields.push_back({"Reassembled from", fmt("%zu fragments, %zu bytes", nfrags, total_len - header_len),
                                   static_cast<uint32_t>(off + ihl), 0});
        }
    }

    void ipv6(size_t off, int depth) {
        d_.protocol = "IPv6";
        if (!b_.have(off, 40)) return truncated();
        if ((b_.u8(off) >> 4) != 6) return truncated();
        Layer& l = layer("Internet Protocol Version 6", off, 40);
        uint32_t vtf = b_.u32(off);
        uint16_t plen = b_.u16(off + 4);
        uint8_t next = b_.u8(off + 6);
        src_ip_ = IpAddr();
        dst_ip_ = IpAddr();
        src_ip_.family = dst_ip_.family = 6;
        std::memcpy(src_ip_.bytes.data(), b_.p + off + 8, 16);
        std::memcpy(dst_ip_.bytes.data(), b_.p + off + 24, 16);
        d_.src = ipv6s(b_.p + off + 8);
        d_.dst = ipv6s(b_.p + off + 24);
        ttl_ = b_.u8(off + 7);
        if (ff_) {
            fproto("ipv6", off, 40u + plen);
            FF(uint("ipv6.tclass", (vtf >> 20) & 0xFF));
            FF(uint("ipv6.flow", vtf & 0xFFFFF));
            FF(uint("ipv6.plen", plen));
            FF(uint("ipv6.nxt", next));
            FF(uint("ipv6.hlim", ttl_));
            FF(ipv6("ipv6.src", b_.p + off + 8));
            FF(ipv6("ipv6.dst", b_.p + off + 24));
            FF(ipv6("ipv6.addr", b_.p + off + 8));
            FF(ipv6("ipv6.addr", b_.p + off + 24));
        }
        if (full_) {
            field(l, "Version", "6", off, 1);
            field(l, "Traffic class", fmt("0x%02x", (vtf >> 20) & 0xFF), off, 2);
            field(l, "Flow label", fmt("0x%05x", vtf & 0xFFFFF), off + 1, 3);
            field(l, "Payload length", fmt("%u", plen), off + 4, 2);
            field(l, "Next header", fmt("%s (%u)", ip_proto_name(next).c_str(), next), off + 6, 1);
            field(l, "Hop limit", fmt("%u", ttl_), off + 7, 1);
            field(l, "Source address", d_.src, off + 8, 16);
            field(l, "Destination address", d_.dst, off + 24, 16);
        }
        size_t pos = off + 40;
        size_t end = plen ? std::min(b_.n, pos + plen) : b_.n;
        for (int hops = 0; hops < 8; ++hops) {
            if (next == 0 || next == 43 || next == 60 || next == 51) {
                if (!b_.have(pos, 2)) return truncated();
                size_t len = next == 51 ? (static_cast<size_t>(b_.u8(pos + 1)) + 2) * 4
                                        : (static_cast<size_t>(b_.u8(pos + 1)) + 1) * 8;
                const char* name = next == 0 ? "IPv6 Hop-by-Hop Option" : next == 43 ? "Routing Header for IPv6"
                                 : next == 60 ? "Destination Options for IPv6" : "Authentication Header";
                Layer& e = layer(name, pos, len);
                FIELD(e, "Next header", fmt("%s (%u)", ip_proto_name(b_.u8(pos)).c_str(), b_.u8(pos)), pos, 1);
                FIELD(e, "Length", fmt("%zu bytes", len), pos + 1, 1);
                next = b_.u8(pos);
                pos += len;
                if (pos > end) return truncated();
                continue;
            }
            if (next == 44) {
                if (!b_.have(pos, 8)) return truncated();
                Layer& e = layer("Fragment Header for IPv6", pos, 8);
                uint16_t fo = b_.u16(pos + 2);
                FIELD(e, "Offset", fmt("%u", (fo >> 3) * 8), pos + 2, 2);
                FIELD(e, "More fragments", (fo & 1) ? "Yes" : "No", pos + 2, 2);
                INFO(fmt("IPv6 fragment (off=%u more=%c ident=0x%08x nxt=%u)", (fo >> 3) * 8, (fo & 1) ? 'y' : 'n',
                         b_.u32(pos + 4), b_.u8(pos)));
                return;
            }
            break;
        }
        l4_reported_ = plen && off + 40 + plen >= pos ? off + 40 + plen - pos : 0;
        l4(next, pos, end, depth);
    }

    // ------------------------------------------------------------ L4
    void l4(uint8_t proto, size_t off, size_t end, int depth) {
        switch (proto) {
            case 6: return tcp(off, end);
            case 17: return udp(off, end, depth);
            case 1: return icmp(off, end);
            case 58: return icmpv6(off, end);
            case 2: return igmp(off, end);
            case 4:
            case 41:
                if (depth < 4) {
                    layer("IP-in-IP encapsulation", off, 0);
                    return proto == 4 ? ipv4(off, depth + 1) : ipv6(off, depth + 1);
                }
                break;
            case 47: return gre(off, end, depth);
            default: break;
        }
        std::string name = ip_proto_name(proto);
        d_.protocol = name.rfind("IP proto", 0) == 0 ? d_.protocol : name;
        INFO(name);
        if (end > off) layer("Data", off, end - off);
    }

    void gre(size_t off, size_t end, int depth) {
        d_.protocol = "GRE";
        if (!b_.have(off, 4)) return truncated();
        uint16_t flags = b_.u16(off), type = b_.u16(off + 2);
        size_t hlen = 4 + ((flags & 0x8000) ? 4 : 0) + ((flags & 0x2000) ? 4 : 0) + ((flags & 0x1000) ? 4 : 0);
        if ((flags & 0x7) == 1) hlen = 8 + ((flags & 0x1000) ? 4 : 0) + ((flags & 0x0080) ? 4 : 0);  // PPTP
        Layer& l = layer("Generic Routing Encapsulation", off, hlen);
        fproto("gre", off, hlen);
        FIELD(l, "Protocol type", fmt("0x%04x", type), off + 2, 2);
        INFO(fmt("Encapsulated 0x%04x", type));
        size_t inner = off + hlen;
        if (depth >= 4 || inner >= end) return;
        if (type == 0x88BE || type == 0x22EB) {
            size_t ehl = type == 0x88BE ? 8 : 12;
            if (type == 0x22EB && b_.have(inner, 12) && (b_.u8(inner + 11) & 1)) ehl += 8;
            fproto("erspan", inner, ehl);
            layer(type == 0x88BE ? "Encapsulated Remote Switch Packet ANalysis Type II"
                                 : "Encapsulated Remote Switch Packet ANalysis Type III", inner, ehl);
            return ethernet(inner + ehl, depth + 1);
        }
        if (type == 0x6558) return ethernet(inner, depth + 1);
        if (type == 0x0800 || type == 0x86DD) return l3(type, inner, depth + 1);
        if (type == 0x880B) return ppp(inner, depth + 1);
    }

    // Conversation state for the current IP pair and ports.
    InspectorState::Conv& conversation(uint8_t proto, uint16_t sport, uint16_t dport, int& dir) {
        PacketInfo pi;
        pi.src = src_ip_;
        pi.dst = dst_ip_;
        pi.sport = sport;
        pi.dport = dport;
        pi.proto = proto;
        bool a_to_b = false;
        key_ = FlowKey::from_packet(pi, a_to_b);
        l4_key_ = key_;
        dir = a_to_b ? 0 : 1;
        return st_.conv(key_);
    }

    // Walks TCP options. The window scale and SACK blocks feed the analysis;
    // the Info suffix and the fields are only built when displaying.
    // Whether the TCP options in [off, off + len) include SACK blocks.
    bool has_sack_option(size_t off, size_t len) const {
        size_t pos = off, end = std::min(off + len, b_.n);
        while (pos < end) {
            uint8_t kind = b_.u8(pos);
            if (kind == 0) return false;
            if (kind == 1) { ++pos; continue; }
            if (pos + 1 >= end) return false;
            size_t olen = b_.u8(pos + 1);
            if (olen < 2 || pos + olen > end) return false;
            if (kind == 5 && olen >= 10) return true;
            pos += olen;
        }
        return false;
    }

    std::string tcp_options(size_t off, size_t len, uint32_t sack_base, int* ws_shift, InspectorState::Dir& fwd,
                            Layer& l) {
        std::string out;
        size_t pos = off, end = off + len;
        while (pos < end) {
            uint8_t kind = b_.u8(pos);
            FF(uint("tcp.option_kind", kind));  // each option in order: the SYN's are an OS fingerprint
            if (kind == 0) break;
            if (kind == 1) {
                ++pos;
                continue;
            }
            if (pos + 1 >= end) break;
            size_t olen = b_.u8(pos + 1);
            if (olen < 2 || pos + olen > end) break;
            if (kind == 3 && olen == 3) {
                *ws_shift = static_cast<int>(std::min<unsigned>(b_.u8(pos + 2), 14));
                FF(uint("tcp.options.wscale.shift", b_.u8(pos + 2)));
            }
            if (kind == 2 && olen == 4) {
                FF(uint("tcp.options.mss_val", b_.u16(pos + 2)));
                fwd.mss = b_.u16(pos + 2);
            }
            if (kind == 5)
                for (size_t b = pos + 2; b + 8 <= pos + olen && fwd.num_sack < 4; b += 8) {
                    fwd.sack_le[fwd.num_sack] = b_.u32(b) - sack_base;
                    fwd.sack_re[fwd.num_sack++] = b_.u32(b + 4) - sack_base;
                }
            if (full_) {
                switch (kind) {
                    case 2:
                        if (olen == 4) {
                            out += fmt(" MSS=%u", b_.u16(pos + 2));
                            field(l, "Option: Maximum segment size", fmt("%u bytes", b_.u16(pos + 2)), pos, olen);
                        }
                        break;
                    case 3:
                        if (olen == 3) {
                            unsigned shift = std::min<unsigned>(b_.u8(pos + 2), 14);
                            out += fmt(" WS=%u", 1u << shift);
                            field(l, "Option: Window scale", fmt("%u (multiply by %u)", shift, 1u << shift), pos, olen);
                        }
                        break;
                    case 4:
                        out += " SACK_PERM";
                        field(l, "Option: SACK permitted", "", pos, olen);
                        break;
                    case 5:
                        for (size_t b = pos + 2; b + 8 <= pos + olen; b += 8)
                            out += fmt(" SLE=%u SRE=%u", b_.u32(b) - sack_base, b_.u32(b + 4) - sack_base);
                        field(l, "Option: SACK", fmt("%zu block(s)", (olen - 2) / 8), pos, olen);
                        break;
                    case 8:
                        if (olen == 10) {
                            out += fmt(" TSval=%u TSecr=%u", b_.u32(pos + 2), b_.u32(pos + 6));
                            field(l, "Option: Timestamps", fmt("TSval %u, TSecr %u", b_.u32(pos + 2), b_.u32(pos + 6)),
                                  pos, olen);
                        }
                        break;
                    case 30: field(l, "Option: Multipath TCP", "", pos, olen); break;
                    case 34: out += olen > 2 ? " TFO=C" : " TFO=R"; break;
                    default: field(l, fmt("Option: kind %u", kind), fmt("%zu bytes", olen), pos, olen);
                }
            }
            pos += olen;
        }
        return out;
    }

    // TCP analysis flags (Wireshark's TCP_A_*).
    enum : uint32_t {
        kRetrans = 0x1, kLost = 0x2, kAckLost = 0x4, kKeepAlive = 0x8, kDupAck = 0x10, kZeroWin = 0x20,
        kZwp = 0x40, kZwpAck = 0x80, kKaAck = 0x100, kOoo = 0x200, kFastRetrans = 0x400, kWinUpdate = 0x800,
        kWinFull = 0x1000, kReused = 0x2000, kSpurious = 0x4000, kOldData = 0x8000,
        // Reported in the SEQ/ACK analysis but not among tcp.analysis.flags.
        kPartialAck = 0x10000, kAmbiguousAck = 0x20000,
    };
    struct AckInfo {
        uint64_t acks_frame = 0;  // the segment this ACK answers
        uint64_t rtt_us = 0;
    };
    static bool seq_gt(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) > 0; }
    static bool seq_lt(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) < 0; }
    static bool seq_ge(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) >= 0; }
    static bool seq_le(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) <= 0; }

    void release(InspectorState::Conv& c) {
        for (auto& d : c.dir)
            for (auto& kv : d.msps) st_.msp_bytes -= std::min(st_.msp_bytes, kv.second.data.size());
    }

    void tcp(size_t off, size_t end) {
        constexpr uint8_t kFin = 0x01, kSyn = 0x02, kRst = 0x04, kAck = 0x10;
        d_.protocol = "TCP";
        if (in_error_ && !b_.have(off, 20)) {
            // An ICMP error quotes only the first 8 bytes: Wireshark still names the
            // ports and sequence number, so filters on them find the error too.
            if (ff_ && b_.have(off, 8) && (end >= off + 8)) {
                fproto("tcp", off, end - off);
                FF(uint("tcp.srcport", b_.u16(off)));
                FF(uint("tcp.dstport", b_.u16(off + 2)));
                FF(uint("tcp.port", b_.u16(off)));
                FF(uint("tcp.port", b_.u16(off + 2)));
                FF(uint("tcp.seq", b_.u32(off + 4)));
            }
            return truncated();
        }
        if (!b_.have(off, 20)) return truncated();
        size_t hlen = static_cast<size_t>(b_.u8(off + 12) >> 4) * 4;
        if (hlen < 20 || !b_.have(off, hlen)) return truncated();
        uint16_t sport = b_.u16(off), dport = b_.u16(off + 2);
        uint32_t seq = b_.u32(off + 4), ack = b_.u32(off + 8);
        uint8_t flags = b_.u8(off + 13);
        uint16_t win = b_.u16(off + 14);
        size_t pay = off + hlen;
        size_t cap = end > pay ? end - pay : 0;
        // Len= and the analysis use the length the IP header reports, even when the
        // capture cut the frame short.
        uint32_t seglen = l4_reported_ >= hlen ? static_cast<uint32_t>(l4_reported_ - hlen) : static_cast<uint32_t>(cap);
        cap = std::min<size_t>(cap, seglen);
        bool syn = flags & kSyn, fin = flags & kFin, rst = flags & kRst, ackf = flags & kAck;
        sport_ = sport;
        dport_ = dport;

        int di = 0;
        InspectorState::Conv* c = &conversation(6, sport, dport, di);
        uint32_t fl = 0;
        {  // A SYN that doesn't continue the connection we know starts a new one.
            auto& f0 = c->dir[di];
            bool fresh = false;
            if ((flags & (kSyn | kAck)) == kSyn && f0.base_set) {
                if (seq != f0.base || c->fin_or_rst) fresh = true;
                else f0.nextseq = f0.maxseqtobeacked;
            } else if ((flags & (kSyn | kAck)) == (kSyn | kAck) && f0.base_set && (seq != f0.base || c->fin_or_rst)) {
                fresh = true;
            }
            if (fresh) {
                release(*c);
                *c = InspectorState::Conv();
                fl |= kReused;
            }
        }
        if (c->stream == ~0ULL) c->stream = st_.next_tcp_stream++;
        auto& fwd = c->dir[di];
        auto& rev = c->dir[1 - di];
        fwd.num_sack = 0;
        if (!fwd.base_set) {
            fwd.base = syn ? seq : seq - 1;
            fwd.base_set = true;
        }
        if (!rev.base_set && ackf) {
            rev.base = ack - 1;
            rev.base_set = true;
        }
        uint32_t rseq = seq - fwd.base, rack = ack - rev.base;
        uint32_t dup_num = 0;
        uint64_t dup_frame = 0;
        AckInfo acked;
        sack_now_ = hlen > 20 && has_sack_option(off + 20, std::min(hlen, b_.n - std::min(off, b_.n)) - 20);
        fl |= analyze_tcp(*c, fwd, rev, seq, ack, seglen, flags, win, dup_num, dup_frame, acked);
        // Wireshark notes (in its expert tap only) a segment longer than the MSS its
        // sender announced; a SYN without the option implies the default MSS.
        if (syn) fwd.mss = src_ip_.family == 6 ? 1220 : 536;  // the MSS option, if any, overrides this
        if (fwd.mss && seglen > fwd.mss) d_.exceeds_mss = true;
        bool fin_active = false;
        if (fin) {  // every FIN from the side that closed first is "active", retransmissions too
            if (c->first_fin_dir < 0) c->first_fin_dir = static_cast<int8_t>(di);
            fin_active = c->first_fin_dir == di;
        }

        if (syn) {
            if (ackf) {
                c->server_port = sport;
                if (c->client < 0) c->client = 1 - di;
            } else {
                c->server_port = dport;
                c->client = di;
                c->syn_time = ts_;
            }
            fwd.is_first_ack = true;
        }
        if ((flags & (kSyn | kAck)) == kAck) {
            if (c->syn_time && !c->first_rtt && ts_ > c->syn_time) c->first_rtt = ts_ - c->syn_time;
            fwd.is_first_ack = false;
        }
        if ((flags & (kFin | kAck)) == (kFin | kAck) || rst) c->fin_or_rst = true;
        uint32_t shown_win = !syn && fwd.win_scale >= 0 ? static_cast<uint32_t>(win) << fwd.win_scale : win;

        Layer& l = layer("Transmission Control Protocol", off, hlen);
        if (ff_) {
            fproto("tcp", off, end > off ? end - off : hlen);
            FF(uint("tcp.srcport", sport));
            FF(uint("tcp.dstport", dport));
            FF(uint("tcp.port", sport));
            FF(uint("tcp.port", dport));
            FF(uint("tcp.stream", c->stream));
            FF(uint("tcp.len", seglen));
            FF(uint("tcp.seq", rseq));
            FF(uint("tcp.seq_raw", seq));
            if (seglen || syn || fin) FF(uint("tcp.nxtseq", rseq + seglen + ((syn || fin) ? 1u : 0u)));
            if (ackf) {
                FF(uint("tcp.ack", rack));
                FF(uint("tcp.ack_raw", ack));
            }
            FF(uint("tcp.hdr_len", hlen));
            FF(uint("tcp.flags", (static_cast<unsigned>(b_.u8(off + 12) & 0x0F) << 8) | flags));
            static const char* fnames[] = {"tcp.flags.fin", "tcp.flags.syn", "tcp.flags.reset", "tcp.flags.push",
                                           "tcp.flags.ack", "tcp.flags.urg", "tcp.flags.ece", "tcp.flags.cwr"};
            for (int i = 0; i < 8; ++i) FF(boolean(fnames[i], flags & (1 << i)));
            FF(uint("tcp.flags.res", (b_.u8(off + 12) & 0x0Eu) >> 1));  // reserved: must be zero (AE, 0x01, is AccECN's)
            FF(uint("tcp.window_size_value", win));
            FF(uint("tcp.window_size", shown_win));
            FF(uint("tcp.urgent_pointer", b_.u16(off + 18)));
            static const std::pair<uint32_t, const char*> analysis[] = {
                {kRetrans, "tcp.analysis.retransmission"}, {kFastRetrans, "tcp.analysis.fast_retransmission"},
                {kSpurious, "tcp.analysis.spurious_retransmission"}, {kOoo, "tcp.analysis.out_of_order"},
                {kReused, "tcp.analysis.reused_ports"}, {kLost, "tcp.analysis.lost_segment"},
                {kAckLost, "tcp.analysis.ack_lost_segment"}, {kWinUpdate, "tcp.analysis.window_update"},
                {kWinFull, "tcp.analysis.window_full"}, {kKeepAlive, "tcp.analysis.keep_alive"},
                {kKaAck, "tcp.analysis.keep_alive_ack"}, {kDupAck, "tcp.analysis.duplicate_ack"},
                {kZwp, "tcp.analysis.zero_window_probe"}, {kZeroWin, "tcp.analysis.zero_window"},
                {kZwpAck, "tcp.analysis.zero_window_probe_ack"}};
            bool any = false;
            for (const auto& [bit, name] : analysis)
                if (fl & bit) {
                    if (!any) fproto("tcp.analysis.flags", 0, 0);
                    any = true;
                    fproto(name, 0, 0);
                }
            if ((fl & (kFastRetrans | kSpurious)) && !(fl & kRetrans)) fproto("tcp.analysis.retransmission", 0, 0);
            if (fl & kDupAck) {
                FF(uint("tcp.analysis.duplicate_ack_num", dup_num));
                FF(uint("tcp.analysis.duplicate_ack_frame", dup_frame));
            }
            if (any) expert("tcp.analysis.flags");
            if (fl & kPartialAck) expert("tcp.analysis.partial_ack");
            if (fl & kAmbiguousAck) expert("tcp.analysis.ambiguous_ack");
            if (acked.acks_frame) {
                FF(uint("tcp.analysis.acks_frame", acked.acks_frame));
                FF(real("tcp.analysis.ack_rtt", static_cast<double>(acked.rtt_us) / 1e6));
            }
            if (c->first_rtt) FF(real("tcp.analysis.initial_rtt", static_cast<double>(c->first_rtt) / 1e6));
            if (syn) expert(ackf ? "tcp.connection.synack" : "tcp.connection.syn");
            if (fin) {
                expert("tcp.connection.fin");
                expert(fin_active ? "tcp.connection.fin_active" : "tcp.connection.fin_passive");
            }
            if (rst) expert("tcp.connection.rst");
            if (!ackf && ack) expert("tcp.ack.nonzero");
            if (syn && hlen > 20) {  // a SYN with options should offer an MSS and SACK
                bool has_mss = false, has_sack_perm = false;
                for (size_t p = off + 20, oe = off + hlen; p < oe;) {
                    uint8_t kind = b_.u8(p);
                    if (kind == 0) break;
                    if (kind == 1) { ++p; continue; }
                    if (p + 1 >= oe || b_.u8(p + 1) < 2) break;
                    has_mss |= kind == 2;
                    has_sack_perm |= kind == 4;
                    p += b_.u8(p + 1);
                }
                if (!has_mss) expert("tcp.options.mss.absent");
                if (!has_sack_perm) expert("tcp.options.sack_perm.absent");
            }
        }
        int ws_shift = -1;
        std::string opts = hlen > 20 ? tcp_options(off + 20, hlen - 20, rev.base, &ws_shift, fwd, l) : "";
        // RFC 2883 D-SACK: the first SACK block reports data received twice, so it lies
        // below the cumulative ACK or inside the second block.
        if (ackf && fwd.num_sack > 0 &&
            (seq_lt(fwd.sack_le[0], rack) ||
             (fwd.num_sack > 1 && seq_ge(fwd.sack_le[0], fwd.sack_le[1]) && seq_le(fwd.sack_re[0], fwd.sack_re[1])))) {
            expert("tcp.options.sack.dsack");
            FF(uint("tcp.options.sack.dsack_le", fwd.sack_le[0]));
            FF(uint("tcp.options.sack.dsack_re", fwd.sack_re[0]));
        }
        if (ws_shift >= 0) fwd.win_scale = ws_shift;
        if (syn) {  // window scaling is only in use when both SYNs offer it
            if (fwd.win_scale == -1) fwd.win_scale = rev.win_scale = -2;
            else if (ackf && rev.win_scale == -2) fwd.win_scale = -2;
        }

        if (full_) {
            static const char* names[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
            std::string fls;
            for (int i = 0; i < 8; ++i)
                if (flags & (1 << i)) fls += (fls.empty() ? "" : ", ") + std::string(names[i]);
            if (fls.empty()) fls = "<None>";
            field(l, "Source port", fmt("%u", sport), off, 2);
            field(l, "Destination port", fmt("%u", dport), off + 2, 2);
            field(l, "Sequence number", fmt("%u (relative sequence number)", rseq), off + 4, 4);
            field(l, "Sequence number (raw)", fmt("%u", seq), off + 4, 4);
            if (ackf) {
                field(l, "Acknowledgment number", fmt("%u (relative ack number)", rack), off + 8, 4);
                field(l, "Acknowledgment number (raw)", fmt("%u", ack), off + 8, 4);
            }
            field(l, "Header length", fmt("%zu bytes (%zu)", hlen, hlen / 4), off + 12, 1);
            field(l, "Flags", fmt("0x%03x (%s)", flags, fls.c_str()), off + 12, 2);
            field(l, "Window", fmt("%u", win), off + 14, 2);
            field(l, "Calculated window size", fmt("%u", shown_win), off + 14, 2);
            field(l, "Checksum", fmt("0x%04x [unverified]", b_.u16(off + 16)), off + 16, 2);
            field(l, "Urgent pointer", fmt("%u", b_.u16(off + 18)), off + 18, 2);
            field(l, "TCP payload", fmt("%u bytes", seglen), pay, cap);
            if (c->first_rtt) field(l, "iRTT", fmt("%.9f seconds", static_cast<double>(c->first_rtt) / 1e6), off, 0);
            col_ = fmt("%u → %u [%s] Seq=%u", sport, dport, fls.c_str(), rseq);
            if (ackf) col_ += fmt(" Ack=%u", rack);
            col_ += fmt(" Win=%u Len=%u", shown_win, seglen);
            if (flags & 0x20) col_ += fmt(" Urg=%u", b_.u16(off + 18));
            col_ += opts;
            fence_ = 0;
            // Prepended one after another, so the last listed ends up first (as in Wireshark).
            static const std::pair<uint32_t, const char*> tags[] = {
                {kRetrans, "[TCP Retransmission] "}, {kFastRetrans, "[TCP Fast Retransmission] "},
                {kSpurious, "[TCP Spurious Retransmission] "}, {kOoo, "[TCP Out-Of-Order] "},
                {kReused, "[TCP Port numbers reused] "}, {kLost, "[TCP Previous segment not captured] "},
                {kAckLost, "[TCP ACKed unseen segment] "}, {kWinUpdate, "[TCP Window Update] "},
                {kWinFull, "[TCP Window Full] "}, {kKeepAlive, "[TCP Keep-Alive] "},
                {kKaAck, "[TCP Keep-Alive ACK] "}, {kDupAck, nullptr}, {kZwp, "[TCP ZeroWindowProbe] "},
                {kZeroWin, "[TCP ZeroWindow] "}, {kZwpAck, "[TCP ZeroWindowProbeAck] "}};
            for (const auto& t : tags)
                if (fl & t.first)
                    col_prepend_fence(t.second ? std::string(t.second)
                                               : fmt("[TCP Dup ACK %llu#%u] ", static_cast<unsigned long long>(dup_frame),
                                                     dup_num));
            if (fence_) {
                d_.expert = col_.substr(0, fence_ - 1);
                field(l, "Expert analysis", d_.expert, off, 0);
            }
            tcp_col_ = col_;
            tcp_fence_ = fence_;
        }

        seg_fin_ = fin;
        if (cap > 0 && !rst) {
            uint32_t pseq = rseq + (syn ? 1 : 0), pnxt = rseq + seglen + (syn ? 1 : 0);
            if (cap == seglen) desegment(*c, di, pay, cap, pseq, pnxt, fl);
            else app_payload(*c, di, pay, cap, false);  // cut short by the capture: nothing to reassemble
        } else if (fin && seglen == 0 && fwd.until_fin) {
            fin_reassembly(*c, di, rseq);
        }
        seg_fin_ = false;
        if (full_) d_.info = col_;
    }

    // Wireshark's tcp_analyze_sequence_number(), on raw sequence numbers and the
    // unscaled window.
    uint32_t analyze_tcp(InspectorState::Conv& c, InspectorState::Dir& fwd, InspectorState::Dir& rev, uint32_t seq,
                         uint32_t ack, uint32_t seglen, uint8_t flags, uint32_t window, uint32_t& dup_num,
                         uint64_t& dup_frame, AckInfo& acked) {
        constexpr uint8_t kFin = 0x01, kSyn = 0x02, kRst = 0x04, kAck = 0x10;
        const bool sfr = flags & (kSyn | kFin | kRst);
        const bool sf = flags & (kSyn | kFin);
        uint32_t fl = 0, nextseq = 0;
        uint64_t t = 0, ooo_thres = 0;
        bool seq_not_advanced = false, seen = false;

        if (seglen == 1 && seq == fwd.nextseq && rev.window == 0) {
            fl |= kZwp;
            goto finished_fwd;
        }
        if (window == 0 && !sfr) fl |= kZeroWin;
        if (fwd.nextseq && seq_gt(seq, fwd.nextseq) && !(flags & kRst)) fl |= kLost;
        if ((seglen == 0 || seglen == 1) && seq == fwd.nextseq - 1 && !sfr) fl |= kKeepAlive;
        // An ACK carrying SACK blocks is a duplicate ACK even when its window changed (Wireshark 4.6).
        if (seglen == 0 && window && window != fwd.window && seq == fwd.nextseq && ack == fwd.lastack && !sfr &&
            !sack_now_)
            fl |= kWinUpdate;
        if (seglen > 0 && rev.win_scale != -1 &&
            seq + seglen ==
                rev.lastack + (rev.window << (rev.is_first_ack ? 0 : (rev.win_scale == -2 ? 0 : rev.win_scale))) &&
            !sfr)
            fl |= kWinFull;
        if (seglen == 0 && window && window == fwd.window && seq == fwd.nextseq && ack == fwd.lastack &&
            (rev.lastsegmentflags & kKeepAlive) && !sfr) {
            fl |= kKaAck;
            goto finished_fwd;
        }
        if (seglen == 0 && window == 0 && window == fwd.window && seq == fwd.nextseq &&
            (ack == fwd.lastack || ack == fwd.lastack + 1) && (rev.lastsegmentflags & kZwp) && !sfr) {
            fl |= kZwpAck;
            if (ack == fwd.lastack + 1) {
                rev.nextseq = ack;
                rev.maxseqtobeacked = ack;
            }
            goto finished_fwd;
        }
        if (seglen == 0 && window && (window == fwd.window || sack_now_) && seq == fwd.nextseq && ack == fwd.lastack &&
            !sfr) {
            ++fwd.dupacknum;
            fl |= kDupAck;
            dup_num = fwd.dupacknum;
            dup_frame = fwd.lastnondupack;
        }
    finished_fwd:
        if (ack != fwd.lastack) {
            fwd.lastnondupack = frame_;
            fwd.dupacknum = 0;
        }
        if (rev.maxseqtobeacked && seq_gt(ack, rev.maxseqtobeacked) && (flags & kAck)) {
            if (ack == fwd.lastack + 1 && seq == fwd.nextseq && (rev.lastsegmentflags & kZwp)) {
                rev.nextseq = ack;
                rev.maxseqtobeacked = ack;
                fl |= kWinUpdate;
            } else {
                // Skip over data we did see beyond the hole, so one gap is reported once.
                uint32_t tail_le = 0, tail_re = 0;
                for (const auto& u : rev.segments) {
                    if (tail_le == tail_re) {
                        tail_le = u.seq;
                        tail_re = u.nextseq;
                    }
                    if (seq_ge(u.seq, ack)) {
                        if (u.nextseq == tail_le) {
                            tail_le = u.seq;
                        } else {
                            tail_le = u.seq;
                            tail_re = u.nextseq;
                        }
                    }
                }
                rev.maxseqtobeacked = (ack == tail_le && seq_gt(tail_re, ack)) ? tail_re : ack;
                fl |= kAckLost;
            }
        }
        seq_not_advanced = fwd.nextseq && seq_lt(seq, fwd.nextseq);
        if (seglen > 0 || sf) {
            if (fl & kKeepAlive) goto finished_checking;
            if (seglen > 1 && fwd.nextseq - 1 == seq) seq_not_advanced = false;
            if (seglen > 0 && rev.lastack && seq_le(seq + seglen, rev.lastack)) {
                fl |= kSpurious;
                goto finished_checking;
            }
            nextseq = seq + seglen;
            if (!seq_not_advanced) goto finished_checking;
            t = ts_ > rev.lastacktime ? ts_ - rev.lastacktime : 0;
            if (t < 20'000 && rev.dupacknum >= 2 && rev.lastack == seq) {
                fl |= kFastRetrans;
                goto finished_checking;
            }
            if (t < 20'000 && rev.dupacknum >= 2 && rev.num_sack > 0) {
                bool sacked = false;
                for (int i = 0; i < rev.num_sack && !sacked; ++i)
                    sacked = seq >= rev.sack_le[i] && nextseq <= rev.sack_re[i];
                if (!sacked) {
                    fl |= kFastRetrans;
                    goto finished_checking;
                }
            }
            ooo_thres = c.first_rtt ? c.first_rtt : 3'000;
            for (const auto& u : fwd.segments)
                if (seq_ge(seq, u.seq) && seq_le(seq + seglen, u.nextseq)) {
                    seen = true;
                    break;
                }
            if (t < ooo_thres && !seen) {
                if (fwd.nextseq != seq + seglen + (sf ? 1u : 0u) || fwd.lastacklen == 0) {
                    fl |= kOoo;
                    goto finished_checking;
                }
            }
            fl |= kRetrans;
        }
    finished_checking:
        nextseq = seq + seglen;
        if ((seglen || sf) && fwd.segments.size() < 10'000) {
            if (sf) nextseq += 1;
            InspectorState::Unacked u{seq, nextseq};
            u.frame = frame_;
            u.ts = ts_;
            u.retrans = fl & (kRetrans | kFastRetrans | kSpurious);
            if (u.retrans)  // the newest earlier segment this one repeats (wholly inside it) is now ambiguous too
                for (auto& e : fwd.segments)
                    if (seq_ge(seq, e.seq) && seq_ge(e.nextseq, nextseq)) {
                        e.retrans = true;
                        break;
                    }
            fwd.segments.push_front(u);
        }
        if (!fwd.nextseq || seq_gt(nextseq, fwd.nextseq + (sf ? 1u : 0u))) fwd.lastacklen = seglen;
        if ((seq_gt(nextseq, fwd.nextseq) || !fwd.nextseq) && !(fl & kZwp)) {
            fwd.nextseq = nextseq;
            fwd.nextseqtime = ts_;
        }
        if ((seq == fwd.maxseqtobeacked || !fwd.maxseqtobeacked) && !(fl & kZwp)) fwd.maxseqtobeacked = fwd.nextseq;
        fwd.window = window;
        fwd.lastack = ack;
        fwd.lastacktime = ts_;
        fwd.lastsegmentflags = fl;
        // Forget what this acknowledges. The list is newest first and every exact match
        // overwrites what the previous one said, so the oldest copy of a segment is the
        // one reported, and it alone decides whether the ACK is ambiguous (Karn).
        bool ambiguous = false, partial = false;
        for (auto it = rev.segments.begin(); it != rev.segments.end();) {
            if (ack == it->nextseq) {
                acked.acks_frame = it->frame;
                acked.rtt_us = ts_ > it->ts ? ts_ - it->ts : 0;
                ambiguous = it->retrans;
                partial = false;
                it = rev.segments.erase(it);
            } else if (seq_gt(ack, it->seq) && seq_le(ack, it->nextseq)) {
                it->seq = ack;  // partly acknowledged
                acked.acks_frame = it->frame;
                acked.rtt_us = ts_ > it->ts ? ts_ - it->ts : 0;
                ambiguous = it->retrans;
                partial = true;
                ++it;
            } else if (seq_gt(it->nextseq, ack)) {
                ++it;
            } else {
                it = rev.segments.erase(it);
            }
        }
        if (ambiguous) fl |= kAmbiguousAck;
        if (partial) fl |= kPartialAck;
        return fl;
    }

    // ----------------------------------------------- TCP payload reassembly
    // Mirrors Wireshark's desegment_tcp(): a dissector that needs more bytes asks
    // for them (deseg_), the message is collected by sequence number, and it is
    // dissected in the frame that completes it. Earlier pieces show the TCP line,
    // annotated "[TCP PDU reassembled in N]" in the two-pass view.
    static constexpr uint32_t kOneMore = 0x0FFFFFFF;   // DESEGMENT_ONE_MORE_SEGMENT
    static constexpr uint32_t kUntilFin = 0x0FFFFFFE;  // DESEGMENT_UNTIL_FIN
    static constexpr size_t kMspKeep = 1 << 20;        // bytes kept per message
    static constexpr size_t kMspBudget = 256u << 20;   // across all messages

    // Wireshark's second pass sees the messages its first pass left behind, so in
    // pass 2 a message only exists if pass 1 began the same one: not one this pass
    // begins because it reads a frame differently (a TLS version settled later),
    // nor one a later frame replaced (a resent segment that begins a message at
    // the same sequence number). Those are phantoms, and lookups skip them; the
    // pass-1 record (final_msp) stands in for what Wireshark finds instead.
    InspectorState::Msp* msp_le(InspectorState::Dir& d, uint32_t key) {
        auto it = d.msps.upper_bound(key);
        if (it == d.msps.begin()) return nullptr;
        auto* m = &std::prev(it)->second;
        return m->phantom ? nullptr : m;
    }

    InspectorState::Msp& msp_new(InspectorState::Dir& d, uint32_t seq, uint32_t nxtpdu) {
        auto it = d.msps.find(seq);
        if (it != d.msps.end()) {
            st_.msp_bytes -= std::min(st_.msp_bytes, it->second.data.size());
            d.msps.erase(it);
        }
        auto& m = d.msps[seq];
        m.seq = seq;
        m.nxtpdu = nxtpdu;
        m.first_frame = m.last_frame = frame_;
        if (st_.use) {
            auto it2 = st_.use->msps.find(conv_hash() * 2 + static_cast<size_t>(cur_dir_));
            const InspectorAnnotations::MspInfo* fin = nullptr;
            if (it2 != st_.use->msps.end()) {
                auto e = it2->second.find(seq);
                if (e != it2->second.end()) fin = &e->second;
            }
            m.phantom = !fin || fin->first_frame != frame_;
        }
        note_msp(m);
        return m;
    }

    void note_msp(const InspectorState::Msp& m) {
        if (st_.record)
            st_.record->msps[conv_hash() * 2 + static_cast<size_t>(cur_dir_)][m.seq] = {
                m.nxtpdu, m.defragmented ? m.reassembled_in : 0, m.first_frame};
    }

    // The message Wireshark's second pass would find for `seq`: one starting there, else the one before it.
    const InspectorAnnotations::MspInfo* final_msp(uint32_t seq, uint32_t& mseq) const {
        if (!st_.use) return nullptr;
        auto it = st_.use->msps.find(conv_hash() * 2 + static_cast<size_t>(cur_dir_));
        if (it == st_.use->msps.end() || it->second.empty()) return nullptr;
        const auto& m = it->second;
        auto e = m.find(seq);
        if (e == m.end()) {
            e = m.upper_bound(seq - 1);
            if (e == m.begin()) return nullptr;
            --e;
        }
        mseq = e->first;
        return &e->second;
    }

    void msp_free(InspectorState::Msp& m) {
        st_.msp_bytes -= std::min(st_.msp_bytes, m.data.size());
        std::string().swap(m.data);
    }

    // Wireshark's fragment_add(): true once [0, total) is covered (or already was).
    bool msp_add(InspectorState::Msp& m, size_t data_off, uint32_t frag_off, size_t flen, bool more) {
        if (m.defragmented) return true;  // overlaps a finished message: a retransmission
        if (m.frames.empty() || m.frames.back() != frame_) m.frames.push_back(frame_);
        if (flen && frag_off < kMspKeep) {
            size_t keep = std::min<size_t>(flen, kMspKeep - frag_off);
            size_t need = frag_off + keep;
            if (m.data.size() < need) {
                if (st_.msp_bytes + (need - m.data.size()) <= kMspBudget) {
                    st_.msp_bytes += need - m.data.size();
                    m.data.resize(need);
                } else {
                    keep = m.data.size() > frag_off ? m.data.size() - frag_off : 0;
                }
            }
            if (keep) std::memcpy(&m.data[frag_off], b_.p + data_off, keep);
        }
        InspectorState::Fragment f{frag_off, static_cast<uint32_t>(flen)};
        m.frags.insert(std::upper_bound(m.frags.begin(), m.frags.end(), f,
                                        [](const InspectorState::Fragment& a, const InspectorState::Fragment& b) {
                                            return a.off < b.off;
                                        }),
                       f);
        if (!more) {
            m.tot_known = true;
            m.tot_len = frag_off + static_cast<uint32_t>(flen);
        }
        if (!m.tot_known) return false;
        uint64_t covered = 0;
        for (const auto& g : m.frags) {
            if (g.off > covered) break;
            covered = std::max<uint64_t>(covered, static_cast<uint64_t>(g.off) + g.len);
        }
        if (covered < m.tot_len) return false;
        m.defragmented = true;
        m.reassembled_in = frame_;
        note_msp(m);
        if (st_.record)
            for (uint64_t fr : m.frames) {
                if (fr == frame_) continue;
                auto& v = st_.record->reassembled_in[fr];
                auto it = std::find_if(v.begin(), v.end(), [&](const auto& e) { return e.first == m.seq; });
                if (it != v.end()) it->second = frame_;
                else v.emplace_back(m.seq, frame_);
            }
        return true;
    }

    // The message continues past a dissected one: carry the rest into a new one.
    InspectorState::Msp* msp_split(InspectorState::Dir& d, InspectorState::Msp& old, uint32_t split) {
        std::string tail = split < old.data.size() ? old.data.substr(split) : std::string();
        uint32_t total = old.tot_len > split ? old.tot_len - split : 0;
        uint32_t nxtpdu = old.nxtpdu;
        auto& m = msp_new(d, old.seq + split, nxtpdu);
        st_.msp_bytes += tail.size();
        m.data = std::move(tail);
        m.frags.push_back({0, total});
        m.frames.push_back(frame_);
        return &m;
    }

    // Where the message starting at `seq` that this frame is part of was finally completed (two-pass view).
    uint64_t final_reassembled_in(uint32_t seq) const {
        if (!st_.use) return 0;
        auto it = st_.use->reassembled_in.find(frame_);
        if (it == st_.use->reassembled_in.end()) return 0;
        for (const auto& e : it->second)
            if (e.first == seq) return e.second;
        return 0;
    }

    // The Info column's "[TCP PDU reassembled in N]" (first message of a segment only).
    void annotate_pdu(uint64_t in) {
        if (!in || annotated_ || frozen_) return;
        annotated_ = true;
        col_append_sep(fmt("[TCP PDU reassembled in %llu]", static_cast<unsigned long long>(in)), " ");
    }

    // The tcp.reassembled_in field: for every message this segment contributed to
    // that was completed in another frame.
    void note_reasm(uint64_t in) {
        if (!ff_ || !in || in == frame_) return;
        for (const auto& f : ff_->fields)
            if (std::strcmp(f.name, "tcp.reassembled_in") == 0 && f.value.u == in) return;
        ff_->uint("tcp.reassembled_in", in);
    }

    static uint64_t piece_key(uint64_t frame, uint32_t seq) { return (frame << 32) ^ seq; }

    void desegment(InspectorState::Conv& c, int di, size_t off, size_t len, uint32_t seq, uint32_t nxtseq,
                   uint32_t& fl) {
        auto& d = c.dir[di];
        cur_dir_ = di;
        struct WritableAgain {
            bool& w;
            ~WritableAgain() { w = true; }
        } writable_again{proto_writable_};
        while (d.msps.size() > 1024) {
            msp_free(d.msps.begin()->second);
            d.msps.erase(d.msps.begin());
        }
        const size_t start = off;
        bool first_pdu = true;
        const FrameFields::Mark start_mark = ff_ ? ff_->mark() : FrameFields::Mark{0, 0};
        for (int round = 0; round < 512 && len > 0; ++round) {
            InspectorState::Msp* msp = nullptr;
            InspectorState::Msp* head = nullptr;
            bool must_desegment = false, called = false, in_msp = false, quiet = false, piece_view = false;
            uint32_t piece_seq = 0;
            uint32_t another = 0;
            size_t last_fragment_len = 0;
            deseg_ = Deseg();
            size_t deseg_offset = off;
            FrameFields::Mark round_mark = ff_ ? ff_->mark() : FrameFields::Mark{0, 0};

            auto exact = d.msps.find(seq);
            if (exact != d.msps.end() && !exact->second.phantom) {
                msp = &exact->second;
                if (nxtseq <= msp->nxtpdu && msp->last_frame != frame_) {  // resends a message's first segment
                    if (fl & kKeepAlive) {
                        msp->nxtpdu = nxtseq;
                        note_msp(*msp);
                    }
                    return;
                }
            }
            if (!msp) msp = msp_le(d, seq - 1);
            bool unfinished = msp && seq_le(msp->seq, seq) && seq_gt(msp->nxtpdu, seq);
            // Resent data, and a keep-alive's one old byte, outside any unfinished message.
            if (!unfinished && d.maxnextseq && seq_le(seq, d.maxnextseq) &&
                (fl & (kSpurious | kRetrans | kFastRetrans | kKeepAlive)))
                fl |= kOldData;
            if (fl & kOldData) {  // "Retransmitted TCP segment data": not dissected again
                // Flagged on a later message of this segment, the flag still makes
                // Wireshark's second pass skip the whole segment.
                if (round > 0 && st_.use) {
                    frozen_ = false;
                    col_ = tcp_col_;
                    fence_ = tcp_fence_;
                    d_.protocol = "TCP";
                    if (ff_) ff_->rollback(start_mark);
                }
                if ((fl & kKeepAlive) && round == 0) {  // a keep-alive's byte goes to the data dissector
                    fproto("data", off, len);
                    layer("Data", off, len);
                }
                return;
            }
            if (!d.until_fin && (seq_lt(d.maxnextseq, nxtseq) || d.maxnextseq == 0)) d.maxnextseq = nxtseq;

            if (msp && seq_le(msp->seq, seq) && seq_gt(msp->nxtpdu, seq)) {
                in_msp = true;
                msp->last_frame = frame_;
                if (msp->first_frame != frame_ && !msp->multi) {
                    msp->multi = true;
                    if (st_.record) st_.record->piece_start.insert(piece_key(msp->first_frame, msp->seq));
                }
                size_t flen = msp->entire_segment ? len : std::min<size_t>(nxtseq - seq, msp->nxtpdu - seq);
                last_fragment_len = flen;
                head = msp_add(*msp, off, seq - msp->seq, flen, seq_lt(nxtseq, msp->nxtpdu)) ? msp : nullptr;
                if (head && msp->entire_segment) {
                    msp->entire_segment = false;
                    if (seq_lt(msp->nxtpdu, nxtseq)) msp->nxtpdu = nxtseq;
                    note_msp(*msp);
                }
                if (msp->nxtpdu < nxtseq && msp->nxtpdu >= seq && flen > 0) another = msp->nxtpdu - seq;
            } else {
                // Wireshark's second pass looks this segment up among the messages the
                // whole first pass created; one that covers it (even one begun later)
                // makes it a piece rather than something to dissect.
                uint32_t fseq = 0;
                const InspectorAnnotations::MspInfo* fin = first_pdu ? final_msp(seq, fseq) : nullptr;
                bool exact_piece = fin && fseq == seq && fin->first_frame == frame_ &&
                                   st_.use->piece_start.count(piece_key(frame_, seq)) && nxtseq <= fin->nxtpdu;
                bool later_piece = fin && !exact_piece && seq_le(fseq, seq) && seq_gt(fin->nxtpdu, seq);
                app_seq_ = seq;
                app_base_ = off;
                app_payload(c, di, off, len, true);
                called = true;
                if (deseg_.len) {
                    must_desegment = true;
                    deseg_offset = off + deseg_.offset;
                }
                if (later_piece) {
                    col_ = tcp_col_;
                    fence_ = tcp_fence_;
                    d_.protocol = "TCP";
                    if (ff_) ff_->rollback(round_mark);
                    if (fin->reassembled_in && fin->reassembled_in != frame_) {
                        annotate_pdu(fin->reassembled_in);
                        note_reasm(fin->reassembled_in);
                    }
                    frozen_ = true;
                }
            }

            if (head && head->reassembled_in == frame_) {
                // Wireshark's second pass dissects a message only where it was finally
                // completed; a completion that then asked for more shows as a piece.
                std::string saved_col = col_;
                size_t saved_fence = fence_;
                std::string saved_proto = d_.protocol;
                size_t saved_layers = d_.layers.size();
                dissect_reassembled(c, di, *msp, true);
                called = true;
                uint64_t final_in = deseg_.len ? final_reassembled_in(msp->seq) : 0;
                quiet = final_in && final_in != frame_;
                if (quiet) {
                    col_ = saved_col;
                    fence_ = saved_fence;
                    d_.protocol = saved_proto;
                    if (ff_) ff_->rollback(round_mark);
                    if (full_) d_.layers.resize(saved_layers);
                    called = false;
                }
                if (deseg_.len) {
                    if (deseg_.offset != 0 && seq_gt(msp->seq + static_cast<uint32_t>(deseg_.offset), seq)) {
                        msp = msp_split(d, *msp, static_cast<uint32_t>(deseg_.offset));
                    } else {  // keep collecting into the same message
                        msp->defragmented = false;
                        msp->tot_known = false;
                    }
                    if (deseg_.len == kOneMore) {
                        msp->nxtpdu = std::max<uint32_t>(seq + static_cast<uint32_t>(len), msp->nxtpdu) + 1;
                        msp->entire_segment = true;
                    } else if (deseg_.len == kUntilFin) {
                        d.until_fin = true;
                        msp->nxtpdu = msp->seq + 0x40000000u;
                    } else if (seq + last_fragment_len >= msp->nxtpdu) {
                        msp->nxtpdu = seq + static_cast<uint32_t>(last_fragment_len) + deseg_.len;
                    } else {
                        msp->nxtpdu += deseg_.len;
                    }
                    note_msp(*msp);
                    another = 0;
                    off += last_fragment_len;
                    len -= last_fragment_len;
                    seq += static_cast<uint32_t>(last_fragment_len);
                    if (quiet) note_reasm(final_in);
                    if (quiet && first_pdu) annotate_pdu(final_in);
                    if (len > 0) continue;
                } else {
                    msp_free(*msp);
                }
                if (quiet) note_reasm(final_in);
                if (quiet && first_pdu) annotate_pdu(final_in);
            }

            if (must_desegment) {
                uint32_t deseg_seq = seq + static_cast<uint32_t>(deseg_offset - off);
                if (deseg_.len == kUntilFin) d.until_fin = true;
                if (nxtseq - deseg_seq <= 1024 * 1024) {
                    uint32_t nxtpdu = deseg_.len == kOneMore    ? nxtseq + 1
                                      : deseg_.len == kUntilFin ? nxtseq + 0x40000000u
                                                                : nxtseq + deseg_.len;
                    auto& m = msp_new(d, deseg_seq, nxtpdu);
                    m.entire_segment = deseg_.len == kOneMore;
                    m.from_start = first_pdu && deseg_offset == start;
                    msp_add(m, deseg_offset, 0, nxtseq - deseg_seq, seq_lt(nxtseq, m.nxtpdu));
                    piece_seq = m.seq;
                    if (st_.use && !frozen_) {
                        uint64_t r = m.defragmented ? m.reassembled_in : final_reassembled_in(m.seq);
                        if (deseg_offset == off && st_.use->piece_start.count(piece_key(frame_, m.seq))) {
                            // A message continued in later frames: Wireshark's second pass
                            // shows its first segment as TCP data, not dissected.
                            if (ff_) ff_->rollback(round_mark);
                            if (first_pdu) {
                                col_ = tcp_col_;
                                fence_ = tcp_fence_;
                                d_.protocol = "TCP";
                                piece_view = true;
                            }
                        } else if (m.from_start && r) {
                            annotate_pdu(r);
                        }
                        note_reasm(r);
                    }
                }
            }
            if (piece_view) {
                annotate_pdu(final_reassembled_in(piece_seq));
            } else if ((!called || deseg_.len != 0) && !quiet) {
                uint64_t r = 0;
                if (head && head->reassembled_in) r = head->reassembled_in;
                else if (!head && in_msp) r = final_reassembled_in(msp->seq);
                note_reasm(r);
                if (deseg_.offset == 0 && first_pdu && r && (head || r != frame_)) annotate_pdu(r);
            }
            deseg_ = Deseg();
            if (!another) break;
            col_set_fence();
            proto_writable_ = false;
            first_pdu = false;
            off += another;
            len -= another;
            seq += another;
        }
        proto_writable_ = true;
    }

    // A FIN ends a message that runs to the end of the stream.
    void fin_reassembly(InspectorState::Conv& c, int di, uint32_t rseq) {
        auto& d = c.dir[di];
        cur_dir_ = di;
        if (d.fin_frame && d.fin_frame != frame_) return;  // a resent FIN
        d.fin_frame = frame_;
        auto* m = msp_le(d, rseq);
        if (!m) return;
        if (msp_add(*m, 0, rseq - m->seq, 0, false) && m->reassembled_in == frame_) {
            dissect_reassembled(c, di, *m, false);
            msp_free(*m);
        }
    }

    void dissect_reassembled(InspectorState::Conv& c, int di, InspectorState::Msp& m, bool can_desegment) {
        if (full_) {
            Layer& r = layer("Reassembled TCP", 0, 0);
            std::string frames;
            for (size_t i = 0; i < m.frames.size() && i < 64; ++i)
                frames += (i ? ", #" : "#") + std::to_string(m.frames[i]);
            if (m.frames.size() > 64) frames += ", ...";
            r.fields.push_back({"Reassembled TCP length", fmt("%u bytes in %zu segments", m.tot_len, m.frames.size()), 0, 0});
            r.fields.push_back({"Segments", frames, 0, 0});
        }
        Bytes saved = b_;
        bool saved_virtual = virtual_;
        size_t saved_reported = reported_;
        b_ = {reinterpret_cast<const uint8_t*>(m.data.data()), std::min<size_t>(m.data.size(), m.tot_len)};
        virtual_ = true;
        reported_ = m.tot_len;
        app_seq_ = m.seq;
        app_base_ = 0;
        app_payload(c, di, 0, b_.n, can_desegment);
        b_ = saved;
        virtual_ = saved_virtual;
        reported_ = saved_reported;
    }

    void udp(size_t off, size_t end, int depth) {
        d_.protocol = "UDP";
        if (!b_.have(off, 8)) return truncated();
        uint16_t sport = b_.u16(off), dport = b_.u16(off + 2), len = b_.u16(off + 4);
        Layer& l = layer("User Datagram Protocol", off, 8);
        uint64_t ustream;
        {
            PacketInfo pi;
            pi.src = src_ip_;
            pi.dst = dst_ip_;
            pi.sport = sport;
            pi.dport = dport;
            pi.proto = 17;
            bool a_to_b = false;
            FlowKey k = FlowKey::from_packet(pi, a_to_b);
            l4_key_ = k;
            udp_a_to_b_ = a_to_b;
            InspectorState& ss = streams_ ? *streams_ : st_;
            if (ss.udp_streams.size() > 1'000'000) ss.udp_streams.clear();
            auto ins = ss.udp_streams.emplace(k, ss.next_udp_stream);
            if (ins.second) ++ss.next_udp_stream;
            ustream = ins.first->second;
        }
        if (ff_) {
            fproto("udp", off, end > off ? end - off : 8);
            FF(uint("udp.srcport", sport));
            FF(uint("udp.dstport", dport));
            FF(uint("udp.port", sport));
            FF(uint("udp.port", dport));
            FF(uint("udp.length", len));
            FF(uint("udp.stream", ustream));
        }
        FIELD(l, "Source port", fmt("%u", sport), off, 2);
        FIELD(l, "Destination port", fmt("%u", dport), off + 2, 2);
        FIELD(l, "Length", fmt("%u", len), off + 4, 2);
        FIELD(l, "Checksum", fmt("0x%04x [unverified]", b_.u16(off + 6)), off + 6, 2);
        size_t pay = off + 8;
        size_t plen = end > pay ? end - pay : 0;
        if (len >= 8 && len - 8u < plen) plen = len - 8u;
        if (len < 8) {
            expert("udp.length.bad", 3, "Malformed", "UDP", fmt("Bad length value %u < 8", len));
            INFO(fmt("%u → %u [BAD UDP LENGTH %u < 8] Len=%zu", sport, dport, len, plen));
        } else if (l4_reported_ && len > l4_reported_) {
            if (!in_error_) expert("udp.length.bad", 3, "Malformed", "UDP", fmt("Bad length value %u > IP payload length", len));
            INFO(fmt("%u → %u [BAD UDP LENGTH %u > IP PAYLOAD LENGTH] Len=%u", sport, dport, len, len - 8u));
        } else {
            INFO(fmt("%u → %u Len=%zu", sport, dport, plen));
        }
        if (!plen) return;
        // Tunnels first: VXLAN / Geneve carry whole frames.
        if (depth < 4 && dport == 4789 && b_.have(pay, 8) && (b_.u8(pay) & 0x08)) {
            Layer& v = layer("Virtual eXtensible Local Area Network", pay, 8);
            fproto("vxlan", pay, 8);
            FF(uint("vxlan.vni", b_.u32(pay + 4) >> 8));
            FIELD(v, "VNI", fmt("%u", b_.u32(pay + 4) >> 8), pay + 4, 3);
            return ethernet(pay + 8, depth + 1);
        }
        if (depth < 4 && dport == 6081 && b_.have(pay, 8) && (b_.u8(pay) >> 6) == 0) {
            size_t glen = 8 + static_cast<size_t>(b_.u8(pay) & 0x3F) * 4;
            uint16_t gtype = b_.u16(pay + 2);
            Layer& g = layer("Generic Network Virtualization Encapsulation", pay, glen);
            fproto("geneve", pay, glen);
            FIELD(g, "VNI", fmt("%u", b_.u32(pay + 4) >> 8), pay + 4, 3);
            if (gtype == 0x6558) return ethernet(pay + glen, depth + 1);
            if (gtype == 0x0800 || gtype == 0x86DD) return l3(gtype, pay + glen, depth + 1);
        }
        udp_app(pay, plen, sport, dport);
    }

    void icmp(size_t off, size_t end) {
        d_.protocol = "ICMP";
        if (!b_.have(off, 4)) return truncated();
        uint8_t type = b_.u8(off), code = b_.u8(off + 1);
        Layer& l = layer("Internet Control Message Protocol", off, end > off ? end - off : 0);
        fproto("icmp", off, end > off ? end - off : 0);
        FF(uint("icmp.type", type));
        if (type == 3 || type == 5 || type == 11) expert("icmp.type.error");
        if (type == 4 || type == 6 || (type >= 15 && type <= 18) || (type >= 30 && type <= 39))
            expert("icmp.type.deprecated");  // RFC 6918
        FF(uint("icmp.code", code));
        if ((type == 0 || type == 8) && b_.have(off, 8)) {
            FF(uint("icmp.ident", b_.u16(off + 4)));
            FF(uint("icmp.seq", b_.u16(off + 6)));
        }
        FIELD(l, "Type", fmt("%u", type), off, 1);
        FIELD(l, "Code", fmt("%u", code), off + 1, 1);
        FIELD(l, "Checksum", fmt("0x%04x", b_.u16(off + 2)), off + 2, 2);
        if ((type == 0 || type == 8) && b_.have(off, 8)) {
            uint16_t id = b_.u16(off + 4), sq = b_.u16(off + 6);
            std::string info;
            if (full_) {
                uint16_t sq_le = static_cast<uint16_t>((sq >> 8) | (sq << 8));
                field(l, "Identifier", fmt("0x%04x", id), off + 4, 2);
                field(l, "Sequence number", fmt("%u (0x%04x)", sq, sq), off + 6, 2);
                info = fmt("Echo (ping) %s id=0x%04x, seq=%u/%u, ttl=%u", type == 8 ? "request " : "reply   ", id, sq,
                           sq_le, ttl_);
            }
            info += echo_pairing(type == 8, fmt("4|%u|%u", id, sq));
            INFO(info);
            if (end > off + 8) fproto("data", off + 8, end - off - 8);
            return;
        }
        if (!full_) return;
        static const char* unreach[] = {"Network unreachable", "Host unreachable", "Protocol unreachable",
                                        "Port unreachable", "Fragmentation needed", "Source route failed",
                                        "Destination network unknown", "Destination host unknown",
                                        "Source host isolated", "Network administratively prohibited",
                                        "Host administratively prohibited", "Network unreachable for TOS",
                                        "Host unreachable for TOS", "Communication administratively filtered",
                                        "Host precedence violation", "Precedence cutoff in effect"};
        switch (type) {
            case 3: d_.info = fmt("Destination unreachable (%s)", code < 16 ? unreach[code] : "Unknown code"); break;
            case 4: d_.info = "Source quench (flow control)"; break;
            case 5: d_.info = fmt("Redirect (%s)", code == 0 ? "Redirect for network" : code == 1 ? "Redirect for host"
                                                    : "Redirect for TOS"); break;
            case 9: d_.info = "Router advertisement"; break;
            case 10: d_.info = "Router solicitation"; break;
            case 11: d_.info = code == 0 ? "Time-to-live exceeded (Time to live exceeded in transit)"
                                         : "Time-to-live exceeded (Fragment reassembly time exceeded)"; break;
            case 12: d_.info = "Parameter problem"; break;
            case 13: d_.info = "Timestamp request"; break;
            case 14: d_.info = "Timestamp reply"; break;
            default: d_.info = fmt("Type %u, code %u", type, code);
        }
        if ((type == 3 || type == 11) && b_.have(off, 8) && end > off + 8)
            layer("Original datagram", off + 8, end - off - 8);
        if ((type == 3 || type == 4 || type == 5 || type == 11 || type == 12) && end > off + 8) error_packet(off + 8, end);
    }

    // The packet quoted in an ICMP error: decoded for its fields only, with
    // throwaway state so it can't disturb the conversations it belongs to.
    // Its UDP header still names a conversation: Wireshark gives it that flow's
    // udp.stream, and opens a new stream for a flow it hasn't seen, so the quoted
    // packet is always decoded (fields or not) against the real stream table.
    void error_packet(size_t off, size_t end) {
        if (frozen_ || ff_virtual_) return;
        if (ff_) ff_->begin_error_packet();
        InspectorState scratch;
        Decoder sub(scratch, b_.p, end, frame_, ts_, true);
        sub.ff_ = ff_;
        sub.in_error_ = true;
        sub.streams_ = streams_ ? streams_ : &st_;
        sub.l3(0, off, 3);
    }

    // Match echo requests and replies like Wireshark: the latest request with a key
    // is answered by the first reply; later duplicates are not cross-referenced.
    std::string echo_pairing(bool request, const std::string& id) {
        std::string out;
        if (request) {
            std::string key = d_.src + ">" + d_.dst + "|" + id;
            if (st_.echo.size() > 100'000) st_.echo.clear();
            st_.echo[key] = {frame_, false};
            if (full_ && st_.use) {
                auto it = st_.use->reply_in.find(frame_);
                if (it != st_.use->reply_in.end()) {
                    out = fmt(" (reply in %llu)", static_cast<unsigned long long>(it->second));
                    if (id[0] == '4') FF(uint("icmp.resp_in", it->second));
                } else if (st_.use->complete) {
                    out = " (no response found!)";
                    if (id[0] == '4') expert("icmp.resp_not_found");
                }
            }
            return out;
        }
        auto it = st_.echo.find(d_.dst + ">" + d_.src + "|" + id);
        if (it != st_.echo.end() && !it->second.answered) {
            it->second.answered = true;
            if (st_.record) {
                st_.record->reply_in[it->second.frame] = frame_;
                st_.record->request_in[frame_] = it->second.frame;
            }
            if (full_) out = fmt(" (request in %llu)", static_cast<unsigned long long>(it->second.frame));
            if (id[0] == '4') FF(uint("icmp.resp_to", it->second.frame));
        }
        return out;
    }

    std::string nd_lladdr(size_t pos, size_t end) {
        while (pos + 8 <= end && b_.have(pos, 8)) {
            uint8_t ot = b_.u8(pos), olen = b_.u8(pos + 1);
            if (olen == 0) break;
            if ((ot == 1 || ot == 2) && olen == 1) return mac_raw(b_.p + pos + 2);
            pos += static_cast<size_t>(olen) * 8;
        }
        return "";
    }

    void icmpv6(size_t off, size_t end) {
        d_.protocol = "ICMPv6";
        if (!b_.have(off, 4)) return truncated();
        uint8_t type = b_.u8(off), code = b_.u8(off + 1);
        Layer& l = layer("Internet Control Message Protocol v6", off, end > off ? end - off : 0);
        fproto("icmpv6", off, end > off ? end - off : 0);
        FF(uint("icmpv6.type", type));
        FF(uint("icmpv6.code", code));
        FIELD(l, "Type", fmt("%u", type), off, 1);
        FIELD(l, "Code", fmt("%u", code), off + 1, 1);
        if ((type == 128 || type == 129) && b_.have(off, 8)) {
            uint16_t id = b_.u16(off + 4), sq = b_.u16(off + 6);
            std::string info;
            if (full_)
                info = fmt("Echo (ping) %s id=0x%04x, seq=%u, hop limit=%u", type == 128 ? "request" : "reply", id, sq,
                           ttl_);
            info += echo_pairing(type == 128, fmt("6|%u|%u", id, sq));
            INFO(info);
            if (end > off + 8) fproto("data", off + 8, end - off - 8);
            return;
        }
        if (!full_) return;
        switch (type) {
            case 1: d_.info = "Destination Unreachable"; break;
            case 2: d_.info = "Packet Too Big"; break;
            case 3: d_.info = "Time Exceeded"; break;
            case 4: d_.info = "Parameter Problem"; break;
            case 130: d_.info = "Multicast Listener Query"; break;
            case 131: d_.info = "Multicast Listener Report"; break;
            case 132: d_.info = "Multicast Listener Done"; break;
            case 133: {
                std::string mac = nd_lladdr(off + 8, end);
                d_.info = mac.empty() ? "Router Solicitation" : "Router Solicitation from " + mac;
                break;
            }
            case 134: {
                std::string mac = nd_lladdr(off + 16, end);
                d_.info = mac.empty() ? "Router Advertisement" : "Router Advertisement from " + mac;
                break;
            }
            case 135:
                if (b_.have(off, 24)) {
                    std::string mac = nd_lladdr(off + 24, end);
                    d_.info = "Neighbor Solicitation for " + ipv6s(b_.p + off + 8) + (mac.empty() ? "" : " from " + mac);
                }
                break;
            case 136:
                if (b_.have(off, 24)) {
                    uint8_t f = b_.u8(off + 4);
                    std::string fl;
                    if (f & 0x80) fl += "rtr, ";
                    if (f & 0x40) fl += "sol, ";
                    if (f & 0x20) fl += "ovr, ";
                    if (!fl.empty()) fl = " (" + fl.substr(0, fl.size() - 2) + ")";
                    std::string mac = nd_lladdr(off + 24, end);
                    d_.info = "Neighbor Advertisement " + ipv6s(b_.p + off + 8) + fl + (mac.empty() ? "" : " is at " + mac);
                }
                break;
            case 137: d_.info = "Redirect"; break;
            case 143: d_.info = "Multicast Listener Report Message v2"; break;
            default: d_.info = fmt("Unknown ICMPv6 type %u", type);
        }
        if (type >= 1 && type <= 4 && end > off + 8) error_packet(off + 8, end);
    }

    void igmp(size_t off, size_t end) {
        if (!b_.have(off, 8)) return truncated();
        uint8_t type = b_.u8(off);
        size_t len = end > off ? end - off : 0;
        d_.protocol = type == 0x22 || (type == 0x11 && len >= 12) ? "IGMPv3" : "IGMPv2";
        if (!full_) return;
        std::string group = ipv4s(b_.p + off + 4);
        Layer& l = layer("Internet Group Management Protocol", off, len);
        fproto("igmp", off, len);
        FF(uint("igmp.type", type));
        field(l, "Type", fmt("0x%02x", type), off, 1);
        switch (type) {
            case 0x11:
                d_.info = group == "0.0.0.0" ? "Membership Query, general" : "Membership Query, specific for group " + group;
                break;
            case 0x12:
            case 0x16: d_.info = "Membership Report group " + group; break;
            case 0x17: d_.info = "Leave Group " + group; break;
            case 0x22:
                if (b_.have(off, 16)) {
                    uint8_t rtype = b_.u8(off + 8);
                    uint16_t nsrc = b_.u16(off + 10);
                    std::string g = ipv4s(b_.p + off + 12);
                    if ((rtype == 4 || rtype == 2) && nsrc == 0) d_.info = "Membership Report / Join group " + g + " for any sources";
                    else if ((rtype == 3 || rtype == 1) && nsrc == 0) d_.info = "Membership Report / Leave group " + g;
                    else d_.info = "Membership Report / group " + g;
                } else {
                    d_.info = "Membership Report";
                }
                break;
            default: d_.info = fmt("Unknown type 0x%02x", type);
        }
        field(l, "Group address", group, off + 4, 4);
    }

    // ----------------------------------------------------- application
    static bool client_side(const InspectorState::Conv& c, int di, uint16_t sport, uint16_t dport, uint16_t server_port) {
        if (dport == server_port && sport != server_port) return true;
        if (sport == server_port && dport != server_port) return false;
        if (c.server_port) {
            if (dport == c.server_port && sport != c.server_port) return true;
            if (sport == c.server_port && dport != c.server_port) return false;
        }
        return c.client < 0 ? sport > dport : c.client == di;
    }

    // ------------------------------------------ TCP application dispatch
    enum App : uint8_t {
        kAppNone, kAppSsh, kAppTls, kAppHttp, kAppDns, kAppFtp, kAppFtpData, kAppSmtp, kAppPop, kAppImap, kAppTelnet,
        kAppKerberos, kAppLdap, kAppSmb, kAppDcerpc, kAppMysql, kAppPgsql, kAppTds, kAppHttp2
    };

    static uint8_t app_for_port(uint16_t p) {
        switch (p) {
            case 20: return kAppFtpData;
            case 21: return kAppFtp;
            case 22: return kAppSsh;
            case 23: return kAppTelnet;
            case 25:
            case 587: return kAppSmtp;
            case 53: return kAppDns;
            case 88: return kAppKerberos;
            case 389:
            case 3268: return kAppLdap;  // and the Global Catalog
            case 139:
            case 445: return kAppSmb;
            case 135: return kAppDcerpc;
            case 3306: return kAppMysql;
            case 5432: return kAppPgsql;
            case 1433:
            case 2433: return kAppTds;
            case 110: return kAppPop;
            case 143: return kAppImap;
            case 80: case 1900: case 2710: case 2869: case 3128: case 3132: case 5985: case 8080: case 8088: case 11371:
                return kAppHttp;
            case 443: case 465: case 563: case 636: case 853: case 989: case 990: case 992: case 993: case 994: case 995:
            case 3269: case 5061: case 6514: case 8883:
                return kAppTls;
            default: return kAppNone;
        }
    }

    size_t conv_hash() const { return FlowKeyHash()(key_); }

    // Wireshark's decode_tcp_ports(): the conversation's dissector, then the
    // server port, the lower and the higher port, then heuristics, else data.
    void app_payload(InspectorState::Conv& c, int di, size_t off, size_t len, bool can_desegment) {
        bool saved = can_desegment_;
        can_desegment_ = can_desegment;
        deseg_ = Deseg();
        if (len) app_dispatch(c, di, off, len);
        // Wireshark calls TLS at the FIN even with no bytes held: the end of a response
        // read until the connection closes.
        else if (seg_fin_ && c.tls_http_need[di & 1] == kMaxTlsHttp) tls_dissect(c, di, off, 0);
        can_desegment_ = saved;
    }

    void app_dispatch(InspectorState::Conv& c, int di, size_t off, size_t len) {
        if (!st_.ftp_data.empty()) {  // data channel announced on an FTP control connection
            // Wireshark's conversation: the announced address and port, and the control
            // connection's other end on any port.
            auto it = st_.ftp_data.find(d_.dst + "|" + std::to_string(dport_) + "|" + d_.src);
            if (it == st_.ftp_data.end()) it = st_.ftp_data.find(d_.src + "|" + std::to_string(sport_) + "|" + d_.dst);
            if (it != st_.ftp_data.end()) {
                set_proto("FTP-DATA");
                fproto("ftp-data", off, len);
                std::string info = fmt("FTP Data: %zu bytes (%s)", len, it->second.mode.c_str());
                if (!it->second.cmd.empty()) info += " (" + it->second.cmd + ")";
                col_set(info);
                layer("FTP Data", off, len);
                return;
            }
        }
        if (c.app && run_app(c.app, c, di, off, len)) return;
        uint16_t ports[3] = {c.server_port, std::min(sport_, dport_), std::max(sport_, dport_)};
        for (int i = 0; i < 3; ++i) {
            if (!ports[i] || (i > 0 && ports[i] == ports[0]) || (i == 2 && ports[2] == ports[1])) continue;
            uint8_t a = app_for_port(ports[i]);
            if (a && run_app(a, c, di, off, len)) return;
        }
        const uint8_t* p = b_.p + off;
        if (tls_heuristic(off, len)) {
            c.app = kAppTls;
            if (run_app(kAppTls, c, di, off, len)) return;
        }
        if (starts_with(p, len, "SSH-")) {
            c.app = kAppSsh;
            run_app(kAppSsh, c, di, off, len);
            return;
        }
        if (len >= 9 && h2_magic(p, len)) {  // cleartext HTTP/2 with prior knowledge: the connection preface
            c.app = kAppHttp2;
            if (run_app(kAppHttp2, c, di, off, len)) return;
        }
        if (http_heuristic(off, len)) {
            c.app = kAppHttp;
            if (run_app(kAppHttp, c, di, off, len)) return;
        }
        if (dcerpc_heuristic(off, len)) {  // DCE/RPC services on the ports the endpoint mapper hands out
            c.app = kAppDcerpc;
            dcerpc_tcp(off, len);
            return;
        }
        fproto("data", off, len);
        Layer& l = layer("Data", off, len);
        FIELD(l, "Length", fmt("%zu bytes", len), off, len);
    }

    bool run_app(uint8_t app, InspectorState::Conv& c, int di, size_t off, size_t len) {
        switch (app) {
            case kAppSsh: return ssh_dissect(c, di, off, len);
            case kAppTls: return tls_dissect(c, di, off, len);
            case kAppHttp: return http_dissect(c, di, off, len);
            case kAppHttp2: return h2_tcp(c, di, off, len);
            case kAppDns: dns_tcp(off, len); return true;
            case kAppKerberos: kerberos_tcp(off, len); return true;
            case kAppLdap: ldap_tcp(c, di, off, len); return true;
            case kAppSmb: nbss_tcp(c, di, off, len); return true;
            case kAppDcerpc: dcerpc_tcp(off, len); return true;
            case kAppMysql: mysql_tcp(c, di, off, len); return true;
            case kAppPgsql: pgsql_tcp(c, di, off, len); return true;
            case kAppTds: tds_tcp(c, di, off, len); return true;
            case kAppFtp: ftp(c, di, off, len); return true;
            case kAppFtpData:
                set_proto("FTP-DATA");
                fproto("ftp-data", off, len);
                col_set(fmt("FTP Data: %zu bytes", len));
                layer("FTP Data", off, len);
                return true;
            case kAppSmtp: line_proto(c, di, off, len, "SMTP", "S: ", "C: ", sport_ == 587 || dport_ == 587 ? 587 : 25); return true;
            case kAppPop: line_proto(c, di, off, len, "POP", "S: ", "C: ", 110); return true;
            case kAppImap: line_proto(c, di, off, len, "IMAP", "Response: ", "Request: ", 143); return true;
            case kAppTelnet:
                set_proto("TELNET");
                fproto("telnet", off, len);
                col_set("Telnet Data ...");
                layer("Telnet", off, len);
                return true;
            default: return false;
        }
    }

    // DNS over TCP: messages with a 2-byte length prefix (tcp_dissect_pdus).
    void dns_tcp(size_t off, size_t len) {
        size_t pos = 0;
        while (pos < len) {
            size_t rem = len - pos;
            if (rem < 2) {
                if (can_desegment_) deseg_ = {pos, kOneMore};
                return;
            }
            size_t plen = 2 + static_cast<size_t>(b_.u16(off + pos));
            if (rem < plen && can_desegment_) {
                deseg_ = {pos, static_cast<uint32_t>(plen - rem)};
                return;
            }
            std::string saved_info = d_.info, saved_proto = d_.protocol;
            bool ok = dns(off + pos + 2, std::min(plen, rem) - 2, "DNS");
            std::string info = d_.info;
            d_.info = saved_info;
            d_.protocol = saved_proto;
            set_proto("DNS");
            if (ok) col_set(info);
            col_set_fence();
            pos += plen;
        }
    }

    // ------------------------------------------------------- databases
    // A NUL-terminated string from `at` (to `end` when there is no NUL); *next is past it.
    std::string zstring(size_t at, size_t end, size_t* next = nullptr) const {
        size_t e = at;
        while (e < end && b_.p[e]) ++e;
        if (next) *next = e < end ? e + 1 : end;
        return at < end ? std::string(reinterpret_cast<const char*>(b_.p + at), e - at) : std::string();
    }

    // MySQL, after packet-mysql.c: packets with a 3-byte length and a sequence number
    // (tcp_dissect_pdus), and the request/response state that tells a greeting, a
    // login, an OK, an error and the pieces of a result set apart.
    enum MysqlState : uint8_t {
        kMyUndefined, kMyLogin, kMyLoginResponse, kMyRequest, kMyResponseOk, kMyResponseTabular, kMyResponseMessage,
        kMyShowFields, kMyFieldPacket, kMyRowPacket, kMyAuthSwitchResponse, kMyLocalInfile, kMyPrepare
    };

    static const char* mysql_command_name(uint8_t c) {
        static const char* const names[] = {
            "SLEEP", "Quit", "Use Database", "Query", "Show Fields", "Create Database", "Drop Database", "Refresh",
            "Shutdown", "Statistics", "Process List", "Connect", "Kill Server Thread", "Dump Debuginfo", "Ping", "Time",
            "Insert Delayed", "Change User", "Send Binlog", "Send Table", "Slave Connect", "Register Slave",
            "Prepare Statement", "Execute Statement", "Send BLOB", "Close Statement", "Reset Statement", "Set Option",
            "Fetch Data", "Daemon", "Send Binlog GTID", "Reset Connection"};
        return c < sizeof(names) / sizeof(names[0]) ? names[c] : nullptr;
    }

    uint64_t mysql_lenenc(size_t at, size_t end, size_t* used) const {
        *used = 0;
        if (at >= end) return 0;
        uint8_t f = b_.u8(at);
        *used = 1;
        if (f < 0xfb) return f;
        if (f == 0xfc && at + 3 <= end) { *used = 3; return b_.le16(at + 1); }
        if (f == 0xfd && at + 4 <= end) { *used = 4; return b_.le32(at) >> 8; }
        if (f == 0xfe && at + 9 <= end) { *used = 9; return b_.le64(at + 1); }
        return 0;
    }

    void mysql_tcp(InspectorState::Conv& c, int di, size_t off, size_t len) {
        bool client = client_side(c, di, sport_, dport_, 3306);
        size_t pos = 0;
        while (pos < len) {
            size_t rem = len - pos;
            if (rem < 3) {
                if (can_desegment_) deseg_ = {pos, kOneMore};
                return;
            }
            size_t plen = 4 + (b_.u8(off + pos) | (b_.u8(off + pos + 1) << 8) | (static_cast<size_t>(b_.u8(off + pos + 2)) << 16));
            if (rem < plen && can_desegment_) {
                deseg_ = {pos, static_cast<uint32_t>(plen - rem)};
                return;
            }
            mysql_pdu(c, client, off + pos, std::min(plen, rem));
            if (c.app == kAppTls) return;  // the login asked for TLS: the rest is TLS
            pos += plen;
        }
    }

    void mysql_error(Layer& l, size_t at, size_t end) {
        if (at + 2 > end) return truncated();
        uint16_t code = b_.le16(at);
        FF(uint("mysql.error_code", code));
        FIELD(l, "Error Code", std::to_string(code), at, 2);
        at += 2;
        if (at < end && b_.u8(at) == '#' && at + 6 <= end) {
            std::string state(reinterpret_cast<const char*>(b_.p + at + 1), 5);
            FF(string("mysql.sqlstate", state));
            FIELD(l, "SQL state", state, at + 1, 5);
            at += 6;
        }
        std::string msg(reinterpret_cast<const char*>(b_.p + at), end > at ? end - at : 0);
        FF(string("mysql.error.message", msg));
        FIELD(l, "Error message", msg, at, end - at);
        col_append(fmt(" Error %u ", code));
    }

    void mysql_pdu(InspectorState::Conv& c, bool client, size_t off, size_t plen) {
        set_proto("MySQL");
        fproto("mysql", off, plen);
        Layer& l = layer("MySQL Protocol", off, plen);
        if (plen < 4) return truncated();
        size_t body = off + 4, end = off + plen;
        size_t blen = plen - 4;
        uint8_t num = b_.u8(off + 3);
        FF(uint("mysql.packet_length", blen));
        FF(uint("mysql.packet_number", num));
        FIELD(l, "Packet Length", std::to_string(blen), off, 3);
        FIELD(l, "Packet Number", std::to_string(num), off + 3, 1);
        uint8_t b0 = blen ? b_.u8(body) : 0;
        uint8_t& st = c.mysql_state;
        size_t used = 0;
        if (!client) {
            if (num == 0 && st == kMyUndefined) {
                col_set("Server Greeting ");
                st = kMyLogin;
                if (b0 == 0xff) {  // the server turns the client away before any login
                    mysql_error(l, body + 1, end);
                    return;
                }
                FF(uint("mysql.protocol", b0));
                FIELD(l, "Protocol", std::to_string(b0), body, 1);
                size_t next = end;
                std::string version = zstring(body + 1, end, &next);
                FF(string("mysql.version", version));
                FIELD(l, "Version", version, body + 1, next - body - 1);
                if (next + 4 <= end) {
                    FF(uint("mysql.thread_id", b_.le32(next)));
                    FIELD(l, "Thread ID", std::to_string(b_.le32(next)), next, 4);
                }
                col_append(fmt(" proto=%u version=%s ", b0, version.c_str()));
                return;
            }
            if (st == kMyLoginResponse && b0 == 0xfe && blen >= 9) {
                col_set("Auth Switch Request ");
                FF(uint("mysql.response_code", b0));
                FF(uint("mysql.eof", b0));
                size_t next = end;
                std::string plugin = zstring(body + 1, end, &next);
                FIELD(l, "Auth Method Name", plugin, body + 1, next - body - 1);
                st = kMyAuthSwitchResponse;
                return;
            }
            if (st == kMyLoginResponse && b0 == 0x01 && blen == 2 && b_.u8(body + 1) == 3) {
                col_set("Caching_sha2_password fast_auth_success");
                return;
            }
            col_set("Response ");
            if (blen) {
                FIELD(l, "Response Code", fmt("0x%02x", b0), body, 1);
                // OK, a prepared statement, a binary row (a text row starting with an empty value is not one)
                if (b0 == 0x00 && (st != kMyRowPacket || c.mysql_binary) && st != kMyFieldPacket)
                    FF(uint("mysql.response_code", b0));
            }
            if (b0 == 0xff && blen >= 3) {
                FF(uint("mysql.response_code", b0));
                mysql_error(l, body + 1, end);
                st = kMyRequest;
                return;
            }
            if (b0 == 0xfe && blen < 9) {
                FF(uint("mysql.response_code", b0));
                FF(uint("mysql.eof", b0));
                st = st == kMyFieldPacket ? kMyRowPacket : kMyRequest;
                return;
            }
            if (b0 == 0x00 && blen && st == kMyPrepare) {  // a prepared statement: its id, columns and parameters
                if (blen >= 7) FF(uint("mysql.num_fields", b_.le16(body + 5)));
                if (blen >= 9) {
                    FIELD(l, "Statement ID", std::to_string(b_.le32(body + 1)), body + 1, 4);
                    FIELD(l, "Fields", std::to_string(b_.le16(body + 5)), body + 5, 2);
                    FIELD(l, "Parameters", std::to_string(b_.le16(body + 7)), body + 7, 2);
                }
                st = kMyFieldPacket;
                return;
            }
            if (b0 == 0x00 && blen && st != kMyFieldPacket && st != kMyRowPacket) {
                uint64_t rows = mysql_lenenc(body + 1, end, &used);
                FF(uint("mysql.affected_rows", rows));
                FIELD(l, "Affected Rows", std::to_string(rows), body + 1, used);
                col_append(" OK ");
                st = kMyRequest;
                return;
            }
            switch (st) {
                case kMyResponseTabular: {
                    if (b0 == 0xfb) {
                        col_append(" LOCAL INFILE");
                        st = kMyLocalInfile;
                        return;
                    }
                    uint64_t n = mysql_lenenc(body, end, &used);
                    FF(uint("mysql.num_fields", n));
                    FIELD(l, "Number of fields", std::to_string(n), body, used);
                    col_append("TABULAR ");
                    col_set_fence();
                    st = kMyFieldPacket;
                    return;
                }
                case kMyFieldPacket:
                case kMyShowFields:
                case kMyRowPacket: return;
                default: st = kMyRequest; return;
            }
        }
        // The client.
        if (num == 1 && (st == kMyLogin || st == kMyUndefined)) {
            col_set("Login Request");
            st = kMyLoginResponse;
            if (blen < 4) return truncated();
            uint32_t caps = b_.le16(body);
            size_t at = body;
            if (caps & 0x0200) {  // CLIENT_PROTOCOL_41
                caps = b_.le32(body);
                at = body + 32;
            } else {
                at = body + 5;
            }
            std::string user, db;
            bool has_db = false;
            if (at >= end) {  // nothing after the fixed part: a request to start TLS (CLIENT_SSL)
                FF(string("mysql.user", ""));
                if (caps & 0x0800) c.app = kAppTls;
            } else {
                size_t next = end;
                user = zstring(at, end, &next);
                FF(string("mysql.user", user));
                FIELD(l, "Username", user, at, next - at);
                at = next;
                if (caps & 0x00200000) {  // CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
                    uint64_t n = mysql_lenenc(at, end, &used);
                    at += used + n;
                } else if (caps & 0x8000) {  // CLIENT_SECURE_CONNECTION
                    at += at < end ? 1 + b_.u8(at) : 0;
                } else {
                    zstring(at, end, &at);
                }
                if ((caps & 0x08) && at < end) {  // CLIENT_CONNECT_WITH_DB
                    size_t dnext = end;
                    db = zstring(at, end, &dnext);
                    has_db = true;
                    FF(string("mysql.schema", db));
                    FIELD(l, "Schema", db, at, dnext - at);
                }
            }
            col_append(" user=" + user + " ");
            if (has_db) col_append("db=" + db + " ");
            return;
        }
        if (st == kMyAuthSwitchResponse) {
            col_set("Auth Switch Response ");
            st = kMyLoginResponse;
            return;
        }
        if (st == kMyLocalInfile) {
            col_set("Request LOCAL INFILE Payload");
            return;
        }
        col_set("Request");
        if (!blen) return truncated();
        FF(uint("mysql.command", b0));
        const char* name = mysql_command_name(b0);
        FIELD(l, "Command", name ? name : fmt("Unknown (%u)", b0), body, 1);
        if (name) col_append(std::string(" ") + name);
        else col_append(fmt(" Unknown (%u) ", b0));
        if (b0 == 3 || b0 == 22) {
            std::string q(reinterpret_cast<const char*>(b_.p + body + 1), blen - 1);
            FF(string("mysql.query", q));
            FIELD(l, "Statement", q, body + 1, blen - 1);
        } else if (b0 == 2 || b0 == 5 || b0 == 6) {  // Use, Create, Drop Database
            std::string q(reinterpret_cast<const char*>(b_.p + body + 1), blen - 1);
            FF(string("mysql.schema", q));
            FIELD(l, "Schema", q, body + 1, blen - 1);
        } else if (b0 == 17) {  // Change User: user, password, database
            size_t at = body + 1;
            std::string user = zstring(at, end, &at);
            FF(string("mysql.user", user));
            FIELD(l, "Username", user, body + 1, user.size());
            at += at < end ? 1 + b_.u8(at) : 0;
            if (at < end) {
                std::string db = zstring(at, end);
                FF(string("mysql.schema", db));
                FIELD(l, "Schema", db, at, db.size());
            }
        }
        c.mysql_binary = b0 == 23;
        switch (b0) {
            case 3: case 10: case 23: st = kMyResponseTabular; break;
            case 4: st = kMyShowFields; break;
            case 9: st = kMyResponseMessage; break;
            case 22: st = kMyPrepare; break;
            case 1: st = kMyRequest; break;
            default: st = kMyResponseOk; break;
        }
    }

    // PostgreSQL, after packet-pgsql.c: messages with a type byte and a 4-byte length
    // (a client's first messages have no type byte). The Info column lists each
    // message's type letter: ">Q" from the client, "<T/D/C/Z" from the server.
    static const char* pgsql_type_name(bool fe, uint8_t t) {
        if (fe) {
            switch (t) {
                case 'p': return "Password message";
                case 'Q': return "Simple query";
                case 'P': return "Parse";
                case 'B': return "Bind";
                case 'E': return "Execute";
                case 'D': return "Describe";
                case 'C': return "Close";
                case 'H': return "Flush";
                case 'S': return "Sync";
                case 'F': return "Function call";
                case 'd': return "Copy data";
                case 'c': return "Copy completion";
                case 'f': return "Copy failure";
                case 'X': return "Termination";
                default: return "Unknown";
            }
        }
        switch (t) {
            case 'R': return "Authentication request";
            case 'K': return "Backend key data";
            case 'S': return "Parameter status";
            case '1': return "Parse completion";
            case '2': return "Bind completion";
            case '3': return "Close completion";
            case 'C': return "Command completion";
            case 't': return "Parameter description";
            case 'T': return "Row description";
            case 'D': return "Data row";
            case 'I': return "Empty query";
            case 'n': return "No data";
            case 'E': return "Error";
            case 'N': return "Notice";
            case 's': return "Portal suspended";
            case 'Z': return "Ready for query";
            case 'A': return "Notification";
            case 'V': return "Function call response";
            case 'G': return "CopyIn response";
            case 'H': return "CopyOut response";
            case 'd': return "Copy data";
            case 'c': return "Copy completion";
            case 'v': return "Negotiate protocol version";
            default: return "Unknown";
        }
    }

    void pgsql_tcp(InspectorState::Conv& c, int di, size_t off, size_t len) {
        bool fe = client_side(c, di, sport_, dport_, 5432);
        if (!fe && c.pgsql_ssl_requested && len == 1) {  // the one-byte answer to an SSL request
            c.pgsql_ssl_requested = false;
            set_proto("PGSQL");
            fproto("pgsql", off, len);
            col_set("<");
            FF(string("pgsql.type", "SSL response"));
            Layer& l = layer("PostgreSQL", off, len);
            FIELD(l, "Type", "SSL response", off, 1);
            if (b_.u8(off) == 'S') c.app = kAppTls;
            return;
        }
        size_t pos = 0;
        bool first = true;
        while (pos < len) {
            size_t rem = len - pos;
            bool untyped = fe && b_.u8(off + pos) == 0;
            size_t head = untyped ? 4 : 5;
            if (rem < head) {
                if (can_desegment_) deseg_ = {pos, kOneMore};
                return;
            }
            uint32_t mlen = untyped ? b_.u32(off + pos) : b_.u32(off + pos + 1);
            size_t plen = untyped ? mlen : 1 + static_cast<size_t>(mlen);
            if (plen < head) plen = head;
            if (rem < plen && can_desegment_) {
                deseg_ = {pos, static_cast<uint32_t>(std::min<size_t>(plen - rem, 0x0FFFFFFDu))};
                return;
            }
            if (first) {
                set_proto("PGSQL");
                col_set(fe ? ">" : "<");
            }
            pgsql_msg(c, fe, first, off + pos, std::min(plen, rem), untyped, mlen);
            first = false;
            pos += plen;
        }
    }

    void pgsql_msg(InspectorState::Conv& c, bool fe, bool first, size_t off, size_t plen, bool untyped, uint32_t mlen) {
        fproto("pgsql", off, plen);
        Layer& l = layer("PostgreSQL", off, plen);
        size_t end = off + plen;
        uint8_t typ = untyped ? 0 : b_.u8(off);
        size_t body = off + (untyped ? 8 : 5);
        const char* name;
        if (untyped) {
            uint32_t tag = plen >= 8 ? b_.u32(off + 4) : 0;
            name = (mlen == 16 && tag == 80877102) ? "Cancel request"
                 : (mlen == 8 && tag == 80877103) ? "SSL request"
                 : (mlen == 8 && tag == 80877104) ? "GSS encrypt request"
                 : tag == 196608 ? "Startup message" : "Unknown";
            if (tag == 80877103) c.pgsql_ssl_requested = true;
        } else {
            name = pgsql_type_name(fe, typ);
        }
        col_append(fmt("%s%c", first ? "" : "/", typ >= 0x20 && typ < 0x7f ? typ : '?'));
        FF(string("pgsql.type", name));
        FF(uint("pgsql.length", mlen));
        FIELD(l, "Type", name, off, untyped ? 0 : 1);
        FIELD(l, "Length", std::to_string(mlen), off + (untyped ? 0 : 1), 4);
        if (body > end) return truncated();
        if (untyped && std::strcmp(name, "Startup message") == 0) {
            size_t at = body;
            while (at < end && b_.p[at]) {
                size_t next = end;
                std::string k = zstring(at, end, &next);
                std::string v = zstring(next, end, &at);
                FF(string("pgsql.parameter_name", k));
                FF(string("pgsql.parameter_value", v));
                FIELD(l, "Parameter name", k, 0, 0);
                FIELD(l, "Parameter value", v, 0, 0);
            }
            return;
        }
        if (fe && (typ == 'Q' || typ == 'P')) {  // a query, or one to prepare (after the statement's name)
            size_t at = body;
            if (typ == 'P') {
                std::string stmt = zstring(body, end, &at);
                FIELD(l, "Statement", stmt, body, at - body);
            }
            std::string q = zstring(at, end);
            FF(string("pgsql.query", q));
            FIELD(l, "Query", q, at, end - at);
        } else if (!fe && typ == 'S') {
            size_t next = end;
            std::string k = zstring(body, end, &next);
            std::string v = zstring(next, end);
            FF(string("pgsql.parameter_name", k));
            FF(string("pgsql.parameter_value", v));
            FIELD(l, "Parameter name", k, body, next - body);
            FIELD(l, "Parameter value", v, next, end - next);
        } else if (!fe && typ == 'Z' && body < end) {
            FF(uint("pgsql.status", b_.u8(body)));
            FIELD(l, "Status", fmt("%c", b_.u8(body)), body, 1);
        } else if (!fe && (typ == 'E' || typ == 'N')) {
            size_t at = body;
            while (at < end && b_.p[at]) {
                uint8_t code = b_.u8(at);
                size_t next = end;
                std::string v = zstring(at + 1, end, &next);
                const char* fname = nullptr;
                const char* label = nullptr;
                switch (code) {
                    case 'S': fname = "pgsql.severity"; label = "Severity"; break;
                    case 'V': fname = "pgsql.text"; label = "Text"; break;
                    case 'C': fname = "pgsql.code"; label = "Code"; break;
                    case 'M': fname = "pgsql.message"; label = "Message"; break;
                    case 'D': fname = "pgsql.detail"; label = "Detail"; break;
                    case 'H': fname = "pgsql.hint"; label = "Hint"; break;
                    case 'P': fname = "pgsql.position"; label = "Position"; break;
                    case 'F': fname = "pgsql.file"; label = "File"; break;
                    case 'L': fname = "pgsql.line"; label = "Line"; break;
                    case 'R': fname = "pgsql.routine"; label = "Routine"; break;
                    default: break;
                }
                if (fname) {
                    FF(string(fname, v));
                    FIELD(l, label, v, at + 1, next - at - 1);
                }
                at = next;
            }
        }
    }

    // Microsoft SQL Server's TDS, after packet-tds.c: 8-byte packet headers (type,
    // status, length), the SQL text of a batch, and the error and message tokens at
    // the start of a response. TLS travels inside pre-login packets, then on its own.
    static const char* tds_type_name(uint8_t t) {
        switch (t) {
            case 1: return "SQL batch";
            case 2: return "TDS4/5 login";
            case 3: return "Remote Procedure Call";
            case 4: return "Response";
            case 5: case 8: case 9: case 10: case 11: case 12: case 13: return "Unused";
            case 6: return "Attention";
            case 7: return "Bulk load data";
            case 14: return "Transaction Manager Request";
            case 15: return "TDS5 query";
            case 16: return "TDS7 login";
            case 17: return "SSPI message";
            case 18: return "TDS7 pre-login message";
            default: return nullptr;
        }
    }

    void tds_tcp(InspectorState::Conv& c, int di, size_t off, size_t len) {
        if (c.tds_tls && tls_heuristic(off, len)) {  // the encrypted connection, as plain TLS records
            tls_dissect(c, di, off, len);
            return;
        }
        size_t pos = 0;
        bool first = true;
        while (pos < len) {
            size_t rem = len - pos;
            if (rem < 8) {
                if (can_desegment_) deseg_ = {pos, kOneMore};
                return;
            }
            size_t plen = std::max<size_t>(8, b_.u16(off + pos + 2));
            if (rem < plen && can_desegment_) {
                deseg_ = {pos, static_cast<uint32_t>(plen - rem)};
                return;
            }
            tds_packet(c, di, first, off + pos, std::min(plen, rem));
            first = false;
            pos += plen;
        }
    }

    void tds_packet(InspectorState::Conv& c, int di, bool first, size_t off, size_t plen) {
        set_proto("TDS");
        fproto("tds", off, plen);
        Layer& l = layer("Tabular Data Stream", off, plen);
        uint8_t type = b_.u8(off), status = b_.u8(off + 1);
        FF(uint("tds.type", type));
        FF(uint("tds.status", status));
        FF(uint("tds.length", b_.u16(off + 2)));
        FF(uint("tds.channel", b_.u16(off + 4)));
        FF(uint("tds.packet_number", b_.u8(off + 6)));
        FF(uint("tds.window", b_.u8(off + 7)));
        const char* name = tds_type_name(type);
        std::string label = name ? name : fmt("Unknown Packet Type: %u", type);
        FIELD(l, "Type", fmt("%s (%u)", label.c_str(), type), off, 1);
        FIELD(l, "Length", std::to_string(b_.u16(off + 2)), off + 2, 2);
        if (first) col_set(label);
        else col_append("," + label);
        bool eom = status & 1;
        if (!eom) col_append(" (Not last buffer)");
        size_t body = off + 8, end = off + plen;
        bool& more = c.tds_more[di & 1];
        bool continuation = more;
        more = !eom;
        if (continuation) return;  // the rest of a message that began in an earlier packet
        if (type == 18 && end - body >= 5 && b_.u8(body) == 0x16 && b_.u8(body + 1) == 3) {
            c.tds_tls = true;  // a TLS handshake inside the pre-login packets
            bool saved = can_desegment_;
            can_desegment_ = false;
            tls_dissect(c, di, body, end - body);
            can_desegment_ = saved;
            return;
        }
        if (type == 1 && end > body) {
            size_t at = body;
            if (end - body >= 8) {  // ALL_HEADERS (TDS 7.2 and later): a total length, then each header's
                uint32_t total = b_.le32(body), h1 = b_.le32(body + 4);
                if (total >= 8 && total <= end - body && h1 >= 6 && h1 <= total - 4) at = body + total;
            }
            std::string q = utf16le(at, end - at);
            FF(string("tds.query", q));
            FIELD(l, "Query", q, at, end - at);
        } else if (type == 4 && eom) {
            tds_tokens(l, body, end);
        }
    }

    void tds_tokens(Layer& l, size_t p, size_t end) {
        for (int n = 0; p < end && n < 256; ++n) {
            uint8_t tok = b_.u8(p);
            if (tok == 0xAA || tok == 0xAB) {  // ERROR, INFO
                if (p + 3 > end) return;
                size_t te = std::min(end, p + 3 + b_.le16(p + 1)), q = p + 3;
                if (q + 8 > te) return;
                bool err = tok == 0xAA;
                fproto(err ? "tds.error" : "tds.info", p, te - p);
                uint32_t number = b_.le32(q);
                FF(uint(err ? "tds.error.number" : "tds.info.number", number));
                FF(uint(err ? "tds.error.state" : "tds.info.state", b_.u8(q + 4)));
                FF(uint(err ? "tds.error.class" : "tds.info.class", b_.u8(q + 5)));
                size_t mlen = static_cast<size_t>(b_.le16(q + 6)) * 2;
                q += 8;
                std::string msg = utf16le(q, std::min(mlen, te - std::min(q, te)));
                FF(string(err ? "tds.error.msgtext" : "tds.info.msgtext", msg));
                FIELD(l, err ? "Error" : "Info", fmt("%u: ", number) + msg, p, te - p);
                q += mlen;
                if (q < te) {
                    size_t sl = static_cast<size_t>(b_.u8(q)) * 2;
                    FF(string(err ? "tds.error.servername" : "tds.info.servername", utf16le(q + 1, std::min(sl, te - q - 1))));
                    q += 1 + sl;
                }
                if (q < te) {
                    size_t pl = static_cast<size_t>(b_.u8(q)) * 2;
                    FF(string(err ? "tds.error.procname" : "tds.info.procname", utf16le(q + 1, std::min(pl, te - q - 1))));
                    q += 1 + pl;
                }
                if (q + 4 <= te) FF(uint(err ? "tds.error.linenumber" : "tds.info.linenumber", b_.le32(q)));
                p = te;
            } else if (tok == 0xFD || tok == 0xFE || tok == 0xFF) {  // DONE, DONEPROC, DONEINPROC
                p += 13;
            } else if (tok == 0x79) {  // RETURNSTATUS
                p += 5;
            } else if (tok == 0xAD || tok == 0xE3 || tok == 0xA9 || tok == 0xA4 || tok == 0xA5 || tok == 0xED) {
                if (p + 3 > end) return;
                p += 3 + b_.le16(p + 1);
            } else {
                return;  // column metadata and rows need the column types: not read further
            }
        }
    }

    void line_proto(InspectorState::Conv& c, int di, size_t off, size_t len, const char* proto, const char* server_tag,
                    const char* client_tag, uint16_t server_port) {
        set_proto(proto);
        fproto(proto[0] == 'S' ? "smtp" : proto[0] == 'P' ? "pop" : "imap", off, len);
        bool client = client_side(c, di, sport_, dport_, server_port);
        std::string line = text_line(b_.p + off, len);
        col_set(std::string(client ? client_tag : server_tag) + line);
        Layer& l = layer(proto, off, len);
        FIELD(l, client ? "Request" : "Response", line, off, line.size());
    }

    void ftp(InspectorState::Conv& c, int di, size_t off, size_t len) {
        set_proto("FTP");
        bool client = client_side(c, di, sport_, dport_, 21);
        Layer& l = layer("File Transfer Protocol (FTP)", off, len);
        fproto("ftp", off, len);
        std::string first;
        size_t pos = 0;
        auto& pending = st_.ftp_pending[key_];
        if (st_.ftp_pending.size() > 10'000) st_.ftp_pending.clear();
        while (pos < len) {
            const uint8_t* p = b_.p + off + pos;
            size_t eol = 0;
            while (pos + eol < len && p[eol] != '\n') ++eol;
            std::string line = text_line(p, eol);
            if (pos == 0) {
                first = line;
                if (client) {
                    size_t sp = line.find(' ');
                    FF(string("ftp.request.command", line.substr(0, sp)));
                    if (sp != std::string::npos) FF(string("ftp.request.arg", line.substr(sp + 1)));
                } else if (line.size() >= 3 && std::isdigit(static_cast<unsigned char>(line[0]))) {
                    FF(uint("ftp.response.code", static_cast<uint64_t>(std::atoi(line.substr(0, 3).c_str()))));
                }
            }
            FIELD(l, client ? "Request" : "Response", line, off + pos, eol);
            ftp_state(pending, client, line);
            pos += eol + 1;
        }
        col_set(std::string(client ? "Request: " : "Response: ") + first);
    }

    void ftp_state(InspectorState::FtpPending& pending, bool client, const std::string& line) {
        auto parse6 = [](const std::string& s, std::string& ip, uint16_t& port) {
            unsigned a[6];
            size_t start = s.find_first_of("0123456789");
            if (start == std::string::npos) return false;
            if (std::sscanf(s.c_str() + start, "%u,%u,%u,%u,%u,%u", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]) != 6)
                return false;
            for (unsigned v : a)
                if (v > 255) return false;
            ip = fmt("%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
            port = static_cast<uint16_t>(a[4] * 256 + a[5]);
            return true;
        };
        std::string cmd = line.substr(0, line.find(' '));
        for (auto& ch : cmd) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        if (client) {
            if (cmd == "PORT" && line.size() > 5) {
                std::string ip;
                uint16_t port = 0;
                if (parse6(line.substr(5), ip, port)) pending = {"PORT", ip, port};
            } else if (cmd == "EPRT" && line.size() > 6) {  // EPRT |1|ip|port|
                char delim = line[5];
                std::vector<std::string> parts;
                size_t s = 6;
                while (s <= line.size()) {
                    size_t e = line.find(delim, s);
                    if (e == std::string::npos) break;
                    parts.push_back(line.substr(s, e - s));
                    s = e + 1;
                }
                if (parts.size() >= 3) pending = {"EPRT", parts[1], static_cast<uint16_t>(std::atoi(parts[2].c_str()))};
            } else if (cmd == "RETR" || cmd == "STOR" || cmd == "STOU" || cmd == "APPE" || cmd == "LIST" ||
                       cmd == "NLST" || cmd == "MLSD") {
                if (!pending.mode.empty()) {
                    if (st_.ftp_data.size() > 10'000) st_.ftp_data.clear();
                    // PASV: the client connects; PORT: the server does.
                    bool passive = pending.mode == "PASV" || pending.mode == "EPASV";
                    st_.ftp_data[pending.ip + "|" + std::to_string(pending.port) + "|" + (passive ? d_.src : d_.dst)] =
                        {pending.mode, line};
                }
            }
        } else if (line.rfind("227", 0) == 0) {
            std::string ip;
            uint16_t port = 0;
            size_t paren = line.find('(');
            if (parse6(paren == std::string::npos ? line.substr(3) : line.substr(paren + 1), ip, port))
                pending = {"PASV", ip, port};
        } else if (line.rfind("229", 0) == 0) {
            size_t a = line.find("(|||");
            if (a != std::string::npos) pending = {"EPASV", d_.src, static_cast<uint16_t>(std::atoi(line.c_str() + a + 4))};
        }
    }

    // ------------------------------------------------------------- SSH
    uint8_t ssh_session_version(const InspectorState::Conv& c) const {
        if (st_.use) {  // the second pass sees the version the whole conversation settled on
            auto it = st_.use->ssh_version.find(conv_hash());
            if (it != st_.use->ssh_version.end()) return it->second;
        }
        return c.ssh_version;
    }

    bool ssh_dissect(InspectorState::Conv& c, int di, size_t off, size_t len) {
        auto& d = c.dir[di];
        bool server = !client_side(c, di, sport_, dport_, 22);
        uint8_t ver = ssh_session_version(c);
        set_proto(ver == 2 ? "SSHv2" : ver == 1 ? "SSHv1" : "SSH");
        col_clear();
        Layer& l = layer("SSH Protocol", off, len);
        fproto("ssh", off, len);
        size_t pos = 0;
        while (pos < len) {
            size_t last = pos;
            const uint8_t* p = b_.p + off + pos;
            size_t rem = len - pos;
            if ((!d.ssh_banner_done || d.ssh_banner_frame == frame_) && starts_with(p, rem, "SSH-")) {
                size_t eol = 0;
                while (eol < rem && p[eol] != '\n') ++eol;
                if (eol == rem && can_desegment_) {
                    deseg_ = {pos, kOneMore};
                    return true;  // waiting for the rest of the banner: no Client/Server prefix
                }
                size_t linelen = eol < rem ? eol + 1 : rem;
                std::string banner = text_line(p, eol, 255);
                col_append_sep("Protocol (" + banner + ")");
                FF(string("ssh.protocol", banner));
                FIELD(l, "Protocol", banner, off + pos, eol);
                ver = starts_with(p, rem, "SSH-2.") || starts_with(p, rem, "SSH-1.99") ? 2
                      : starts_with(p, rem, "SSH-1.")                                 ? 1
                                                                                       : 0;
                if (ver) {
                    c.ssh_version = ver;
                    if (st_.record) st_.record->ssh_version[conv_hash()] = ver;
                }
                d.ssh_banner_done = true;
                d.ssh_banner_frame = frame_;
                pos += linelen;
            } else if (ver == 2) {
                if (!ssh2(c, di, off, len, pos, l)) return true;  // waiting for more: no prefix
            } else {
                col_append_sep(fmt("Encrypted packet (len=%zu)", rem));
                FIELD(l, "Encrypted packet", fmt("%zu bytes", rem), off + pos, rem);
                pos = len;
            }
            if (pos <= last) break;
        }
        col_prepend(server ? "Server: " : "Client: ");
        return true;
    }

    // SSH-2 binary packets; false when the dissector asked for more data.
    bool ssh2(InspectorState::Conv& c, int di, size_t off, size_t len, size_t& pos, Layer& l) {
        auto& d = c.dir[di];
        while (pos < len) {
            size_t rem = len - pos;
            bool cleartext = !d.ssh_newkeys || (d.ssh_newkeys_frame == frame_ && pos < d.ssh_newkeys_offset);
            if (!cleartext) {  // after New Keys the packet lengths are encrypted too
                col_append_sep(fmt("Encrypted packet (len=%zu)", rem));
                FIELD(l, "Encrypted packet", fmt("%zu bytes", rem), off + pos, rem);
                pos = len;
                return true;
            }
            if (rem < 4) {
                if (can_desegment_) {
                    deseg_ = {pos, kOneMore};
                    return false;
                }
                pos = len;
                return true;
            }
            uint32_t plen = b_.u32(off + pos);
            if (can_desegment_ && static_cast<uint32_t>(plen + 4) > rem) {
                deseg_ = {pos, static_cast<uint32_t>(plen + 4 - rem)};
                return false;
            }
            if (plen >= 32768) plen = static_cast<uint32_t>(rem - 4);
            if (rem < 6) {
                pos = len;
                return true;
            }
            uint8_t code = b_.u8(off + pos + 5);
            FF(uint("ssh.message_code", code));
            std::string name = ssh_message(c, code);
            col_append_sep(name);
            size_t total = std::min<size_t>(static_cast<size_t>(plen) + 4, rem);
            FIELD(l, "Message", name, off + pos, total);
            if (code == 20) ssh_kexinit(d, off + pos + 6, total - 6);
            if (code == 21 && !d.ssh_newkeys) {
                d.ssh_newkeys = true;
                d.ssh_newkeys_frame = frame_;
                d.ssh_newkeys_offset = pos + 6;
            }
            pos += total;
        }
        return true;
    }

    void ssh_kexinit(InspectorState::Dir& d, size_t off, size_t len) {
        // 16-byte cookie, then the kex_algorithms name-list.
        if (len < 20 || !b_.have(off + 16, 4)) return;
        uint32_t n = b_.u32(off + 16);
        if (n > len - 20 || !b_.have(off + 20, n)) return;
        d.ssh_kex.assign(reinterpret_cast<const char*>(b_.p + off + 20), n);
    }

    std::string ssh_message(const InspectorState::Conv& c, uint8_t code) const {
        if (code >= 30 && code <= 39) {
            // Meaning depends on the negotiated key exchange: the first client algorithm the server also offers.
            int cl_dir = c.client < 0 ? 0 : c.client;
            const std::string& cl = c.dir[cl_dir].ssh_kex;
            const std::string& sv = c.dir[1 - cl_dir].ssh_kex;
            std::string kex;
            if (!cl.empty() && !sv.empty()) {
                size_t s = 0;
                while (s <= cl.size()) {
                    size_t e = cl.find(',', s);
                    std::string alg = cl.substr(s, e == std::string::npos ? std::string::npos : e - s);
                    if (("," + sv + ",").find("," + alg + ",") != std::string::npos) {
                        kex = alg;
                        break;
                    }
                    if (e == std::string::npos) break;
                    s = e + 1;
                }
            }
            if (kex == "diffie-hellman-group-exchange-sha1" || kex == "diffie-hellman-group-exchange-sha256") {
                static const char* gex[] = {"Diffie-Hellman Group Exchange Request (Old)",
                                            "Diffie-Hellman Group Exchange Group", "Diffie-Hellman Group Exchange Init",
                                            "Diffie-Hellman Group Exchange Reply", "Diffie-Hellman Group Exchange Request"};
                return code <= 34 ? gex[code - 30] : fmt("Unknown (%u)", code);
            }
            bool ecdh = kex.rfind("ecdh-sha2-", 0) == 0 || kex == "curve25519-sha256@libssh.org" ||
                        kex == "curve25519-sha256" || kex == "curve448-sha512";
            bool hybrid = kex == "mlkem768nistp256-sha256" || kex == "mlkem1024nistp384-sha384" ||
                          kex == "sntrup761x25519-sha512" || kex == "mlkem768x25519-sha256";
            const char* base = ecdh ? "Elliptic Curve Diffie-Hellman Key Exchange"
                               : hybrid ? "PQ/T Hybrid Key Exchange"
                                        : "Diffie-Hellman Key Exchange";
            if (code == 30) return std::string(base) + " Init";
            if (code == 31) return std::string(base) + " Reply";
            return fmt("Unknown (%u)", code);
        }
        switch (code) {
            case 1: return "Disconnect";
            case 2: return "Ignore";
            case 3: return "Unimplemented";
            case 4: return "Debug";
            case 5: return "Service Request";
            case 6: return "Service Accept";
            case 7: return "Extension Information";
            case 8: return "New Compression";
            case 20: return "Key Exchange Init";
            case 21: return "New Keys";
            case 50: return "User Authentication Request";
            case 51: return "User Authentication Failure";
            case 52: return "User Authentication Success";
            case 53: return "User Authentication Banner";
            case 60: return "Public Key algorithm accepted";
            case 80: return "Global Request";
            case 81: return "Request Success";
            case 82: return "Request Failure";
            case 90: return "Channel Open";
            case 91: return "Channel Open Confirmation";
            case 92: return "Channel Open Failure";
            case 93: return "Window Adjust";
            case 94: return "Channel Data";
            case 95: return "Channel Extended Data";
            case 96: return "Channel EOF";
            case 97: return "Channel Close";
            case 98: return "Channel Request";
            case 99: return "Channel Success";
            case 100: return "Channel Failure";
            default: return fmt("Unknown (%u)", code);
        }
    }

    // ------------------------------------------------------------- TLS
    static constexpr uint16_t kPctVersion = 0x8001;
    static bool tls_valid_ct(uint8_t t) { return t >= 20 && t <= 26; }

    // Wireshark's record sniffing for a session whose version isn't known yet.
    bool ssl_looks_like_sslv2(size_t at) const {  // an unencrypted SSLv2 handshake header
        uint8_t mt = b_.u8(at + 2);  // Error, Client Hello, Client Master Key or Server Hello
        return b_.u8(at) >= 0x80 && (mt <= 2 || mt == 4);
    }
    bool ssl_looks_like_sslv3(size_t at) const {
        uint16_t v = b_.u16(at + 1);
        return tls_valid_ct(b_.u8(at)) && (v == 0x0300 || v == 0x0301 || v == 0x0302 || v == 0x0303 ||
                                            v == 0x0304 || v == 0x0101);
    }
    static bool ssl_valid_version(uint16_t v) {  // Wireshark's ssl_versions table
        return v == 0x0002 || v == 0x0100 || v == 0x0101 || (v >= 0x0300 && v <= 0x0304) || v == 0xfeff ||
               v == 0xfefd || v == 0xfefc || (v >= 0x7f0e && v <= 0x7f1c) || v == 0xfb17 || v == 0xfb1a;
    }
    // Bytes of the frame (or reassembled message) at `at`, or nothing past its end.
    bool byte_at(size_t at, size_t end, uint8_t& out) const {
        if (at >= end || !b_.have(at, 1)) return false;
        out = b_.u8(at);
        return true;
    }
    bool ssl2_valid_handshake(size_t m, size_t end, size_t rlen) const {
        uint8_t t;
        if (!byte_at(m, end, t)) return false;
        auto u16at = [&](size_t at, uint16_t& v) {
            if (at + 2 > end || !b_.have(at, 2)) return false;
            v = b_.u16(at);
            return true;
        };
        uint16_t a = 0, b = 0, c2 = 0;
        switch (t) {
            case 1: return u16at(m + 1, a) && ssl_valid_version(a);
            case 4: return u16at(m + 3, a) && ssl_valid_version(a);
            case 2: return u16at(m + 4, a) && u16at(m + 6, b) && u16at(m + 8, c2) && size_t(a) + b + c2 <= rlen;
            default: return false;
        }
    }
    bool pct_valid_handshake(size_t m, size_t end, size_t rlen) const {
        uint8_t t;
        if (!byte_at(m, end, t)) return false;
        auto u16at = [&](size_t at, uint16_t& v) {
            if (at + 2 > end || !b_.have(at, 2)) return false;
            v = b_.u16(at);
            return true;
        };
        uint16_t v = 0;
        switch (t) {
            case 1: return u16at(m + 1, v) && v == kPctVersion;
            case 2: return u16at(m + 2, v) && v == kPctVersion;
            case 3: {
                size_t sum = 0;
                for (size_t at : {6u, 8u, 10u, 12u, 14u, 16u}) {
                    if (!u16at(m + at, v)) return false;
                    sum += v;
                }
                return sum <= rlen;
            }
            case 4: return u16at(m + 34, v) && size_t(v) + 36 == rlen;
            default: return false;
        }
    }

    // One SSLv2 (or PCT) record, as Wireshark's dissect_ssl2_record reads it: a
    // 2-byte length (high bit set) or a 3-byte one (with padding). Returns false
    // when the record needs more segments.
    bool ssl2_record(InspectorState::Conv& c, size_t off, size_t& pos, size_t len) {
        size_t avail = len - pos, at = off + pos;
        uint8_t b0 = b_.u8(at);
        size_t hl = (b0 & 0x80) ? 2 : 3;
        if (avail < hl) {
            if (can_desegment_) deseg_ = {pos, kOneMore};
            else pos = len;
            return false;
        }
        size_t rlen = hl == 2 ? ((static_cast<size_t>(b0 & 0x7F) << 8) | b_.u8(at + 1))
                              : ((static_cast<size_t>(b0 & 0x3F) << 8) | b_.u8(at + 1));
        if (avail < hl + rlen) {
            if (can_desegment_) deseg_ = {pos, static_cast<uint32_t>(hl + rlen - avail)};
            else pos = len;
            return false;
        }
        size_t m = at + hl, end = off + len;
        uint8_t mt = 0;
        byte_at(m, end, mt);
        uint16_t sv = tls_session_version(c);
        if (!sv) {  // a server hello or later SSLv2 message settles the session's version
            uint16_t nv = pct_valid_handshake(m, end, rlen) ? kPctVersion : (mt >= 2 && mt <= 8) ? 0x0002 : 0;
            if (nv) {
                c.tls_version = nv;
                if (st_.record) st_.record->tls_version[conv_hash()] = nv;
                sv = nv;
            }
        }
        bool pct = sv == kPctVersion;
        set_proto(pct ? "PCT" : "SSLv2");
        static const char* v2_types[] = {"Error", "Client Hello", "Client Master Key", "Client Finished", "Server Hello",
                                         "Server Verify", "Server Finished", "Request Certificate", "Client Certificate"};
        static const char* pct_types[] = {nullptr, "Client Hello", "Server Hello", "Client Master Key", "Server Verify",
                                          "Error"};
        const char* name = pct ? (mt <= 5 ? pct_types[mt] : nullptr) : (mt <= 8 ? v2_types[mt] : nullptr);
        bool valid = name && (pct ? pct_valid_handshake(m, end, rlen) : ssl2_valid_handshake(m, end, rlen));
        Layer& l = layer(fmt("%s Record Layer: %s", pct ? "PCT" : "SSLv2", valid ? name : "Encrypted Data").c_str(), at,
                         hl + rlen);
        FIELD(l, "Length", fmt("%zu", rlen), at, hl);
        FF(uint("tls.record.version", 2));
        col_append_sep(valid ? name : "Encrypted Data");
        pos += hl + rlen;
        return true;
    }

    static uint16_t tls_norm_version(uint16_t v) {
        if (v == 0x0300 || v == 0x0301 || v == 0x0302 || v == 0x0303 || v == 0x0304 || v == 0x0101) return v;
        if ((v & 0xFF00) == 0x7F00 || v == 0xFB17 || v == 0xFB1A) return 0x0304;  // TLS 1.3 drafts
        return 0;
    }

    static const char* tls_version_name(uint16_t v) {
        switch (v) {
            case 0x0002: return "SSLv2";
            case kPctVersion: return "PCT";
            case 0x0300: return "SSLv3";
            case 0x0301: return "TLSv1";
            case 0x0101: return "TLCP";
            case 0x0302: return "TLSv1.1";
            case 0x0303: return "TLSv1.2";
            case 0x0304: return "TLSv1.3";
            default: return nullptr;
        }
    }

    static const char* tls_hs_name(uint8_t t) {
        switch (t) {
            case 0: return "Hello Request";
            case 1: return "Client Hello";
            case 2: return "Server Hello";
            case 4: return "New Session Ticket";
            case 5: return "End of Early Data";
            case 6: return "Hello Retry Request";
            case 8: return "Encrypted Extensions";
            case 11: return "Certificate";
            case 12: return "Server Key Exchange";
            case 13: return "Certificate Request";
            case 14: return "Server Hello Done";
            case 15: return "Certificate Verify";
            case 16: return "Client Key Exchange";
            case 20: return "Finished";
            case 21: return "Client Certificate URL";
            case 22: return "Certificate Status";
            case 23: return "Supplemental Data";
            case 24: return "Key Update";
            case 25: return "Compressed Certificate";
            case 67: return "Encrypted Extensions";
            default: return nullptr;
        }
    }

    // What Wireshark's session->version holds when this frame is shown.
    uint16_t tls_session_version(const InspectorState::Conv& c) const {
        if (st_.use) {
            auto it = st_.use->tls_version.find(conv_hash());
            if (it != st_.use->tls_version.end() && it->second) return it->second;
        }
        return c.tls_version;
    }

    void tls_set_version(InspectorState::Conv& c, uint8_t ct, uint8_t hs, uint16_t v) {
        bool authoritative = (ct == 22 && tls_hs_name(hs) && hs != 1) || (ct != 22 && tls_valid_ct(ct));
        v = tls_norm_version(v);
        if (!authoritative || !v) return;
        c.tls_version = v;
        if (st_.record) st_.record->tls_version[conv_hash()] = v;
    }

    bool tls_heuristic(size_t off, size_t len) const {
        if (len < 5) return false;
        uint8_t ct = b_.u8(off);
        uint16_t v = b_.u16(off + 1), rlen = b_.u16(off + 3);
        if (ct != 22 && ct != 23) return false;
        if (v != 0x0300 && v != 0x0301 && v != 0x0302 && v != 0x0303 && v != 0x0101) return false;
        return rlen != 0 && rlen < 16384 + 2048;
    }

    // Decrypt a TLS 1.3 Application Data record when the user supplied the keys (a key
    // log, like Wireshark's tls.keylog_file). Only records the user already holds the
    // secrets for can be read; a handshake record (different keys) simply won't open.
    // Returns true when the record was decrypted and shown.
    bool tls_try_decrypt(InspectorState::Conv& c, int di, size_t body, size_t rlen, Layer& l) {
        (void)l;
        if (st_.keylog && c.tls_cr_set && c.tls_early_offered && !c.tls_early_done && di == c.tls_client_dir &&
            tls13_early_record(c, di, body, rlen))
            return true;
        if (!st_.keylog || !c.tls_cr_set || tls_session_version(c) != 0x0304)
            return false;
        if (!c.tls_dec_looked_up) {
            c.tls_dec_looked_up = true;
            c.tls_secrets = st_.keylog->find(c.tls_client_random);
        }
        if (!c.tls_secrets || !tls13_cipher_supported(c.tls_cipher))
            return false;
        int side = di & 1;
        if (tls13_handshake_record(c, di, body, rlen))
            return true;
        if (!c.tls_app_ready[side]) {
            auto which = (di == c.tls_server_dir) ? TlsSecrets::ServerApp : TlsSecrets::ClientApp;
            if (!c.tls_secrets->has(which))
                return false;
            c.tls_app[side] = tls13_record_keys(c.tls_secrets->secret[which], c.tls_secrets->len[which], c.tls_cipher);
            c.tls_app_ready[side] = c.tls_app[side].valid;
            if (!c.tls_app_ready[side])
                return false;
        }
        if (body < 5 || rlen < 9 || !b_.have(body, rlen))  // (inner type and the shortest tag, CCM_8's)
            return false;
        const uint8_t* aad = b_.p + body - 5;
        std::string plain(rlen, '\0');
        long n = tls13_open(c.tls_app[side], c.tls_app_seq[side], aad, b_.p + body, rlen,
                            reinterpret_cast<uint8_t*>(&plain[0]));
        if (n < 0)
            return false;  // a handshake record (handshake keys), or not ours: leave it encrypted
        c.tls_app_seq[side]++;
        tls13_plaintext(c, di, body, rlen, plain, static_cast<size_t>(n));
        return true;
    }

    // A TLS 1.3 record opened under application or early-data keys: strip the padding,
    // read the inner content type, and hand the plaintext on.
    void tls13_plaintext(InspectorState::Conv& c, int di, size_t body, size_t rlen, std::string& plain, size_t pn) {
        while (pn && plain[pn - 1] == '\0')  // strip TLS 1.3 zero padding
            --pn;
        if (!pn) {
            col_append_sep("Application Data");
            return;
        }
        uint8_t inner = static_cast<uint8_t>(plain[pn - 1]);
        --pn;  // the last non-zero byte is the real content type
        plain.resize(pn);
        const uint8_t* pp = reinterpret_cast<const uint8_t*>(plain.data());
        if (full_)
            tls_show_plaintext(body, rlen, inner, pp, pn);
        fproto("tls", body, rlen);
        if (inner == 23 && pn && st_.tap) st_.tap->tls_data(pp, pn);
        if (inner == 23 && pn)
            tls_app_data(c, di, pp, pn);
        else if (inner == 21)
            tls_decrypted_alert(c, di, pp, pn);
        else if (inner == 22)
            tls13_post_handshake(c, di & 1, pp, pn);
        else
            col_append_sep("Application Data");
    }

    // TLS 1.3 early data (0-RTT): the client's records after a Client Hello offering it,
    // under CLIENT_EARLY_TRAFFIC_SECRET, up to its End of Early Data, or to the first
    // record those keys don't open (the server turned the early data down). The suite is
    // the resumed session's, not known before the Server Hello: the one the record's tag
    // checks with. False when the record isn't early data.
    bool tls13_early_record(InspectorState::Conv& c, int di, size_t body, size_t rlen) {
        if (body < 5 || rlen < 9 || !b_.have(body, rlen)) return false;
        if (!c.tls_dec_looked_up) {
            c.tls_dec_looked_up = true;
            c.tls_secrets = st_.keylog->find(c.tls_client_random);
        }
        if (!c.tls_secrets || !c.tls_secrets->has(TlsSecrets::ClientEarly)) {
            c.tls_early_done = true;
            return false;
        }
        const uint8_t* aad = b_.p + body - 5;
        std::string plain(rlen, '\0');
        uint8_t* pp = reinterpret_cast<uint8_t*>(&plain[0]);
        long n = -1;
        if (c.tls_early.valid) {
            n = tls13_open(c.tls_early, c.tls_early_seq, aad, b_.p + body, rlen, pp);
        } else {
            const uint8_t* secret = c.tls_secrets->secret[TlsSecrets::ClientEarly];
            size_t sl = c.tls_secrets->len[TlsSecrets::ClientEarly];
            for (uint16_t cs = 0x1301; cs <= 0x1305 && n < 0; ++cs) {
                TlsRecordKeys k = tls13_record_keys(secret, sl, cs);
                if (k.valid && (n = tls13_open(k, 0, aad, b_.p + body, rlen, pp)) >= 0) c.tls_early = k;
            }
        }
        if (n < 0) {
            c.tls_early_done = true;  // the client's handshake keys from here on
            return false;
        }
        c.tls_early_seq++;
        size_t pn = static_cast<size_t>(n);
        while (pn && plain[pn - 1] == '\0') --pn;
        if (pn >= 2 && plain[pn - 1] == 22 && plain[0] == 5) c.tls_early_done = true;  // End of Early Data
        tls13_plaintext(c, di, body, rlen, plain, static_cast<size_t>(n));
        return true;
    }

    // Handshake messages after the handshake (New Session Ticket, Key Update). A Key
    // Update (RFC 8446 §4.6.3) moves its sender to the next traffic secret: that side's
    // following records use new keys, counted from 0.
    void tls13_post_handshake(InspectorState::Conv& c, int side, const uint8_t* pp, size_t pn) {
        bool update = false;
        for (size_t pos = 0; pos + 4 <= pn;) {
            size_t mlen = (static_cast<size_t>(pp[pos + 1]) << 16) | (pp[pos + 2] << 8) | pp[pos + 3];
            if (pp[pos] == 24) update = true;
            pos += 4 + mlen;
        }
        col_append_sep(tls_decrypted_handshake(pp, pn));
        if (update) {
            c.tls_app[side] = tls13_next_keys(c.tls_app[side]);
            c.tls_app_seq[side] = 0;
        }
    }

    // A TLS 1.3 record under the sender's handshake traffic keys (Encrypted Extensions,
    // Certificate, Certificate Verify, Finished, or an alert during the handshake).
    // Returns false when it isn't one, so the application keys are tried.
    bool tls13_handshake_record(InspectorState::Conv& c, int di, size_t body, size_t rlen) {
        int side = di & 1;
        if (c.tls_hs_done[side] || body < 5 || rlen < 9 || !b_.have(body, rlen)) return false;
        if (!c.tls_hs_ready[side]) {
            auto which = di == c.tls_server_dir ? TlsSecrets::ServerHandshake : TlsSecrets::ClientHandshake;
            if (!c.tls_secrets->has(which)) return false;
            c.tls_hs[side] = tls13_record_keys(c.tls_secrets->secret[which], c.tls_secrets->len[which], c.tls_cipher);
            c.tls_hs_ready[side] = c.tls_hs[side].valid;
            if (!c.tls_hs_ready[side]) return false;
        }
        std::string plain(rlen, '\0');
        long n = tls13_open(c.tls_hs[side], c.tls_hs_seq[side], b_.p + body - 5, b_.p + body, rlen,
                            reinterpret_cast<uint8_t*>(&plain[0]));
        if (n < 0) return false;
        c.tls_hs_seq[side]++;
        size_t pn = static_cast<size_t>(n);
        while (pn && plain[pn - 1] == '\0') --pn;
        if (!pn) return true;
        uint8_t inner = static_cast<uint8_t>(plain[--pn]);
        plain.resize(pn);
        const uint8_t* pp = reinterpret_cast<const uint8_t*>(plain.data());
        if (full_) tls_show_plaintext(body, rlen, inner, pp, pn);
        fproto("tls", body, rlen);
        if (inner == 21) {
            tls_decrypted_alert(c, di, pp, pn);
            return true;
        }
        if (inner != 22) {
            col_append_sep("Application Data");
            return true;
        }
        // Handshake messages, whole or continued from the previous record.
        std::string& buf = c.tls_hs_buf[side];
        if (buf.size() + pn > (1u << 20)) buf.clear();
        buf.append(plain);
        size_t pos = 0;
        bool any = false;
        while (buf.size() - pos >= 4) {
            const uint8_t* m = reinterpret_cast<const uint8_t*>(buf.data()) + pos;
            size_t mlen = (static_cast<size_t>(m[1]) << 16) | (m[2] << 8) | m[3];
            if (buf.size() - pos < 4 + mlen) break;
            const char* name = tls_hs_name(m[0]);
            col_append_sep(name ? name : "Encrypted Handshake Message");
            FF(uint("tls.handshake.type", m[0]));
            any = true;
            if (m[0] == 8) tls13_encrypted_extensions(c, m + 4, mlen);
            if (m[0] == 20) c.tls_hs_done[side] = true;  // its application keys come next
            pos += 4 + mlen;
        }
        buf.erase(0, pos);
        if (!any && !buf.empty()) {
            const char* name = tls_hs_name(static_cast<uint8_t>(buf[0]));
            col_append_sep(std::string("[") + (name ? name : "Encrypted Handshake Message") + " Fragment]");
        }
        return true;
    }

    // Encrypted Extensions: the ALPN protocol the server chose picks the application
    // dissector for the decrypted data (Wireshark does the same).
    void tls13_encrypted_extensions(InspectorState::Conv& c, const uint8_t* p, size_t n) {
        if (n < 2) return;
        size_t end = std::min(n, 2 + static_cast<size_t>((p[0] << 8) | p[1])), pos = 2;
        while (pos + 4 <= end) {
            uint16_t type = static_cast<uint16_t>((p[pos] << 8) | p[pos + 1]);
            size_t len = static_cast<size_t>((p[pos + 2] << 8) | p[pos + 3]);
            pos += 4;
            if (pos + len > end) return;
            if (type == 16 && len >= 3) {  // ALPN: list length (2), then one protocol name (1 + n)
                size_t plen = p[pos + 2];
                if (3 + plen <= len) c.tls_alpn.assign(reinterpret_cast<const char*>(p + pos + 3), plen);
            }
            pos += len;
        }
    }

    // Add a "Decrypted TLS Record" layer with the plaintext, shared by the 1.2 and 1.3 paths.
    void tls_show_plaintext(size_t body, size_t rlen, uint8_t inner, const uint8_t* pp, size_t pn) {
        const char* innn = inner == 23 ? "Application Data" : inner == 22 ? "Handshake"
                         : inner == 21 ? "Alert" : "Unknown";
        Layer& dl = layer(fmt("Decrypted TLS Record (%zu bytes)", pn).c_str(), body, rlen);
        FIELD(dl, "Inner Content Type", fmt("%s (%u)", innn, inner), body, 0);
        bool text = pn && std::all_of(pp, pp + std::min<size_t>(pn, 512), [](uint8_t ch) {
            return (ch >= 0x20 && ch < 0x7f) || ch == '\r' || ch == '\n' || ch == '\t';
        });
        if (text)
            FIELD(dl, "Decrypted", std::string(reinterpret_cast<const char*>(pp), std::min<size_t>(pn, 16384)), body, 0);
        else
            FIELD(dl, "Decrypted length", fmt("%zu bytes", pn), body, 0);
    }

    // ------------------------------------------------------------------ HTTP/2
    // As Wireshark's http2 dissector shows it: an item per frame, Info "TYPE[stream]"
    // (": GET /path" or ": 200 OK" when a HEADERS or PUSH_PROMISE frame ends a header
    // block), HPACK decoded with each side's dynamic table, and a stream's body handed to
    // the media dissectors when the stream ends.

    static const char* h2_status_phrase(int s) {
        switch (s) {
            case 100: return "Continue"; case 101: return "Switching Protocols"; case 102: return "Processing";
            case 103: return "Early Hints"; case 199: return "Informational - Others";
            case 200: return "OK"; case 201: return "Created"; case 202: return "Accepted";
            case 203: return "Non-authoritative Information"; case 204: return "No Content";
            case 205: return "Reset Content"; case 206: return "Partial Content"; case 207: return "Multi-Status";
            case 208: return "Already Reported"; case 226: return "IM Used"; case 299: return "Success - Others";
            case 300: return "Multiple Choices"; case 301: return "Moved Permanently"; case 302: return "Found";
            case 303: return "See Other"; case 304: return "Not Modified"; case 305: return "Use Proxy";
            case 307: return "Temporary Redirect"; case 308: return "Permanent Redirect";
            case 399: return "Redirection - Others"; case 400: return "Bad Request"; case 401: return "Unauthorized";
            case 402: return "Payment Required"; case 403: return "Forbidden"; case 404: return "Not Found";
            case 405: return "Method Not Allowed"; case 406: return "Not Acceptable";
            case 407: return "Proxy Authentication Required"; case 408: return "Request Time-out";
            case 409: return "Conflict"; case 410: return "Gone"; case 411: return "Length Required";
            case 412: return "Precondition Failed"; case 413: return "Request Entity Too Large";
            case 414: return "Request-URI Too Long"; case 415: return "Unsupported Media Type";
            case 416: return "Requested Range Not Satisfiable"; case 417: return "Expectation Failed";
            case 418: return "I'm a teapot"; case 421: return "Misdirected Request";
            case 422: return "Unprocessable Entity"; case 423: return "Locked"; case 424: return "Failed Dependency";
            case 425: return "Too Early"; case 426: return "Upgrade Required"; case 428: return "Precondition Required";
            case 429: return "Too Many Requests"; case 431: return "Request Header Fields Too Large";
            case 451: return "Unavailable For Legal Reasons"; case 499: return "Client Error - Others";
            case 500: return "Internal Server Error"; case 501: return "Not Implemented"; case 502: return "Bad Gateway";
            case 503: return "Service Unavailable"; case 504: return "Gateway Time-out";
            case 505: return "HTTP Version not supported"; case 506: return "Variant Also Negotiates";
            case 507: return "Insufficient Storage"; case 508: return "Loop Detected"; case 510: return "Not Extended";
            case 511: return "Network Authentication Required"; case 599: return "Server Error - Others";
            default: return "Unknown";
        }
    }

    static bool h2_magic(const uint8_t* p, size_t n) {
        static const char kMagic[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        return n && std::memcmp(p, kMagic, std::min<size_t>(n, 24)) == 0;
    }

    // Bytes the PDU at p needs: the 24-byte connection preface, or a frame (9 + length).
    // 0: too few bytes to tell yet.
    static size_t h2_pdu_len(const uint8_t* p, size_t n) {
        if (h2_magic(p, n)) return 24;
        if (n < 9) return 0;
        return 9 + ((static_cast<size_t>(p[0]) << 16) | (p[1] << 8) | p[2]);
    }

    // One call of the HTTP/2 dissector over [off, off+len): every whole PDU in it. Returns
    // the bytes used; `need` is how many more the partial PDU after them needs (0 unknown).
    size_t h2_pdus(InspectorState::Conv& c, int di, size_t off, size_t len, uint64_t spos, size_t& need) {
        set_proto("HTTP2");
        col_clear();
        size_t pos = 0;
        need = 0;
        while (pos < len) {
            size_t pl = h2_pdu_len(b_.p + off + pos, len - pos);
            if (!pl || pl > len - pos) {
                need = pl ? pl - (len - pos) : 0;
                break;
            }
            h2_pdu(c, di, off + pos, pl, spos + pos);
            pos += pl;
        }
        return pos;
    }

    void h2_pdu(InspectorState::Conv& c, int di, size_t off, size_t pl, uint64_t spos) {
        const uint8_t* p = b_.p + off;
        fproto("http2", off, pl);
        Layer& l = layer("HyperText Transfer Protocol 2", off, pl);
        int side = di & 1;
        auto& hs = c.h2[side];
        bool replay = spos < hs.pos_done;  // dissected already (TCP can hand the same bytes over again)
        if (!replay) hs.pos_done = spos + pl;
        if (pl == 24 && h2_magic(p, pl)) {
            if (c.h2_client < 0) c.h2_client = static_cast<int8_t>(side);
            col_append_sep("Magic");
            FF(string("http2.magic", std::string(reinterpret_cast<const char*>(p), 24)));
            FIELD(l, "Magic", "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n", off, 24);
            return;
        }
        uint32_t len = static_cast<uint32_t>(pl - 9);
        uint8_t type = p[3], flags = p[4];
        uint32_t raw = (static_cast<uint32_t>(p[5]) << 24) | (p[6] << 16) | (p[7] << 8) | p[8];
        uint32_t sid = raw & 0x7fffffffu;
        const char* tn = http2_frame_name(type);
        std::string info = tn ? fmt("%s[%u]", tn, sid) : fmt("Unknown type (%u)[%u]", type, sid);
        fproto("http2.stream", 0, 0);
        FF(uint("http2.length", len));
        FF(uint("http2.type", type));
        FF(uint("http2.flags", flags));
        FF(uint("http2.r", raw >> 31));
        FF(uint("http2.streamid", sid));
        FIELD(l, "Stream", fmt("%s, Stream ID: %u, Length %u", tn ? tn : "Unknown", sid, len), off, pl);
        FIELD(l, "Type", fmt("%s (%u)", tn ? tn : "Unknown", type), off + 3, 1);
        FIELD(l, "Flags", fmt("0x%02x", flags), off + 4, 1);
        const uint8_t* q = p + 9;
        size_t qo = off + 9;
        bool malformed = false, end_stream = false;
        uint32_t promised = 0;
        std::string extra;
        switch (type) {
            case 0: {  // DATA
                FF(boolean("http2.flags.end_stream", flags & 1));
                FF(boolean("http2.flags.padded", flags & 8));
                size_t pad = 0, start = 0;
                if (flags & 8) {
                    if (!len) { malformed = true; break; }
                    pad = q[0];
                    start = 1;
                    FF(uint("http2.padding", pad));
                }
                FF(uint("http2.pad_length", pad));
                if (start + pad > len) { malformed = true; break; }
                size_t dlen = len - start - pad;
                auto it = c.h2_streams.find(sid);
                if (it != c.h2_streams.end() && !replay && it->second.body[side].size() < (4u << 20))
                    it->second.body[side].append(reinterpret_cast<const char*>(q + start), dlen);
                if (st_.tap && !replay) h2_tap_data(it == c.h2_streams.end() ? nullptr : &it->second, side, sid,
                                                    q + start, dlen, flags & 1);
                end_stream = flags & 1;
                // The frame ending the stream shows the whole body (Wireshark reassembles it).
                if (!(end_stream && it != c.h2_streams.end() && h2_show_body(it->second, side)) && dlen)
                    FF(bytes("http2.data.data", q + start, dlen));
                if (pad) FF(bytes("http2.data.padding", q + len - pad, pad));
                FIELD(l, "Data", fmt("%zu bytes", dlen), qo + start, dlen);
                break;
            }
            case 1:    // HEADERS
            case 5: {  // PUSH_PROMISE
                if (type == 1) FF(boolean("http2.flags.end_stream", flags & 1));
                FF(boolean("http2.flags.eh", flags & 4));
                FF(boolean("http2.flags.padded", flags & 8));
                if (type == 1) FF(boolean("http2.flags.priority", flags & 0x20));
                size_t pos = 0, pad = 0;
                if (flags & 8) {
                    if (!len) { malformed = true; break; }
                    pad = q[0];
                    pos = 1;
                    FF(uint("http2.padding", pad));
                }
                FF(uint("http2.pad_length", pad));
                if (type == 1 && (flags & 0x20)) {
                    if (pos + 5 > len) { malformed = true; break; }
                    uint32_t dep = (static_cast<uint32_t>(q[pos]) << 24) | (q[pos + 1] << 16) | (q[pos + 2] << 8) | q[pos + 3];
                    FF(boolean("http2.exclusive", dep >> 31));
                    FF(uint("http2.stream_dependency", dep & 0x7fffffffu));
                    FF(uint("http2.headers.weight", q[pos + 4]));
                    FF(uint("http2.headers.weight_real", q[pos + 4] + 1u));
                    pos += 5;
                }
                uint32_t target = sid;
                if (type == 5) {
                    if (pos + 4 > len) { malformed = true; break; }
                    promised = 0;
                    uint32_t pr = (static_cast<uint32_t>(q[pos]) << 24) | (q[pos + 1] << 16) | (q[pos + 2] << 8) | q[pos + 3];
                    target = pr & 0x7fffffffu;
                    promised = target;
                    FF(uint("http2.push_promise.r", pr >> 31));
                    FF(uint("http2.push_promise.promised_stream_id", target));
                    FIELD(l, "Promised-Stream-ID", std::to_string(target), qo + pos, 4);
                    pos += 4;
                }
                if (pos + pad > len) { malformed = true; break; }
                size_t blen = len - pos - pad;
                FF(bytes(type == 1 ? "http2.headers" : "http2.push_promise.header", q + pos, blen));
                if (pad) FF(bytes(type == 1 ? "http2.headers.padding" : "http2.push_promise.padding", q + len - pad, pad));
                if (!replay) {  // a new header block begins
                    hs.block.clear();
                    hs.block_open = !(flags & 4);
                    hs.block_sid = target;
                    hs.block_frame_sid = sid;
                    hs.block_type = type;
                }
                // The request (a client's HEADERS, or the request a PUSH_PROMISE makes for the
                // promised stream) dates from its first frame; responses are the server's HEADERS.
                bool request = type == 5 || h2_from_client(c, di);
                auto& st = c.h2_streams[target];
                if (request && !st.req_frame && !replay) {
                    st.req_frame = frame_;
                    st.req_ts = ts_;
                }
                extra = h2_fragment(c, di, target, sid, q + pos, blen, flags & 4, spos, replay, l, request, true);
                if (type == 1 && (flags & 1)) {
                    end_stream = true;
                    h2_show_body(st, side);  // trailers end it: the reassembled body is shown here
                }
                break;
            }
            case 9: {  // CONTINUATION
                FF(boolean("http2.flags.eh", flags & 4));
                FF(boolean("http2.flags.padded", false));
                FF(uint("http2.pad_length", 0));
                FF(bytes("http2.continuation.header", q, len));
                bool open = replay || (hs.block_open && hs.block_frame_sid == sid);
                if (open) {
                    std::string frag;
                    if (!replay) {
                        frag.swap(hs.block);
                        frag.append(reinterpret_cast<const char*>(q), len);
                        hs.block_open = !(flags & 4);
                    }
                    h2_fragment(c, di, hs.block_sid, sid, reinterpret_cast<const uint8_t*>(frag.data()), frag.size(),
                                flags & 4, spos, replay, l, hs.block_type == 5 || h2_from_client(c, di), false);
                }
                break;
            }
            case 2:  // PRIORITY
                if (len < 5) { malformed = true; break; }
                FF(boolean("http2.exclusive", q[0] >> 7));
                FF(uint("http2.stream_dependency", ((static_cast<uint32_t>(q[0]) << 24) | (q[1] << 16) | (q[2] << 8) | q[3]) & 0x7fffffffu));
                FF(uint("http2.headers.weight", q[4]));
                FF(uint("http2.headers.weight_real", q[4] + 1u));
                break;
            case 3:  // RST_STREAM
                if (len < 4) { malformed = true; break; }
                FF(uint("http2.rst_stream.error", (static_cast<uint32_t>(q[0]) << 24) | (q[1] << 16) | (q[2] << 8) | q[3]));
                break;
            case 4: {  // SETTINGS
                FF(boolean("http2.flags.ack.settings", flags & 1));
                static const char* const kSet[] = {nullptr, "http2.settings.header_table_size", "http2.settings.enable_push",
                    "http2.settings.max_concurrent_streams", "http2.settings.initial_window_size",
                    "http2.settings.max_frame_size", "http2.settings.max_header_list_size", nullptr,
                    "http2.settings.extended_connect", "http2.settings.no_rfc7540_priorities"};
                for (size_t i = 0; i + 6 <= len; i += 6) {
                    uint16_t id = static_cast<uint16_t>((q[i] << 8) | q[i + 1]);
                    uint32_t v = (static_cast<uint32_t>(q[i + 2]) << 24) | (q[i + 3] << 16) | (q[i + 4] << 8) | q[i + 5];
                    fproto("http2.settings", 0, 0);
                    FF(uint("http2.settings.id", id));
                    const char* fname = id < 10 ? kSet[id] : id == 16 ? "http2.settings.tls_reneg_permitted" : nullptr;
                    if (ff_) ff_->uint(fname ? fname : "http2.settings.unknown", v);
                    FIELD(l, "Setting", fmt("%u = %u", id, v), qo + i, 6);
                }
                if (len % 6) malformed = true;
                break;
            }
            case 6:  // PING
                FF(boolean("http2.flags.ack.ping", flags & 1));
                FF(bytes(flags & 1 ? "http2.pong" : "http2.ping", q, len));
                break;
            case 7:  // GOAWAY
                if (len < 8) { malformed = true; break; }
                FF(uint("http2.goaway.r", q[0] >> 7));
                FF(uint("http2.goaway.last_stream_id", ((static_cast<uint32_t>(q[0]) << 24) | (q[1] << 16) | (q[2] << 8) | q[3]) & 0x7fffffffu));
                FF(uint("http2.goaway.error", (static_cast<uint32_t>(q[4]) << 24) | (q[5] << 16) | (q[6] << 8) | q[7]));
                if (len > 8) FF(bytes("http2.goaway.addata", q + 8, len - 8));
                break;
            case 8:  // WINDOW_UPDATE
                if (len < 4) { malformed = true; break; }
                FF(uint("http2.window_update.r", q[0] >> 7));
                FF(uint("http2.window_update.window_size_increment",
                        ((static_cast<uint32_t>(q[0]) << 24) | (q[1] << 16) | (q[2] << 8) | q[3]) & 0x7fffffffu));
                break;
            case 0xa: {  // ALTSVC: origin length, origin, field value
                if (len < 2) { malformed = true; break; }
                size_t ol = static_cast<size_t>((q[0] << 8) | q[1]);
                FF(uint("http2.altsvc.origin.len", ol));
                if (2 + ol > len) { malformed = true; break; }
                FF(string("http2.altsvc.origin", std::string(reinterpret_cast<const char*>(q + 2), ol)));
                FF(string("http2.altsvc.field_value", std::string(reinterpret_cast<const char*>(q + 2 + ol), len - 2 - ol)));
                break;
            }
            case 0xc:  // ORIGIN: entries of length + origin
                for (size_t i = 0; i < len;) {
                    if (i + 2 > len) { malformed = true; break; }
                    size_t ol = static_cast<size_t>((q[i] << 8) | q[i + 1]);
                    fproto("http2.origin", 0, 0);
                    FF(uint("http2.origin.origin_len", ol));
                    if (i + 2 + ol > len) { malformed = true; break; }
                    FF(string("http2.origin.origin", std::string(reinterpret_cast<const char*>(q + i + 2), ol)));
                    i += 2 + ol;
                }
                break;
            case 0x10:  // PRIORITY_UPDATE: prioritized stream, field value
                if (len < 4) { malformed = true; break; }
                FF(uint("http2.priority_update_stream_id", ((static_cast<uint32_t>(q[0]) << 24) | (q[1] << 16) | (q[2] << 8) | q[3]) & 0x7fffffffu));
                FF(string("http2.priority_update_field_value", std::string(reinterpret_cast<const char*>(q + 4), len - 4)));
                break;
            default:
                if (!len) malformed = true;
                else FF(bytes("http2.unknown", q, len));
                break;
        }
        if (promised) h2_full_uri(c, promised, l);
        if (sid) h2_full_uri(c, sid, l);
        if (st_.tap && !replay && sid && type != 0 && type != 1 && type != 5 && type != 9)
            st_.tap->h2_data(sid, p, pl);  // Follow HTTP/2 Stream shows other frames on the stream as they are
        col_append_sep(info + extra);
        if (malformed) {
            col_append("[Malformed Packet]");
            d_.malformed = true;
            if (ff_ && !frozen_ && !ff_->has_proto("_ws.malformed")) ff_->proto("_ws.malformed", 0, 0);
            return;
        }
        if (end_stream) h2_body_done(c, side, sid);
    }

    // Header text as Wireshark shows it: ASCII, each other byte a replacement character.
    static std::string h2_ascii(const std::string& s) {
        if (std::all_of(s.begin(), s.end(), [](char ch) { return static_cast<unsigned char>(ch) < 0x80; })) return s;
        std::string out;
        for (unsigned char ch : s) out += ch < 0x80 ? std::string(1, static_cast<char>(ch)) : std::string("\xEF\xBF\xBD");
        return out;
    }

    bool h2_from_client(const InspectorState::Conv& c, int di) const {
        if (c.tls_server_dir >= 0) return di != c.tls_server_dir;
        return c.h2_client < 0 || (di & 1) == c.h2_client;
    }

    // A stream's request URI as Wireshark builds it: scheme://authority path (just the
    // authority for CONNECT), with C's "(null)" for a part not seen yet.
    static std::string h2_uri(const InspectorState::Conv::H2Stream& st) {
        if (st.has_method && st.method == "CONNECT") return st.has_authority ? st.authority : "(null)";
        return (st.has_scheme ? st.scheme : "(null)") + "://" + (st.has_authority ? st.authority : "(null)") +
               (st.has_path ? st.path : "(null)");
    }

    // The URI every frame of a stream carries: in the file view, the request as the whole
    // capture shows it (Wireshark's first pass saw all of it); live, as known so far.
    void h2_full_uri(InspectorState::Conv& c, uint32_t sid, Layer& l) {
        std::string uri;
        if (st_.use) {
            auto it = st_.use->h2_uri.find({conv_hash(), sid});
            if (it == st_.use->h2_uri.end()) return;
            uri = it->second;
        } else {
            auto it = c.h2_streams.find(sid);
            if (it == c.h2_streams.end()) return;
            const auto& st = it->second;
            if (!st.has_method && !st.has_path && !st.has_authority && !st.has_scheme) return;
            uri = h2_uri(st);
        }
        FF(string("http2.request.full_uri", uri));
        FIELD(l, "Full request URI", uri, 0, 0);
    }

    // One fragment of a header block (a HEADERS or PUSH_PROMISE frame's, or a
    // CONTINUATION's together with what the previous fragment left half-decoded): the
    // fields whole in it are decoded now, as Wireshark does, shown and noted on the stream.
    // Returns the Info text a HEADERS/PUSH_PROMISE frame adds (": GET /x", ": 200 OK").
    std::string h2_fragment(InspectorState::Conv& c, int di, uint32_t sid, uint32_t frame_sid, const uint8_t* p,
                            size_t n, bool end, uint64_t spos, bool replay, Layer& l, bool request, bool first) {
        int side = di & 1;
        auto& hs = c.h2[side];
        InspectorState::Conv::H2Side::Decoded d;
        bool ok;
        if (replay) {
            auto it = hs.cache.find(spos);
            ok = it != hs.cache.end();
            if (ok) d = it->second;
        } else {
            size_t used = n;
            ok = !hs.hpack_broken && hs.hpack.decode(p, n, d.headers, &d.reprs, &d.updates, end ? nullptr : &used);
            if (!ok) {
                hs.hpack_broken = true;  // the sender's table can't be followed past this
                hs.block_open = false;
            } else {
                if (!end) hs.block.assign(reinterpret_cast<const char*>(p + used), n - used);
                if (c.app == kAppHttp2) {  // cleartext h2c: TCP may hand this frame over again
                    hs.cache[spos] = d;
                    if (hs.cache.size() > 512) hs.cache.erase(hs.cache.begin());
                }
            }
        }
        auto& st = c.h2_streams[sid];
        if (c.h2_streams.size() > 4096) c.h2_streams.erase(c.h2_streams.begin());
        static const struct { const char* name; const char* field; bool number; } kMap[] = {
            {":authority", "http2.headers.authority", false},
            {":status", "http2.headers.status", true},
            {":path", "http2.headers.path", false},
            {":method", "http2.headers.method", false},
            {":scheme", "http2.headers.scheme", false},
            {":protocol", "http2.headers.protocol", false},
            {"accept", "http2.headers.accept", false},
            {"accept-charset", "http2.headers.accept_charset", false},
            {"accept-encoding", "http2.headers.accept_encoding", false},
            {"accept-language", "http2.headers.accept_language", false},
            {"accept-ranges", "http2.headers.accept_ranges", false},
            {"access-control-allow-origin", "http2.headers.access_control_allow_origin", false},
            {"age", "http2.headers.age", true},
            {"allow", "http2.headers.allow", false},
            {"authorization", "http2.headers.authorization", false},
            {"cache-control", "http2.headers.cache_control", false},
            {"content-disposition", "http2.headers.content_disposition", false},
            {"content-encoding", "http2.headers.content_encoding", false},
            {"content-language", "http2.headers.content_language", false},
            {"content-length", "http2.headers.content_length", true},
            {"content-location", "http2.headers.content_location", false},
            {"content-range", "http2.headers.content_range", false},
            {"content-type", "http2.headers.content_type", false},
            {"cookie", "http2.headers.cookie", false},
            {"date", "http2.headers.date", false},
            {"etag", "http2.headers.etag", false},
            {"expect", "http2.headers.expect", false},
            {"expires", "http2.headers.expires", false},
            {"from", "http2.headers.from", false},
            {"if-match", "http2.headers.if_match", false},
            {"if-modified-since", "http2.headers.if_modified_since", false},
            {"if-none-match", "http2.headers.if_none_match", false},
            {"if-range", "http2.headers.if_range", false},
            {"if-unmodified-since", "http2.headers.if_unmodified_since", false},
            {"last-modified", "http2.headers.last_modified", false},
            {"link", "http2.headers.link", false},
            {"location", "http2.headers.location", false},
            {"max-forwards", "http2.headers.max_forwards", true},
            {"proxy-authenticate", "http2.headers.proxy_authenticate", false},
            {"proxy-authorization", "http2.headers.proxy_authorization", false},
            {"range", "http2.headers.range", false},
            {"referer", "http2.headers.referer", false},
            {"refresh", "http2.headers.refresh", false},
            {"retry-after", "http2.headers.retry_after", false},
            {"server", "http2.headers.server", false},
            {"set-cookie", "http2.headers.set_cookie", false},
            {"strict-transport-security", "http2.headers.strict_transport_security", false},
            {"user-agent", "http2.headers.user_agent", false},
            {"vary", "http2.headers.vary", false},
            {"via", "http2.headers.via", false},
            {"www-authenticate", "http2.headers.www_authenticate", false},
        };
        static const char* const kRepr[4][2] = {
            {"Indexed Header Field", "Indexed Header Field"},
            {"Literal Header Field with Incremental Indexing - Indexed Name",
             "Literal Header Field with Incremental Indexing - New Name"},
            {"Literal Header Field without Indexing - Indexed Name", "Literal Header Field without Indexing - New Name"},
            {"Literal Header Field never Indexed - Indexed Name", "Literal Header Field never Indexed - New Name"}};
        std::string line;
        const std::string *method = nullptr, *path = nullptr, *status = nullptr;
        if (ok) {
            for (uint32_t u : d.updates) {
                fproto("http2.header_table_size_update", 0, 0);
                FF(uint("http2.header_table_size_update.header_table_size", u));
            }
            size_t total = 0;
            for (size_t i = 0; i < d.headers.size(); ++i) {
                const auto& [name, value] = d.headers[i];
                total += 8 + name.size() + value.size();
                fproto("http2.header", 0, 0);
                FF(uint("http2.header.name.length", name.size()));
                FF(string("http2.header.name", h2_ascii(name)));
                FF(uint("http2.header.value.length", value.size()));
                FF(string("http2.header.value", h2_ascii(value)));
                FF(string("http2.header.unescaped", h2_ascii(value)));
                if (i < d.reprs.size()) {
                    FF(string("http2.header.repr", kRepr[d.reprs[i].kind][d.reprs[i].new_name]));
                    if (d.reprs[i].index) FF(uint("http2.header.index", d.reprs[i].index));
                }
                for (const auto& m : kMap) {
                    if (name != m.name) continue;
                    if (!m.number) FF(string(m.field, h2_ascii(value)));
                    else if (!value.empty() && std::isdigit(static_cast<unsigned char>(value[0])))
                        FF(uint(m.field, std::strtoull(value.c_str(), nullptr, 10)));
                    break;
                }
                FIELD(l, "Header", name + ": " + value, 0, 0);
                if (name == ":method") method = &value;
                else if (name == ":path") path = &value;
                else if (name == ":status") status = &value;
                if (replay) continue;
                if (request) {  // the stream's request, as it is decoded
                    if (name == ":method") { st.method = value; st.has_method = true; }
                    else if (name == ":path") { st.path = value; st.has_path = true; }
                    else if (name == ":authority") { st.authority = value; st.has_authority = true; }
                    else if (name == ":scheme") { st.scheme = value; st.has_scheme = true; }
                    else if (name == "host" && !st.has_authority) { st.authority = value; st.has_authority = true; }
                }
                // The media type of the body this side sends (a PUSH_PROMISE's request has none).
                bool promise = request && !h2_from_client(c, di);
                if (name == "content-type" && !promise) {
                    std::string v = value.substr(0, value.find(';'));
                    while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.pop_back();
                    for (auto& ch : v) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                    st.ctype[side] = v;
                } else if (name == "content-encoding" && !promise) {
                    st.cenc[side] = value;
                }
            }
            if (!d.headers.empty() || end) {
                FF(uint("http2.header.length", total));
                FF(uint("http2.header.count", d.headers.size()));
            }
        }
        if (ok && !replay && st_.tap && !d.headers.empty()) {
            // Follow HTTP/2 Stream: each fragment's headers as "name: value" lines, on the
            // stream the frame is on (a PUSH_PROMISE's request shows on the pushing stream).
            auto fs = c.h2_streams.find(frame_sid);
            if (fs != c.h2_streams.end()) h2_follow_flush(fs->second, side, frame_sid);
            std::string text;
            for (const auto& [name, value] : d.headers) text += h2_ascii(name) + ": " + h2_ascii(value) + "\n";
            st_.tap->h2_block(frame_sid, text + "\n");
        }
        if (!replay && st_.record && (st.has_method || st.has_path || st.has_authority || st.has_scheme))
            st_.record->h2_uri[{conv_hash(), sid}] = h2_uri(st);
        // Cross-references: a request's first frame names the response; a response names
        // its request and the time it took (a response in the request's own frame shows
        // as the request does).
        if (!request && status && !replay) st.resp_frame = frame_;
        bool response_side = !request && st.req_frame && st.req_frame != frame_;
        if (first && !response_side && st.req_frame == frame_) {
            uint64_t resp = st.resp_frame;  // live: what this frame has shown so far
            if (st_.use) {
                auto it = st_.use->h2_response_in.find((frame_ << 32) | sid);
                resp = it != st_.use->h2_response_in.end() ? it->second : 0;
            }
            if (resp) {
                FF(uint("http2.response_in", resp));
                FIELD(l, "Response in frame", std::to_string(resp), 0, 0);
            }
        }
        if (first && response_side) {
            FF(uint("http2.request_in", st.req_frame));
            FF(real("http2.time", static_cast<double>(ts_ - std::min(ts_, st.req_ts)) / 1e6));
            FIELD(l, "Request in frame", std::to_string(st.req_frame), 0, 0);
        }
        if (!request && status && st.req_frame && st_.record && !replay)
            st_.record->h2_response_in[(st.req_frame << 32) | sid] = frame_;
        if (first && method && path) line = ": " + *method + " " + *path;
        else if (first && status) line = ": " + *status + " " + h2_status_phrase(std::atoi(status->c_str()));
        return line;
    }

    // Follow HTTP/2 Stream, as Wireshark shows it: a body once it is whole (decoded if it
    // was sent compressed), or before the next header block from that side (trailers); a
    // CONNECT tunnel's bytes are no body.
    void h2_tap_data(InspectorState::Conv::H2Stream* st, int side, uint32_t sid, const uint8_t* p, size_t n, bool end) {
        if (!st) {
            if (n) st_.tap->h2_data(sid, p, n);
            return;
        }
        if (st->has_method && st->method == "CONNECT") return;
        if (st->follow_body[side].size() < (64u << 20)) st->follow_body[side].append(reinterpret_cast<const char*>(p), n);
        if (end) h2_follow_flush(*st, side, sid);
    }

    void h2_follow_flush(InspectorState::Conv::H2Stream& st, int side, uint32_t sid) {
        std::string& body = st.follow_body[side];
        if (body.empty() || !st_.tap) return;
        std::string enc = st.cenc[side], decoded;
        for (auto& ch : enc) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        bool compressed = enc == "gzip" || enc == "x-gzip" || enc == "deflate";
        const std::string& out = compressed && http_decode_body(body, enc, decoded, 64u << 20) ? decoded : body;
        st_.tap->h2_data(sid, reinterpret_cast<const uint8_t*>(out.data()), out.size());
        std::string().swap(body);
    }

    // The reassembled body as data, decoded if it was sent compressed (not a CONNECT
    // tunnel's bytes). False when there is none to show.
    bool h2_show_body(const InspectorState::Conv::H2Stream& st, int side) {
        const std::string& body = st.body[side];
        if (body.empty() || (st.has_method && st.method == "CONNECT")) return false;
        std::string enc = st.cenc[side], decoded;
        for (auto& ch : enc) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        const std::string* use = &body;
        if ((enc == "gzip" || enc == "x-gzip" || enc == "deflate") && http_decode_body(body, enc, decoded, 64u << 20))
            use = &decoded;
        FF(bytes("http2.data.data", reinterpret_cast<const uint8_t*>(use->data()), use->size()));
        return true;
    }

    // A stream's body from one side is complete: the media dissectors see it (decoded
    // first if it was sent compressed), as for an HTTP/1.x body.
    void h2_body_done(InspectorState::Conv& c, int side, uint32_t sid) {
        auto it = c.h2_streams.find(sid);
        if (it == c.h2_streams.end()) return;
        auto& st = it->second;
        const std::string& body = st.body[side];
        if (body.empty() || st.ctype[side].empty()) return;
        std::string enc = st.cenc[side];
        for (auto& ch : enc) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        std::string decoded;
        const std::string* use = &body;
        if ((enc == "gzip" || enc == "x-gzip" || enc == "deflate") && http_decode_body(body, enc, decoded, 64u << 20))
            use = &decoded;
        http_media(st.ctype[side], reinterpret_cast<const uint8_t*>(use->data()), use->size(), false);
    }

    // Decrypted TLS application data carrying HTTP/2, record by record, the way
    // Wireshark's TLS layer hands it on: a frame begun in an earlier record is completed
    // and dissected first (then the Info column is fenced), the rest of the record is
    // dissected, and a frame left incomplete waits for the next record.
    void tls_h2(InspectorState::Conv& c, int di, const uint8_t* pp, size_t pn) {
        int side = di & 1;
        auto& hs = c.h2[side];
        size_t used = 0;
        Bytes saved_b = b_;
        bool saved_virtual = virtual_;
        auto view = [&](const uint8_t* p, size_t n) {
            b_ = {p, n};
            virtual_ = true;
        };
        if (!hs.pend.empty()) {
            uint64_t pdu_pos = hs.stream_pos - hs.pend.size();
            size_t need = 0;
            while (used < pn) {
                need = h2_pdu_len(reinterpret_cast<const uint8_t*>(hs.pend.data()), hs.pend.size());
                size_t want = need ? need : 9;
                if (hs.pend.size() >= want) break;
                size_t take = std::min(pn - used, want - hs.pend.size());
                hs.pend.append(reinterpret_cast<const char*>(pp + used), take);
                used += take;
            }
            need = h2_pdu_len(reinterpret_cast<const uint8_t*>(hs.pend.data()), hs.pend.size());
            if (hs.pend_frames.empty() || hs.pend_frames.back() != frame_) hs.pend_frames.push_back(frame_);
            if (!need || hs.pend.size() < need) {  // still incomplete: this record is only a piece of it
                hs.stream_pos += pn;
                tls_piece(c);
                return;
            }
            if (st_.record)
                for (uint64_t f : hs.pend_frames)
                    if (f != frame_) st_.record->tls_reassembled_in[f] = frame_;
            std::string pdu;
            pdu.swap(hs.pend);
            hs.pend_frames.clear();
            view(reinterpret_cast<const uint8_t*>(pdu.data()), pdu.size());
            size_t more = 0;
            h2_pdus(c, di, 0, pdu.size(), pdu_pos, more);
            b_ = saved_b;
            virtual_ = saved_virtual;
            col_set_fence();
            if (used < pn) proto_writable_ = false;  // what follows must not relabel the frame
        }
        if (used < pn) {
            view(pp + used, pn - used);
            size_t need = 0;
            size_t done = h2_pdus(c, di, 0, pn - used, hs.stream_pos + used, need);
            b_ = saved_b;
            virtual_ = saved_virtual;
            if (done < pn - used) {
                hs.pend.assign(reinterpret_cast<const char*>(pp + used + done), pn - used - done);
                hs.pend_frames.assign(1, frame_);
            }
            if (!done) {
                tls_piece(c);
            } else if (done < pn - used && st_.use) {  // a frame begins here and ends in a later record
                auto it = st_.use->tls_reassembled_in.find(frame_);
                if (it != st_.use->tls_reassembled_in.end()) FF(uint("tls.reassembled_in", it->second));
            }
        }
        hs.stream_pos += pn;
        proto_writable_ = true;
    }

    // A record that only carries part of a PDU finished later. (Wireshark's second pass
    // leaves Info empty on the record that begins a message read until the close.)
    void tls_piece(InspectorState::Conv& c, bool until_close = false) {
        const char* vn = tls_version_name(tls_session_version(c));
        set_proto(vn ? vn : "TLS");
        if (!(until_close && st_.use)) col_set("[TLS segment of a reassembled PDU]");
        if (st_.use) {
            auto it = st_.use->tls_reassembled_in.find(frame_);
            if (it != st_.use->tls_reassembled_in.end()) FF(uint("tls.reassembled_in", it->second));
        }
    }

    // Cleartext HTTP/2 (h2c) over TCP, with TCP's own reassembly.
    bool h2_tcp(InspectorState::Conv& c, int di, size_t off, size_t len) {
        size_t need = 0;
        uint64_t spos = static_cast<uint64_t>(app_seq_) + (off - app_base_);
        size_t done = h2_pdus(c, di, off, len, spos, need);
        if (done < len && can_desegment_) deseg_ = {done, need ? static_cast<uint32_t>(need) : kOneMore};
        return true;
    }

    // Decrypted application data handed to HTTP, as Wireshark hands it on: a message
    // spanning several records is collected and dissected in the frame completing it;
    // the frames before show "[TLS segment of a reassembled PDU]".
    enum class TlsHttp { No, Piece, Done };
    static constexpr size_t kMaxTlsHttp = 4u << 20;  // past this, a message is shown as it stands

    // `flush`: the sender's close_notify ended its stream, so a message read "until
    // close" (no length) is complete; it is dissected as it stands.
    TlsHttp tls_http(InspectorState::Conv& c, int di, const uint8_t* pp, size_t pn, bool flush = false) {
        int side = di & 1;
        std::string& pend = c.tls_http_pend[side];
        auto& frames = c.tls_http_frames[side];
        if (flush) {
            if (pend.empty()) return TlsHttp::No;
        } else {
            if (pend.empty() && !c.http_seen && !http_method(pp, pn) && !starts_with(pp, pn, "HTTP/"))
                return TlsHttp::No;  // HTTP/2 or another protocol: left as decrypted bytes
            pend.append(reinterpret_cast<const char*>(pp), pn);
            if ((frames.empty() || frames.back() != frame_) && frames.size() < 4096) frames.push_back(frame_);
            if (c.tls_http_need[side] && pend.size() < c.tls_http_need[side] && pend.size() < kMaxTlsHttp)
                return TlsHttp::Piece;  // the rest of the message is still to come
        }

        Bytes saved_b = b_;
        bool saved_virtual = virtual_, saved_can = can_desegment_, saved_tls = http_tls_;
        size_t saved_reported = reported_;
        b_ = {reinterpret_cast<const uint8_t*>(pend.data()), pend.size()};
        virtual_ = true;
        reported_ = pend.size();
        http_tls_ = true;
        size_t pos = 0, need = 0;
        bool piece = false, any = false;
        while (pos < pend.size()) {
            FrameFields::Mark mark = ff_ ? ff_->mark() : FrameFields::Mark{0, 0};
            std::string col = col_, proto = d_.protocol;
            size_t fence = fence_, layers = d_.layers.size();
            can_desegment_ = !flush && pend.size() < kMaxTlsHttp;
            deseg_ = Deseg();
            long r = http_message(c, pos, pend.size() - pos, pend.size() - pos, pos);
            if (deseg_.len) {  // the message continues in a later record
                col_ = col;
                fence_ = fence;
                d_.protocol = proto;
                if (ff_) ff_->rollback(mark);
                if (full_) d_.layers.resize(layers);
                piece = true;
                // A body without a length runs until close_notify (or the size cap).
                if (deseg_.len == kUntilFin) need = kMaxTlsHttp;
                else if (deseg_.len != kOneMore) need = pend.size() - pos + deseg_.len;
                break;
            }
            if (r == -2) break;
            any = true;
            if (r <= 0) {
                pos = pend.size();
                break;
            }
            pos += static_cast<size_t>(r);
            col_set_fence();
        }
        deseg_ = Deseg();
        b_ = saved_b;
        virtual_ = saved_virtual;
        can_desegment_ = saved_can;
        http_tls_ = saved_tls;
        reported_ = saved_reported;

        if (any && st_.record) {  // the earlier frames were pieces of what completed here
            for (uint64_t f : frames)
                if (f != frame_) st_.record->tls_reassembled_in[f] = frame_;
        }
        if (piece) {
            pend.erase(0, pos);
            c.tls_http_need[side] = need ? need : 0;
            if (any) frames.assign(1, frame_);
            return any ? TlsHttp::Done : TlsHttp::Piece;
        }
        pend.clear();
        c.tls_http_need[side] = 0;
        frames.clear();
        return any ? TlsHttp::Done : TlsHttp::No;
    }

    // The Info column and fields for one decrypted application-data record.
    void tls_app_data(InspectorState::Conv& c, int di, const uint8_t* pp, size_t pn) {
        // HTTP/2 when the handshake negotiated it (ALPN "h2"), or when the client's first
        // data is HTTP/2's connection preface; HTTP/1.x otherwise.
        if (!c.tls_proto && (c.tls_alpn == "h2" || (pn >= 24 && h2_magic(pp, pn)))) c.tls_proto = 2;
        if (c.tls_proto == 2) {
            tls_h2(c, di, pp, pn);
            return;
        }
        TlsHttp h = tls_http(c, di, pp, pn);
        if (h == TlsHttp::Done) return;
        if (h == TlsHttp::No) {  // no application protocol for it: as Wireshark lists it
            col_append_sep("Application Data");
            return;
        }
        tls_piece(c, c.tls_http_need[di & 1] == kMaxTlsHttp);
    }

    // A handshake message read under the traffic keys (TLS 1.2's Finished, TLS 1.3's
    // New Session Ticket or Key Update), named as Wireshark names it.
    static std::string tls_decrypted_handshake(const uint8_t* pp, size_t pn) {
        const char* name = pn >= 4 ? tls_hs_name(pp[0]) : nullptr;
        return name ? name : "Encrypted Handshake Message";
    }

    // A decrypted alert, shown as Wireshark shows a plaintext one. close_notify ends
    // that side's stream: an HTTP body read until close is complete there.
    void tls_decrypted_alert(InspectorState::Conv& c, int di, const uint8_t* pp, size_t pn) {
        if (pn != 2) {
            col_append_sep("Alert");
            return;
        }
        FF(uint("tls.alert_message.desc", pp[1]));
        col_append_sep(fmt("Alert (Level: %s, Description: %s)",
                           pp[0] == 1 ? "Warning" : pp[0] == 2 ? "Fatal" : "Unknown", tls_alert_name(pp[1])));
        if (pp[1] == 0) tls_eos_ = true;
    }

    // Decrypt a TLS 1.2 record once the user's key log gives this session's master secret.
    // Called for every record after a direction's ChangeCipherSpec, so the per-direction
    // sequence number stays aligned (the Finished is the first protected record).
    bool tls12_try_decrypt(InspectorState::Conv& c, int di, uint8_t ct, uint16_t rv, size_t body, size_t rlen, Layer& l) {
        if (!st_.keylog)
            return false;
        uint16_t sv = tls_session_version(c);
        int side = di & 1;
        if (sv == 0x0304 || !c.tls12_enc[side])  // TLS 1.3 uses its own path; 1.2 only after CCS
            return false;
        if (!c.tls12_ready[side]) {  // this side's first record after its ChangeCipherSpec
            if (!c.tls_cr_set || !c.tls_sr_set || !tls12_cipher_supported(c.tls_cipher))
                return false;
            // (the hellos of a renegotiation name a new session: keys of their own)
            if (!c.tls_master_set) {
                const TlsSecrets* sec = st_.keylog->find(c.tls_client_random);
                if (sec && sec->has(TlsSecrets::Master)) {
                    std::memcpy(c.tls_master, sec->secret[TlsSecrets::Master], 48);
                    c.tls_master_set = true;
                } else {  // the premaster: PMS_CLIENT_RANDOM, or RSA by its ciphertext
                    std::string pms = sec ? sec->premaster : std::string();
                    if (pms.empty() && c.tls_rsa_enc_set) pms = st_.keylog->find_rsa(c.tls_rsa_enc8);
                    c.tls_master_set = !pms.empty() && c.tls_transcript_done &&
                        tls_master_secret(reinterpret_cast<const uint8_t*>(pms.data()), pms.size(), c.tls_client_random,
                                          c.tls_server_random, c.tls_cipher, sv, c.tls_ems, c.tls_transcript, c.tls_master);
                }
                if (!c.tls_master_set)
                    return false;
            }
            c.tls12[side] = tls12_keys(c.tls_master, c.tls_client_random, c.tls_server_random, c.tls_cipher, sv,
                                       c.tls_etm);
            c.tls12_ready[side] = c.tls12[side].valid;
            if (!c.tls12_ready[side])
                return false;
        }
        if (body < 5 || !b_.have(body, rlen))
            return false;
        bool server = di == c.tls_server_dir;
        Tls12Keys& keys = c.tls12[side];
        std::string plain(rlen, '\0');
        long n = tls12_open(keys, server, c.tls12_seq[side], ct, rv, b_.p + body, rlen,
                            reinterpret_cast<uint8_t*>(&plain[0]));
        c.tls12_seq[side]++;  // every protected record consumes a sequence number
        tls12_chain_iv(keys, server, b_.p + body, rlen);  // (TLS 1.0 CBC: the next record's IV)
        if (n < 0) {
            col_append_sep(ct == 22 ? "Encrypted Handshake Message" : ct == 21 ? "Encrypted Alert" : "Application Data");
            return true;
        }
        size_t pn = static_cast<size_t>(n);
        plain.resize(pn);
        const uint8_t* pp = reinterpret_cast<const uint8_t*>(plain.data());
        if (full_ && ct == 23)
            tls_show_plaintext(body, rlen, ct, pp, pn);
        fproto("tls", body, rlen);
        if (ct == 23 && pn && st_.tap) st_.tap->tls_data(pp, pn);
        if (ct == 23 && pn)
            tls_app_data(c, di, pp, pn);
        else if (ct == 21)
            tls_decrypted_alert(c, di, pp, pn);
        else if (ct == 22)
            tls12_decrypted_handshake(c, di, pp, pn, l);
        else if (ct == 20) {  // a renegotiation's ChangeCipherSpec, under the old keys: new keys follow
            col_append_sep("Change Cipher Spec");
            c.tls12_ready[side] = false;
            c.tls12_seq[side] = 0;
        } else
            col_append_sep("Application Data");
        return true;
    }

    // Handshake messages read under the record keys: the Finished, a Hello Request, and
    // a renegotiation's whole handshake, dissected as the plaintext handshake is (its
    // hellos give the new session's randoms and suite).
    void tls12_decrypted_handshake(InspectorState::Conv& c, int di, const uint8_t* pp, size_t pn, Layer& l) {
        Bytes saved = b_;
        bool saved_virtual = virtual_;
        tls_transcript_add(c, pp, pn);
        b_ = {pp, pn};
        virtual_ = true;
        tls_handshake(c, di, 0, pn, l);
        b_ = saved;
        virtual_ = saved_virtual;
    }

    bool tls_dissect(InspectorState::Conv& c, int di, size_t off, size_t len) {
        if (len > 4 && std::all_of(b_.p + off, b_.p + off + 4, [](uint8_t ch) { return ch >= 0x20 && ch < 0x7f; }))
            return false;  // looks like text, not TLS
        uint16_t sv = tls_session_version(c);
        const char* vn = tls_version_name(sv);
        set_proto(vn ? vn : "SSL");
        col_clear();
        fproto("tls", off, len);
        size_t pos = 0;
        tls_eos_ = false;
        // Wireshark's dissect_ssl(): an SSLv2/PCT session reads SSLv2 records; an
        // SSLv3-TLS 1.2 session reads TLS records (unless an SSLv2 Client Hello turns
        // up); any other (unknown, or TLS 1.3) sniffs each record, and what looks
        // like neither is "Continuation Data" to the end of the frame.
        while (pos < len) {
            size_t avail = len - pos;
            sv = tls_session_version(c);
            bool classic = sv == 0x0300 || sv == 0x0301 || sv == 0x0302 || sv == 0x0303 || sv == 0x0101;
            if (sv == 0x0002 || sv == kPctVersion) {
                if (!ssl2_record(c, off, pos, len)) return true;
                continue;
            }
            if (avail < 5) {
                if (can_desegment_) deseg_ = {pos, kOneMore};
                return true;
            }
            size_t at = off + pos;
            bool v2_hello = b_.u8(at) == 0x80 && b_.u8(at + 2) == 0x01;
            if ((classic && v2_hello) || (!classic && ssl_looks_like_sslv2(at))) {
                if (!ssl2_record(c, off, pos, len)) return true;
                continue;
            }
            if (!classic && !ssl_looks_like_sslv3(at)) {
                col_append_sep("Continuation Data");
                break;
            }
            uint8_t ct = b_.u8(off + pos);
            if (classic && sv != 0x0300 && !tls_valid_ct(ct)) {
                col_append_sep("Ignored Unknown Record");
                break;
            }
            uint16_t rv = b_.u16(off + pos + 1);
            if (!classic && !(tls_valid_ct(ct) && (tls_norm_version(rv) || rv == 0x0101))) {
                col_append_sep("Continuation Data");
                break;
            }
            size_t rlen = b_.u16(off + pos + 3);
            if (!tls_valid_ct(ct)) {
                col_append_sep("Continuation Data");
                pos += 5 + rlen;
                continue;
            }
            if (avail < rlen + 5) {
                if (can_desegment_) deseg_ = {pos, static_cast<uint32_t>(rlen + 5 - avail)};
                return true;
            }
            size_t body = off + pos + 5;
            uint16_t ver = sv;
            if (!sv) {
                tls_set_version(c, ct, rlen ? b_.u8(body) : 0, rv);
                const char* rn = tls_version_name(rv);
                set_proto(rn ? rn : "SSL");
                ver = rv;
            }
            const char* ctn = ct == 20 ? "Change Cipher Spec" : ct == 21 ? "Alert" : ct == 22 ? "Handshake"
                            : ct == 23 ? "Application Data" : ct == 24 ? "Heartbeat" : "Unknown";
            const char* lvn = tls_version_name(ver);
            Layer& l = layer(fmt("%s Record Layer: %s", lvn ? lvn : "TLS", ctn).c_str(), off + pos, 5 + rlen);
            FIELD(l, "Content Type", fmt("%s (%u)", ctn, ct), off + pos, 1);
            if (sv == 0x0304 && ct == 23) FF(uint("tls.record.opaque_type", ct));
            else FF(uint("tls.record.content_type", ct));
            FF(uint("tls.record.version", rv));
            FF(uint("tls.record.length", rlen));
            FIELD(l, "Version", fmt("0x%04x", rv), off + pos + 1, 2);
            FIELD(l, "Length", fmt("%zu", rlen), off + pos + 3, 2);
            if (tls12_try_decrypt(c, di, ct, rv, body, rlen, l)) {  // an encrypted TLS 1.2 record we have keys for
                pos += 5 + rlen;
                continue;
            }
            switch (ct) {
                case 20:
                    col_append_sep("Change Cipher Spec");
                    c.dir[di].tls_ccs_frame = frame_;
                    // TLS 1.2 and earlier: this direction's following records are encrypted,
                    // and its record sequence number restarts at 0.
                    if (tls_session_version(c) != 0x0304) {
                        c.tls12_enc[di & 1] = true;
                        c.tls12_seq[di & 1] = 0;
                    }
                    if (di == c.tls_server_dir && c.tls_resumed && tls_session_version(c) != 0x0304)
                        expert("tls.resumed", 1, "Sequence", "TLS",
                               "This session reuses previously negotiated keys (Session resumption)");
                    break;
                case 21:
                    if (rlen != 2) {
                        col_append_sep("Encrypted Alert");
                    } else {
                        uint8_t lv = b_.u8(body), ds = b_.u8(body + 1);
                        FF(uint("tls.alert_message.desc", ds));
                        if (ds == 0) tls_eos_ = true;
                        col_append_sep(fmt("Alert (Level: %s, Description: %s)",
                                           lv == 1 ? "Warning" : lv == 2 ? "Fatal" : "Unknown", tls_alert_name(ds)));
                    }
                    break;
                case 22:
                    if (b_.have(body, rlen)) tls_transcript_add(c, b_.p + body, rlen);
                    tls_handshake(c, di, body, rlen, l);
                    break;
                case 23:
                    if (!tls_try_decrypt(c, di, body, rlen, l)) col_append_sep("Application Data");
                    break;
                case 24: {
                    uint8_t ht = rlen ? b_.u8(body) : 0;
                    size_t hl = rlen >= 3 ? b_.u16(body + 1) : 0;
                    if ((ht == 1 || ht == 2) && 3 + hl + 16 <= rlen)
                        col_append_sep(ht == 1 ? "Heartbeat Request" : "Heartbeat Response");
                    else
                        col_append_sep("Encrypted Heartbeat");
                    break;
                }
                default: break;
            }
            pos += 5 + rlen;
        }
        tls_end_of_stream(c, di, len);
        return true;
    }

    // Wireshark's dissect_ssl() after the records (its "reassemble at end of stream"):
    // decrypted HTTP read until the connection closes is complete once this dissection
    // read the sender's close_notify, or the TCP segment carries a FIN. Until then TCP
    // holds the rest of the stream until the FIN, as it does for plain HTTP.
    void tls_end_of_stream(InspectorState::Conv& c, int di, size_t len) {
        int side = di & 1;
        bool until_close = c.tls_http_need[side] == kMaxTlsHttp && !c.tls_http_pend[side].empty();
        if (until_close && (tls_eos_ || seg_fin_))
            tls_http(c, di, nullptr, 0, true);
        else if (until_close && can_desegment_)
            deseg_ = {len, kUntilFin};
        tls_eos_ = false;
    }

    static const char* tls_alert_name(uint8_t d) {
        switch (d) {
            case 0: return "Close Notify";
            case 1: return "End of Early Data";
            case 10: return "Unexpected Message";
            case 20: return "Bad Record MAC";
            case 21: return "Decryption Failed";
            case 22: return "Record Overflow";
            case 30: return "Decompression Failure";
            case 40: return "Handshake Failure";
            case 41: return "No Certificate";
            case 42: return "Bad Certificate";
            case 43: return "Unsupported Certificate";
            case 44: return "Certificate Revoked";
            case 45: return "Certificate Expired";
            case 46: return "Certificate Unknown";
            case 47: return "Illegal Parameter";
            case 48: return "Unknown CA";
            case 49: return "Access Denied";
            case 50: return "Decode Error";
            case 51: return "Decrypt Error";
            case 60: return "Export Restriction";
            case 70: return "Protocol Version";
            case 71: return "Insufficient Security";
            case 80: return "Internal Error";
            case 86: return "Inappropriate Fallback";
            case 90: return "User Canceled";
            case 100: return "No Renegotiation";
            case 109: return "Missing Extension";
            case 110: return "Unsupported Extension";
            case 111: return "Certificate Unobtainable";
            case 112: return "Unrecognized Name";
            case 113: return "Bad Certificate Status Response";
            case 114: return "Bad Certificate Hash Value";
            case 115: return "Unknown PSK Identity";
            case 116: return "Certificate Required";
            case 120: return "No application Protocol";
            case 121: return "ECH Required";
            default: return "Unknown";
        }
    }

    // Encrypted Finished messages and the like (Wireshark's heuristic).
    bool tls_hs_encrypted(InspectorState::Dir& d, size_t off, size_t len) const {
        if (len < 16) return false;
        bool enc = b_.u8(off) == 0 && b_.u32(off + 1) == 0;
        uint8_t t = b_.u8(off);
        uint32_t ml = (static_cast<uint32_t>(b_.u8(off + 1)) << 16) | b_.u16(off + 2);
        if (!enc) enc = !tls_hs_name(t) || ml >= 0x10000;
        if (!enc && d.tls_ccs_frame && frame_ > d.tls_ccs_frame) {
            if (t == 1 || t == 2) {
                enc = !tls_norm_version(b_.u16(off + 4)) || ml >= 0x400;
                if (!enc) d.tls_ccs_frame = 0;
            } else {
                enc = true;
            }
        }
        return enc;
    }

    void tls_handshake(InspectorState::Conv& c, int di, size_t off, size_t len, Layer& l) {
        auto& d = c.dir[di];
        size_t pos = 0;
        bool first = true;
        if (d.hs_pending) {  // the rest of a handshake message split across records
            if (len < d.hs_remaining) {
                d.hs_remaining -= static_cast<uint32_t>(len);
                const char* n = tls_hs_name(d.hs_type);
                col_append_sep(std::string("[") + (n ? n : "Encrypted Handshake Message") + " Fragment]");
                return;
            }
            pos = d.hs_remaining;
            d.hs_pending = false;
            const char* n = tls_hs_name(d.hs_type);
            col_append_sep(n ? n : "Encrypted Handshake Message");
            first = false;
        } else if (tls_hs_encrypted(d, off, len)) {
            col_append_sep("Encrypted Handshake Message");
            return;
        }
        while (pos < len) {
            size_t sub = len - pos;
            uint8_t t = b_.u8(off + pos);
            size_t mlen = sub >= 4 ? 4 + ((static_cast<size_t>(b_.u8(off + pos + 1)) << 16) | b_.u16(off + pos + 2)) : 0;
            if (mlen == 0 || sub < mlen) {
                if (mlen) {
                    d.hs_pending = true;
                    d.hs_type = t;
                    d.hs_remaining = static_cast<uint32_t>(mlen - sub);
                }
                if (first) {
                    const char* n = tls_hs_name(t);
                    col_append_sep(std::string("[") + (n ? n : "Encrypted Handshake Message") + " Fragment]");
                }
                return;
            }
            const char* n = tls_hs_name(t);
            if (!n && !first) return;
            std::string name = n ? n : "Encrypted Handshake Message";
            size_t m = off + pos;
            if (first && t == 2 && mlen - 4 > 2) {
                bool hrr = false;
                uint16_t v = tls_server_hello_version(m + 4, mlen - 4, hrr);
                tls_set_version(c, 22, 2, v);
                if (hrr) name = "Hello Retry Request";
                FIELD(l, "Negotiated version", fmt("0x%04x", v), m, mlen);
            }
            if (t == 2) {  // the Server Hello names the session's version
                const char* vn = tls_version_name(tls_session_version(c));
                set_proto(vn ? vn : "SSL");
                if (name != "Hello Retry Request") {
                    c.tls_resumed = true;  // an abbreviated handshake, unless the server goes on to authenticate
                    c.tls_server_dir = static_cast<int8_t>(di);
                }
            }
            if ((t == 11 || t == 14) && di == c.tls_server_dir) c.tls_resumed = false;
            if (t == 1 && !tls_session_version(c)) {
                // Before the version is settled, Wireshark shows the last entry of the
                // Client Hello's supported_versions list.
                uint16_t last = 0;
                bool any = false;
                if (tls_client_versions(m + 4, mlen - 4, last, any) && any) {
                    const char* vn = tls_version_name(last);
                    set_proto(vn ? vn : "TLS");
                }
            }
            col_append_sep(name);
            FF(uint("tls.handshake.type", t));
            if ((t == 1 || t == 2) && tls_hello_has_ext(m + 4, mlen - 4, t == 2, 0x002b))
                expert("tls.handshake.legacy_version");
            if ((t == 1 || t == 2) && mlen >= 4) tls_check_hello_extensions(m + 4, mlen - 4, t == 2);
            FIELD(l, "Handshake Type", fmt("%s (%u)", name.c_str(), t), m, 1);
            if (t == 1) {
                c.tls_client_dir = static_cast<int8_t>(di);
                c.tls_early_offered = mlen >= 4 && tls_hello_has_ext(m + 4, mlen - 4, false, 0x002a);
                // The ClientHello random (body offset 2, after the legacy version) keys the
                // session's secrets in a key log. type(1)+len(3)+version(2) = offset 6.
                if (st_.keylog && mlen >= 38 && b_.have(m + 6, 32)) {
                    std::memcpy(c.tls_client_random, b_.p + m + 6, 32);
                    c.tls_cr_set = true;
                }
                std::string rec("\x16\x03\x01", 3);
                rec.push_back(static_cast<char>((mlen >> 8) & 0xFF));
                rec.push_back(static_cast<char>(mlen & 0xFF));
                rec.append(reinterpret_cast<const char*>(b_.p + m), mlen);
                if (auto ch = parse_tls_client_hello(rec)) {
                    if (!ch->sni.empty()) col_append(" (SNI=" + ch->sni + ")");
                    if (!ch->sni.empty()) FF(string("tls.handshake.extensions_server_name", ch->sni));
                    FF(string("tls.handshake.ja3_full", ch->ja3));  // Wireshark's names
                    FF(string("tls.handshake.ja3", ch->ja3_hash));
                    FF(string("tls.handshake.ja3_hash", ch->ja3_hash));
                    FF(string("tls.handshake.ja4", ch->ja4));
                    if (full_) {
                        if (!ch->sni.empty()) field(l, "Server Name Indication", ch->sni, m, 0);
                        std::string alpn;
                        for (const auto& a : ch->alpn) alpn += (alpn.empty() ? "" : ", ") + a;
                        if (!alpn.empty()) field(l, "ALPN", alpn, m, 0);
                        field(l, "JA3", ch->ja3_hash, m, 0);
                        field(l, "JA3 string", ch->ja3, m, 0);
                        field(l, "JA4", ch->ja4, m, 0);
                    }
                }
            } else if (t == 2) {
                std::string rec("\x16\x03\x03", 3);
                rec.push_back(static_cast<char>((mlen >> 8) & 0xFF));
                rec.push_back(static_cast<char>(mlen & 0xFF));
                rec.append(reinterpret_cast<const char*>(b_.p + m), mlen);
                if (st_.keylog && mlen >= 38 && b_.have(m + 6, 32)) {  // the server random, for TLS 1.2 key derivation
                    std::memcpy(c.tls_server_random, b_.p + m + 6, 32);
                    c.tls_sr_set = true;
                }
                if (auto sh = parse_tls_server_hello(rec)) {
                    c.tls_cipher = sh->cipher;  // the negotiated suite picks the record protection
                    c.tls_etm = sh->etm;
                    c.tls_ems = sh->ems;
                    FF(string("tls.handshake.ja3s_full", sh->ja3s));
                    FF(string("tls.handshake.ja3s", sh->ja3s_hash));
                    if (full_) {
                        field(l, "JA3S", sh->ja3s_hash, m, 0);
                        field(l, "JA3S string", sh->ja3s, m, 0);
                        field(l, "JA4S", sh->ja4s, m, 0);
                    }
                }
            }
            tls_transcript_mark(c, t, pos, mlen, m);
            pos += mlen;
            first = false;
        }
    }

    // The handshake record about to be read, added to the transcript an extended master
    // secret hashes (until the Client Key Exchange; a renegotiation's Client Hello starts
    // a new one).
    void tls_transcript_add(InspectorState::Conv& c, const uint8_t* p, size_t n) {
        tls_rec_base_ = kNoBase;
        if (n && p[0] == 1 && c.tls_transcript_done) {
            c.tls_transcript.clear();
            c.tls_transcript_done = false;
        }
        if (c.tls_transcript_done || c.tls_transcript.size() + n > (1u << 20)) return;
        tls_rec_base_ = static_cast<long long>(c.tls_transcript.size());
        c.tls_transcript.append(reinterpret_cast<const char*>(p), n);
    }

    // A handshake message read (at `pos` in the record, `mlen` bytes with its header): a
    // Client Hello starts the transcript; the Client Key Exchange ends it, and an RSA one
    // names the premaster a key log's RSA line is keyed by.
    void tls_transcript_mark(InspectorState::Conv& c, uint8_t t, size_t pos, size_t mlen, size_t m) {
        if (tls_rec_base_ == kNoBase) return;
        if (t == 1) {
            long long from = tls_rec_base_ + static_cast<long long>(pos);
            if (from > 0) c.tls_transcript.erase(0, static_cast<size_t>(from));
            tls_rec_base_ -= from;
            c.tls_master_set = false;
            c.tls_rsa_enc_set = false;
        } else if (t == 16) {
            c.tls_transcript.resize(static_cast<size_t>(tls_rec_base_ + static_cast<long long>(pos + mlen)));
            c.tls_transcript_done = true;
            size_t body = m + 4, blen = mlen - 4;
            if (blen >= 10 && b_.u16(body) == blen - 2 && b_.have(body + 2, 8)) {  // TLS: length, then the RSA ciphertext
                std::memcpy(c.tls_rsa_enc8, b_.p + body + 2, 8);
                c.tls_rsa_enc_set = true;
            } else if (blen >= 8 && b_.have(body, 8)) {  // SSL 3.0: the ciphertext alone
                std::memcpy(c.tls_rsa_enc8, b_.p + body, 8);
                c.tls_rsa_enc_set = true;
            }
        }
    }

    // Extensions too short for the vector they must start with, reported the way
    // Wireshark does ("No more room for vector of length N").
    void tls_check_hello_extensions(size_t off, size_t len, bool server) {
        size_t p = off + 34, end = off + len;
        if (len < 35 || !b_.have(off, len)) return;
        p += 1 + b_.u8(p);
        if (server) {
            p += 3;
        } else {
            if (p + 2 > end) return;
            p += 2 + b_.u16(p);
            if (p + 1 > end) return;
            p += 1 + b_.u8(p);
        }
        if (p + 2 > end) return;
        size_t ext_end = std::min(end, p + 2 + b_.u16(p));
        for (p += 2; p + 4 <= ext_end; p += 4 + b_.u16(p + 2)) {
            uint16_t type = b_.u16(p), elen = b_.u16(p + 2);
            unsigned need = 0;  // size of the length prefix the extension starts with
            switch (type) {
                case 0xff01: case 11: need = 1; break;                       // renegotiation_info, ec_point_formats
                case 16: need = 2; break;                                    // ALPN
                case 0: case 10: case 13: case 51: case 17513: case 17613:   // SNI, groups, sig algs, key_share, ALPS
                    need = server ? 0 : 2; break;
                case 43: case 45: case 27: need = server ? 0 : 1; break;     // versions, PSK modes, cert compression
                case 5:                                                      // status_request: a type byte
                    if (!server && elen == 0)
                        expert("tls.malformed.buffer_too_small", 3, "Malformed", "TLS",
                               "Dissector processed too much data (1 byte)");
                    break;
            }
            if (need && elen < need)
                expert("tls.malformed.buffer_too_small", 3, "Malformed", "TLS",
                       fmt("No more room for vector of length %u", need));
        }
    }

    // Whether a Client or Server Hello body carries an extension.
    bool tls_hello_has_ext(size_t off, size_t len, bool server, uint16_t want) const {
        size_t p = off + 34, end = off + len;  // version, random
        if (len < 35 || !b_.have(off, len)) return false;
        p += 1 + b_.u8(p);                     // session id
        if (server) {
            p += 3;                            // cipher suite, compression method
        } else {
            if (p + 2 > end) return false;
            p += 2 + b_.u16(p);                // cipher suites
            if (p + 1 > end) return false;
            p += 1 + b_.u8(p);                 // compression methods
        }
        if (p + 2 > end) return false;
        size_t ext_end = std::min(end, p + 2 + b_.u16(p));
        for (p += 2; p + 4 <= ext_end; p += 4 + b_.u16(p + 2))
            if (b_.u16(p) == want) return true;
        return false;
    }

    // The supported_versions extension of a Client Hello body: its last entry, and
    // whether it lists any real (non-GREASE) version.
    bool tls_client_versions(size_t off, size_t len, uint16_t& last, bool& any) const {
        size_t p = off + 34, end = off + len;  // legacy_version, random
        if (p >= end) return false;
        p += 1 + b_.u8(p);                     // session id
        if (p + 2 > end) return false;
        p += 2 + b_.u16(p);                    // cipher suites
        if (p + 1 > end) return false;
        p += 1 + b_.u8(p);                     // compression methods
        if (p + 2 > end) return false;
        size_t ext_end = std::min(end, p + 2 + b_.u16(p));
        p += 2;
        while (p + 4 <= ext_end) {
            uint16_t type = b_.u16(p), elen = b_.u16(p + 2);
            if (type == 0x002b && p + 5 <= ext_end) {
                size_t q = p + 5, qend = std::min<size_t>(ext_end, q + b_.u8(p + 4));
                bool found = false;
                for (; q + 2 <= qend; q += 2) {
                    last = b_.u16(q);
                    found = true;
                    if ((last & 0x0F0F) != 0x0A0A && tls_norm_version(last)) any = true;
                }
                return found;
            }
            p += 4 + elen;
        }
        return false;
    }

    // ServerHello body: the negotiated version (supported_versions wins) and
    // whether it is really a HelloRetryRequest.
    uint16_t tls_server_hello_version(size_t off, size_t len, bool& hrr) const {
        static const uint8_t magic[32] = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
                                          0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
                                          0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
        if (len < 2) return 0;
        uint16_t v = b_.u16(off);
        if (len < 35) return v;
        hrr = std::memcmp(b_.p + off + 2, magic, 32) == 0;
        size_t p = off + 34, end = off + len;
        if (p >= end) return v;
        p += 1 + b_.u8(p);  // session id
        p += 3;             // cipher suite, compression
        if (p + 2 > end) return v;
        size_t ext_end = std::min(end, p + 2 + b_.u16(p));
        p += 2;
        while (p + 4 <= ext_end) {
            uint16_t type = b_.u16(p), elen = b_.u16(p + 2);
            if (type == 0x002b && elen >= 2 && p + 6 <= ext_end) return b_.u16(p + 4);
            p += 4 + elen;
        }
        return v;
    }

    // ------------------------------------------------------------ HTTP
    static bool http_method(const uint8_t* p, size_t n) {
        static const char* methods[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ",
                                        "TRACE ", "PROPFIND ", "PROPPATCH ", "MKCOL ", "COPY ", "MOVE ", "LOCK ",
                                        "UNLOCK ", "SEARCH ", "REPORT ", "NOTIFY ", "M-SEARCH ", "SUBSCRIBE ",
                                        "UNSUBSCRIBE "};
        for (const char* m : methods)
            if (starts_with(p, n, m)) return true;
        return false;
    }

    // Wireshark's tvb_find_line_end(): a line ends at CR, LF or CR LF. With
    // `deseg`, a missing (or possibly split) line end gives npos.
    static size_t find_line_end(const uint8_t* p, size_t n, bool deseg, size_t& next) {
        for (size_t i = 0; i < n; ++i) {
            if (p[i] == '\n') {
                next = i + 1;
                return i;
            }
            if (p[i] == '\r') {
                if (i + 1 >= n) {
                    if (deseg) return std::string::npos;
                    next = n;
                    return i;
                }
                next = p[i + 1] == '\n' ? i + 2 : i + 1;
                return i;
            }
        }
        if (deseg) return std::string::npos;
        next = n;
        return n;
    }

    bool http_heuristic(size_t off, size_t len) const {
        const uint8_t* p = b_.p + off;
        size_t next = 0;
        size_t linelen = find_line_end(p, len, true, next);
        if (linelen == std::string::npos || linelen == 8) return false;
        auto ieq = [&](size_t at) {
            static const char k[] = "HTTP/1.";
            for (size_t i = 0; i < 7; ++i)
                if (std::toupper(p[at + i]) != k[i]) return false;
            return true;
        };
        return (linelen >= 8 && ieq(linelen - 8)) || (linelen >= 7 && ieq(0));
    }

    bool http_dissect(InspectorState::Conv& c, int di, size_t off, size_t len) {
        size_t reported = virtual_ && reported_ >= off ? reported_ - off : len;
        size_t pos = 0;
        bool any = false;
        while (pos < len) {
            long r = http_message(c, off + pos, len - pos, reported - pos, pos);
            if (r == -2) return any;
            any = true;
            if (r <= 0) break;  // needs more data, or nothing more to take
            pos += static_cast<size_t>(r);
            col_set_fence();
        }
        (void)di;
        return true;
    }

    // One HTTP message: bytes used, -1 (stop here) or -2 (not HTTP).
    long http_message(InspectorState::Conv& c, size_t off, size_t avail, size_t reported, size_t at) {
        if (reported < 1 || avail < 1) return -1;
        size_t lead = 0;
        if (reported > 3 && avail >= 2 && b_.u8(off) == '\r' && b_.u8(off + 1) == '\n') lead = 2;  // stray CRLF
        const uint8_t* p = b_.p + off + lead;
        avail -= lead;
        reported -= lead;
        if (!avail) return -1;
        if (!(p[0] >= 0x20 && p[0] < 0x7f)) {  // binary: file data, if this is an HTTP conversation
            if (c.http_seen) {
                set_proto("HTTP");
                col_set("Continuation");
                fproto("http", off, avail + lead);
                fproto("data", off + lead, avail);
                Layer& l = layer("Hypertext Transfer Protocol", off, avail + lead);
                FIELD(l, "File Data", fmt("%zu bytes", avail), off + lead, avail);
            }
            return -1;
        }
        size_t next = 0;
        size_t first_len = find_line_end(p, avail, true, next);
        if (first_len == std::string::npos) {
            if (can_desegment_) {
                deseg_ = {at, kOneMore};
                return -1;
            }
            first_len = avail;
        }
        std::string first = text_line(p, first_len, 1000);
        bool response = starts_with(p, avail, "HTTP/");
        bool request = !response && http_method(p, avail);
        if (!request && !response) {
            if (!c.http_seen) return -2;
            set_proto("HTTP");
            col_set("Continuation");
            fproto("http", off, avail + lead);
            fproto("data", off + lead, avail);
            layer("Hypertext Transfer Protocol", off, avail + lead);
            return -1;
        }
        col_set(first + " ");
        int status = 0;
        if (response) {
            size_t sp = first.find(' ');
            if (sp != std::string::npos) status = std::atoi(first.c_str() + sp + 1);
        }
        bool body_allowed = true;
        if (response) {
            const std::string& m = c.http_method;
            if (m == "HEAD" || (status / 100 == 2 && m == "CONNECT") || status / 100 == 1 || status == 204 ||
                status == 304)
                body_allowed = false;
        }
        // The header block, and what it says about the body.
        size_t hend = 0;
        bool headers_done = false, chunked = false;
        long long clen = -1;
        std::string ctype;
        Layer& l = layer("Hypertext Transfer Protocol", off, avail + lead);
        for (int lines = 0; lines < 1000 && hend < avail; ++lines) {
            size_t nx = 0;
            size_t ll = find_line_end(p + hend, avail - hend, true, nx);
            if (ll == std::string::npos) break;  // the header block continues past this data
            std::string text(reinterpret_cast<const char*>(p + hend), ll);
            FIELD(l, lines == 0 ? (request ? "Request line" : "Status line") : "Header", text_line(p + hend, ll, 400),
                  off + lead + hend, ll);
            hend += nx;
            if (ll == 0) {
                headers_done = true;
                break;
            }
            if (lines == 0) continue;
            size_t colon = text.find(':');
            if (colon == std::string::npos) continue;
            std::string name = text.substr(0, colon), value = text.substr(colon + 1);
            for (auto& ch : name) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            value.erase(0, std::min(value.size(), value.find_first_not_of(" \t")));
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.pop_back();
            if (name == "content-length") {
                char* endp = nullptr;
                long long v = std::strtoll(value.c_str(), &endp, 10);
                if (endp != value.c_str() && v >= 0 && v <= 0x7FFFFFFF) clen = v;
            } else if (name == "content-type") {
                ctype = value.substr(0, value.find(';'));
                while (!ctype.empty() && (ctype.back() == ' ' || ctype.back() == '\t')) ctype.pop_back();
                for (auto& ch : ctype) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            } else if (name == "transfer-encoding") {
                std::string v = value;
                for (auto& ch : v) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                chunked = v.rfind("chunked", 0) == 0;
            }
        }
        if (!headers_done && can_desegment_) {
            deseg_ = {at, kOneMore};
            return -1;
        }
        // req_resp_hdrs_do_reassembly(): ask for the rest of the body. A
        // reassembled message may hold more than we keep, so count `reported`.
        size_t have = avail > hend ? avail - hend : 0;
        size_t have_all = reported > hend ? reported - hend : 0;
        size_t body = 0;
        if (body_allowed && headers_done && can_desegment_) {
            if (chunked) {
                size_t q = hend;
                while (true) {
                    if (q >= avail) {
                        deseg_ = {at, kOneMore};
                        return -1;
                    }
                    size_t nx = 0;
                    size_t ll = find_line_end(p + q, avail - q, true, nx);
                    if (ll == std::string::npos) {
                        deseg_ = {at, kOneMore};
                        return -1;
                    }
                    std::string sz(reinterpret_cast<const char*>(p + q), ll);
                    char* endp = nullptr;
                    unsigned long chunk = std::strtoul(sz.c_str(), &endp, 16);
                    if (endp == sz.c_str() || chunk > (1ul << 31)) break;
                    if (chunk == 0) {
                        size_t t = q + nx;
                        size_t nx2 = 0;
                        if (t >= avail || find_line_end(p + t, avail - t, true, nx2) == std::string::npos) {
                            deseg_ = {at, kOneMore};
                            return -1;
                        }
                        body = t + nx2 - hend;
                        break;
                    }
                    if (avail - q > chunk) {
                        q += nx + chunk + 2;
                    } else {
                        deseg_ = {at, kOneMore};
                        return -1;
                    }
                }
            } else if (clen >= 0) {
                if (have_all < static_cast<size_t>(clen)) {
                    deseg_ = {at, static_cast<uint32_t>(static_cast<size_t>(clen) - have_all)};
                    return -1;
                }
            } else if (response) {
                deseg_ = {at, kUntilFin};
                return -1;
            }
        }
        if (!body_allowed) body = 0;
        else if (chunked && body == 0) body = have;
        else if (clen >= 0) body = std::min<size_t>(static_cast<size_t>(clen), have_all);
        else if (!chunked && response) body = have_all;
        c.http_seen = true;
        if (request) c.http_method = first.substr(0, first.find(' '));
        // Request/response matching, as Wireshark's HTTP dissector does it: a request adds
        // a pair; a response takes the newest pair if it has no final response yet (a 1xx
        // interim one doesn't use it up), else stands alone. The file view shows each frame
        // as the first pass left it: every message in it with the pair of its last message.
        std::string req_uri, full_uri;
        if (request) {
            size_t a = first.find(' '), b2 = first.rfind(' ');
            if (a != std::string::npos && b2 > a) req_uri = first.substr(a + 1, b2 - a - 1);
            std::string host = http_header(p, hend, "host");
            if (req_uri.find("://") != std::string::npos) full_uri = req_uri;
            else if (!host.empty() && !req_uri.empty() && req_uri[0] == '/')
                full_uri = (http_tls_ ? "https://" : "http://") + host + req_uri;
        }
        uint64_t key = (frame_ << 24) ^ (static_cast<uint64_t>(at) << 1) ^ (virtual_ ? 1 : 0);
        InspectorState::Conv::HttpPair* pair = nullptr;
        if (!c.http_pairs.empty() && c.http_pairs.back().key == key) {
            pair = &c.http_pairs.back();  // the same message dissected twice
        } else if (request || c.http_pairs.empty() || c.http_pairs.back().res_frame) {
            c.http_pairs.emplace_back();
            if (c.http_pairs.size() > 256) c.http_pairs.pop_front();
            pair = &c.http_pairs.back();
            pair->key = key;
            if (request) {
                pair->req_frame = frame_;
                pair->req_ts = ts_;
                pair->uri = req_uri;
                pair->full_uri = full_uri;
            }
            if (st_.record) {
                pair->ann = static_cast<uint32_t>(st_.record->http_pairs.size());
                st_.record->http_pairs.push_back({pair->req_frame, pair->req_ts, 0, pair->uri, pair->full_uri});
            }
        } else {
            pair = &c.http_pairs.back();
            pair->key = key;
        }
        if (!request && (status / 100 != 1 || status == 101)) {
            pair->res_frame = frame_;
            if (st_.record && pair->ann != UINT32_MAX) st_.record->http_pairs[pair->ann].res_frame = frame_;
        }
        if (st_.record && pair->ann != UINT32_MAX) st_.record->http_frame_pair[frame_] = pair->ann;
        InspectorAnnotations::HttpPair shown{pair->req_frame, pair->req_ts, 0, pair->uri, pair->full_uri};
        if (st_.use) {
            auto it = st_.use->http_frame_pair.find(frame_);
            shown = it != st_.use->http_frame_pair.end() ? st_.use->http_pairs[it->second] : InspectorAnnotations::HttpPair{};
        }
        InspectorState::Conv::HttpPair answered;  // what a response shows of its request
        if (!request && shown.req_frame && shown.req_frame != frame_) {
            answered.req_frame = shown.req_frame;
            answered.req_ts = shown.req_ts;
            answered.uri = shown.uri;
            answered.full_uri = shown.full_uri;
        }
        if (request && st_.use) full_uri = shown.full_uri;  // (the frame's last request's, in the file view)
        set_proto("HTTP");
        if (ff_) {
            fproto("http", off, lead + hend + body);
            if (request) {
                fproto("http.request", 0, 0);
                size_t a = first.find(' '), b2 = first.rfind(' ');
                FF(string("http.request.method", first.substr(0, a)));
                if (a != std::string::npos && b2 > a) {
                    FF(string("http.request.uri", first.substr(a + 1, b2 - a - 1)));
                    FF(string("http.request.version", first.substr(b2 + 1)));
                }
                if (!full_uri.empty()) FF(string("http.request.full_uri", full_uri));
            } else {
                fproto("http.response", 0, 0);
                FF(uint("http.response.code", static_cast<uint64_t>(status)));
                size_t a = first.find(' ');
                size_t b2 = a == std::string::npos ? a : first.find(' ', a + 1);
                if (b2 != std::string::npos) FF(string("http.response.phrase", first.substr(b2 + 1)));
            }
            for (const auto& [hname, hfield] : std::initializer_list<std::pair<const char*, const char*>>{
                     {"host", "http.host"}, {"user-agent", "http.user_agent"}, {"server", "http.server"},
                     {"content-type", "http.content_type"}, {"transfer-encoding", "http.transfer_encoding"}}) {
                std::string v = http_header(p, hend, hname);
                if (!v.empty()) ff_->string(hfield, v);
            }
            if (clen >= 0) FF(uint("http.content_length", static_cast<uint64_t>(clen)));
            if (answered.req_frame) {
                FF(uint("http.request_in", answered.req_frame));
                FF(real("http.time", static_cast<double>(ts_ - std::min(ts_, answered.req_ts)) / 1e6));
                if (!answered.uri.empty()) FF(string("http.request.uri", answered.uri));
                if (!answered.full_uri.empty()) FF(string("http.request.full_uri", answered.full_uri));
            }
            if (request && shown.res_frame) FF(uint("http.response_in", shown.res_frame));
        }
        if (request && shown.res_frame) FIELD(l, "Response in frame", std::to_string(shown.res_frame), 0, 0);
        if (answered.req_frame) {
            FIELD(l, "Request in frame", std::to_string(answered.req_frame), 0, 0);
            FIELD(l, "Time since request", fmt("%.9f seconds", static_cast<double>(ts_ - std::min(ts_, answered.req_ts)) / 1e6), 0, 0);
            if (!answered.uri.empty()) FIELD(l, "Request URI", answered.uri, 0, 0);
            if (!answered.full_uri.empty()) FIELD(l, "Full request URI", answered.full_uri, 0, 0);
        } else if (!full_uri.empty()) {
            FIELD(l, "Full request URI", full_uri, 0, 0);
        }
        // (before the media dissectors: they add layers, which moves the one `l` refers to)
        if (body > 0) FIELD(l, "File Data", fmt("%zu bytes", body), off + lead + hend, body);
        if (body > 0 && !ctype.empty()) http_media(ctype, p + hend, std::min(body, have));
        else if (body > 0) fproto("data", off + lead + hend, body);
        if (!headers_done) return -1;  // a header block cut short: it runs to the end of the data
        return static_cast<long>(lead + hend + body);
    }

    // The value of a header in [p, p + len) (case-insensitive name), or "".
    static std::string http_header(const uint8_t* p, size_t len, const char* name) {
        size_t nl = std::strlen(name), pos = 0;
        while (pos < len) {
            size_t e = pos;
            while (e < len && p[e] != '\n') ++e;
            size_t ll = e - pos;
            if (ll && p[pos + ll - 1] == '\r') --ll;
            if (ll > nl && p[pos + nl] == ':') {
                bool same = true;
                for (size_t i = 0; i < nl && same; ++i)
                    same = std::tolower(p[pos + i]) == name[i];
                if (same) {
                    size_t v = pos + nl + 1;
                    while (v < pos + ll && (p[v] == ' ' || p[v] == '\t')) ++v;
                    return text_line(p + v, pos + ll - v, 400);
                }
            }
            pos = e + 1;
        }
        return "";
    }

    // A DER length: its value and how many bytes encode it.
    static bool der_length(const uint8_t* p, size_t n, size_t& value, size_t& used) {
        if (!n) return false;
        if (p[0] < 0x80) {
            value = p[0];
            used = 1;
            return true;
        }
        size_t k = p[0] & 0x7F;
        if (k == 0 || k > 4 || k + 1 > n) return false;
        value = 0;
        for (size_t i = 0; i < k; ++i) value = (value << 8) | p[1 + i];
        used = 1 + k;
        return true;
    }

    // The column text a media-type dissector adds for the message body.
    // A GIF's blocks all inside the body: the screen descriptor and its color table, then
    // extensions and images (each a run of length-prefixed sub-blocks) up to the trailer.
    static bool gif_whole(const uint8_t* b, size_t n) {
        size_t pos = 13;
        if (b[10] & 0x80) pos += static_cast<size_t>(3) << ((b[10] & 7) + 1);
        auto sub_blocks = [&]() {
            for (;;) {
                if (pos >= n) return false;
                size_t len = b[pos++];
                if (!len) return true;
                if (len > n - pos) return false;
                pos += len;
            }
        };
        while (pos < n) {
            uint8_t kind = b[pos++];
            if (kind == 0x3b) return true;  // the trailer: anything after it is ignored
            if (kind == 0x21) {             // an extension: its label, then sub-blocks
                if (pos >= n) return false;
                ++pos;
                if (!sub_blocks()) return false;
            } else if (kind == 0x2c) {      // an image: descriptor, local color table, LZW size, data
                if (n - pos < 9) return false;
                uint8_t flags = b[pos + 8];
                pos += 9;
                if (flags & 0x80) pos += static_cast<size_t>(3) << ((flags & 7) + 1);
                if (pos >= n) return false;
                ++pos;
                if (!sub_blocks()) return false;
            } else {
                return true;
            }
        }
        return pos <= n;
    }

    void media_malformed() {
        col_append("[Malformed Packet]");
        d_.malformed = true;
        if (ff_ && !frozen_ && !ff_->has_proto("_ws.malformed")) ff_->proto("_ws.malformed", 0, 0);
    }

    // `fallback`: HTTP/1.x hands a type no dissector claims to the generic media
    // dissector, which names it; HTTP/2 doesn't, so such a body adds nothing.
    void http_media(const std::string& ctype, const uint8_t* body, size_t blen, bool fallback = true) {
        if (ctype == "application/dns-message") {  // DNS over HTTPS (RFC 8484)
            Bytes saved = b_;
            bool saved_virtual = virtual_;
            b_ = {body, blen};
            virtual_ = true;
            std::string before = d_.info;
            dns(0, blen, "DoH");  // (written for UDP, it sets the final Info itself)
            std::string info = d_.info;
            d_.info = before;
            b_ = saved;
            virtual_ = saved_virtual;
            return col_set(info);
        }
        if (ctype == "application/grpc" || ctype.rfind("application/grpc+", 0) == 0) {
            set_proto("GRPC");
            fproto("grpc", 0, 0);
            return col_append_sep("(GRPC)", " ");
        }
        if (ctype == "application/sdp") {
            if (proto_writable_ && !frozen_) d_.protocol += "/SDP";
            return fproto("sdp", 0, 0);
        }
        if (ctype == "multipart/mixed" || ctype == "multipart/form-data" || ctype == "multipart/related" ||
            ctype == "multipart/alternative" || ctype == "multipart/signed" || ctype == "multipart/byteranges")
            return fproto("mime_multipart", 0, 0);
        if (ctype == "application/ocsp-request" || ctype == "application/ocsp-response") {
            bool request = ctype == "application/ocsp-request";
            set_proto("OCSP");
            fproto("ocsp", 0, 0);
            col_set(request ? "Request" : "Response");
            // OCSPRequest/OCSPResponse is a DER SEQUENCE; one claiming more bytes than
            // the body holds runs off the end.
            size_t hl = 0, inner = 0;
            bool ok = blen < 2 || body[0] != 0x30 || (der_length(body + 1, blen - 1, inner, hl) && 1 + hl + inner <= blen);
            if (!ok) {
                col_append("[Malformed Packet]");
                d_.malformed = true;
            }
            return;
        }
        if (ctype == "application/json" || ctype == "application/senml+json" || ctype == "application/sensml+json" ||
            ctype == "application/json-rpc" || ctype == "application/jsonrequest" ||
            ctype == "application/dds-web+json") {
            if (proto_writable_ && !frozen_) d_.protocol += "/JSON";
            fproto("json", 0, 0);
            col_append_sep("JSON");
            col_append_sep("(" + ctype + ")", " ");
            return;
        }
        // XML (HTTP/2 doesn't hand it XHTML). Its dissector runs off the end of a one-byte body.
        if (ctype == "text/xml" || ctype == "application/xml" || ctype == "application/soap+xml" ||
            (ctype == "application/xhtml+xml" && fallback) || ctype == "image/svg+xml" ||
            ctype == "application/atom+xml" || ctype == "application/rss+xml" || ctype == "application/rdf+xml" ||
            ctype == "application/xml-dtd" || ctype == "application/x-wms-logplaystats") {
            if (blen == 1) return media_malformed();
            if (proto_writable_ && !frozen_) d_.protocol += "/XML";
            fproto("xml", 0, 0);
            return;
        }
        // WebP is a RIFF container: a 12-byte header, then chunks of fourcc + size + data,
        // read back to back (no pad byte); one running past the end is malformed. A body
        // that isn't RIFF at all is left to the next dissector.
        if (ctype == "image/webp" && blen >= 4 && std::memcmp(body, "RIFF", 4) == 0) {
            fproto("riff", 0, 0);
            if (blen < 12) return media_malformed();
            for (size_t pos = 12; pos < blen;) {
                if (blen - pos < 8) return media_malformed();
                uint32_t sz = static_cast<uint32_t>(body[pos + 4] | (body[pos + 5] << 8) | (body[pos + 6] << 16) |
                                                    (static_cast<uint32_t>(body[pos + 7]) << 24));
                if (sz > blen - pos - 8) return media_malformed();
                pos += 8 + sz;
            }
            return;
        }
        if (ctype == "application/pkix-crl") {  // certificate revocation lists, fetched by Windows all day
            set_proto("PKIX-CRL");
            fproto("x509af", 0, 0);
            return col_set("Certificate Revocation List");
        }
        if (ctype == "application/pkcs7-mime" || ctype == "application/pkcs7-signature")
            return fproto("cms", 0, 0);  // CMS leaves the columns alone
        if (ctype == "application/octet-stream") return fproto("data", 0, 0);  // the data dissector
        if (ctype == "image/png" && blen >= 8 && std::memcmp(body, "\x89PNG\r\n\x1a\n", 8) == 0) {
            fproto("png", 0, 0);
            return col_append(" (PNG)");
        }
        if ((ctype == "image/jpeg" || ctype == "image/jpg" || ctype == "image/jfif") && blen >= 2 && body[0] == 0xFF &&
            body[1] == 0xD8) {
            fproto("image-jfif", 0, 0);
            return col_append_sep("(JPEG JFIF image)", " ");
        }
        // GIF: Wireshark's dissector takes 20 bytes or more, then walks the blocks; one cut
        // short is malformed.
        if (ctype == "image/gif" && blen >= 20 &&
            (std::memcmp(body, "GIF87a", 6) == 0 || std::memcmp(body, "GIF89a", 6) == 0)) {
            fproto("image-gif", 0, 0);
            col_append(" (" + std::string(reinterpret_cast<const char*>(body), 6) + ")");
            if (!gif_whole(body, blen)) media_malformed();
            return;
        }
        // The line-based text dissector's media types; under HTTP/1.x every other type
        // goes to the generic media dissector, which names it the same way.
        static const char* const kTextLines[] = {
            "text/plain", "text/html", "text/css", "text/javascript", "text/richtext", "text/enriched",
            "text/parameters", "text/vnd.sun.j2me.app-descriptor", "application/x-javascript",
            "application/x-www-form-urlencoded", "application/x-ns-proxy-autoconfig", "application/vnd.drm.message",
            "application/x-rtsp-udp-packetpair", "message/http"};
        bool text_lines = std::any_of(std::begin(kTextLines), std::end(kTextLines), [&](const char* t) { return ctype == t; });
        if (!text_lines && !fallback) return;
        fproto(text_lines || ctype.rfind("text/", 0) == 0 ? "data-text-lines" : "media", 0, 0);
        col_append_sep("(" + ctype + ")", " ");
    }

    void udp_app(size_t off, size_t len, uint16_t sport, uint16_t dport) {
        auto port = [&](uint16_t x) { return sport == x || dport == x; };
        // DTLS is found by Wireshark's heuristic, once no port's dissector took the datagram.
        static const uint16_t kPorts[] = {53, 5353, 5355, 67, 68, 546, 547, 137, 138, 88, 389, 123, 1900, 69, 514, 443};
        if (!full_) {  // of the UDP decoders only DNS, QUIC, CLDAP and DTLS keep cross-frame state
            if ((port(53) || port(5353) || port(5355)) && dns_header_ok(off, len))
                dns_transaction(b_.u16(off), b_.u16(off + 2) & 0x8000);
            else if (port(443))
                quic(off, len);  // connection IDs, packet numbers, the Client Hello's pieces
            else if (port(389))
                cldap(off, len);  // search entries, counted per conversation
            else if (std::none_of(std::begin(kPorts), std::end(kPorts), port) && dtls_heuristic(off, len))
                dtls(off, len);   // the version, handshake reassembly, the record keys
            return;
        }
        if (port(53) && dns(off, len, "DNS")) return;
        if (port(5353) && dns(off, len, "MDNS")) return;
        if (port(5355) && dns(off, len, "LLMNR")) return;
        if ((port(67) || port(68)) && dhcp(off, len)) return;
        if ((port(546) || port(547)) && dhcpv6(off, len)) return;
        if (port(137) && nbns(off, len)) return;
        if (port(138) && nbdgm(off, len)) return;
        if (port(88) && kerberos(off, len)) return;
        if (port(389) && cldap(off, len)) return;
        if (port(123) && ntp(off, len)) return;
        if (port(1900) && ssdp(off, len)) return;
        if (port(69) && tftp(off, len)) return;
        if (port(514) && syslog(off, len)) return;
        if (port(443) && quic(off, len)) return;
        if (dtls_heuristic(off, len)) return dtls(off, len);
        fproto("data", off, len);
        Layer& l = layer("Data", off, len);
        field(l, "Length", fmt("%zu bytes", len), off, len);
    }

    // Wireshark's DNS request/response tracking: per conversation and transaction
    // ID, a request without a response yet, repeated within 5 seconds, is a
    // retransmission; so is a second response to the same request.
    void dns_transaction(uint16_t id, bool response, const char* proto = "DNS") {
        if (st_.dns.size() > 200'000) st_.dns.clear();
        auto& per_conv = st_.dns[l4_key_];
        if (per_conv.size() > 4096) per_conv.clear();
        auto it = per_conv.find(id);
        if (!response) {
            uint64_t req = frame_;
            if (it != per_conv.end() && !it->second.rep_frame && it->second.req_frame != frame_ &&
                static_cast<int64_t>(ts_ - it->second.req_ts) < 5'000'000) {
                req = it->second.req_frame;
                FF(uint("dns.retransmit_request_in", req));
                expert("dns.retransmit_request", 2, "Protocol", proto,
                       fmt("DNS query retransmission. Original request in frame %llu", static_cast<unsigned long long>(req)));
            } else {
                per_conv[id] = {frame_, 0, ts_};
            }
            if (st_.use && req == frame_) {  // a retransmission isn't cross-referenced
                auto r = st_.use->dns_response_in.find(req);
                if (r != st_.use->dns_response_in.end()) FF(uint("dns.response_in", r->second));
                else if (st_.use->complete) expert("dns.response_missing", 2, "Protocol", proto, "DNS response missing");
            }
            return;
        }
        if (it == per_conv.end()) return;
        auto& t = it->second;
        if (!t.rep_frame) {
            t.rep_frame = frame_;
            if (st_.record) st_.record->dns_response_in[t.req_frame] = frame_;
        } else if (t.rep_frame != frame_) {
            FF(uint("dns.retransmit_response_in", t.rep_frame));
            expert("dns.retransmit_response", 2, "Protocol", proto,
                   fmt("DNS response retransmission. Original response in frame %llu",
                       static_cast<unsigned long long>(t.rep_frame)));
            return;
        }
        FF(uint("dns.response_to", t.req_frame));
        FF(real("dns.time", static_cast<double>(ts_ > t.req_ts ? ts_ - t.req_ts : 0) / 1e6));
    }

    bool dns_header_ok(size_t off, size_t len) const {
        if (len < 12 || !b_.have(off, len)) return false;
        uint16_t flags = b_.u16(off + 2), qd = b_.u16(off + 4), an = b_.u16(off + 6);
        return qd <= 16 && ((flags >> 11) & 0xF) <= 6 && (qd || an);
    }

    bool dns(size_t off, size_t len, const char* label) {
        // Wireshark decodes whatever is on port 53 as DNS and marks what doesn't parse
        // [Malformed Packet]; mDNS and LLMNR keep a plausibility check.
        const bool always = label[0] == 'D';
        if (len < (always ? 4u : 12u) || !b_.have(off, len)) return false;
        const uint8_t* m = b_.p + off;
        uint16_t id = b_.u16(off), flags = b_.u16(off + 2);
        uint16_t qd = 0, an = 0, ns = 0, ar = 0;
        if (len >= 12) {
            qd = b_.u16(off + 4);
            an = b_.u16(off + 6);
            ns = b_.u16(off + 8);
            ar = b_.u16(off + 10);
        }
        uint8_t opcode = (flags >> 11) & 0xF, rcode = flags & 0xF;
        bool response = flags & 0x8000;
        if (!always && (qd > 16 || opcode > 6 || (qd == 0 && an == 0))) return false;
        static const char* ops[] = {"Standard query", "Inverse query", "Server status request", nullptr,
                                    "Zone change notification", "Dynamic update", "DNS Stateful operations (DSO)"};
        std::string info = (opcode < 7 && ops[opcode] ? std::string(ops[opcode]) : fmt("Unknown operation (%u)", opcode)) +
                           (response ? " response" : "") + fmt(" 0x%04x", id);
        static const char* rcodes[] = {"", "Format error", "Server failure", "No such name", "Not implemented",
                                       "Refused", "YXDomain", "YXRRSet", "NXRRSet", "Not auth", "Not zone"};
        if (response && rcode) info += std::string(" ") + (rcode <= 10 ? rcodes[rcode] : "Unknown error");
        Layer& l = layer(label[0] == 'M' ? "Multicast Domain Name System" : "Domain Name System", off, len);
        // Where Wireshark's dissector runs off the end of the message.
        auto malformed = [&]() {
            d_.protocol = label;
            d_.info = info + "[Malformed Packet]";
            d_.malformed = true;
            return true;
        };
        if (ff_) {
            fproto(label[0] == 'M' ? "mdns" : label[0] == 'L' ? "llmnr" : "dns", off, len);
            FF(uint("dns.id", id));
            FF(boolean("dns.flags.response", response));
            FF(uint("dns.flags.opcode", opcode));
            FF(boolean("dns.flags.z", flags & 0x0040));
            if (response) FF(uint("dns.flags.rcode", rcode));
            if (len >= 12) {
                FF(uint("dns.count.queries", qd));
                FF(uint("dns.count.answers", an));
            }
        }
        field(l, "Transaction ID", fmt("0x%04x", id), off, 2);
        field(l, "Flags", fmt("0x%04x %s", flags, response ? "response" : "query"), off + 2, 2);
        field(l, "Questions", fmt("%u", qd), off + 4, 2);
        field(l, "Answer RRs", fmt("%u", an), off + 6, 2);
        if (len < 12) return malformed();
        size_t pos = 12;
        bool mdns = label[0] == 'M';
        std::string first_qname;
        for (uint16_t i = 0; i < qd; ++i) {
            std::string name;
            size_t next = 0;
            if (!read_dns_name(m, len, pos, name, next) || next + 4 > len) {
                if (always) return malformed();
                return i > 0;
            }
            if (i == 0) first_qname = name;
            uint16_t type = static_cast<uint16_t>((m[next] << 8) | m[next + 1]);
            FF(string("dns.qry.name", name.empty() ? "<Root>" : name));
            FF(uint("dns.qry.type", type));
            info += " " + dns_type(type) + " " + (name.empty() ? "<Root>" : name);
            if (mdns) info += (m[next + 2] & 0x80) ? ", \"QU\" question" : ", \"QM\" question";
            field(l, "Query", (name.empty() ? "<Root>" : name) + ": type " + dns_type(type), off + pos, next + 4 - pos);
            pos = next + 4;
        }
        int total = an + ns + ar;
        for (int i = 0; i < total && i < 64; ++i) {
            std::string name;
            size_t next = 0;
            if (!read_dns_name(m, len, pos, name, next) || next + 10 > len) {
                if (always) return malformed();
                break;
            }
            uint16_t type = static_cast<uint16_t>((m[next] << 8) | m[next + 1]);
            uint16_t rdlen = static_cast<uint16_t>((m[next + 8] << 8) | m[next + 9]);
            size_t rd = next + 10;
            if (rd + rdlen > len) {
                if (always) return malformed();
                break;
            }
            std::string value = dns_rdata(m, len, type, rd, rdlen);
            if (ff_) {  // records in every section carry their fields
                FF(string("dns.resp.name", name.empty() ? "<Root>" : name));
                FF(uint("dns.resp.type", type));
                if (type == 1 && rdlen == 4) FF(ipv4("dns.a", m + rd));
                if (type == 28 && rdlen == 16) FF(ipv6("dns.aaaa", m + rd));
                if (i < an && ((type == 1 && rdlen == 4) || (type == 28 && rdlen == 16)))  // name -> address
                    FF(string("_anta.dns_answer", (first_qname.empty() ? name : first_qname) + "\t" + value));
                if (type == 5 && !value.empty()) FF(string("dns.cname", value));
                if (type == 12 && !value.empty()) FF(string("dns.ptr.domain_name", value));
            }
            info += " " + dns_type(type) + (mdns && (m[next + 2] & 0x80) ? ", cache flush" : "") +
                    (value.empty() ? "" : " " + value);
            const char* section = i < an ? "Answer" : i < an + ns ? "Authority" : "Additional";
            field(l, section, (name.empty() ? "<Root>" : name) + ": type " + dns_type(type) +
                                  (value.empty() ? "" : ", " + value), off + pos, rd + rdlen - pos);
            pos = rd + rdlen;
        }
        // Like Wireshark, the request/response pairing is only made for a message that parsed.
        dns_transaction(id, response, label[0] == 'M' ? "mDNS" : label[0] == 'L' ? "LLMNR" : "DNS");
        d_.protocol = label;
        if (info.size() > 2000) info = info.substr(0, 1997) + "...";
        d_.info = info;
        return true;
    }

    static std::string dns_rdata(const uint8_t* m, size_t len, uint16_t type, size_t rd, uint16_t rdlen) {
        std::string name;
        size_t next = 0;
        if (rdlen == 0) return "";  // e.g. a dynamic update's "name is not in use" prerequisite
        switch (type) {
            case 1: return rdlen == 4 ? ipv4s(m + rd) : "";
            case 28: return rdlen == 16 ? ipv6s(m + rd) : "";
            case 2:
            case 5:
            case 6:
            case 12: return read_dns_name(m, len, rd, name, next) ? name : "";
            case 15:
                if (rdlen > 2 && read_dns_name(m, len, rd + 2, name, next))
                    return fmt("%u ", (m[rd] << 8) | m[rd + 1]) + name;
                return "";
            case 33:
                if (rdlen > 6 && read_dns_name(m, len, rd + 6, name, next))
                    return fmt("%u %u %u ", (m[rd] << 8) | m[rd + 1], (m[rd + 2] << 8) | m[rd + 3],
                               (m[rd + 4] << 8) | m[rd + 5]) + name;
                return "";
            default: return "";
        }
    }

    bool dhcp(size_t off, size_t len) {
        if (len < 240 || !b_.have(off, 240)) return false;
        if (b_.u32(off + 236) != 0x63825363) return false;
        uint8_t op = b_.u8(off);
        uint32_t xid = b_.u32(off + 4);
        Layer& l = layer("Dynamic Host Configuration Protocol", off, len);
        if (ff_) {
            fproto("dhcp", off, len);
            FF(uint("dhcp.type", op));
            FF(uint("dhcp.hops", b_.u8(off + 3)));
            FF(uint("dhcp.id", xid));
            // Some clients send the seconds little-endian: a big-endian value over 255
            // with a zero low byte is read the other way round, as Wireshark does.
            uint16_t secs = b_.u16(off + 8);
            bool secs_le = secs > 0xFF && (secs & 0xFF) == 0;
            FF(uint("dhcp.secs", secs_le ? secs >> 8 : secs));
            if (secs_le) expert("dhcp.secs_le");
            FF(boolean("dhcp.flags.bc", b_.u16(off + 10) & 0x8000));
            FF(ipv4("dhcp.ip.client", b_.p + off + 12));
            FF(ipv4("dhcp.ip.your", b_.p + off + 16));
            if (b_.u8(off + 1) == 1 && b_.u8(off + 2) == 6) FF(mac("dhcp.hw.mac_addr", b_.p + off + 28));
        }
        field(l, "Message type", op == 1 ? "Boot Request (1)" : "Boot Reply (2)", off, 1);
        field(l, "Transaction ID", fmt("0x%08x", xid), off + 4, 4);
        field(l, "Client IP address", ipv4s(b_.p + off + 12), off + 12, 4);
        field(l, "Your (client) IP address", ipv4s(b_.p + off + 16), off + 16, 4);
        field(l, "Next server IP address", ipv4s(b_.p + off + 20), off + 20, 4);
        field(l, "Relay agent IP address", ipv4s(b_.p + off + 24), off + 24, 4);
        if (b_.u8(off + 1) == 1 && b_.u8(off + 2) == 6) field(l, "Client MAC address", mac_name(b_.p + off + 28), off + 28, 6);
        static const char* types[] = {"", "Discover", "Offer", "Request", "Decline", "ACK", "NAK", "Release",
                                      "Inform", "Force Renew", "Lease query", "Lease Unassigned", "Lease Unknown",
                                      "Lease Active"};
        int mtype = -1;
        size_t pos = off + 240, end = off + len;
        while (pos < end) {
            uint8_t code = b_.u8(pos);
            if (code == 255) break;
            if (code == 0) {
                ++pos;
                continue;
            }
            if (pos + 2 > end) break;
            size_t olen = b_.u8(pos + 1);
            if (pos + 2 + olen > end) break;
            size_t v = pos + 2;
            switch (code) {
                case 53:
                    if (olen == 1) {
                        mtype = b_.u8(v);
                        FF(uint("dhcp.option.dhcp", static_cast<uint64_t>(mtype)));
                        field(l, "Option: (53) DHCP Message Type", mtype < 14 ? types[mtype] : fmt("%d", mtype), pos, olen + 2);
                    }
                    break;
                case 50:
                    if (olen == 4) {
                        FF(ipv4("dhcp.option.requested_ip_address", b_.p + v));
                        field(l, "Option: (50) Requested IP Address", ipv4s(b_.p + v), pos, olen + 2);
                    }
                    break;
                case 54:
                    if (olen == 4) {
                        FF(ipv4("dhcp.option.dhcp_server_id", b_.p + v));
                        field(l, "Option: (54) DHCP Server Identifier", ipv4s(b_.p + v), pos, olen + 2);
                    }
                    break;
                case 51: if (olen == 4) field(l, "Option: (51) IP Address Lease Time", fmt("%u s", b_.u32(v)), pos, olen + 2); break;
                case 1: if (olen == 4) field(l, "Option: (1) Subnet Mask", ipv4s(b_.p + v), pos, olen + 2); break;
                case 3:
                    if (olen >= 4) {
                        for (size_t i = 0; i + 4 <= olen; i += 4) FF(ipv4("dhcp.option.router", b_.p + v + i));
                        field(l, "Option: (3) Router", ipv4s(b_.p + v), pos, olen + 2);
                    }
                    break;
                case 6: {
                    std::string dns;
                    for (size_t i = 0; i + 4 <= olen; i += 4) {
                        dns += (dns.empty() ? "" : ", ") + ipv4s(b_.p + v + i);
                        FF(ipv4("dhcp.option.domain_name_server", b_.p + v + i));
                    }
                    field(l, "Option: (6) Domain Name Server", dns, pos, olen + 2);
                    break;
                }
                case 12:
                    FF(string("dhcp.option.hostname", text_line(b_.p + v, olen, 255)));
                    field(l, "Option: (12) Host Name", text_line(b_.p + v, olen, 255), pos, olen + 2);
                    break;
                case 60:
                    FF(string("dhcp.option.vendor_class_id", text_line(b_.p + v, olen, 255)));
                    field(l, "Option: (60) Vendor class identifier", text_line(b_.p + v, olen, 255), pos, olen + 2);
                    break;
                case 61: field(l, "Option: (61) Client identifier", fmt("%zu bytes", olen), pos, olen + 2); break;
                case 55:  // which options the client asks for, in its order: a DHCP fingerprint of the OS
                    for (size_t i = 0; i < olen; ++i) FF(uint("dhcp.option.request_list_item", b_.u8(v + i)));
                    field(l, "Option: (55) Parameter Request List", fmt("%zu items", olen), pos, olen + 2);
                    break;
                default: field(l, fmt("Option: (%u)", code), fmt("%zu bytes", olen), pos, olen + 2);
            }
            pos += 2 + olen;
        }
        d_.protocol = "DHCP";
        if (mtype > 0 && mtype < 14) d_.info = fmt("DHCP %-8s - Transaction ID 0x%08x", types[mtype], xid);
        else d_.info = fmt("%s - Transaction ID 0x%08x", op == 1 ? "Boot Request" : "Boot Reply", xid);
        return true;
    }

    bool dhcpv6(size_t off, size_t len) {
        if (len < 4) return false;
        static const char* names[] = {"", "Solicit", "Advertise", "Request", "Confirm", "Renew", "Rebind", "Reply",
                                      "Release", "Decline", "Reconfigure", "Information-request", "Relay-forw",
                                      "Relay-reply"};
        uint8_t t = b_.u8(off);
        if (t == 0 || t > 13) return false;
        d_.protocol = "DHCPv6";
        Layer& l = layer("DHCPv6", off, len);
        fproto("dhcpv6", off, len);
        FF(uint("dhcpv6.msgtype", t));
        field(l, "Message type", names[t], off, 1);
        if (t >= 12) {
            d_.info = names[t];
            return true;
        }
        uint32_t xid = (b_.u8(off + 1) << 16) | (b_.u8(off + 2) << 8) | b_.u8(off + 3);
        std::string info = fmt("%s XID: 0x%06x", names[t], xid);
        size_t pos = off + 4, end = off + len;
        while (pos + 4 <= end) {
            uint16_t code = b_.u16(pos), olen = b_.u16(pos + 2);
            if (pos + 4 + olen > end) break;
            if (code == 1) {
                std::string hex;
                for (size_t i = 0; i < olen && i < 64; ++i) hex += fmt("%02x", b_.u8(pos + 4 + i));
                info += " CID: " + hex;
                field(l, "Client Identifier", hex, pos, olen + 4u);
            }
            pos += 4 + olen;
        }
        d_.info = info;
        return true;
    }

    std::string netbios_name(size_t off, size_t end, size_t& next) {
        // First-level encoding: 32 chars 'A'..'P' -> 16 bytes; then optional scope labels.
        if (!b_.have(off, 34) || off + 34 > end || b_.u8(off) != 32) return "";
        uint8_t raw[16];
        for (int i = 0; i < 16; ++i) {
            uint8_t hi = static_cast<uint8_t>(b_.u8(off + 1 + 2 * i) - 'A');
            uint8_t lo = static_cast<uint8_t>(b_.u8(off + 2 + 2 * i) - 'A');
            raw[i] = static_cast<uint8_t>(((hi & 0xF) << 4) | (lo & 0xF));
        }
        int last = 14;
        while (last >= 0 && raw[last] == ' ') --last;
        std::string name;
        for (int i = 0; i <= last; ++i)
            name += (raw[i] >= 0x21 && raw[i] < 0x7f) ? std::string(1, static_cast<char>(raw[i])) : fmt("<%02x>", raw[i]);
        name += fmt("<%02x>", raw[15]);
        size_t pos = off + 33;
        while (pos < end && b_.have(pos, 1) && b_.u8(pos) != 0 && b_.u8(pos) < 64 && b_.have(pos + 1, b_.u8(pos))) {
            name += "." + text_line(b_.p + pos + 1, b_.u8(pos), 63);
            pos += 1 + b_.u8(pos);
        }
        next = pos + 1;
        return name;
    }

    // ----------------------------------------------------------- Kerberos
    // Just enough DER to read Kerberos (RFC 4120): one tag byte, short or long lengths.
    struct Tlv {
        uint8_t tag = 0;
        size_t off = 0, len = 0, next = 0;
    };
    bool tlv(size_t pos, size_t end, Tlv& t) const {
        if (pos + 2 > end || !b_.have(pos, 2)) return false;
        t.tag = b_.u8(pos);
        if ((t.tag & 0x1f) == 0x1f) return false;
        size_t l = b_.u8(pos + 1), p = pos + 2;
        if (l & 0x80) {
            size_t nb = l & 0x7f;
            if (nb == 0 || nb > 4 || p + nb > end) return false;
            l = 0;
            for (size_t i = 0; i < nb; ++i) l = (l << 8) | b_.u8(p + i);
            p += nb;
        }
        if (l > end - p || !b_.have(p, l)) return false;
        t.off = p;
        t.len = l;
        t.next = p + l;
        return true;
    }
    bool tlv_in(const Tlv& t, Tlv& inner) const { return tlv(t.off, t.off + t.len, inner); }
    int64_t der_int(const Tlv& t) const {
        if (!t.len || t.len > 8) return 0;
        int64_t v = static_cast<int8_t>(b_.u8(t.off));
        for (size_t i = 1; i < t.len; ++i) v = static_cast<int64_t>((static_cast<uint64_t>(v) << 8) | b_.u8(t.off + i));
        return v;
    }
    // [n] EXPLICIT INTEGER / KerberosString inside a context tag
    int64_t ctx_int(const Tlv& t) const {
        Tlv in;
        return tlv_in(t, in) && in.tag == 0x02 ? der_int(in) : 0;
    }
    std::string ctx_str(const Tlv& t) const {
        Tlv in;
        return tlv_in(t, in) ? text_line(b_.p + in.off, in.len, 255) : std::string();
    }
    template <class F>
    void tlv_each(const Tlv& parent, F fn) const {
        for (size_t pos = parent.off, end = parent.off + parent.len; pos < end;) {
            Tlv c;
            if (!tlv(pos, end, c)) return;
            fn(c);
            pos = c.next;
        }
    }
    // PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }
    void krb_principal(const Tlv& t, const char* string_field, Layer& l, const char* label) {
        Tlv seq;
        if (!tlv_in(t, seq) || seq.tag != 0x30) return;
        std::string joined;
        tlv_each(seq, [&](const Tlv& c) {
            if (c.tag == 0xa0) {
                FF(sint("kerberos.name_type", ctx_int(c)));
            } else if (c.tag == 0xa1) {
                Tlv names;
                if (!tlv_in(c, names) || names.tag != 0x30) return;
                tlv_each(names, [&](const Tlv& n) {
                    std::string v = text_line(b_.p + n.off, n.len, 255);
                    FF(string(string_field, v));
                    joined += (joined.empty() ? "" : "/") + v;
                });
            }
        });
        FIELD(l, label, joined, t.off, t.len);
    }
    void krb_ticket(const Tlv& t, Layer& l) {  // Ticket ::= [APPLICATION 1] SEQUENCE
        Tlv app, seq;
        if (!tlv_in(t, app) || app.tag != 0x61 || !tlv_in(app, seq) || seq.tag != 0x30) return;
        tlv_each(seq, [&](const Tlv& c) {
            if (c.tag == 0xa0) FF(sint("kerberos.tkt_vno", ctx_int(c)));
            else if (c.tag == 0xa1) FF(string("kerberos.realm", ctx_str(c)));
            else if (c.tag == 0xa2) krb_principal(c, "kerberos.SNameString", l, "Ticket server name");
        });
    }
    static const char* krb_error_name(int64_t code) {
        static const char* names[] = {
            nullptr, "KRB5KDC_ERR_NAME_EXP", "KRB5KDC_ERR_SERVICE_EXP", "KRB5KDC_ERR_BAD_PVNO",
            "KRB5KDC_ERR_C_OLD_MAST_KVNO", "KRB5KDC_ERR_S_OLD_MAST_KVNO", "KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN",
            "KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN", "KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE", "KRB5KDC_ERR_NULL_KEY",
            "KRB5KDC_ERR_CANNOT_POSTDATE", "KRB5KDC_ERR_NEVER_VALID", "KRB5KDC_ERR_POLICY", "KRB5KDC_ERR_BADOPTION",
            "KRB5KDC_ERR_ETYPE_NOSUPP", "KRB5KDC_ERR_SUMTYPE_NOSUPP", "KRB5KDC_ERR_PADATA_TYPE_NOSUPP",
            "KRB5KDC_ERR_TRTYPE_NOSUPP", "KRB5KDC_ERR_CLIENT_REVOKED", "KRB5KDC_ERR_SERVICE_REVOKED",
            "KRB5KDC_ERR_TGT_REVOKED", "KRB5KDC_ERR_CLIENT_NOTYET", "KRB5KDC_ERR_SERVICE_NOTYET",
            "KRB5KDC_ERR_KEY_EXP", "KRB5KDC_ERR_PREAUTH_FAILED", "KRB5KDC_ERR_PREAUTH_REQUIRED",
            "KRB5KDC_ERR_SERVER_NOMATCH", "KRB5KDC_ERR_MUST_USE_USER2USER", "KRB5KDC_ERR_PATH_NOT_ACCEPTED",
            "KRB5KDC_ERR_SVC_UNAVAILABLE", nullptr, "KRB5KRB_AP_ERR_BAD_INTEGRITY", "KRB5KRB_AP_ERR_TKT_EXPIRED",
            "KRB5KRB_AP_ERR_TKT_NYV", "KRB5KRB_AP_ERR_REPEAT", "KRB5KRB_AP_ERR_NOT_US", "KRB5KRB_AP_ERR_BADMATCH",
            "KRB5KRB_AP_ERR_SKEW", "KRB5KRB_AP_ERR_BADADDR", "KRB5KRB_AP_ERR_BADVERSION", "KRB5KRB_AP_ERR_MSG_TYPE",
            "KRB5KRB_AP_ERR_MODIFIED", "KRB5KRB_AP_ERR_BADORDER", "KRB5KRB_AP_ERR_ILL_CR_TKT",
            "KRB5KRB_AP_ERR_BADKEYVER", "KRB5KRB_AP_ERR_NOKEY", "KRB5KRB_AP_ERR_MUT_FAIL",
            "KRB5KRB_AP_ERR_BADDIRECTION", "KRB5KRB_AP_ERR_METHOD", "KRB5KRB_AP_ERR_BADSEQ",
            "KRB5KRB_AP_ERR_INAPP_CKSUM", "KRB5KDC_AP_PATH_NOT_ACCEPTED", "KRB5KRB_ERR_RESPONSE_TOO_BIG", nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, "KRB5KRB_ERR_GENERIC", "KRB5KRB_ERR_FIELD_TOOLONG",
            "KDC_ERROR_CLIENT_NOT_TRUSTED", "KDC_ERROR_KDC_NOT_TRUSTED", "KDC_ERROR_INVALID_SIG", "KDC_ERR_KEY_TOO_WEAK",
            "KDC_ERR_CERTIFICATE_MISMATCH", "KRB_AP_ERR_NO_TGT", "KDC_ERR_WRONG_REALM",
            "KRB_AP_ERR_USER_TO_USER_REQUIRED", "KDC_ERR_CANT_VERIFY_CERTIFICATE", "KDC_ERR_INVALID_CERTIFICATE",
            "KDC_ERR_REVOKED_CERTIFICATE", "KDC_ERR_REVOCATION_STATUS_UNKNOWN",
            "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE", "KDC_ERR_CLIENT_NAME_MISMATCH", "KDC_ERR_KDC_NAME_MISMATCH"};
        static const char* fast[] = {"KDC_ERR_PREAUTH_EXPIRED", "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED",
                                     "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET", "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS"};
        if (code >= 0 && code < static_cast<int64_t>(sizeof names / sizeof names[0])) return names[code];
        if (code >= 90 && code <= 93) return fast[code - 90];
        return nullptr;
    }

    // One Kerberos message: fields in Wireshark's order, and the Info text.
    bool krb_message(size_t off, size_t len, Layer* parent, std::string* info) {
        Tlv top, seq;
        if (!tlv(off, off + len, top) || (top.tag & 0xe0) != 0x60 || !tlv_in(top, seq) || seq.tag != 0x30) return false;
        int mt = top.tag & 0x1f;
        static const std::pair<int, const char*> kinds[] = {{10, "AS-REQ"}, {11, "AS-REP"}, {12, "TGS-REQ"},
                                                            {13, "TGS-REP"}, {14, "AP-REQ"}, {15, "AP-REP"},
                                                            {20, "KRB-SAFE"}, {21, "KRB-PRIV"}, {22, "KRB-CRED"},
                                                            {30, "KRB-ERROR"}};
        const char* kind = nullptr;
        for (const auto& [n, name] : kinds)
            if (n == mt) kind = name;
        if (!kind) return false;
        Layer& l = parent ? *parent : layer("Kerberos", off, len);
        FIELD(l, "Message type", fmt("%s (%d)", kind, mt), top.off, 0);
        int64_t error = 0, rep_etype = -1;
        bool req = mt == 10 || mt == 12, rep = mt == 11 || mt == 13;
        tlv_each(seq, [&](const Tlv& c) {
            uint8_t n = c.tag & 0x1f;
            if ((c.tag & 0xe0) != 0xa0) return;
            if (req) {  // KDC-REQ: pvno[1] msg-type[2] padata[3] req-body[4]
                if (n == 1) FF(sint("kerberos.pvno", ctx_int(c)));
                else if (n == 2) FF(sint("kerberos.msg_type", ctx_int(c)));
                else if (n == 3) krb_padata(c, l);
                else if (n == 4) krb_req_body(c, l);
            } else if (rep) {  // KDC-REP: pvno[0] msg-type[1] padata[2] crealm[3] cname[4] ticket[5]
                if (n == 0) FF(sint("kerberos.pvno", ctx_int(c)));
                else if (n == 1) FF(sint("kerberos.msg_type", ctx_int(c)));
                else if (n == 3) {
                    std::string realm = ctx_str(c);
                    FF(string("kerberos.crealm", realm));
                    FIELD(l, "Client realm", realm, c.off, c.len);
                } else if (n == 4) krb_principal(c, "kerberos.CNameString", l, "Client name");
                else if (n == 5) krb_ticket(c, l);
                else if (n == 6) {  // enc-part: EncryptedData { etype[0] ... }
                    Tlv enc, et;
                    if (tlv_in(c, enc) && enc.tag == 0x30 && tlv_in(enc, et) && et.tag == 0xa0) rep_etype = ctx_int(et);
                }
            } else if (mt == 30) {  // KRB-ERROR
                if (n == 0) FF(sint("kerberos.pvno", ctx_int(c)));
                else if (n == 1) FF(sint("kerberos.msg_type", ctx_int(c)));
                else if (n == 6) {
                    error = ctx_int(c);
                    FF(sint("kerberos.error_code", error));
                } else if (n == 7) FF(string("kerberos.crealm", ctx_str(c)));
                else if (n == 8) krb_principal(c, "kerberos.CNameString", l, "Client name");
                else if (n == 9) FF(string("kerberos.realm", ctx_str(c)));
                else if (n == 10) krb_principal(c, "kerberos.SNameString", l, "Server name");
                else if (n == 11) FF(string("kerberos.e_text", ctx_str(c)));
            } else if (mt == 14) {  // AP-REQ: pvno[0] msg-type[1] ap-options[2] ticket[3]
                if (n == 0) FF(sint("kerberos.pvno", ctx_int(c)));
                else if (n == 1) FF(sint("kerberos.msg_type", ctx_int(c)));
                else if (n == 3) krb_ticket(c, l);
            } else if (n == 0) {
                FF(sint("kerberos.pvno", ctx_int(c)));
            } else if (n == 1) {
                FF(sint("kerberos.msg_type", ctx_int(c)));
            }
        });
        if (mt == 13 && rep_etype >= 0) {  // Wireshark tries to decrypt a TGS-REP and has no keys
            expert("kerberos.missing_keytype", 2, "Decryption", "KRB5",
                   fmt("Missing keytype %lld usage 8 or 9 (id=missing.1)", static_cast<long long>(rep_etype)));
            expert("kerberos.decrypted_keytype", 2, "Decryption", "KRB5", "Used keymap=(null) num_keys=0 num_tries=0)");
        }
        if (info) {
            if (mt != 30 || !error) {
                *info = kind;
            } else {
                const char* name = krb_error_name(error);
                *info = std::string("KRB Error: ") + (name ? name : fmt("Unknown error code %#llx",
                                                                        static_cast<unsigned long long>(error)).c_str());
                FIELD(l, "Error code", *info, top.off, 0);
            }
        }
        return true;
    }
    void krb_padata(const Tlv& t, Layer& l) {  // SEQUENCE OF PA-DATA { padata-type[1], padata-value[2] }
        Tlv seq;
        if (!tlv_in(t, seq) || seq.tag != 0x30) return;
        tlv_each(seq, [&](const Tlv& pa) {
            int64_t type = -1;
            Tlv value{};
            bool have = false;
            tlv_each(pa, [&](const Tlv& c) {
                if (c.tag == 0xa1) type = ctx_int(c);
                else if (c.tag == 0xa2 && tlv_in(c, value) && value.tag == 0x04) have = true;
            });
            if (type == 1 && have) krb_message(value.off, value.len, &l, nullptr);  // PA-TGS-REQ: the AP-REQ
        });
    }
    void krb_req_body(const Tlv& t, Layer& l) {
        Tlv body;
        if (!tlv_in(t, body) || body.tag != 0x30) return;
        tlv_each(body, [&](const Tlv& c) {
            if (c.tag == 0xa1) krb_principal(c, "kerberos.CNameString", l, "Client name");
            else if (c.tag == 0xa2) {
                std::string realm = ctx_str(c);
                FF(string("kerberos.realm", realm));
                FIELD(l, "Realm", realm, c.off, c.len);
            } else if (c.tag == 0xa3) krb_principal(c, "kerberos.SNameString", l, "Server name");
            else if (c.tag == 0xa9) {  // HostAddresses: a NetBIOS name names the client machine
                Tlv addrs;
                if (!tlv_in(c, addrs) || addrs.tag != 0x30) return;
                tlv_each(addrs, [&](const Tlv& a) {
                    int64_t type = -1;
                    Tlv value{};
                    bool have = false;
                    tlv_each(a, [&](const Tlv& f) {
                        if (f.tag == 0xa0) type = ctx_int(f);
                        else if (f.tag == 0xa1 && tlv_in(f, value) && value.tag == 0x04) have = true;
                    });
                    if (type == 20 && have) {
                        std::string nb = text_line(b_.p + value.off, value.len, 16);
                        while (!nb.empty() && nb.back() == ' ') nb.pop_back();
                        FF(string("kerberos.addr_nb", nb));
                        FIELD(l, "NetBIOS name", nb, value.off, value.len);
                    }
                });
            }
        });
    }

    bool krb_looks_valid(size_t off, size_t len) const {
        Tlv top, seq;
        if (!tlv(off, off + len, top) || (top.tag & 0xe0) != 0x60 || !tlv_in(top, seq) || seq.tag != 0x30) return false;
        int mt = top.tag & 0x1f;
        return (mt >= 10 && mt <= 15) || (mt >= 20 && mt <= 22) || mt == 30;
    }

    bool kerberos(size_t off, size_t len) {
        if (!krb_looks_valid(off, len)) return false;
        set_proto("KRB5");
        fproto("kerberos", off, len);
        Layer& l = layer("Kerberos", off, len);
        std::string info;
        krb_message(off, len, &l, &info);
        INFO(info);  // UDP: the Info column is ours alone
        return true;
    }

    // Over TCP each message has a 4-byte length (RFC 4120 7.2.2) and may span segments.
    void kerberos_tcp(size_t off, size_t len) {
        set_proto("KRB5");
        col_clear();
        size_t pos = 0;
        while (pos < len) {
            size_t rem = len - pos;
            if (rem < 4) {
                if (can_desegment_) deseg_ = {pos, kOneMore};
                return;
            }
            size_t plen = 4 + static_cast<size_t>(b_.u32(off + pos) & 0x7fffffffu);
            if (rem < plen && can_desegment_) {
                deseg_ = {pos, static_cast<uint32_t>(std::min<size_t>(plen - rem, 0x0FFFFFFDu))};
                return;
            }
            Layer& l = layer("Kerberos", off + pos, std::min(plen, rem));
            FIELD(l, "Record mark", fmt("%zu bytes", plen - 4), off + pos, 4);
            fproto("kerberos", off + pos, std::min(plen, rem));
            std::string info;
            if (plen == 4) expert("ber.error", 2, "Malformed", "KRB5", "BER Error: Empty choice was found");
            else if (krb_message(off + pos + 4, std::min(plen, rem) - 4, &l, &info)) col_append_sep(info);
            pos += plen;
        }
    }

    // ------------------------------------------- Kerberos in GSS-API tokens
    // The AP-REQ / AP-REP / KRB-ERROR a raw krb5 GSS token (or one inside SPNEGO)
    // carries: LDAP SASL binds, SMB session setups, DCE/RPC authentication.
    // A GSS-API security blob: which of Wireshark's layers it has, and any Kerberos in it.
    void gss_blob(size_t off, size_t len, Layer& l, bool gss_layer = true) {
        if (!len || !b_.have(off, len)) return;
        static const uint8_t spnego_oid[] = {0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
        uint8_t b0 = b_.u8(off);
        bool spnego = b0 == 0xa1 || (b0 == 0x60 && std::search(b_.p + off, b_.p + off + std::min<size_t>(len, 16),
                                                               spnego_oid, spnego_oid + sizeof spnego_oid) !=
                                                       b_.p + off + std::min<size_t>(len, 16));
        if (gss_layer) fproto("gss-api", off, len);
        if (!spnego) return gss_krb5(off, len, l);
        fproto("spnego", off, len);
        size_t tok = 0, tlen = 0;
        if (!spnego_token(off, len, tok, tlen)) return;
        if (b_.u8(tok) == 0x60) gss_krb5(tok, tlen, l);
        else gss_raw_krb5(tok, tlen, l);  // DCE-style Kerberos: no GSS-API header
    }

    // SPNEGO's mechanism token: negTokenInit's mechToken or negTokenResp's responseToken.
    bool spnego_token(size_t off, size_t len, size_t& tok, size_t& tlen) const {
        Tlv t, seq, inner;
        size_t end = off + len;
        if (!tlv(off, end, t)) return false;
        if (t.tag == 0x60) {  // GSS-API header: the SPNEGO OID, then [0] NegTokenInit
            Tlv oid, init;
            if (!tlv_in(t, oid) || oid.tag != 0x06 || !tlv(oid.next, t.next, init) || init.tag != 0xa0 ||
                !tlv_in(init, seq) || seq.tag != 0x30)
                return false;
        } else if (t.tag != 0xa1 || !tlv_in(t, seq) || seq.tag != 0x30) {
            return false;
        }
        for (size_t at = seq.off; tlv(at, seq.next, inner); at = inner.next) {
            Tlv os;
            if (inner.tag == 0xa2 && tlv_in(inner, os) && os.tag == 0x04 && os.len) {
                tok = os.off;
                tlen = os.len;
                return true;
            }
        }
        return false;
    }

    // Kerberos SSP in DCE/RPC: a bare AP-REQ / AP-REP, no GSS-API header.
    bool gss_raw_krb5(size_t off, size_t len, Layer& l) {
        if (!b_.have(off, 1) || (b_.u8(off) != 0x6e && b_.u8(off) != 0x6f && b_.u8(off) != 0x7e)) return false;
        if (!krb_message(off, len, &l, nullptr)) return false;
        fproto("kerberos", off, len);
        return true;
    }

    void gss_krb5(size_t off, size_t len, Layer& l) {
        static const uint8_t oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02};
        if (!b_.have(off, len) || len < sizeof oid + 4) return;
        const uint8_t* p = b_.p + off;
        const uint8_t* e = p + len;
        for (const uint8_t* hit = std::search(p, e, oid, oid + sizeof oid); hit != e;
             hit = std::search(hit + 1, e, oid, oid + sizeof oid)) {
            const uint8_t* tok = hit + sizeof oid;
            if (tok + 3 > e) break;
            uint16_t id = static_cast<uint16_t>((tok[0] << 8) | tok[1]);
            if (id != 0x0100 && id != 0x0200 && id != 0x0300) continue;  // AP-REQ, AP-REP, KRB-ERROR
            size_t at = off + static_cast<size_t>(tok + 2 - p);
            if (krb_message(at, off + len - at, &l, nullptr)) {
                fproto("kerberos", at, off + len - at);
                return;
            }
        }
    }

    // ---------------------------------------------------------- LDAP
    // Wireshark's dissect_ldap_tcp(): BER messages, or after a SASL bind 4-byte
    // length-prefixed buffers (GSS-API wrapped: encrypted, so only their size shows).
    static constexpr uint32_t kLdapSaslMax = 1024 * 1024;

    static const char* ldap_op_name(unsigned op) {
        static const char* names[26] = {"bindRequest", "bindResponse", "unbindRequest", "searchRequest",
                                        "searchResEntry", "searchResDone", "modifyRequest", "modifyResponse",
                                        "addRequest", "addResponse", "delRequest", "delResponse", "modDNRequest",
                                        "modDNResponse", "compareRequest", "compareResponse", "abandonRequest",
                                        nullptr, nullptr, "searchResRef", nullptr, nullptr, nullptr, "extendedReq",
                                        "extendedResp", "intermediateResponse"};
        return op < 26 ? names[op] : nullptr;
    }
    static std::string ldap_result_name(unsigned r) {
        switch (r) {
            case 0: return "success"; case 1: return "operationsError"; case 2: return "protocolError";
            case 3: return "timeLimitExceeded"; case 4: return "sizeLimitExceeded"; case 5: return "compareFalse";
            case 6: return "compareTrue"; case 7: return "authMethodNotSupported"; case 8: return "strongAuthRequired";
            case 10: return "referral"; case 11: return "adminLimitExceeded";
            case 12: return "unavailableCriticalExtension"; case 13: return "confidentialityRequired";
            case 14: return "saslBindInProgress"; case 16: return "noSuchAttribute";
            case 17: return "undefinedAttributeType"; case 18: return "inappropriateMatching";
            case 19: return "constraintViolation"; case 20: return "attributeOrValueExists";
            case 21: return "invalidAttributeSyntax"; case 32: return "noSuchObject"; case 33: return "aliasProblem";
            case 34: return "invalidDNSyntax"; case 36: return "aliasDereferencingProblem";
            case 48: return "inappropriateAuthentication"; case 49: return "invalidCredentials";
            case 50: return "insufficientAccessRights"; case 51: return "busy"; case 52: return "unavailable";
            case 53: return "unwillingToPerform"; case 54: return "loopDetect"; case 64: return "namingViolation";
            case 65: return "objectClassViolation"; case 66: return "notAllowedOnNonLeaf";
            case 67: return "notAllowedOnRDN"; case 68: return "entryAlreadyExists";
            case 69: return "objectClassModsProhibited"; case 71: return "affectsMultipleDSAs"; case 80: return "other";
            case 118: return "canceled"; case 119: return "noSuchOperation"; case 120: return "tooLate";
            case 121: return "cannotCancel";
            default: return fmt("Unknown result(%u)", r);
        }
    }
    static std::string ldap_oid_name(const std::string& oid) {
        if (oid == "1.3.6.1.4.1.1466.20037") return "LDAP_START_TLS_OID";
        return oid;
    }
    // LDAP strings are UTF-8: keep them, but not control characters.
    std::string ldap_text(const Tlv& t) const {
        std::string s;
        for (size_t i = 0; i < t.len && s.size() < 4096; ++i) {
            unsigned char ch = b_.u8(t.off + i);
            s.push_back(ch < 0x20 || ch == 0x7f ? '.' : static_cast<char>(ch));
        }
        return s;
    }
    uint64_t ber_uint(const Tlv& t) const {
        uint64_t v = 0;
        for (size_t i = 0; i < t.len && i < 8; ++i) v = (v << 8) | b_.u8(t.off + i);
        return v;
    }

    // Wireshark counts a conversation's search entries on its first pass and
    // shows that total with every searchResDone.
    void ldap_count_entry(size_t key) {
        if (st_.use) return;
        if (st_.ldap_results.size() > 100'000) st_.ldap_results.clear();
        uint32_t n = ++st_.ldap_results[key];
        if (st_.record) st_.record->ldap_results[key] = n;
    }
    uint32_t ldap_entries(size_t key) const {
        const auto& m = st_.use ? st_.use->ldap_results : st_.ldap_results;
        auto it = m.find(key);
        return it == m.end() ? 0 : it->second;
    }

    void ldap_tcp(InspectorState::Conv& c, int di, size_t off, size_t len) {
        if (c.ldap_tls_from && frame_ >= c.ldap_tls_from) {  // after StartTLS
            tls_dissect(c, di, off, len);
            return;
        }
        bool sasl = c.ldap_sasl && c.ldap_sasl_from && frame_ >= c.ldap_sasl_from;
        uint32_t sasl_len = len >= 4 ? b_.u32(off) : 0;
        if (sasl && len >= 4 && sasl_len >= 2 && sasl_len <= kLdapSaslMax) return ldap_pdus(c, off, len, true);
        size_t blen = 0, used = 0;
        if (b_.u8(off) == 0x30 && der_length(b_.p + off + 1, len - 1, blen, used) && blen >= 2)
            return ldap_pdus(c, off, len, false);
        if (sasl && len >= 4 && static_cast<size_t>(sasl_len) + 4 == len) ldap_pdus(c, off, len, true);
    }

    // tcp_dissect_pdus() over LDAP messages or SASL buffers.
    void ldap_pdus(InspectorState::Conv& c, size_t off, size_t len, bool sasl) {
        size_t fixed = sasl ? 4 : 5, pos = 0;
        while (pos < len) {
            size_t rem = len - pos;
            if (rem < fixed) {
                if (can_desegment_) deseg_ = {pos, kOneMore};
                return;
            }
            size_t plen = 0;
            if (sasl) {
                plen = 4 + static_cast<size_t>(b_.u32(off + pos));
            } else {
                size_t blen = 0, used = 0;
                if (!der_length(b_.p + off + pos + 1, rem - 1, blen, used)) {
                    if (can_desegment_) deseg_ = {pos, kOneMore};
                    return;
                }
                plen = 1 + used + blen;
            }
            if (rem < plen && can_desegment_) {
                deseg_ = {pos, static_cast<uint32_t>(std::min<size_t>(plen - rem, 0x0FFFFFFDu))};
                return;
            }
            size_t take = std::min(plen, rem);
            if (sasl) ldap_sasl_pdu(c, off + pos, take);
            else ldap_pdu(&c, off + pos, take, false);
            pos += plen;
        }
    }

    void ldap_pdu_start(bool cldap) {
        set_proto(cldap ? "CLDAP" : "LDAP");
        if (ldap_in_frame_) {
            col_append(" | ");
            col_set_fence();
        } else {
            col_clear();
            ldap_in_frame_ = true;
        }
    }

    bool cldap(size_t off, size_t len) {
        if (len < 6 || !b_.have(off, len) || b_.u8(off) != 0x30) return false;
        std::string saved = std::move(col_);  // UDP decoders set the Info column directly
        size_t saved_fence = fence_;
        col_.clear();
        fence_ = 0;
        ldap_pdu(nullptr, off, len, true);
        if (full_) d_.info = col_;
        col_ = std::move(saved);
        fence_ = saved_fence;
        return true;
    }

    // One PDU: LDAPMessages back to back (Wireshark's dissect_ldap_payload).
    void ldap_pdu(InspectorState::Conv* c, size_t off, size_t len, bool cldap) {
        ldap_pdu_start(cldap);
        Layer& l = layer(cldap ? "Connectionless Lightweight Directory Access Protocol"
                               : "Lightweight Directory Access Protocol", off, len);
        fproto(cldap ? "cldap" : "ldap", off, len);
        size_t pos = 0;
        while (len - pos >= 6) {
            Tlv m;
            if (!tlv(off + pos, off + len, m) || m.tag != 0x30) {
                d_.malformed = true;
                break;
            }
            std::string info;
            if (ldap_message(c, m, l, info, cldap)) col_append(info);
            pos = m.next - off;
        }
    }

    bool ldap_message(InspectorState::Conv* c, const Tlv& m, Layer& l, std::string& info, bool cldap) {
        Tlv id, op;
        if (!tlv_in(m, id) || id.tag != 0x02 || !tlv(id.next, m.next, op) || (op.tag & 0xC0) != 0x40) return false;
        uint64_t msgid = ber_uint(id);
        unsigned opn = op.tag & 0x1F;
        size_t conv = FlowKeyHash()(l4_key_);
        FF(uint("ldap.messageID", msgid));
        FF(uint("ldap.protocolOp", opn));
        std::string text;
        Tlv a, b, x;
        bool constructed = op.tag & 0x20;
        auto dn = [&](const Tlv& t) { return "\"" + (t.len ? ldap_text(t) : std::string("<ROOT>")) + "\" "; };
        auto result = [&](const Tlv& code) {  // LDAPResult: resultCode, matchedDN, errorMessage
            unsigned r = static_cast<unsigned>(ber_uint(code));
            FF(uint(opn == 1 ? "ldap.bindResponse_resultCode" : "ldap.resultCode", r));
            std::string s = ldap_result_name(r);
            Tlv md, em;
            if (tlv(code.next, op.next, md) && tlv(md.next, op.next, em) && em.len) {
                FF(string("ldap.errorMessage", ldap_text(em)));
                s += " (" + ldap_text(em) + ")";
            }
            return s + " ";
        };
        bool first = constructed && tlv_in(op, a);
        switch (opn) {
            case 0:  // bindRequest: version, name, authentication
                if (first && tlv(a.next, op.next, b)) {
                    FF(string("ldap.name", ldap_text(b)));
                    text = dn(b);
                    if (tlv(b.next, op.next, x)) {
                        unsigned at = x.tag & 0x1F;
                        text += at == 0 ? "simple " : at == 3 ? "sasl " : at == 10 ? "ntlmsspNegotiate "
                              : at == 11 ? "ntlmsspAuth " : "";
                        Tlv mech, cred;
                        if (at == 3 && (x.tag & 0x20) && tlv_in(x, mech)) {
                            std::string mn = ldap_text(mech);
                            FF(string("ldap.mechanism", mn));
                            if (c) c->ldap_sasl = mn == "GSS-SPNEGO" || mn == "GSSAPI" ? 1 : 2;
                            if (tlv(mech.next, x.next, cred)) gss_blob(cred.off, cred.len, l, b_.u8(cred.off) == 0x60);
                        }
                    }
                }
                break;
            case 1:  // bindResponse: a successful SASL bind wraps what follows
                if (first) {
                    text = result(a);
                    if (c && c->ldap_sasl && ber_uint(a) == 0) c->ldap_sasl_from = frame_ + 1;
                    for (size_t at = a.next; tlv(at, op.next, x); at = x.next)
                        if (x.tag == 0x87) gss_blob(x.off, x.len, l, b_.u8(x.off) == 0x60);  // serverSaslCreds
                }
                break;
            case 3:  // searchRequest: baseObject, scope
                if (first && tlv(a.next, op.next, b)) {
                    FF(string("ldap.baseObject", ldap_text(a)));
                    unsigned sc = static_cast<unsigned>(ber_uint(b));
                    FF(uint("ldap.scope", sc));
                    text = dn(a) + (sc == 0 ? "baseObject" : sc == 1 ? "singleLevel" : sc == 2 ? "wholeSubtree"
                                                                                             : fmt("%u", sc)) + " ";
                }
                break;
            case 4:  // searchResEntry: objectName, attributes
                if (first) {
                    FF(string("ldap.objectName", ldap_text(a)));
                    text = dn(a);
                    if (cldap && tlv(a.next, op.next, b)) ldap_netlogon(b, l);
                }
                ldap_count_entry(conv);
                break;
            case 5:
                if (first) {
                    uint32_t n = ldap_entries(conv);
                    text = result(a) + fmt(" [%u result%s]", n, n == 1 ? "" : "s");
                }
                break;
            case 6: case 8: case 12: case 14:  // requests that name an entry
                if (first) text = dn(a);
                break;
            case 10:  // delRequest: the DN itself
                if (!constructed) text = dn(op);
                break;
            case 7: case 9: case 11: case 13: case 15:
                if (first) text = result(a);
                break;
            case 16:  // abandonRequest: Wireshark shows the abandoned message's ID
                if (!constructed) msgid = ber_uint(op);
                break;
            case 23:  // extendedReq: requestName [0]
                if (first && a.tag == 0x80) {
                    std::string oid = text_line(b_.p + a.off, a.len);
                    FF(string("ldap.requestName", oid));
                    text = ldap_oid_name(oid) + " ";
                    if (c && oid == "1.3.6.1.4.1.1466.20037") c->ldap_starttls = true;
                }
                break;
            case 24:  // extendedResp: LDAPResult's parts, then responseName [10]
                if (first) {
                    unsigned r = static_cast<unsigned>(ber_uint(a));
                    FF(uint("ldap.extendedResponse_resultCode", r));
                    for (size_t at = a.next; tlv(at, op.next, x); at = x.next) {
                        if (x.tag != 0x8A) continue;
                        std::string oid = text_line(b_.p + x.off, x.len);
                        FF(string("ldap.responseName", oid));
                        text = ldap_oid_name(oid) + " ";
                    }
                    if (c && c->ldap_starttls) {
                        c->ldap_starttls = false;
                        if (r == 0) c->ldap_tls_from = frame_ + 1;
                    }
                }
                break;
            default: break;
        }
        const char* name = ldap_op_name(opn);
        std::string head = name ? fmt("%s(%llu) ", name, static_cast<unsigned long long>(msgid))
                                : fmt("Unknown (%u)(%llu) ", opn, static_cast<unsigned long long>(msgid));
        FIELD(l, "LDAPMessage", head + text, m.off, m.len);
        info = head + text;
        return true;
    }

    // A domain controller's "Netlogon" attribute in a CLDAP ping reply
    // (MS-ADTS NETLOGON_SAM_LOGON_RESPONSE_EX): who and where the DC is.
    void ldap_netlogon(const Tlv& attrs, Layer& l) {
        Tlv item, type, vals, val;
        for (size_t at = attrs.off; tlv(at, attrs.next, item); at = item.next) {
            if (!tlv_in(item, type) || !tlv(type.next, item.next, vals) || !tlv_in(vals, val)) continue;
            std::string t = ldap_text(type);
            for (auto& ch : t) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            if (t != "netlogon" || val.len < 24) continue;
            const uint8_t* p = b_.p + val.off;
            uint16_t opcode = static_cast<uint16_t>(p[0] | (p[1] << 8));
            FF(uint("mscldap.netlogon.opcode", opcode));
            if (opcode < 23 || opcode > 25) continue;
            FF(uint("mscldap.netlogon.flags", static_cast<uint32_t>(p[4] | (p[5] << 8) | (p[6] << 16) |
                                                                      (static_cast<uint32_t>(p[7]) << 24))));
            static const std::pair<const char*, const char*> names[] = {
                {"mscldap.forest", "Forest"}, {"mscldap.domain", "Domain"}, {"mscldap.hostname", "Hostname"},
                {"mscldap.nb_domain", "NetBIOS Domain"}, {"mscldap.nb_hostname", "NetBIOS Hostname"},
                {"mscldap.username", "Username"}, {"mscldap.sitename", "Server Site"},
                {"mscldap.clientsitename", "Client Site"}};
            size_t pos = 24;
            for (const auto& nm : names) {
                std::string v;
                size_t next = 0;
                if (!read_dns_name(p, val.len, pos, v, next)) break;
                if (v.empty()) v = "<Root>";
                FF(string(nm.first, v));
                FIELD(l, nm.second, v, val.off + pos, next - pos);
                pos = next;
            }
        }
    }

    // A SASL buffer: GSS-API wrapped, so encrypted unless the token says otherwise.
    void ldap_sasl_pdu(InspectorState::Conv& c, size_t off, size_t len) {
        ldap_pdu_start(false);
        Layer& l = layer("Lightweight Directory Access Protocol", off, len);
        fproto("ldap", off, len);
        uint32_t sasl_len = b_.u32(off);
        FF(uint("ldap.sasl_buffer_length", sasl_len));
        FIELD(l, "SASL Buffer Length", fmt("%u", sasl_len), off, 4);
        if (c.ldap_sasl != 1) return;  // other mechanisms: Wireshark leaves Info empty
        size_t t = off + 4, tl = std::min<size_t>(sasl_len, len - 4);
        fproto("gss-api", t, tl);
        if (tl >= 16 && b_.u8(t) == 0x05 && b_.u8(t + 1) == 0x04) {  // RFC 4121 wrap token
            if (b_.u8(t + 2) & 0x02) {
                long n = static_cast<long>(sasl_len) - 60 - b_.u16(t + 4);  // header, confounder, checksum; filler
                col_set(fmt("SASL GSS-API Privacy: payload (%ld byte%s)", n, n == 1 ? "" : "s"));
            } else {
                col_set("SASL GSS-API Integrity: ");
            }
        } else if (tl >= 2 && b_.u8(t) == 0x60) {  // RFC 1964 token
            col_set("SASL GSS-API Integrity: ");
        }
    }

    // ------------------------------------------- NetBIOS session service, SMB
    std::string utf16le(size_t off, size_t len) const {
        std::string out;
        if (!b_.have(off, len)) len = off < b_.n ? b_.n - off : 0;
        for (size_t i = 0; i + 1 < len && out.size() < 4096; i += 2) {
            uint32_t cp = b_.le16(off + i);
            if (cp == 0) break;
            if (cp >= 0xD800 && cp < 0xE000) {  // a surrogate pair, or U+FFFD for a stray half
                uint32_t lo = cp < 0xDC00 && i + 3 < len ? b_.le16(off + i + 2) : 0;
                if (lo >= 0xDC00 && lo < 0xE000) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    i += 2;
                } else {
                    cp = 0xFFFD;
                }
            }
            if (cp < 0x20) out.push_back('.');
            else if (cp < 0x80) out.push_back(static_cast<char>(cp));
            else if (cp < 0x800) {
                out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            } else if (cp < 0x10000) {
                out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            } else {
                out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            }
        }
        return out;
    }
    std::string raw_key(size_t off, size_t len) const {
        return b_.have(off, len) ? std::string(reinterpret_cast<const char*>(b_.p + off), len) : std::string();
    }

    // Wireshark's dissect_nbss(): messages with a 4-byte header (on 445 a 24-bit
    // length), each handed to SMB; a later message's Info replaces an earlier one's.
    void nbss_tcp(InspectorState::Conv& c, int di, size_t off, size_t len) {
        bool cifs = sport_ == 445 || dport_ == 445;
        set_proto("NBSS");
        size_t pos = 0;
        while (pos < len) {
            size_t rem = len - pos;
            if (rem < 4) {
                if (can_desegment_) deseg_ = {pos, kOneMore};
                return;
            }
            uint8_t type = b_.u8(off + pos), flags = cifs ? 0 : b_.u8(off + pos + 1);
            size_t mlen = cifs ? (static_cast<size_t>(b_.u8(off + pos + 1)) << 16) | b_.u16(off + pos + 2)
                               : b_.u16(off + pos + 2) + ((flags & 1) ? 0x10000u : 0u);
            bool ok = (flags & ~1) == 0;
            switch (type) {
                case 0x00: ok = ok && mlen != 0; break;
                case 0x81: ok = ok && mlen >= 2 && mlen <= 256; break;
                case 0x82: case 0x85: ok = ok && mlen == 0; break;
                case 0x83: ok = ok && mlen == 1; break;
                case 0x84: ok = ok && mlen == 6; break;
                default: ok = false;
            }
            if (!ok) {
                if (pos == 0) {
                    col_set("NBSS Continuation Message");
                    fproto("nbss", off, len);
                }
                return;
            }
            static const char* names[] = {"Session message", "Session request", "Positive session response",
                                          "Negative session response", "Retarget session response",
                                          "Session keep-alive"};
            set_proto("NBSS");
            col_set(names[type ? type - 0x80 : 0]);  // before asking for the rest of a split message
            size_t plen = 4 + mlen;
            if (rem < plen && can_desegment_) {
                deseg_ = {pos, static_cast<uint32_t>(plen - rem)};
                return;
            }
            size_t take = std::min(plen, rem);
            fproto("nbss", off + pos, take);
            FF(uint("nbss.type", type));
            FF(uint("nbss.length", mlen));
            Layer& l = layer("NetBIOS Session Service", off + pos, take);
            FIELD(l, "Message Type", fmt("0x%02x", type), off + pos, 1);
            FIELD(l, "Length", fmt("%zu", mlen), off + pos + 1, 3);
            if (type != 0x00) {
                // the message type is all the Info there is
            } else if (take >= 8 && b_.u8(off + pos + 5) == 'S' && b_.u8(off + pos + 6) == 'M' &&
                       b_.u8(off + pos + 7) == 'B') {
                uint8_t m = b_.u8(off + pos + 4);
                if (m == 0xFE) smb2(c, di, off + pos + 4, take - 4);
                else if (m == 0xFD) smb2_transform(off + pos + 4, take - 4);
                else if (m == 0xFF) smb1(off + pos + 4, take - 4);
                else col_set("Session message");
            } else {
                col_set("Session message");
            }
            pos += plen;
        }
    }

    void smb2_transform(size_t off, size_t len) {
        set_proto("SMB2");
        col_clear();
        fproto("smb2", off, len);
        layer("SMB2 (Server Message Block Protocol version 2)", off, len);
        col_append("Encrypted SMB3");
    }

    void smb1(size_t off, size_t len) {
        set_proto("SMB");
        col_clear();
        fproto("smb", off, len);
        if (len < 32) return;
        uint8_t cmd = b_.u8(off + 4), flags = b_.u8(off + 9);
        uint32_t status = b_.le32(off + 5);
        uint16_t flags2 = b_.le16(off + 10);
        bool resp = flags & 0x80;
        Layer& l = layer("SMB (Server Message Block Protocol)", off, len);
        FF(uint("smb.cmd", cmd));
        const char* name = lookup_name(kSmb1Cmd, cmd);
        std::string info = (name ? std::string(name) : fmt("unknown-0x%02X", cmd)) + (resp ? " Response" : " Request");
        if (resp && status) {
            if (flags2 & 0x4000) info += ", Error: " + nt_status_name(status);
            else info += ", Error: Unknown error class!";  // DOS error codes: Wireshark's own wording for most
        }
        FIELD(l, "Command", info, off + 4, 1);
        col_append(info);
    }

    // NTLMSSP inside a security blob (SPNEGO or bare): what Wireshark appends.
    std::string ntlmssp_info(size_t off, size_t len) {
        static const char sig[] = "NTLMSSP";
        if (!b_.have(off, len) || len < 12) return "";
        const uint8_t* p = b_.p + off;
        const uint8_t* hit = std::search(p, p + len, sig, sig + 8);
        if (hit == p + len || hit + 12 > p + len) return "";
        size_t m = off + static_cast<size_t>(hit - p), end = off + len;
        uint32_t type = b_.le32(m + 8);
        fproto("ntlmssp", m, end - m);
        FF(uint("ntlmssp.messagetype", type));
        if (type == 1) return "NTLMSSP_NEGOTIATE";
        if (type == 2) return "NTLMSSP_CHALLENGE";
        if (type != 3) return "";
        auto buffer = [&](size_t at, size_t& boff, size_t& blen) {
            if (m + at + 8 > end) return false;
            blen = b_.le16(m + at);
            boff = m + b_.le32(m + at + 4);
            return boff <= end && blen <= end - boff;
        };
        uint32_t flags = m + 64 <= end ? b_.le32(m + 60) : 1;
        auto text = [&](size_t at) {
            size_t bo = 0, bl = 0;
            if (!buffer(at, bo, bl)) return std::string();
            return (flags & 1) ? utf16le(bo, bl) : text_line(b_.p + bo, bl);
        };
        std::string domain = text(28), user = text(36), host = text(44);
        FF(string("ntlmssp.auth.domain", domain));
        FF(string("ntlmssp.auth.username", user));
        FF(string("ntlmssp.auth.hostname", host));
        return "NTLMSSP_AUTH, User: " + domain + "\\" + user;
    }

    static std::string smb2_level_name(uint8_t cls, uint8_t level) {
        const char* c = cls == 1 ? "FILE_INFO" : cls == 2 ? "FS_INFO" : cls == 3 ? "SEC_INFO" : cls == 4 ? "QUOTA_INFO"
                                                                                                            : nullptr;
        const char* l = cls == 1 ? lookup_name(kSmb2FileInfo, level)
                      : cls == 2 ? lookup_name(kSmb2FsInfo, level)
                      : cls == 3 && level == 0 ? "SMB2_SEC_INFO_00"
                                               : nullptr;
        return (c ? std::string(c) : fmt("(Class:0x%02X)", cls)) + "/" + (l ? std::string(l) : fmt("(Level:0x%02X)", level));
    }

    // One SMB2 message chain (compounded requests or responses joined by "; ").
    void smb2(InspectorState::Conv& c, int di, size_t off, size_t len) {
        set_proto("SMB2");
        col_clear();
        fproto("smb2", off, len);
        if (st_.smb_requests.size() > 200'000) st_.smb_requests.clear();
        if (st_.smb_files.size() > 200'000) st_.smb_files.clear();
        size_t pos = 0;
        for (int n = 0; n < 64 && pos + 64 <= len; ++n) {
            size_t h = off + pos;
            if (!b_.have(h, 64) || b_.u32(h) != 0xFE534D42u) break;
            size_t mlen = len - pos;
            uint32_t next = b_.le32(h + 20);
            if (next && next < mlen) mlen = next;
            if (n) col_append("; ");
            smb2_message(c, di, h, mlen);
            if (!next || next < 64) break;
            pos += next;
        }
    }

    void smb2_message(InspectorState::Conv& c, int di, size_t h, size_t len) {
        uint32_t status = b_.le32(h + 8), flags = b_.le32(h + 16);
        uint16_t cmd = b_.le16(h + 12);
        uint64_t msgid = b_.le64(h + 24);
        uint32_t tid = b_.le32(h + 36);
        bool resp = flags & 1, async = flags & 2;
        std::string sess = raw_key(h + 40, 8);
        if (async) tid = 0;
        Layer& l = layer("SMB2 (Server Message Block Protocol version 2)", h, len);
        FF(uint("smb2.cmd", cmd));
        FF(boolean("smb2.flags.response", resp));
        FF(uint("smb2.msg_id", msgid));
        FF(uint("smb2.nt_status", status));
        if (!async) FF(uint("smb2.tid", tid));
        FF(uint("smb2.sesid", b_.le64(h + 40)));
        size_t body = h + 64, end = h + len;
        auto have = [&](size_t at, size_t n) { return at + n <= end && b_.have(at, n); };
        std::string tree_key = sess + raw_key(h + 36, 4);
        std::string req_key = std::to_string(FlowKeyHash()(l4_key_)) + "/" + std::to_string(msgid) + "/" + sess;
        auto fid_at = [&](size_t at) { return have(at, 16) ? raw_key(at, 16) : std::string(); };
        auto file_name = [&](const std::string& fid) -> const std::string* {
            if (fid.empty()) return nullptr;
            auto it = st_.smb_files.find(sess + fid);
            return it == st_.smb_files.end() ? nullptr : &it->second;
        };
        static const char* cmds[] = {"Negotiate Protocol", "Session Setup", "Session Logoff", "Tree Connect",
                                     "Tree Disconnect", "Create", "Close", "Flush", "Read", "Write", "Lock", "Ioctl",
                                     "Cancel", "KeepAlive", "Find", "Notify", "GetInfo", "SetInfo", "Break",
                                     "Server notification"};
        std::string info;
        if (cmd == 18) {  // oplock and lease breaks have names of their own
            bool lease = have(body, 2) && b_.le16(body) != 24;
            std::string kind = lease ? "Lease Break " : "Oplock Break ";
            info = kind + (!resp ? "Acknowledgment" : msgid == ~0ULL ? "Notification" : "Response");
        } else {
            info = (cmd < 20 ? std::string(cmds[cmd]) : fmt("unknown-0x%02X", cmd)) + (resp ? " Response" : " Request");
        }
        if (resp && status) info += ", Error: " + nt_status_name(status);
        InspectorState::SmbRequest* req = nullptr;
        if (resp) {
            auto it = st_.smb_requests.find(req_key);
            if (it != st_.smb_requests.end() && it->second.cmd == cmd) req = &it->second;
        }
        auto add_file = [&](const std::string& fid) {
            if (const std::string* nm = file_name(fid)) {
                info += ", File: " + *nm;
                FF(string("smb2.filename", *nm));
            }
        };
        // A response names its request's file (or tree) only in Wireshark's second pass.
        bool two_pass = st_.use != nullptr;
        auto add_req_file = [&](const std::string& fid) {
            if (two_pass) add_file(fid);
        };

        auto tree_of = [&]() -> InspectorState::SmbTree* {
            auto it = st_.smb_trees.find(tree_key);
            return it == st_.smb_trees.end() ? nullptr : &it->second;
        };
        auto pipe = [&]() {
            auto* t = tree_of();
            return t && t->type == 2;
        };
        std::string rpc_key = std::to_string(FlowKeyHash()(l4_key_)) + "/";
        bool ok = !status;
        if (!resp) {
            InspectorState::SmbRequest r;
            r.cmd = cmd;
            switch (cmd) {
                case 1:  // Session Setup: the security blob
                    if (have(body, 24)) {
                        std::string nt = ntlmssp_info(h + b_.le16(body + 12), b_.le16(body + 14));
                        if (!nt.empty()) info += ", " + nt;
                        gss_blob(h + b_.le16(body + 12), b_.le16(body + 14), l);
                    }
                    break;
                case 3:  // Tree Connect
                    if (have(body, 8)) {
                        r.name = utf16le(h + b_.le16(body + 4), b_.le16(body + 6));
                        FF(string("smb2.tree", r.name));
                        info += ", Tree: '" + r.name + "'";
                    }
                    break;
                case 4:
                    if (auto* t = tree_of()) info += ", Tree: '" + t->path + "'";
                    break;
                case 5:  // Create
                    if (have(body, 56)) {
                        r.name = utf16le(h + b_.le16(body + 44), b_.le16(body + 46));
                        FF(string("smb2.filename", r.name));
                        info += ", File: " + r.name;
                    }
                    break;
                case 6: case 7: case 10: case 15:  // Close, Flush, Lock, Notify
                    r.fid = fid_at(body + 8);
                    add_file(r.fid);
                    break;
                case 8:  // Read
                    if (have(body, 32)) {
                        uint32_t n = b_.le32(body + 4);
                        uint64_t at = b_.le64(body + 8);
                        FF(uint("smb2.read_length", n));
                        FF(uint("smb2.file_offset", at));
                        info += fmt(" Len:%u Off:%llu", n, static_cast<unsigned long long>(at));
                        r.fid = fid_at(body + 16);
                        add_file(r.fid);
                    }
                    break;
                case 9:  // Write: to a named pipe, DCE/RPC
                    if (have(body, 32)) {
                        uint32_t n = b_.le32(body + 4);
                        uint64_t at = b_.le64(body + 8);
                        FF(uint("smb2.write_length", n));
                        FF(uint("smb2.file_offset", at));
                        info += fmt(" Len:%u Off:%llu", n, static_cast<unsigned long long>(at));
                        r.fid = fid_at(body + 16);
                        add_file(r.fid);
                        size_t data = h + b_.le16(body + 2);
                        if (pipe() && data < end && have(data, std::min<size_t>(n, end - data)))
                            smb2_pipe(rpc_key + r.fid, data, std::min<size_t>(n, end - data), info);
                        else if (n && data < end)
                            fproto("data", data, std::min<size_t>(n, end - data));
                    }
                    break;
                case 11:  // Ioctl
                    if (have(body, 56)) {
                        uint32_t code = b_.le32(body + 4);
                        FF(uint("smb2.ioctl.function", code));
                        const char* fn = lookup_name(kFsctl, code);
                        info += " " + (fn ? std::string(fn) : fmt("0x%08x", code));
                        r.fid = fid_at(body + 8);
                        size_t in = h + b_.le32(body + 24), in_len = b_.le32(body + 28);
                        if (code == 0x00060194 && in_len >= 2 && in < end)  // FSCTL_DFS_GET_REFERRALS
                            info += ", Path: " + utf16le(in + 2, std::min<size_t>(in_len - 2, end - in - 2));
                        if (code == 0x0011C017 && pipe() && in_len && in < end)  // FSCTL_PIPE_TRANSCEIVE
                            smb2_pipe(rpc_key + r.fid, in, std::min<size_t>(in_len, end - in), info);
                    }
                    break;
                case 14:  // Find
                    if (have(body, 32)) {
                        r.level = b_.u8(body + 2);
                        r.fid = fid_at(body + 8);
                        r.pattern = utf16le(h + b_.le16(body + 24), b_.le16(body + 26));
                        add_file(r.fid);
                        const char* lv = lookup_name(kSmb2FindLevel, r.level);
                        info += ", " + (lv ? std::string(lv) : fmt("(Level:0x%02X)", r.level)) + ", Pattern: " + r.pattern;
                    }
                    break;
                case 16:  // GetInfo
                    if (have(body, 40)) {
                        r.cls = b_.u8(body + 2);
                        r.level = b_.u8(body + 3);
                        info += " " + smb2_level_name(r.cls, r.level);
                        r.fid = fid_at(body + 24);
                        add_file(r.fid);
                    }
                    break;
                case 17:  // SetInfo: the class and level, a rename's new name; Wireshark names the file in the response
                    if (have(body, 32)) {
                        r.cls = b_.u8(body + 2);
                        r.level = b_.u8(body + 3);
                        info += " " + smb2_level_name(r.cls, r.level);
                        r.fid = fid_at(body + 16);
                        size_t buf = h + b_.le16(body + 8), blen = b_.le32(body + 4);
                        if (r.cls == 1 && r.level == 10 && blen >= 20 && have(buf, 20))
                            info += " NewName:" + utf16le(buf + 20, std::min<size_t>(b_.le32(buf + 16), end - buf - 20));
                    }
                    break;
                default: break;
            }
            if (cmd != 12 && cmd != 13) st_.smb_requests[req_key] = r;
        } else {
            switch (cmd) {
                case 0:  // Negotiate: the server's SPNEGO hint
                    if (ok && have(body, 64)) gss_blob(h + b_.le16(body + 56), b_.le16(body + 58), l);
                    break;
                case 1:
                    if ((ok || status == 0xC0000016) && have(body, 8)) {
                        std::string nt = ntlmssp_info(h + b_.le16(body + 4), b_.le16(body + 6));
                        if (!nt.empty()) info += ", " + nt;
                        gss_blob(h + b_.le16(body + 4), b_.le16(body + 6), l);
                    }
                    break;
                case 3:
                    if (ok && req && have(body, 4)) {
                        st_.smb_trees[tree_key] = {req->name, b_.u8(body + 2)};
                        if (two_pass) info += ", Tree: '" + req->name + "'";
                    }
                    break;
                case 4:
                    if (ok)
                        if (auto* t = tree_of()) info += ", Tree: '" + t->path + "'";
                    break;
                case 5:
                    if (ok && req && have(body, 80)) {
                        std::string fid = raw_key(body + 64, 16);
                        st_.smb_files[sess + fid] = req->name;
                        info += ", File: " + req->name;
                        FF(string("smb2.filename", req->name));
                    }
                    break;
                case 6: case 7: case 9: case 10: case 15:
                    if (ok && req) add_req_file(req->fid);
                    break;
                case 8:  // Read: from a named pipe, DCE/RPC
                    if ((ok || status == 0x80000005) && req) {
                        add_req_file(req->fid);
                        if (have(body, 16)) {
                            size_t data = h + b_.u8(body + 2), n = b_.le32(body + 4);
                            if (pipe() && data < end)
                                smb2_pipe(rpc_key + req->fid, data, std::min<size_t>(n, end - data), info);
                            else if (n && data < end)
                                fproto("data", data, std::min<size_t>(n, end - data));
                        }
                    }
                    break;
                case 11:
                    if ((ok || status == 0x80000005) && have(body, 48)) {
                        uint32_t code = b_.le32(body + 4);
                        FF(uint("smb2.ioctl.function", code));
                        const char* fn = lookup_name(kFsctl, code);
                        info += " " + (fn ? std::string(fn) : fmt("0x%08x", code));
                        size_t out = h + b_.le32(body + 32), out_len = b_.le32(body + 36);
                        if (code == 0x0011C017 && pipe() && out_len && out < end)
                            smb2_pipe(rpc_key + fid_at(body + 8), out, std::min<size_t>(out_len, end - out), info);
                    }
                    break;
                case 14:
                    if (req) {
                        add_req_file(req->fid);
                        const char* lv = lookup_name(kSmb2FindLevel, req->level);
                        info += ", " + (lv ? std::string(lv) : fmt("(Level:0x%02X)", req->level)) + ", Pattern: " +
                                req->pattern;
                        if (ok && have(body, 8)) {  // the entries, chained by NextEntryOffset
                            size_t at = h + b_.le16(body + 2), blen = b_.le32(body + 4), stop = std::min(at + blen, end);
                            unsigned n = 0;
                            while (at + 4 <= stop && b_.have(at, 4) && n < 100000) {
                                ++n;
                                uint32_t next = b_.le32(at);
                                if (!next) break;
                                at += next;
                            }
                            if (n) info += fmt(", %u match%s", n, n == 1 ? "" : "es");
                        }
                    }
                    break;
                case 16:
                    if ((ok || status == 0x80000005) && req) add_req_file(req->fid);
                    break;
                case 17:
                    if (req) add_req_file(req->fid);
                    break;
                default: break;
            }
        }
        if (auto* t = tree_of()) FF(string("smb2.tree", t->path));
        FIELD(l, "Command", info, h + 12, 2);
        col_append(info);
        (void)c;
        (void)di;
    }

    // DCE/RPC in data written to or read from a named pipe: its Info replaces SMB2's.
    void smb2_pipe(const std::string& key, size_t off, size_t len, std::string& info) {
        if (!dcerpc_header_ok(off, len)) return;
        std::string saved = std::move(col_);
        size_t saved_fence = fence_;
        col_.clear();
        fence_ = 0;
        rpc_ctx_ = 0;
        for (size_t pos = 0; pos + 16 <= len;) {
            size_t flen = dcerpc_frag_len(off + pos);
            dcerpc_pdu(key, off + pos, std::min(flen, len - pos));
            pos += flen;
        }
        info = col_;
        col_ = std::move(saved);
        fence_ = saved_fence;
    }

    // ------------------------------------------------------ DCE/RPC
    bool dcerpc_header_ok(size_t off, size_t len) const {
        if (len < 16 || !b_.have(off, 16)) return false;
        uint8_t minor = b_.u8(off + 1), ptype = b_.u8(off + 2);
        return b_.u8(off) == 5 && minor <= 1 && ptype <= 20 && dcerpc_frag_len(off) >= 16;
    }
    size_t dcerpc_frag_len(size_t off) const {
        bool little = b_.u8(off + 4) & 0x10;
        return little ? b_.le16(off + 8) : b_.u16(off + 8);
    }
    bool dcerpc_heuristic(size_t off, size_t len) const { return dcerpc_header_ok(off, len); }

    void dcerpc_tcp(size_t off, size_t len) {
        std::string key = std::to_string(FlowKeyHash()(l4_key_)) + "/tcp";
        size_t pos = 0;
        while (pos < len) {
            size_t rem = len - pos;
            if (rem < 16) {
                if (can_desegment_) deseg_ = {pos, kOneMore};
                return;
            }
            if (!dcerpc_header_ok(off + pos, rem)) {
                if (pos == 0) return;
                break;
            }
            size_t flen = dcerpc_frag_len(off + pos);
            if (rem < flen && can_desegment_) {
                deseg_ = {pos, static_cast<uint32_t>(flen - rem)};
                return;
            }
            dcerpc_pdu(key, off + pos, std::min(flen, rem));
            pos += flen;
        }
    }

    std::string uuid_at(size_t at, bool little) const {
        if (!b_.have(at, 16)) return "";
        uint32_t a = little ? b_.le32(at) : b_.u32(at);
        uint16_t b = little ? b_.le16(at + 4) : b_.u16(at + 4), c = little ? b_.le16(at + 6) : b_.u16(at + 6);
        std::string s = fmt("%08x-%04x-%04x-%02x%02x-", a, b, c, b_.u8(at + 8), b_.u8(at + 9));
        for (int i = 10; i < 16; ++i) s += fmt("%02x", b_.u8(at + i));
        return s;
    }
    static std::string syntax_name(const std::string& uuid, uint32_t ver) {
        if (uuid == "8a885d04-1ceb-11c9-9fe8-08002b104860" && ver == 2) return "32bit NDR";
        if (uuid == "71710533-beba-4937-8319-b5dbef9ccc36" && ver == 1) return "64bit NDR";
        return uuid;
    }

    void dcerpc_pdu(const std::string& key, size_t off, size_t len) {
        if (st_.rpc.size() > 100'000) st_.rpc.clear();
        auto& rc = st_.rpc[key];
        bool little = b_.u8(off + 4) & 0x10;
        auto u16x = [&](size_t at) { return little ? b_.le16(at) : b_.u16(at); };
        auto u32x = [&](size_t at) { return little ? b_.le32(at) : b_.u32(at); };
        uint8_t ptype = b_.u8(off + 2), flags = b_.u8(off + 3);
        uint32_t call = u32x(off + 12);
        size_t end = off + len;
        auto have = [&](size_t at, size_t n) { return at + n <= end && b_.have(at, n); };
        static const char* frag_names[] = {"Mid", "1st", "Last", "Single"};
        const char* frag = frag_names[flags & 3];
        static const char* ptypes[] = {"Request", "Ping", "Response", "Fault", "Working", "Nocall", "Reject", "Ack",
                                       "Cl_cancel", "Fack", "Cancel_ack", "Bind", "Bind_ack", "Bind_nak",
                                       "Alter_context", "Alter_context_resp", "AUTH3", "Shutdown", "Co_cancel",
                                       "Orphaned", "RPC-over-HTTP RTS"};
        if (rpc_ctx_ != 0) {
            col_append(" # ");
            col_set_fence();
            expert("dcerpc.fragment_multiple", 0, "Sequence", "DCERPC", "Multiple DCE/RPC fragments/PDU's in one packet");
        }
        set_proto("DCERPC");
        fproto("dcerpc", off, len);
        Layer& l = layer("Distributed Computing Environment / Remote Procedure Call (DCE/RPC)", off, len);
        FF(uint("dcerpc.pkt_type", ptype));
        FF(uint("dcerpc.cn_call_id", call));
        size_t auth_len = u16x(off + 10);
        if (auth_len && auth_len + 24 <= len && have(end - auth_len - 8, 8)) {  // sec_trailer, then the token
            size_t tr = end - auth_len - 8;
            uint8_t auth_type = b_.u8(tr);
            FF(uint("dcerpc.auth_type", auth_type));
            FF(uint("dcerpc.auth_level", b_.u8(tr + 1)));
            size_t tok = end - auth_len;
            // (Kerberos SSP binds carry a bare AP-REQ/AP-REP: no GSS-API layer.)
            if (auth_type == 9 || (auth_type == 16 && ptype < 11)) fproto("gss-api", tok, auth_len);
            if (ptype >= 11 || ptype == 16) {  // binds and AUTH3 carry the logon itself
                if (auth_type == 9) gss_blob(tok, auth_len, l, false);
                if (auth_type == 16 && !gss_raw_krb5(tok, auth_len, l)) gss_krb5(tok, auth_len, l);
                if (auth_type == 9 || auth_type == 10) ntlmssp_info(tok, auth_len);
            }
        }
        std::string info = fmt("%s: call_id: %u, Fragment: %s", ptypes[ptype], call, frag);
        auto iface_name = [&](const std::string& uuid, uint16_t major) {
            const RpcInterface* i = rpc_interface(uuid, major);
            return i ? std::string(i->ctx_name) : uuid;
        };
        // Which frame completes a fragmented call (Wireshark's "reas: #N").
        auto reassembled = [&]() -> std::string {
            uint64_t k = (static_cast<uint64_t>(call) << 8) | ptype;
            auto& frames = rc.frags[k];
            if (flags & 1) frames.clear();
            frames.push_back(frame_);
            if ((flags & 2) && st_.record)
                for (uint64_t f : frames) st_.record->rpc_reassembled[f] = frame_;
            if (flags & 2) frames.clear();
            if (st_.use) {
                auto it = st_.use->rpc_reassembled.find(frame_);
                if (it != st_.use->rpc_reassembled.end()) return fmt("#%llu", static_cast<unsigned long long>(it->second));
            }
            return "";
        };
        switch (ptype) {
            case 11: case 14: {  // Bind, Alter_context
                if (!have(off + 16, 12)) break;
                unsigned n = b_.u8(off + 24);
                info += fmt(", %u context items: ", n);
                size_t at = off + 28;
                bool first = true;
                for (unsigned i = 0; i < n && have(at, 24); ++i) {
                    uint16_t ctx = u16x(at);
                    FF(uint("dcerpc.cn_ctx_id", ctx));
                    unsigned nts = b_.u8(at + 2);
                    InspectorState::RpcBinding b{uuid_at(at + 4, little), u16x(at + 20), u16x(at + 22)};
                    FF(string("dcerpc.cn_bind_to_uuid", b.uuid));
                    rpc_ctx_ = ctx;
                    at += 24;
                    for (unsigned t = 0; t < nts && have(at, 20); ++t, at += 20) {
                        std::string syn = syntax_name(uuid_at(at, little), u32x(at + 16));
                        if (t == 0) b.ndr64 = syn == "64bit NDR";
                        info += (first ? "" : ", ") + fmt("%s V%u.%u (%s)", iface_name(b.uuid, b.major).c_str(), b.major,
                                                          b.minor, syn.c_str());
                        first = false;
                    }
                    rc.ctx[ctx] = b;
                }
                break;
            }
            case 12: case 15: {  // Bind_ack, Alter_context_resp
                if (!have(off + 16, 10)) break;
                info += fmt(", max_xmit: %u max_recv: %u", u16x(off + 16), u16x(off + 18));
                size_t at = off + 24 + 2 + u16x(off + 24);
                at += (4 - (at - off) % 4) % 4;
                if (!have(at, 4)) break;
                unsigned n = b_.u8(at);
                info += fmt(", %u results: ", n);
                at += 4;
                static const char* results[] = {"Acceptance", "User rejection", "Provider rejection", "Negotiate ACK"};
                for (unsigned i = 0; i < n && have(at, 24); ++i, at += 24) {
                    uint16_t r = u16x(at);
                    info += (i ? ", " : "") + std::string(r < 4 ? results[r] : "Unknown");
                }
                break;
            }
            case 13: {  // Bind_nak
                if (!have(off + 16, 2)) break;
                uint16_t r = u16x(off + 16);
                const char* why = lookup_name(kRpcRejectReason, r);
                info += std::string(" reason: ") + (why ? why : fmt("Unknown (%u)", r).c_str());
                break;
            }
            case 0: case 2: case 3: {  // Request, Response, Fault
                if (!have(off + 16, 8)) break;
                uint16_t ctx = u16x(off + 20);
                FF(uint("dcerpc.cn_ctx_id", ctx));
                rpc_ctx_ = ctx;
                uint16_t opnum = 0;
                if (ptype == 0) {
                    opnum = u16x(off + 22);
                    rc.calls[call] = {ctx, opnum};
                } else {
                    auto it = rc.calls.find(call);
                    if (it != rc.calls.end()) opnum = it->second.second;
                }
                auto bit = rc.ctx.find(ctx);
                const RpcInterface* iface = bit == rc.ctx.end() ? nullptr : rpc_interface(bit->second.uuid, bit->second.major);
                std::string bound = bit == rc.ctx.end() ? "" : fmt(" %s V%u", bit->second.uuid.c_str(), bit->second.major);
                if (bit == rc.ctx.end() && ptype != 3)
                    expert("dcerpc.cn_ctx_id.no_bind", 1, "Undecoded", "DCERPC",
                           fmt("No bind info for interface Context ID %u - capture start too late?", ctx));
                if (ptype == 3) {
                    if (!have(off + 24, 4)) break;
                    uint32_t st = u32x(off + 24);
                    const char* sn = lookup_name(kRpcFault, st);
                    std::string status = sn ? sn : fmt("Unknown (0x%08x)", st);
                    info += fmt(", Ctx: %u, status: %s", ctx, status.c_str());
                    expert("dcerpc.cn_status", 1, "Response", "DCERPC", "Fault: " + status);
                    break;
                }
                FF(uint("dcerpc.opnum", opnum));
                std::string reas = (flags & 3) == 3 ? "" : reassembled();
                bool last = flags & 2;
                if (iface && last) {
                    set_proto(iface->proto);
                    fproto(iface->filter, off, len);
                    FF(uint(iface->opnum_field, opnum));
                    const char* op = lookup_name(iface->ops, iface->n_ops, opnum);
                    info = (op ? std::string(op) : fmt("Unknown operation %u", opnum)) +
                           (ptype == 0 ? " request" : " response");
                    size_t stub = off + 24 + (ptype == 0 && (flags & 0x80) ? 16 : 0);
                    if (std::strcmp(iface->proto, "EPM") == 0 && opnum == 3)
                        info += epm_map(stub, end, ptype == 0, little, bit->second.ndr64);
                    if (std::strcmp(iface->proto, "RPC_NETLOGON") == 0 && opnum == 4 && ptype == 0)
                        info += netlogon_server_name(stub, end, little);
                    break;
                }
                info += ptype == 0 ? fmt(", opnum: %u, Ctx: %u", opnum, ctx) : fmt(", Ctx: %u", ctx);
                if (!iface) info += bound;
                if (!last)
                    info += fmt(" [DCE/RPC %s fragment, ", (flags & 1) ? "1st" : "Mid") +
                            (reas.empty() ? std::string("unreassembled]") : "reas: " + reas + "]");
                break;
            }
            default: break;
        }
        FIELD(l, "Packet type", info, off + 2, 1);
        col_set(info);
    }

    // NDR (and NDR64: 8-byte pointers and sizes), aligned from the stub's start.
    struct Ndr {
        const Bytes& b;
        size_t base, pos, end;
        bool little, ndr64;
        bool align(size_t a) {
            pos = base + ((pos - base + a - 1) / a) * a;
            return pos <= end;
        }
        bool u32(uint64_t& v) {
            if (!align(4) || pos + 4 > end || !b.have(pos, 4)) return false;
            v = little ? b.le32(pos) : b.u32(pos);
            pos += 4;
            return true;
        }
        bool u64(uint64_t& v) {
            if (!align(8) || pos + 8 > end || !b.have(pos, 8)) return false;
            v = little ? b.le64(pos) : (static_cast<uint64_t>(b.u32(pos)) << 32) | b.u32(pos + 4);
            pos += 8;
            return true;
        }
        bool ptr(uint64_t& v) { return ndr64 ? u64(v) : u32(v); }
        bool size(uint64_t& v) { return ndr64 ? u64(v) : u32(v); }
        bool skip(size_t n, size_t a) {
            if (!align(a) || pos + n > end) return false;
            pos += n;
            return true;
        }
    };

    // The endpoint mapper's Map: the interface and transfer syntax of each tower.
    std::string epm_map(size_t at, size_t end, bool request, bool little, bool ndr64) {
        auto tower = [&](size_t a, size_t tl) {
            std::string out;
            size_t tend = std::min(a + tl, end);
            if (a + 2 > tend || !b_.have(a, 2)) return out;
            unsigned floors = b_.le16(a);
            size_t p = a + 2;
            for (unsigned f = 0; f < floors && f < 2 && p + 2 <= tend; ++f) {
                size_t lhs = b_.le16(p), lp = p + 2;
                if (lp + lhs + 2 > tend) break;
                size_t rhs = b_.le16(lp + lhs);
                if (lhs >= 19 && b_.u8(lp) == 0x0D) {
                    std::string uuid = uuid_at(lp + 1, true);
                    uint16_t major = b_.le16(lp + 17);
                    const RpcInterface* i = f == 0 ? rpc_interface(uuid, major) : nullptr;
                    out += ", " + (f == 0 ? (i ? std::string(i->ctx_name) : uuid) : syntax_name(uuid, major));
                }
                p = lp + lhs + 2 + rhs;
            }
            return out;
        };
        Ndr n{b_, at, at, end, little, ndr64};
        std::string out;
        uint64_t v = 0, len = 0;
        if (request) {  // object (UUID pointer), map_tower (twr_t pointer)
            if (!n.ptr(v)) return out;
            if (v && !n.skip(16, 4)) return out;
            if (!n.ptr(v) || !v || !n.size(v) || !n.u32(len)) return out;
            return tower(n.pos, len);
        }
        // entry_handle, num_towers, then a varying array of tower pointers
        uint64_t count = 0, max = 0, offset = 0;
        if (!n.skip(20, 4) || !n.u32(count) || !n.size(max) || !n.size(offset) || !n.size(count)) return out;
        std::vector<uint64_t> refs;
        for (uint64_t i = 0; i < count && i < 64; ++i) {
            if (!n.ptr(v)) return out;
            refs.push_back(v);
        }
        for (uint64_t r : refs) {
            if (!r) continue;
            if (!n.size(v) || !n.u32(len) || n.pos + len > end) break;
            out += tower(n.pos, len);
            n.pos += len;
        }
        return out;
    }

    // Wireshark reads NetrServerReqChallenge's server name as 32-bit NDR whatever
    // was negotiated, and puts it in the Info column.
    std::string netlogon_server_name(size_t at, size_t end, bool little) {
        Ndr n{b_, at, at, end, little, false};
        uint64_t ref = 0, max = 0, offset = 0, actual = 0;
        if (!n.ptr(ref) || !ref) return "";
        if (!n.u32(max) || !n.u32(offset) || !n.u32(actual)) return ", ";
        size_t bytes = static_cast<size_t>(std::min<uint64_t>(actual * 2, end > n.pos ? end - n.pos : 0));
        return ", " + utf16le(n.pos, bytes);
    }

    // ------------------------------------- NetBIOS datagrams and the Browser
    static const char* browser_server_type(int bit) {
        static const char* names[32] = {
            "Workstation", "Server", "SQL Server", "Domain Controller", "Backup Controller", "Time Source",
            "Apple Server", "Novell Server", "Domain Member Server", "Print Queue Server", "Dialin Server",
            "Xenix Server", "NT Workstation", "Windows for Workgroups", nullptr, "NT Server", "Potential Browser",
            "Backup Browser", "Master Browser", "Domain Master Browser", "OSF", "VMS", "Windows 95 or above",
            "DFS server", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, "Local List Only", "Domain Enum"};
        return names[bit];
    }

    bool nbdgm(size_t off, size_t len) {
        if (len < 10 || !b_.have(off, 10)) return false;
        uint8_t type = b_.u8(off);
        static const char* types[] = {"Direct_unique datagram", "Direct_group datagram", "Broadcast datagram",
                                      "Datagram error", "Datagram query request", "Datagram positive query response",
                                      "Datagram negative query response"};
        if (type < 0x10 || type > 0x16) return false;
        size_t end = off + len;
        set_proto("NBDS");
        fproto("nbdgm", off, len);
        Layer& l = layer("NetBIOS Datagram Service", off, len);
        INFO(std::string(types[type - 0x10]));
        FF(uint("nbdgm.type", type));
        FIELD(l, "Message type", fmt("%s (%u)", types[type - 0x10], type), off, 1);
        FF(uint("nbdgm.dgram_id", b_.u16(off + 2)));
        FF(ipv4("nbdgm.src.ip", b_.p + off + 4));
        FF(uint("nbdgm.src.port", b_.u16(off + 8)));
        FIELD(l, "Source", fmt("%s:%u", ipv4s(b_.p + off + 4).c_str(), b_.u16(off + 8)), off + 4, 6);
        if (type > 0x12 || len < 14) return true;
        FF(uint("nbdgm.dgram_len", b_.u16(off + 10)));
        FF(uint("nbdgm.pkt_offset", b_.u16(off + 12)));
        size_t next = 0;
        std::string src = netbios_name(off + 14, end, next);
        if (src.empty()) return true;
        FF(string("nbdgm.source_name", src));
        FIELD(l, "Source name", src, off + 14, next - off - 14);
        size_t dst_at = next;
        std::string dst = netbios_name(dst_at, end, next);
        if (dst.empty()) return true;
        FF(string("nbdgm.destination_name", dst));
        FIELD(l, "Destination name", dst, dst_at, next - dst_at);
        if (next < end) smb_mailslot(next, end);
        return true;
    }

    // SMB Trans request carrying a mailslot write: only \MAILSLOT\BROWSE is decoded.
    void smb_mailslot(size_t s, size_t end) {
        if (end - s < 70 || !b_.have(s, 70) || std::memcmp(b_.p + s, "\xffSMB", 4) != 0 || b_.u8(s + 4) != 0x25 ||
            b_.u8(s + 32) != 17)
            return;
        auto le16 = [&](size_t at) { return static_cast<uint16_t>(b_.u8(at) | (b_.u8(at + 1) << 8)); };
        size_t data_count = le16(s + 33 + 2 * 11), data_offset = le16(s + 33 + 2 * 12);
        size_t name_at = s + 33 + 2 * 17 + 2;
        size_t name_end = name_at;
        while (name_end < end && b_.u8(name_end)) ++name_end;
        if (name_end >= end) return;
        std::string name = text_line(b_.p + name_at, name_end - name_at, 64);
        fproto("smb", s, end - s);
        FF(uint("smb.cmd", 0x25));
        FF(string("smb.trans_name", name));
        Layer& sl = layer("SMB (Server Message Block Protocol)", s, end - s);
        FIELD(sl, "Command", "Trans (0x25)", s + 4, 1);
        FIELD(sl, "Transaction name", name, name_at, name_end - name_at);
        fproto("mailslot", s, end - s);
        FF(uint("mailslot.opcode", le16(s + 33 + 2 * 14)));
        FF(string("mailslot.name", name));
        size_t d = s + data_offset;
        if (name != "\\MAILSLOT\\BROWSE" || data_offset < 70 || d >= end || !data_count) return;
        browser(d, std::min(end, d + data_count));
    }

    void browser(size_t d, size_t end) {
        auto le32 = [&](size_t at) {
            return static_cast<uint32_t>(b_.u8(at) | (b_.u8(at + 1) << 8) | (b_.u8(at + 2) << 16) |
                                         (static_cast<uint32_t>(b_.u8(at + 3)) << 24));
        };
        auto cstr = [&](size_t at, size_t max) {
            size_t e = at;
            while (e < end && e - at < max && b_.u8(e)) ++e;
            return text_line(b_.p + at, e - at, max);
        };
        uint8_t cmd = b_.u8(d);
        static const std::pair<uint8_t, const char*> cmds[] = {
            {0x01, "Host Announcement"}, {0x02, "Request Announcement"}, {0x08, "Browser Election Request"},
            {0x09, "Get Backup List Request"}, {0x0a, "Get Backup List Response"}, {0x0b, "Become Backup Browser"},
            {0x0c, "Domain/Workgroup Announcement"}, {0x0d, "Master Announcement"},
            {0x0e, "Reset Browser State Announcement"}, {0x0f, "Local Master Announcement"}};
        const char* what = nullptr;
        for (const auto& [c, n] : cmds)
            if (c == cmd) what = n;
        if (!what) return;
        set_proto("BROWSER");
        fproto("browser", d, end - d);
        Layer& l = layer("Microsoft Windows Browser Protocol", d, end - d);
        FF(uint("browser.command", cmd));
        FIELD(l, "Command", fmt("%s (0x%02x)", what, cmd), d, 1);
        std::string info = what;
        if ((cmd == 0x01 || cmd == 0x0c || cmd == 0x0f) && end - d >= 32) {
            std::string server = cstr(d + 6, 16);
            uint32_t type = le32(d + 24);
            FF(uint("browser.update_count", b_.u8(d + 1)));
            FF(uint("browser.period", le32(d + 2)));
            FF(string("browser.server", server));
            FF(uint("browser.os_major", b_.u8(d + 22)));
            FF(uint("browser.os_minor", b_.u8(d + 23)));
            FF(uint("browser.server_type", type));
            static const char* flag_fields[32] = {
                "browser.server_type.workstation", "browser.server_type.server", "browser.server_type.sql",
                "browser.server_type.domain_controller", "browser.server_type.backup_controller",
                "browser.server_type.time", "browser.server_type.apple", "browser.server_type.novell",
                "browser.server_type.member", "browser.server_type.print", "browser.server_type.dialin",
                "browser.server_type.xenix", "browser.server_type.ntw", "browser.server_type.wfw", nullptr,
                "browser.server_type.nts", "browser.server_type.browser.potential", "browser.server_type.browser.backup",
                "browser.server_type.browser.master", "browser.server_type.browser.domain_master",
                "browser.server_type.osf", "browser.server_type.vms", "browser.server_type.w95",
                "browser.server_type.dfs", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                "browser.server_type.local", "browser.server_type.domainenum"};
            for (int bit = 0; bit < 32; ++bit)
                if (flag_fields[bit]) FF(boolean(flag_fields[bit], type & (1u << bit)));
            FF(uint("browser.proto_major", b_.u8(d + 28)));
            FF(uint("browser.proto_minor", b_.u8(d + 29)));
            FF(uint("browser.sig", b_.u16(d + 30)));
            std::string comment = cstr(d + 32, 256);
            FF(string("browser.comment", comment));
            FIELD(l, cmd == 0x0c ? "Domain/workgroup" : "Server name", server, d + 6, 16);
            FIELD(l, "Windows version", fmt("%u.%u", b_.u8(d + 22), b_.u8(d + 23)), d + 22, 2);
            std::string types;
            for (int bit = 0; bit < 32; ++bit) {
                if (!(type & (1u << bit))) continue;
                const char* n = browser_server_type(bit);
                std::string label = n ? n : fmt("Unknown server type:%d", bit);
                info += ", " + label;
                types += (types.empty() ? "" : ", ") + label;
            }
            FIELD(l, "Server type", fmt("0x%08x", type) + (types.empty() ? "" : " (" + types + ")"), d + 24, 4);
            if (!comment.empty()) FIELD(l, "Comment", comment, d + 32, comment.size());
            info = std::string(what) + " " + server + info.substr(std::strlen(what));
        } else if (cmd == 0x02 && end - d >= 2) {
            std::string name = cstr(d + 2, 64);
            FF(uint("browser.unused", b_.u8(d + 1)));
            FF(string("browser.response_computer_name", name));
            FIELD(l, "Response computer name", name, d + 2, name.size());
            info += " " + name;
        } else if (cmd == 0x08 && end - d >= 14) {
            FF(uint("browser.election.version", b_.u8(d + 1)));
            FF(uint("browser.election.criteria", le32(d + 2)));
            FF(uint("browser.uptime", le32(d + 6)));
            std::string server = cstr(d + 14, 64);
            FF(string("browser.server", server));
            FIELD(l, "Server name", server, d + 14, server.size());
        }
        INFO(info);
    }

    bool nbns(size_t off, size_t len) {
        if (len < 12) return false;
        uint16_t id = b_.u16(off), flags = b_.u16(off + 2), an = b_.u16(off + 6);
        bool response = flags & 0x8000;
        uint8_t opcode = (flags >> 11) & 0xF;
        size_t next = 0;
        std::string name = netbios_name(off + 12, off + len, next);
        if (name.empty()) return false;
        uint16_t type = b_.have(next, 2) ? b_.u16(next) : 0;
        const char* tname = type == 0x21 ? "NBSTAT" : "NB";
        static const char* ops[] = {"Name query", "Unknown", "Unknown", "Unknown", "Unknown", "Registration",
                                    "Release", "Wait for acknowledgment", "Refresh", "Refresh (alt)", "Unknown",
                                    "Unknown", "Unknown", "Unknown", "Unknown", "Multi-homed registration"};
        d_.protocol = "NBNS";
        Layer& l = layer("NetBIOS Name Service", off, len);
        fproto("nbns", off, len);
        FF(string("nbns.name", name));
        field(l, "Transaction ID", fmt("0x%04x", id), off, 2);
        field(l, "Name", name, off + 12, next > off + 12 ? next - off - 12 : 0);
        static const char* rcodes[] = {"No error", "Request was invalidly formatted", "Server failure",
                                       "Requested name does not exist", "Request is not implemented",
                                       "Request was refused", "Name is owned by another node", "Name is in conflict"};
        uint8_t rcode = flags & 0xF;
        std::string head = std::string(ops[opcode]) + (response ? " response" : "");
        if (response && rcode) head += rcode < 8 ? std::string(", ") + rcodes[rcode] : fmt(", Unknown error (%u)", rcode);
        std::string info = head + " " + tname + " " + name;
        if (response && an && type == 0x20) {
            size_t rd = next + 10;  // type, class, ttl, rdlength -> flags(2) + address(4)
            if (b_.have(rd, 6)) info = head + " NB " + ipv4s(b_.p + rd + 2);
        } else if (response && an && type == 0x21) {
            info = head + " NBSTAT";  // the node status answer itself isn't summarised
        }
        d_.info = info;
        return true;
    }

    bool ntp(size_t off, size_t len) {
        if (len < 48 && !(len >= 12 && (b_.u8(off) & 0x7) == 6) && !(len >= 4 && (b_.u8(off) & 0x7) == 7)) return false;
        uint8_t b0 = b_.u8(off);
        unsigned vn = (b0 >> 3) & 0x7, mode = b0 & 0x7;
        static const char* modes[] = {"reserved", "symmetric active", "symmetric passive", "client", "server",
                                      "broadcast", "control", "private"};
        // Mode 7 (ntpdc) request codes, as Wireshark names them: MON_GETLIST_1 is the
        // "monlist" query behind NTP amplification attacks.
        static const char* priv_codes[] = {
            "PEER_LIST", "PEER_LIST_SUM", "PEER_INFO", "PEER_STATS", "SYS_INFO", "SYS_STATS", "IO_STATS", "MEM_STATS",
            "LOOP_INFO", "TIMER_STATS", "CONFIG", "UNCONFIG", "SET_SYS_FLAG", "CLR_SYS_FLAG", "MONITOR", "NOMONITOR",
            "GET_RESTRICT", "RESADDFLAGS", "RESSUBFLAGS", "UNRESTRICT", "MON_GETLIST", "RESET_STATS", "RESET_PEER",
            "REREAD_KEYS", "DO_DIRTY_HACK", "DONT_DIRTY_HACK", "TRUSTKEY", "UNTRUSTKEY", "AUTHINFO", "TRAPS", "ADD_TRAP",
            "CLR_TRAP", "REQUEST_KEY", "CONTROL_KEY", "GET_CTLSTATS", "GET_LEAPINFO", "GET_CLOCKINFO", "SET_CLKFUDGE",
            "GET_KERNEL", "GET_CLKBUGINFO", "UNASSIGNED", "SET_PRECISION", "MON_GETLIST_1", "HOSTNAME_ASSOCID",
            "IF_STATS", "IF_RELOAD"};
        d_.protocol = "NTP";
        Layer& l = layer("Network Time Protocol", off, len);
        fproto("ntp", off, len);
        field(l, "Version", fmt("%u", vn), off, 1);
        field(l, "Mode", modes[mode], off, 1);
        if (mode != 6 && mode != 7 && len >= 48) field(l, "Stratum", fmt("%u", b_.u8(off + 1)), off + 1, 1);
        std::string version = vn >= 1 && vn <= 4 ? fmt("NTP Version %u", vn) : std::string("reserved");
        d_.info = version + ", " + modes[mode];
        if (mode == 7) {
            uint8_t code = b_.u8(off + 3);
            d_.info += fmt(", %s, %s", (b0 & 0x80) ? "Response" : "Request",
                           code < sizeof priv_codes / sizeof *priv_codes ? priv_codes[code] : "Unknown");
            field(l, "Request code", code < sizeof priv_codes / sizeof *priv_codes ? priv_codes[code] : "Unknown", off + 3, 1);
        }
        return true;
    }

    bool ssdp(size_t off, size_t len) {
        std::string first = text_line(b_.p + off, len);
        if (first.find("HTTP/1.") == std::string::npos) return false;
        d_.protocol = "SSDP";
        Layer& l = layer("Simple Service Discovery Protocol", off, len);
        fproto("ssdp", off, len);
        field(l, "Request line", first, off, first.size());
        d_.info = first + " ";
        return true;
    }

    bool tftp(size_t off, size_t len) {
        if (len < 4) return false;
        uint16_t op = b_.u16(off);
        if (op < 1 || op > 6) return false;
        auto cstr = [&](size_t pos, size_t& out_next) {
            std::string s;
            size_t i = pos;
            while (i < off + len && b_.u8(i) != 0 && s.size() < 256) s.push_back(static_cast<char>(b_.u8(i++)));
            out_next = i + 1;
            return text_line(reinterpret_cast<const uint8_t*>(s.data()), s.size());
        };
        d_.protocol = "TFTP";
        Layer& l = layer("Trivial File Transfer Protocol", off, len);
        fproto("tftp", off, len);
        size_t nx = 0, nx2 = 0;
        switch (op) {
            case 1:
            case 2: {
                std::string file = cstr(off + 2, nx), mode = cstr(nx, nx2);
                field(l, "Source File", file, off + 2, file.size());
                d_.info = fmt("%s Request, File: %s, Transfer type: %s", op == 1 ? "Read" : "Write", file.c_str(),
                              mode.c_str());
                return true;
            }
            case 3: d_.info = fmt("Data Packet, Block: %u%s", b_.u16(off + 2), len - 4 < 512 ? " (last)" : ""); return true;
            case 4: d_.info = fmt("Acknowledgement, Block: %u", b_.u16(off + 2)); return true;
            case 5: {
                std::string msg = cstr(off + 4, nx);
                d_.info = fmt("Error Code, Code: %u, Message: %s", b_.u16(off + 2), msg.c_str());
                return true;
            }
            default: d_.info = "Option Acknowledgement"; return true;
        }
    }

    bool syslog(size_t off, size_t len) {
        if (len < 4 || b_.u8(off) != '<') return false;
        size_t i = 1;
        unsigned pri = 0;
        while (i < len && i < 5 && std::isdigit(b_.u8(off + i))) pri = pri * 10 + (b_.u8(off + i++) - '0');
        if (i >= len || b_.u8(off + i) != '>' || pri > 191) return false;
        static const char* fac[] = {"KERN", "USER", "MAIL", "DAEMON", "AUTH", "SYSLOG", "LPR", "NEWS", "UUCP",
                                    "CRON", "AUTHPRIV", "FTP", "NTP", "SECURITY", "CONSOLE", "SOLARIS-CRON",
                                    "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7"};
        static const char* sev[] = {"EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"};
        d_.protocol = "Syslog";
        std::string msg = text_line(b_.p + off + i + 1, len - i - 1, 300);
        Layer& l = layer("Syslog message", off, len);
        fproto("syslog", off, len);
        field(l, "Facility", fac[pri / 8], off, i + 1);
        field(l, "Severity", sev[pri % 8], off, i + 1);
        field(l, "Message", msg, off + i + 1, len - i - 1);
        d_.info = fmt("%s.%s: %s", fac[pri / 8], sev[pri % 8], msg.c_str());
        return true;
    }

    static std::string hex_id(const std::string& id) {
        std::string out;
        for (unsigned char c : id) out += fmt("%02x", c);
        return out;
    }

    // ------------------------------------------------------------------ DTLS
    // Wireshark's DTLS dissector (packet-dtls.c) as its UDP heuristic runs it. The
    // Protocol column names the session's version as known at each record: a Client Hello
    // doesn't settle it (a Hello Verify Request, the Server Hello or a later record does),
    // and Wireshark's second pass starts from the version the first one ended on.
    // Handshake messages split across records are reassembled, "(Fragment)" until the
    // piece that ends a complete message, "(Reassembled)".

    static bool dtls_ct_ok(uint8_t ct) { return ct >= 20 && ct <= 26; }  // through connection ID and ACK

    static const char* dtls_version_name(uint16_t v) {
        switch (v) {
            case 0xfeff: return "DTLSv1.0";
            case 0xfefd: return "DTLSv1.2";
            case 0xfefc: return "DTLSv1.3";
            case 0x0100: return "DTLS 1.0 (OpenSSL pre 0.9.8f)";
            default: return "DTLS";
        }
    }

    static const char* dtls_hs_name(uint8_t t) { return t == 3 ? "Hello Verify Request" : tls_hs_name(t); }

    uint32_t u24(size_t at) const { return (static_cast<uint32_t>(b_.u8(at)) << 16) | b_.u16(at + 1); }

    // Whether the conversation has a DTLS session (a DTLS 1.3 unified header needs one).
    bool dtls_known() const {
        return st_.dtls.count(l4_key_) || (st_.use && st_.use->dtls_version.count(FlowKeyHash()(l4_key_)));
    }

    // dissect_dtls_heur(): every record must look like DTLS and the records must end
    // exactly at the datagram's end.
    bool dtls_heuristic(size_t off, size_t len) const {
        if (len < 13 || !b_.have(off, len)) return false;
        size_t o = 0;
        while (o + 13 <= len) {
            uint8_t rt = b_.u8(off + o);
            bool unified = (rt & 0xE0) == 0x20;
            if (dtls_ct_ok(rt)) {
                uint16_t v = b_.u16(off + o + 1);
                if (v != 0xfeff && v != 0xfefd && v != 0x0100) return false;
                unified = false;
            } else if (!unified) {
                return false;
            }
            size_t rl;
            if (unified) {
                if ((rt & 0x10) || !dtls_known()) return false;  // (no session is known by a connection ID)
                o += 1 + ((rt & 0x08) ? 2 : 1);
                if (rt & 0x04) {
                    rl = b_.u16(off + o);
                    o += 2;
                } else {
                    rl = len - o;
                }
            } else {
                rl = b_.u16(off + o + 11);
                o += 13;
            }
            o += rl;
            if (o == len) return true;
        }
        return false;
    }

    void dtls(size_t off, size_t len) {
        if (st_.dtls.size() > 100'000) st_.dtls.clear();
        auto& dc = st_.dtls[l4_key_];
        if (!dc.started) {
            dc.started = true;
            size_t h = FlowKeyHash()(l4_key_);
            if (st_.use) {
                auto it = st_.use->dtls_version.find(h);
                if (it != st_.use->dtls_version.end()) dc.version = it->second;
            }
            if (st_.record) st_.record->dtls_version.emplace(h, 0);
        }
        set_proto("DTLS");
        std::string saved = std::move(col_);  // UDP decoders set the Info column directly
        size_t saved_fence = fence_;
        col_.clear();
        fence_ = 0;
        fproto("dtls", off, len);
        size_t saved_base = dtls_base_, saved_end = dtls_end_;
        dtls_base_ = off;
        dtls_end_ = off + len;
        int dir = udp_a_to_b_ ? 0 : 1;
        for (size_t at = off; at < dtls_end_;) at = dtls_record(dc, dir, at);
        dtls_base_ = saved_base;
        dtls_end_ = saved_end;
        if (full_) d_.info = col_;
        col_ = std::move(saved);
        fence_ = saved_fence;
    }

    // ssl_try_set_version(): any valid handshake message but a Client Hello, or any other
    // valid record, settles the version.
    void dtls_set_version(InspectorState::DtlsConn& dc, uint8_t ct, uint8_t hs, uint16_t v) {
        bool authoritative = (ct == 22 && dtls_hs_name(hs) && hs != 1) || (ct != 22 && dtls_ct_ok(ct));
        if (!authoritative || (v != 0xfeff && v != 0xfefd && v != 0xfefc && v != 0x0100)) return;
        dc.version = v;
        if (st_.record) st_.record->dtls_version[FlowKeyHash()(l4_key_)] = v;
    }

    // tls_scan_server_hello() on `p` (n bytes): the version, supported_versions' when the
    // legacy one is [D]TLS 1.2, and whether it is a Hello Retry Request. Offsets are
    // Wireshark's, in its unsigned arithmetic (one caller passes a length as the end).
    static uint16_t dtls_scan_server_hello(const uint8_t* p, size_t n, uint32_t offset, uint32_t offset_end, bool* hrr) {
        static const uint8_t kHrrRandom[32] = {
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
            0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
        auto have = [&](uint32_t o, size_t k) { return o <= n && k <= n - o; };
        if (hrr) *hrr = false;
        if (!have(offset, 2)) return 0;
        uint16_t v = static_cast<uint16_t>((p[offset] << 8) | p[offset + 1]);
        if ((v != 0x0303 && v != 0xfefd) || offset_end - offset < 46) return v;
        offset += 2;
        if (hrr) *hrr = have(offset, 32) && std::memcmp(p + offset, kHrrRandom, 32) == 0;
        offset += 32;
        if (!have(offset, 1)) return v;
        uint8_t sid = p[offset++];
        if (offset_end - offset < sid + 5u) return v;
        offset += sid + 5u;
        while (offset_end - offset >= 6) {
            if (!have(offset, 4)) return v;
            uint16_t et = static_cast<uint16_t>((p[offset] << 8) | p[offset + 1]);
            uint16_t el = static_cast<uint16_t>((p[offset + 2] << 8) | p[offset + 3]);
            if (offset_end - offset < 4u + el) break;
            if (et == 0x002b) {  // supported_versions
                if (el == 2 && have(offset + 4, 2)) v = static_cast<uint16_t>((p[offset + 4] << 8) | p[offset + 5]);
                return v;
            }
            offset += 4u + el;
        }
        return v;
    }

    // dissect_dtls_record() for DTLS 1.0 and 1.2 records (13-byte header). Returns where
    // the next record starts.
    size_t dtls_record(InspectorState::DtlsConn& dc, int dir, size_t at) {
        uint8_t ct = b_.u8(at);
        if ((ct & 0xE0) == 0x20) return dtls13_record(dc, at);
        uint16_t rv = b_.u16(at + 1), epoch = b_.u16(at + 3);
        uint64_t seq = (static_cast<uint64_t>(b_.u16(at + 5)) << 32) | b_.u32(at + 7);
        size_t rlen = b_.u16(at + 11), body = at + 13;
        if (!dtls_ct_ok(ct)) {
            col_append_sep("Continuation Data");
            return body + rlen;
        }
        if (body >= dtls_end_) {  // Wireshark reads the byte after the header: past the datagram
            media_malformed();
            return dtls_end_;
        }
        if (!dc.version) {
            uint16_t v = rv;
            uint8_t next = b_.u8(body);
            if (rv == 0xfefd && ct == 22 && next == 2 && rlen > 12 && body + 12 <= dtls_end_) {
                uint32_t fo = u24(body + 6), fl = u24(body + 9);
                if (fo == 0 && body + 12 + fl <= dtls_end_)
                    v = dtls_scan_server_hello(b_.p + dtls_base_, dtls_end_ - dtls_base_,
                                               static_cast<uint32_t>(body + 12 - dtls_base_),
                                               static_cast<uint32_t>(body + 12 + fl - dtls_base_), nullptr);
            }
            dtls_set_version(dc, ct, next, v);
        }
        const char* vn = dtls_version_name(dc.version);
        set_proto(vn);
        const char* ctn = ct == 20 ? "Change Cipher Spec" : ct == 21 ? "Alert" : ct == 22 ? "Handshake"
                        : ct == 23 ? "Application Data" : ct == 24 ? "Heartbeat" : ct == 25 ? "Connection ID" : "ACK";
        Layer& l = layer(fmt("%s Record Layer: %s Protocol", vn, ctn).c_str(), at, 13 + rlen);
        FIELD(l, "Content Type", fmt("%s (%u)", ctn, ct), at, 1);
        FIELD(l, "Version", fmt("%s (0x%04x)", dtls_version_name(rv), rv), at + 1, 2);
        FIELD(l, "Epoch", fmt("%u", epoch), at + 3, 2);
        FIELD(l, "Sequence Number", fmt("%llu", static_cast<unsigned long long>(seq)), at + 5, 6);
        FIELD(l, "Length", fmt("%zu", rlen), at + 11, 2);
        FF(uint("dtls.record.content_type", ct));
        FF(uint("dtls.record.version", rv));
        FF(uint("dtls.record.epoch", epoch));
        FF(uint("dtls.record.sequence_number", seq));
        FF(uint("dtls.record.length", rlen));
        switch (ct) {
            case 20:
                col_append_sep("Change Cipher Spec");
                break;
            case 21:
                dtls_alert(body, l);
                break;
            case 22:
                dtls_handshake(dc, dir, body, rlen, epoch, l);
                break;
            case 23:
                col_append_sep("Application Data");  // (encrypted: what it carries isn't read)
                break;
            case 24:
                dtls_heartbeat(body, rlen);
                break;
            case 25:
                col_append_sep("Connection ID");
                break;
            case 26:
                col_append_sep("Acknowledgement");
                break;
        }
        return body + rlen;
    }

    // A DTLS 1.3 record with the unified header: protected, so "Encrypted Data".
    size_t dtls13_record(InspectorState::DtlsConn& dc, size_t at) {
        uint8_t f = b_.u8(at);
        size_t o = at + 1 + ((f & 0x08) ? 2 : 1);  // (no connection ID: no session negotiated one)
        size_t rl;
        if (f & 0x04) {
            if (o + 2 > dtls_end_) {
                media_malformed();
                return dtls_end_;
            }
            rl = b_.u16(o);
            o += 2;
        } else {
            rl = dtls_end_ > o ? dtls_end_ - o : 0;
        }
        const char* vn = dtls_version_name(dc.version);
        set_proto(vn);
        Layer& l = layer(fmt("%s Record Layer: Encrypted Data", vn).c_str(), at, o - at + rl);
        FIELD(l, "Unified Header", fmt("0x%02x", f), at, 1);
        FIELD(l, "Length", fmt("%zu", rl), o, 0);
        col_append_sep("Encrypted Data");
        return o + rl;
    }

    void dtls_alert(size_t body, Layer& l) {
        if (body + 2 > dtls_end_) {
            media_malformed();
            return;
        }
        uint8_t lv = b_.u8(body), ds = b_.u8(body + 1);
        const char* dn = tls_alert_name(ds);
        // No length check, as in Wireshark: two bytes that read as an alert are shown as one.
        if ((lv == 1 || lv == 2) && std::strcmp(dn, "Unknown") != 0) {
            const char* ln = lv == 1 ? "Warning" : "Fatal";
            col_append_sep(fmt("Alert (Level: %s, Description: %s)", ln, dn));
            FIELD(l, "Level", fmt("%s (%u)", ln, lv), body, 1);
            FIELD(l, "Description", fmt("%s (%u)", dn, ds), body + 1, 1);
            FF(uint("dtls.alert_message.level", lv));
            FF(uint("dtls.alert_message.desc", ds));
        } else {
            col_append_sep("Encrypted Alert");
        }
    }

    void dtls_heartbeat(size_t body, size_t rlen) {
        if (body + 3 > dtls_end_) {
            media_malformed();
            return;
        }
        uint8_t ht = b_.u8(body);
        uint32_t pl = b_.u16(body + 1);
        // (record_length - 16 - 3 is unsigned in Wireshark: a short record passes)
        if ((ht == 1 || ht == 2) && pl <= static_cast<uint32_t>(rlen) - 16u - 3u)
            col_append_sep(ht == 1 ? "Heartbeat Request" : "Heartbeat Response");
        else
            col_append_sep("Encrypted Heartbeat");
    }

    // dissect_dtls_handshake() on a record that may be encrypted: each message's name
    // (or "Encrypted Handshake Message" when the first doesn't look like one), with
    // fragments reassembled.
    void dtls_handshake(InspectorState::DtlsConn& dc, int dir, size_t start, size_t rlen, uint16_t epoch, Layer& l) {
        size_t end = start + rlen;
        const char* name = nullptr;  // (like Wireshark's msg_type_str, kept from one message to the next)
        for (size_t o = start; o < end;) {
            bool first = o == start;
            if (o + 12 > dtls_end_) {
                media_malformed();
                return;
            }
            uint8_t t = b_.u8(o);
            uint32_t fl = u24(o + 9);
            if (o + fl <= end) {
                bool hrr = false;
                if (t == 2)
                    dtls_scan_server_hello(b_.p + dtls_base_, dtls_end_ - dtls_base_,
                                           static_cast<uint32_t>(o + 12 - dtls_base_), fl, &hrr);
                name = hrr ? "Hello Retry Request" : dtls_hs_name(t);
            }
            if (!name && !first) return;
            if (!name) {
                col_append_sep("Encrypted Handshake Message");
                return;
            }
            col_append_sep(name);
            uint32_t length = u24(o + 1), foff = u24(o + 6);
            uint16_t mseq = b_.u16(o + 4);
            size_t hb = o + 12;
            FIELD(l, "Handshake Type", fmt("%s (%u)", name, t), o, 1);
            FIELD(l, "Length", fmt("%u", length), o + 1, 3);
            FIELD(l, "Message Sequence", fmt("%u", mseq), o + 4, 2);
            FIELD(l, "Fragment Offset", fmt("%u", foff), o + 6, 3);
            FIELD(l, "Fragment Length", fmt("%u", fl), o + 9, 3);
            FF(uint("dtls.handshake.type", t));
            FF(uint("dtls.handshake.length", length));
            FF(uint("dtls.handshake.message_seq", mseq));
            FF(uint("dtls.handshake.fragment_offset", foff));
            FF(uint("dtls.handshake.fragment_length", fl));
            bool fragmented = false;
            const std::string* whole = nullptr;
            if (static_cast<uint64_t>(fl) + foff > length) {
                fragmented = foff != 0;  // (a fragment past the message's end isn't reassembled)
            } else if (foff > 0 && fl == 0) {
                o = hb;
                continue;
            } else if (fl < length) {
                fragmented = true;
                if (dtls_hs_name(t)) {
                    if (hb + fl > dtls_end_) {
                        media_malformed();
                        return;
                    }
                    uint64_t key = (static_cast<uint64_t>(dir) << 32) | (static_cast<uint64_t>(epoch) << 16) | mseq;
                    whole = dtls_reassemble(dc, key, foff, fl, length, hb);
                    col_append(whole ? " (Reassembled)" : " (Fragment)");
                }
            }
            o = hb + fl;
            if (fragmented && !whole) continue;
            if (!whole && hb + fl > dtls_end_) {
                media_malformed();
                return;
            }
            const uint8_t* mp = whole ? reinterpret_cast<const uint8_t*>(whole->data()) : b_.p + hb;
            size_t mn = whole ? whole->size() : fl;
            if (t == 1) {
                if (!dc.version) dtls_client_versions(mp, mn);
                dtls_client_hello(mp, mn, hb, l);
            } else if (t == 2) {
                uint16_t v = dtls_scan_server_hello(mp, mn, 0, fl, nullptr);
                dtls_set_version(dc, 22, 2, v);
                dtls_server_hello(mp, mn, hb, l);
            }
        }
    }

    // Wireshark's fragment_add() as DTLS calls it (more fragments always expected: the
    // total is the message length the first fragment named). The message, when this
    // fragment ends it and every byte is there; otherwise nullptr.
    const std::string* dtls_reassemble(InspectorState::DtlsConn& dc, uint64_t key, uint32_t foff, uint32_t flen,
                                       uint32_t length, size_t at) {
        size_t h = FlowKeyHash()(l4_key_);
        if (st_.use) {  // the second pass: what the first one reassembled, whole
            auto it = st_.use->dtls_reassembled.find({h, key});
            if (it == st_.use->dtls_reassembled.end() || foff + flen != it->second.length) return nullptr;
            return &it->second.data;
        }
        if (dc.frags.size() > 4096 || dc.frag_bytes > (8u << 20)) {
            dc.frags.clear();
            dc.frag_bytes = 0;
        }
        auto& fr = dc.frags[key];
        bool already = false;
        for (const auto& p : fr.pieces) already = already || (p.frame == frame_ && p.offset == foff);
        bool complete = false;
        if (already) {
            complete = false;  // (the same fragment of this frame again)
        } else if (fr.defragmented) {
            complete = foff + flen <= fr.length;  // a retransmission: the message stays as it was
        } else if (length <= (1u << 20)) {
            fr.pieces.push_back({foff, std::string(reinterpret_cast<const char*>(b_.p + at), flen), frame_});
            dc.frag_bytes += flen;
            if (fr.length) {
                std::vector<const InspectorState::DtlsFragment::Piece*> order;
                for (const auto& p : fr.pieces) order.push_back(&p);
                std::stable_sort(order.begin(), order.end(), [](auto* a, auto* b) { return a->offset < b->offset; });
                uint64_t contiguous = 0;
                for (auto* p : order) {
                    if (p->offset > contiguous) break;
                    contiguous = std::max<uint64_t>(contiguous, static_cast<uint64_t>(p->offset) + p->data.size());
                }
                if (contiguous >= fr.length) {  // the earliest copy of each byte wins, as in Wireshark
                    fr.data.assign(fr.length, '\0');
                    uint64_t pos = 0;
                    for (auto* p : order) {
                        if (p->offset >= fr.length) continue;
                        uint64_t take = std::min<uint64_t>(p->data.size(), fr.length - p->offset);
                        if (p->offset + take > pos) {
                            uint64_t skip = pos - p->offset;
                            std::memcpy(&fr.data[pos], p->data.data() + skip, take - skip);
                            pos = p->offset + take;
                        }
                    }
                    fr.defragmented = true;
                    complete = true;
                    if (st_.record) st_.record->dtls_reassembled[{h, key}] = {fr.length, fr.data};
                }
            }
        }
        uint32_t total = fr.length;
        if (!total) fr.length = length;  // fragment_set_tot_len(), after the first fragment
        if (complete && total && foff + flen == total) return &fr.data;
        return nullptr;
    }

    // Before the version is settled, a Client Hello's supported_versions names the
    // Protocol column: its last entry, if any entry is a DTLS version.
    void dtls_client_versions(const uint8_t* p, size_t n) {
        Bytes m{p, n};
        size_t o = 34;  // version, random
        if (o + 1 > n) return;
        o += 1 + m.u8(o);           // session id
        if (o + 1 > n) return;
        o += 1 + m.u8(o);           // cookie
        if (o + 2 > n) return;
        o += 2 + m.u16(o);          // cipher suites
        if (o + 1 > n) return;
        o += 1 + m.u8(o);           // compression methods
        if (o + 2 > n) return;
        size_t end = std::min(n, o + 2 + m.u16(o));
        for (o += 2; o + 4 <= end; o += 4 + m.u16(o + 2)) {
            if (m.u16(o) != 0x002b) continue;
            size_t vo = o + 4, vend = std::min(end, vo + m.u16(o + 2));
            if (vo + 1 > vend) return;
            size_t lend = std::min(vend, vo + 1 + m.u8(vo));
            bool any = false;
            uint16_t last = 0;
            for (size_t q = vo + 1; q + 2 <= lend; q += 2) {
                last = m.u16(q);
                any = any || last == 0xfeff || last == 0xfefd || last == 0xfefc || last == 0x0100;
            }
            if (any) {
                const char* tn = tls_version_name(last);
                set_proto(tn && last != kPctVersion ? tn : dtls_version_name(last));
            }
            return;
        }
    }

    // A Client Hello's server name, as Wireshark lists it, and its fingerprints.
    void dtls_client_hello(const uint8_t* mp, size_t mn, size_t at, Layer& l) {
        std::string rec("\x16\x03\x01", 3);
        size_t mlen = 4 + mn;
        rec.push_back(static_cast<char>((mlen >> 8) & 0xFF));
        rec.push_back(static_cast<char>(mlen & 0xFF));
        rec.push_back('\x01');
        rec.push_back(static_cast<char>((mn >> 16) & 0xFF));
        rec.push_back(static_cast<char>((mn >> 8) & 0xFF));
        rec.push_back(static_cast<char>(mn & 0xFF));
        rec.append(reinterpret_cast<const char*>(mp), mn);
        auto ch = parse_tls_client_hello(rec, true);
        if (!ch) return;
        if (!ch->sni.empty()) {
            col_append(" (SNI=" + ch->sni + ")");
            FF(string("dtls.handshake.extensions_server_name", ch->sni));
            FIELD(l, "Server Name Indication", ch->sni, at, 0);
        }
        FF(string("dtls.handshake.ja3_full", ch->ja3));
        FF(string("dtls.handshake.ja3", ch->ja3_hash));
        FF(string("dtls.handshake.ja4", ch->ja4));
        FIELD(l, "JA3", ch->ja3_hash, at, 0);
        FIELD(l, "JA4", ch->ja4, at, 0);
    }

    void dtls_server_hello(const uint8_t* mp, size_t mn, size_t at, Layer& l) {
        std::string rec("\x16\x03\x03", 3);
        size_t mlen = 4 + mn;
        rec.push_back(static_cast<char>((mlen >> 8) & 0xFF));
        rec.push_back(static_cast<char>(mlen & 0xFF));
        rec.push_back('\x02');
        rec.push_back(static_cast<char>((mn >> 16) & 0xFF));
        rec.push_back(static_cast<char>((mn >> 8) & 0xFF));
        rec.push_back(static_cast<char>(mn & 0xFF));
        rec.append(reinterpret_cast<const char*>(mp), mn);
        auto sh = parse_tls_server_hello(rec, true);
        if (!sh) return;
        FF(string("dtls.handshake.ja3s_full", sh->ja3s));
        FF(string("dtls.handshake.ja3s", sh->ja3s_hash));
        FIELD(l, "JA3S", sh->ja3s_hash, at, 0);
        FIELD(l, "JA4S", sh->ja4s, at, 0);
    }

    // QUIC: each packet of a datagram rewrites the Info column, as in Wireshark.
    // Initial packets are decrypted (their keys follow from the connection ID)
    // to list their frames and read the Client Hello's server name.
    bool quic(size_t off, size_t len) {
        if (len < 7 || !b_.have(off, len)) return false;
        uint8_t b0 = b_.u8(off);
        if (!(b0 & 0x40)) return false;  // QUIC's fixed bit
        d_.protocol = "QUIC";
        Layer& l = layer("QUIC IETF", off, len);
        fproto("quic", off, len);
        if (st_.quic.size() > 100'000) st_.quic.clear();
        auto& qc = st_.quic[l4_key_];
        size_t pos = 0;
        while (pos < len) {
            const uint8_t* p = b_.p + off + pos;
            size_t avail = len - pos;
            if (!(p[0] & 0x80)) {  // short header: the DCID's length is whatever the receiver chose
                bool from_client = qc.odcid.empty() || udp_a_to_b_ == qc.client_a_to_b;
                int dl = qc.odcid.empty() ? 0 : qc.cid_len[from_client ? 1 : 0];
                // The key phase bit is under header protection, which needs 1-RTT keys:
                // unknown, so Wireshark shows phase 0.
                d_.info = "Protected Payload (KP0)";
                if (dl > 0 && static_cast<size_t>(dl) + 1 <= avail) {
                    d_.info += ", DCID=" + hex_id(std::string(reinterpret_cast<const char*>(p + 1), dl));
                    if (!qc.short_tried[from_client ? 0 : 1]) {  // without 1-RTT keys, once per direction
                        qc.short_tried[from_client ? 0 : 1] = true;
                        expert("quic.decryption_failed", 2, "Decryption", "QUIC",
                               "Failed to create decryption context: Secrets are not available");
                    }
                }
                break;
            }
            QuicLongHeader h;
            if (!quic_parse_long_header(p, avail, h)) {
                if (pos == 0) d_.info = "Long Header";
                break;
            }
            if (h.version == 0) {
                d_.info = "Version Negotiation";
                break;
            }
            static const char* types[] = {"Initial", "0-RTT", "Handshake", "Retry"};
            if (!quic_known_version(h.version)) {
                d_.info = fmt("%s, DCID=%s", types[(p[0] >> 4) & 3], hex_id(h.dcid).c_str());
                break;
            }
            FIELD(l, "Version", fmt("0x%08x", h.version), off + pos + 1, 4);
            FIELD(l, "Destination Connection ID", hex_id(h.dcid), off + pos + 6, h.dcid.size());
            if (!h.scid.empty()) FIELD(l, "Source Connection ID", hex_id(h.scid), off + pos + 7 + h.dcid.size(), h.scid.size());
            std::string info = types[static_cast<int>(h.type)];
            if (!h.dcid.empty()) info += ", DCID=" + hex_id(h.dcid);
            if (!h.scid.empty()) info += ", SCID=" + hex_id(h.scid);
            if (h.type == QuicType::Initial && qc.odcid.empty() && !h.dcid.empty()) {  // the client's first
                qc.odcid = h.dcid;
                qc.version = h.version;
                qc.client_a_to_b = udp_a_to_b_;
            }
            bool from_client = qc.odcid.empty() || udp_a_to_b_ == qc.client_a_to_b;
            if (h.type != QuicType::Retry) qc.cid_len[from_client ? 0 : 1] = static_cast<int>(h.scid.size());
            if ((h.type == QuicType::Handshake || h.type == QuicType::ZeroRtt) && !qc.odcid.empty())
                expert("quic.decryption_failed", 2, "Decryption", "QUIC",
                       "Failed to create decryption context: Secrets are not available");
            QuicKeys keys;
            uint64_t pn = 0;
            std::string payload;
            if (h.type == QuicType::Initial && !qc.odcid.empty() &&
                quic_initial_keys(qc.version, qc.odcid, !from_client, keys) &&
                quic_open(p, h, keys, qc.largest[from_client ? 0 : 1], pn, payload)) {
                int64_t& largest = qc.largest[from_client ? 0 : 1];
                if (static_cast<int64_t>(pn) > largest) largest = static_cast<int64_t>(pn);
                info += fmt(", PKN: %llu", static_cast<unsigned long long>(pn));
                QuicFrames frames = quic_frames(payload);
                for (const auto& name : frames.names) info += ", " + name;
                // Wireshark hands TLS the CRYPTO stream as a frame extends it from its start, whole
                // hello or not, but not while out-of-order pieces still wait beyond a gap.
                QuicCryptoStream& cs = from_client ? qc.crypto : qc.server_crypto;
                for (const auto& c : frames.crypto) {
                    size_t had = cs.head().size();
                    cs.add(c.first, c.second);
                    if (cs.head().size() > had && cs.contiguous()) fproto("tls", 0, 0);
                }
                if (from_client) quic_client_hello(qc, l, off + pos);
                else quic_server_hello(qc);
            }
            d_.info = info;
            if (h.length == 0) break;
            pos += h.length;
        }
        return true;
    }

    // The checks Wireshark's TLS dissector makes on a hello, run on one that QUIC carried.
    void quic_hello_checks(const std::string& hs, bool server) {
        Bytes saved = b_;
        bool saved_virtual = virtual_;
        b_ = {reinterpret_cast<const uint8_t*>(hs.data()), hs.size()};
        virtual_ = true;
        size_t mlen = hs.size() - 4;
        if (tls_hello_has_ext(4, mlen, server, 0x002b)) expert("tls.handshake.legacy_version");
        tls_check_hello_extensions(4, mlen, server);
        b_ = saved;
        virtual_ = saved_virtual;
    }

    void quic_server_hello(InspectorState::QuicConn& qc) {
        const std::string& hs = qc.server_crypto.head();
        if (qc.server_hello_done || hs.size() < 4 || hs[0] != 2) return;
        size_t mlen = (static_cast<size_t>(static_cast<uint8_t>(hs[1])) << 16) |
                      (static_cast<size_t>(static_cast<uint8_t>(hs[2])) << 8) | static_cast<uint8_t>(hs[3]);
        if (hs.size() < 4 + mlen) return;
        qc.server_hello_done = true;
        fproto("tls", 0, 0);
        FF(uint("tls.handshake.type", 2));
        quic_hello_checks(hs.substr(0, 4 + mlen), true);
        std::string rec("\x16\x03\x03", 3);
        rec.push_back(static_cast<char>(((4 + mlen) >> 8) & 0xFF));
        rec.push_back(static_cast<char>((4 + mlen) & 0xFF));
        rec.append(hs, 0, 4 + mlen);
        if (auto sh = parse_tls_server_hello(rec)) {
            FF(string("tls.handshake.ja3s_full", sh->ja3s));
            FF(string("tls.handshake.ja3s", sh->ja3s_hash));
        }
    }

    // Once the client's CRYPTO stream holds its whole Client Hello: the TLS fields.
    void quic_client_hello(InspectorState::QuicConn& qc, Layer& l, size_t at) {
        if (qc.hello_done) return;
        bool complete = false;
        auto ch = anta::quic_client_hello(qc.crypto.head(), complete);
        qc.hello_done = complete;
        if (!ch) return;
        fproto("tls", 0, 0);
        FF(uint("tls.handshake.type", 1));
        quic_hello_checks(qc.crypto.head(), false);
        if (!ch->sni.empty()) FF(string("tls.handshake.extensions_server_name", ch->sni));
        FF(string("tls.handshake.ja3_full", ch->ja3));
        FF(string("tls.handshake.ja3", ch->ja3_hash));
        FF(string("tls.handshake.ja4", ch->ja4));
        if (full_) {
            if (!ch->sni.empty()) field(l, "Server Name Indication", ch->sni, at, 0);
            field(l, "JA4", ch->ja4, at, 0);
        }
    }

#undef FIELD
#undef INFO
#undef FF

    InspectorState& st_;
    Bytes b_;
    uint64_t frame_;
    uint64_t ts_;
    bool full_;
    DecodedFrame d_;
    Layer dummy_;
    IpAddr src_ip_, dst_ip_;
    uint8_t ttl_ = 0;
    size_t l4_reported_ = 0;  // L4 length per the IP header (0 = unknown)
    FlowKey key_;
    uint16_t sport_ = 0, dport_ = 0;
    bool udp_a_to_b_ = false;
    bool ldap_in_frame_ = false;
    bool sack_now_ = false;  // this TCP segment carries SACK blocks  // a later LDAP PDU in the frame gets " | " before it
    // Wireshark's decode_data->dcectxid: the context of the frame's previous DCE/RPC
    // PDU. Only when it is non-zero does the next PDU get " # " (and a fence) before
    // it; otherwise the next PDU's Info replaces it.
    uint16_t rpc_ctx_ = 0;
    FlowKey l4_key_{};  // the TCP or UDP conversation the current payload belongs to
    size_t wire_len_ = 0;  // the frame's length on the wire (0: same as captured)
    bool in_error_ = false;  // decoding the packet quoted in an ICMP error
    InspectorState* streams_ = nullptr;  // whose udp.stream table a quoted packet uses
    // TCP payload state for this frame.
    struct Deseg {
        size_t offset = 0;
        uint32_t len = 0;  // 0: complete; else bytes still needed, kOneMore or kUntilFin
    };
    Deseg deseg_;
    bool can_desegment_ = false;
    bool http_tls_ = false;  // decoding HTTP decrypted from TLS (its URIs are https://)
    bool seg_fin_ = false;   // the TCP segment being dissected carries a FIN
    bool tls_eos_ = false;   // a close_notify was read in this TLS dissection: the sender's stream ended
    size_t dtls_base_ = 0, dtls_end_ = 0;  // the DTLS datagram being read
    static constexpr long long kNoBase = -(1LL << 40);
    long long tls_rec_base_ = kNoBase;  // where the handshake record being read starts in the transcript
    uint32_t app_seq_ = 0;   // the TCP sequence number of the application data at app_base_
    size_t app_base_ = 0;
    bool virtual_ = false;   // decoding a reassembled buffer rather than the frame
    size_t reported_ = 0;    // its full length (more than is kept for huge messages)
    std::string col_, tcp_col_;
    size_t fence_ = 0, tcp_fence_ = 0;
    bool proto_writable_ = true;
    bool annotated_ = false;
    FrameFields* ff_ = nullptr;
    bool ff_virtual_ = false;  // field offsets don't map onto the frame (a rebuilt IP datagram)
    bool frozen_ = false;    // the Info/Protocol columns are final for this frame
    int cur_dir_ = 0;
};

void write_layers(JsonWriter& w, const DecodedFrame& d) {
    w.key("layers").begin_array();
    for (const auto& l : d.layers) {
        w.begin_object().kv("name", l.name).kv("offset", l.offset).kv("length", l.length);
        w.key("fields").begin_array();
        for (const auto& f : l.fields) {
            w.begin_array().value(f.name).value(f.value).value(f.offset).value(f.length).end_array();
        }
        w.end_array();
        w.end_object();
    }
    w.end_array();
}

}  // namespace

Inspector::Inspector() : st_(std::make_unique<InspectorState>()) {}

Inspector::Inspector(InspectorAnnotations* record, const InspectorAnnotations* use)
    : st_(std::make_unique<InspectorState>()) {
    st_->record = record;
    st_->use = use;
}

Inspector::~Inspector() = default;

void Inspector::set_keylog(const TlsKeyLog* keylog) { st_->keylog = keylog; }
void Inspector::set_follow_tap(FollowTap* tap) { st_->tap = tap; }

DecodedFrame Inspector::decode(LinkType link, const uint8_t* data, size_t caplen, uint64_t frame, uint64_t ts_us,
                               FrameFields* fields, uint32_t wire_len) {
    if (!st_->first_ts_set) {
        st_->first_ts = ts_us;
        st_->first_ts_set = true;
    }
    if (fields) {
        fields->clear();
        fields->frame = data;
        fields->frame_len = caplen;
        fields->proto("frame", 0, caplen);
        fields->uint("frame.number", frame);
        fields->uint("frame.len", wire_len ? wire_len : caplen);
        fields->uint("frame.cap_len", caplen);
        fields->real("frame.time_epoch", static_cast<double>(ts_us) / 1e6);
        fields->real("frame.time_relative", (static_cast<double>(ts_us) - static_cast<double>(st_->first_ts)) / 1e6);
        fields->real("frame.time_delta", st_->prev_ts_set ? (static_cast<double>(ts_us) - static_cast<double>(st_->prev_ts)) / 1e6 : 0.0);
    }
    st_->prev_ts = ts_us;
    st_->prev_ts_set = true;
    Decoder dec(*st_, data, caplen, frame, ts_us, true);
    dec.want_fields(fields);
    dec.set_wire_len(wire_len);
    DecodedFrame d = dec.run(link);
    if (fields) {
        if (d.malformed) {
            fields->proto("_ws.malformed", 0, 0);
            if (!fields->has_proto("_ws.expert")) fields->proto("_ws.expert", 0, 0);
        }
        fields->string("frame.protocols", fields->protocols());
    }
    return d;
}

void Inspector::observe(LinkType link, const uint8_t* data, size_t caplen, uint64_t frame, uint64_t ts_us) {
    if (!st_->first_ts_set) {
        st_->first_ts = ts_us;
        st_->first_ts_set = true;
    }
    st_->prev_ts = ts_us;
    st_->prev_ts_set = true;
    Decoder(*st_, data, caplen, frame, ts_us, false).run(link);
}

DecodedFrame decode_frame(LinkType link, const uint8_t* data, size_t caplen) {
    InspectorState st;
    return Decoder(st, data, caplen, 1, 0, true).run(link);
}

void write_packet_summary(JsonWriter& w, const DecodedFrame& d, uint64_t frame, uint64_t ts_us, uint32_t wire_len,
                          uint32_t caplen, int color) {
    w.begin_object()
        .kv("type", "packet")
        .kv("n", frame)
        .kv("ts", static_cast<double>(ts_us) / 1e6)
        .kv("len", wire_len)
        .kv("cap", caplen)
        .kv("src", d.src)
        .kv("dst", d.dst)
        .kv("proto", d.protocol)
        .kv("info", d.info);
    if (!d.expert.empty()) w.kv("expert", true);
    if (color >= 0) w.kv("color", static_cast<uint64_t>(color));
    w.end_object();
}

void write_packet_detail(JsonWriter& w, const DecodedFrame& d, uint64_t frame, uint64_t ts_us, uint32_t wire_len,
                         const uint8_t* data, uint32_t caplen, const FrameFields* fields) {
    static const char* hex = "0123456789abcdef";
    std::string bytes;
    bytes.reserve(static_cast<size_t>(caplen) * 2);
    for (uint32_t i = 0; i < caplen; ++i) {
        bytes.push_back(hex[data[i] >> 4]);
        bytes.push_back(hex[data[i] & 0x0F]);
    }
    w.begin_object()
        .kv("type", "packet_detail")
        .kv("n", frame)
        .kv("ts", static_cast<double>(ts_us) / 1e6)
        .kv("len", wire_len)
        .kv("cap", caplen)
        .kv("src", d.src)
        .kv("dst", d.dst)
        .kv("proto", d.protocol)
        .kv("info", d.info)
        .kv("malformed", d.malformed)
        .kv("hex", bytes);
    write_layers(w, d);
    if (fields) {
        w.kv("protocols", fields->protocols());
        w.key("fields").begin_array();
        for (const auto& p : fields->protos) {
            if (std::strcmp(p.name, "frame") == 0) continue;
            w.begin_array().value(p.name).value("").end_array();
        }
        for (const auto& f : fields->fields) {
            if (std::strncmp(f.name, "_anta.", 6) == 0) continue;  // internal, not filterable
            w.begin_array().value(f.name).value(filter_literal(f.value)).end_array();
        }
        w.end_array();
    }
    w.end_object();
}

}  // namespace anta
