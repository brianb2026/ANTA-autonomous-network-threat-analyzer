// Per-frame decoding for the packet viewer: a one-line summary (No., Time,
// Source, Destination, Protocol, Length, Info) and a full layer breakdown with
// byte offsets so the UI can highlight fields in a hex dump.
//
// Like Wireshark, some columns depend on earlier frames (relative TCP sequence
// numbers, window scaling, retransmission analysis, SSH key-exchange state, FTP
// data channels, ICMP request/reply pairing). An Inspector carries that state:
// feed it every frame in capture order, calling observe() for frames you don't
// need to display (cheap) and decode() for the ones you do.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "dfilter.h"
#include "json.h"
#include "packet.h"

namespace anta {

struct Field {
    std::string name;
    std::string value;
    uint32_t offset = 0;
    uint32_t length = 0;
};

struct Layer {
    std::string name;
    uint32_t offset = 0;
    uint32_t length = 0;
    std::vector<Field> fields;
};

// An expert-info item whose wording varies, for the statistics' Expert Information.
struct ExpertNote {
    int severity = 0;        // 0 Chat, 1 Note, 2 Warning, 3 Error
    const char* group = "";  // Wireshark's group, e.g. "Malformed"
    std::string protocol, summary;
};

struct DecodedFrame {
    std::vector<Layer> layers;
    std::string protocol = "Frame";  // deepest protocol recognised
    std::string info;
    std::string src, dst;
    std::string expert;              // TCP analysis flags, e.g. "TCP Retransmission"
    bool malformed = false;
    bool exceeds_mss = false;        // TCP segment longer than the receiver's MSS (an expert-tap-only note)
    std::vector<ExpertNote> notes;   // other expert items of the outer packet
};

struct InspectorState;
class TlsKeyLog;

// What the decoder decrypts and decodes, for Follow TLS Stream and Follow HTTP/2 Stream.
// Called while a frame is decoded; the frame's own addresses say which side sent it.
class FollowTap {
public:
    virtual ~FollowTap() = default;
    virtual void tls_data(const uint8_t* p, size_t n) = 0;                  // decrypted application data
    virtual void h2_block(uint32_t stream, const std::string& text) = 0;    // a header block, "name: value" lines
    virtual void h2_data(uint32_t stream, const uint8_t* p, size_t n) = 0;  // a DATA frame's content
};

// Cross-references that need to look ahead (Wireshark fills these in on its
// second pass): which frame completes a reassembled TCP message, which reply
// answers an ICMP echo request, which frame reassembles an IP fragment, and the
// TLS version a conversation ends up negotiating.
struct InspectorAnnotations {
    // TCP message pieces: frame -> (message's first sequence number, frame that completed it)
    std::unordered_map<uint64_t, std::vector<std::pair<uint32_t, uint64_t>>> reassembled_in;
    std::unordered_map<uint64_t, uint64_t> reply_in;        // ICMP echo request -> reply
    std::unordered_map<uint64_t, uint64_t> request_in;      // ICMP echo reply -> request
    std::unordered_map<uint64_t, uint64_t> dns_response_in; // DNS request -> response
    std::unordered_map<uint64_t, uint64_t> fragment_in;     // IP fragment -> reassembling frame
    std::unordered_set<uint64_t> piece_start;               // frame starts a multi-segment TCP message
    struct MspInfo {
        uint32_t nxtpdu = 0;
        uint64_t reassembled_in = 0;
        uint64_t first_frame = 0;  // the frame that began it (a later one can replace it)
    };
    // Every TCP message's final extent, per conversation direction (keyed by first sequence number).
    std::unordered_map<size_t, std::map<uint32_t, MspInfo>> msps;
    std::unordered_map<size_t, uint16_t> tls_version;       // conversation hash -> TLS version
    std::unordered_map<size_t, uint32_t> ldap_results;      // conversation hash -> LDAP search entries
    std::unordered_map<uint64_t, uint64_t> rpc_reassembled; // DCE/RPC fragment frame -> frame completing it
    std::unordered_map<size_t, uint8_t> ssh_version;        // conversation hash -> SSH protocol version
    std::unordered_map<uint64_t, uint64_t> tls_reassembled_in; // decrypted TLS piece frame -> frame completing it
    std::unordered_map<uint64_t, uint64_t> h2_response_in;  // (request frame << 32 | stream) -> response frame
    std::map<std::pair<size_t, uint32_t>, std::string> h2_uri;  // (conversation, stream) -> its request URI
    // HTTP/1.x request/response pairs as the first pass made them, and which pair each
    // frame's last HTTP message used (Wireshark's second pass shows a frame that way).
    struct HttpPair {
        uint64_t req_frame = 0, req_ts = 0, res_frame = 0;
        std::string uri, full_uri;
    };
    std::vector<HttpPair> http_pairs;
    std::unordered_map<uint64_t, uint32_t> http_frame_pair;
    // DTLS: the version each conversation ends on (0 when none was settled; every
    // conversation DTLS was read on is listed), and the handshake messages the first pass
    // reassembled, by (conversation, direction << 32 | epoch << 16 | message_seq).
    std::unordered_map<size_t, uint16_t> dtls_version;
    struct DtlsMessage {
        uint32_t length = 0;
        std::string data;
    };
    std::map<std::pair<size_t, uint64_t>, DtlsMessage> dtls_reassembled;
    bool complete = false;                                  // the first pass saw the whole capture
};

class Inspector {
public:
    Inspector();
    // Two-pass use: a first Inspector records annotations, a second one uses them.
    Inspector(InspectorAnnotations* record, const InspectorAnnotations* use);
    ~Inspector();
    Inspector(const Inspector&) = delete;
    Inspector& operator=(const Inspector&) = delete;

    // `fields`, if given, receives the frame's display-filter fields (Wireshark names).
    DecodedFrame decode(LinkType link, const uint8_t* data, size_t caplen, uint64_t frame, uint64_t ts_us,
                        FrameFields* fields = nullptr, uint32_t wire_len = 0);
    void observe(LinkType link, const uint8_t* data, size_t caplen, uint64_t frame, uint64_t ts_us);

    // TLS secrets (from a user-supplied key log) used to decrypt records; not owned.
    void set_keylog(const TlsKeyLog* keylog);
    void set_follow_tap(FollowTap* tap);

private:
    std::unique_ptr<InspectorState> st_;
};

// Stateless one-off decode (no cross-frame context).
DecodedFrame decode_frame(LinkType link, const uint8_t* data, size_t caplen);

// `color`: index of the first coloring rule the frame matched (-1: none).
void write_packet_summary(JsonWriter& w, const DecodedFrame& d, uint64_t frame, uint64_t ts_us, uint32_t wire_len,
                          uint32_t caplen, int color = -1);
// `fields`, if given, adds the frame's filter fields so a viewer can build filters from them.
void write_packet_detail(JsonWriter& w, const DecodedFrame& d, uint64_t frame, uint64_t ts_us, uint32_t wire_len,
                         const uint8_t* data, uint32_t caplen, const FrameFields* fields = nullptr);

}  // namespace anta
