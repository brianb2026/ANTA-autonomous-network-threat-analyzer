// anta-engine: capture -> dissect -> reassemble -> emit session metadata as
// JSON records over stdout, ZeroMQ (ZMTP 3.0) or a Unix socket.

#include "platform.h"

#ifndef _WIN32
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <signal.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "capture.h"
#include "emitter.h"
#include "flow.h"
#include "dfilter.h"
#include "dpi.h"
#include "inspect.h"
#include "sanitize.h"
#include "stats.h"
#include "tlskeys.h"
#include "json.h"

using namespace anta;

namespace {

constexpr const char* kVersion = "0.1.0";

// Also touched from signal handlers and watcher threads.
std::atomic<PacketSource*> g_source{nullptr};
std::atomic<Emitter*> g_emitter{nullptr};
volatile sig_atomic_t g_signals = 0;

#ifndef _WIN32
void on_deadline(int) { _exit(1); }  // still not down 15 s after being told to stop: something blocked
#endif

void on_signal(int) {
    if (PacketSource* src = g_source.load()) src->stop();
    // A second Ctrl-C abandons records still waiting for an absent analyzer.
    if (++g_signals > 1)
        if (Emitter* em = g_emitter.load()) em->abort();
#ifndef _WIN32
    // Whatever happens, a stop request ends the process: a capture left running
    // as root after its app is gone is exactly what must not happen.
    if (g_signals == 1) {
        signal(SIGALRM, on_deadline);
        alarm(15);
    }
#endif
}

uint64_t wall_us() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<microseconds>(system_clock::now().time_since_epoch()).count());
}

bool g_redact = false;
bool g_compact = false;  // --index: session records without events, entropy or rates

// Drop root after the capture device and output files are open. Packet parsing
// then runs unprivileged, so a parser bug can't be leveraged into root.
// Target: --user NAME, else the account that invoked sudo (SUDO_UID/SUDO_GID)
// or pkexec (PKEXEC_UID). Windows has no root to drop: Npcap grants capture access.
#ifdef _WIN32
bool drop_privileges(const std::string&, const std::vector<std::string>&) { return true; }
#else
bool drop_privileges(const std::string& user, const std::vector<std::string>& owned_files) {
    if (geteuid() != 0) return true;
    uid_t uid = 0;
    gid_t gid = 0;
    if (!user.empty()) {
        passwd* pw = getpwnam(user.c_str());
        if (!pw) {
            std::fprintf(stderr, "anta-engine: unknown user '%s'\n", user.c_str());
            return false;
        }
        uid = pw->pw_uid;
        gid = pw->pw_gid;
    } else if (const char* su = std::getenv("SUDO_UID")) {
        uid = static_cast<uid_t>(std::strtoul(su, nullptr, 10));
        const char* sg = std::getenv("SUDO_GID");
        gid = sg ? static_cast<gid_t>(std::strtoul(sg, nullptr, 10)) : uid;
    } else if (const char* pk = std::getenv("PKEXEC_UID")) {
        uid = static_cast<uid_t>(std::strtoul(pk, nullptr, 10));
        passwd* pw = getpwuid(uid);
        gid = pw ? pw->pw_gid : uid;
    }
    if (uid == 0) {
        std::fprintf(stderr, "anta-engine: warning: still running as root; pass --user NAME to drop privileges\n");
        return true;
    }
    // The recording must stay writable (rotation) and readable by the analyzer.
    for (const auto& path : owned_files)
        if (!path.empty() && chown(path.c_str(), uid, gid) != 0)
            std::fprintf(stderr, "anta-engine: chown %s: %s\n", path.c_str(), std::strerror(errno));
    if (setgroups(1, &gid) != 0 || setgid(gid) != 0 || setuid(uid) != 0) {
        std::fprintf(stderr, "anta-engine: failed to drop privileges: %s\n", std::strerror(errno));
        return false;
    }
    if (setuid(0) == 0) {  // must be irreversible
        std::fprintf(stderr, "anta-engine: privilege drop is reversible; refusing to continue\n");
        return false;
    }
    std::fprintf(stderr, "anta-engine: dropped privileges to uid %u\n", static_cast<unsigned>(uid));
    return true;
}
#endif

// Minimal portable option parser (getopt_long is not available on Windows).
// Accepts -x VALUE, -xVALUE, --long VALUE and --long=VALUE.
struct OptSpec {
    char short_name;
    const char* long_name;
    bool has_value;
    int id;
};

bool next_option(int argc, char** argv, int& i, const std::vector<OptSpec>& specs, int& id, std::string& value) {
    if (i >= argc) return false;
    std::string arg = argv[i++];
    const OptSpec* spec = nullptr;
    std::string inline_value;
    bool has_inline = false;
    if (arg.rfind("--", 0) == 0) {
        std::string name = arg.substr(2);
        size_t eq = name.find('=');
        if (eq != std::string::npos) {
            inline_value = name.substr(eq + 1);
            name = name.substr(0, eq);
            has_inline = true;
        }
        for (const auto& s : specs)
            if (name == s.long_name) spec = &s;
    } else if (arg.size() >= 2 && arg[0] == '-') {
        for (const auto& s : specs)
            if (s.short_name && arg[1] == s.short_name) spec = &s;
        if (arg.size() > 2) {
            inline_value = arg.substr(2);
            has_inline = true;
        }
    }
    if (!spec || (has_inline && !spec->has_value)) {
        std::fprintf(stderr, "anta-engine: unknown option '%s'\n", arg.c_str());
        id = -1;
        return true;
    }
    id = spec->id;
    value.clear();
    if (spec->has_value) {
        if (has_inline) {
            value = inline_value;
        } else if (i < argc) {
            value = argv[i++];
        } else {
            std::fprintf(stderr, "anta-engine: option '%s' needs a value\n", arg.c_str());
            id = -1;
        }
    }
    return true;
}

int print_interfaces() {
    std::vector<InterfaceInfo> devs;
    std::string error;
    if (!list_interfaces(devs, error)) {
        std::fprintf(stderr, "anta-engine: %s\n", error.c_str());
        return 1;
    }
    JsonWriter w;
    w.begin_array();
    for (const auto& d : devs) {
        w.begin_object()
            .kv("name", d.name)
            .kv("description", d.description)
            .kv("loopback", d.loopback)
            .kv("up", d.up)
            .kv("running", d.running)
            .kv("wireless", d.wireless);
        w.key("addresses").begin_array();
        for (const auto& a : d.addresses) w.value(a);
        w.end_array();
        w.end_object();
    }
    w.end_array();
    std::printf("%s\n", w.str().c_str());
    return 0;
}

std::string redact_uri(const std::string& uri) {
    size_t q = uri.find_first_of("?#");
    return q == std::string::npos ? uri : uri.substr(0, q) + "?[redacted]";
}

const char* proto_name(uint8_t p) { return p == 6 ? "tcp" : p == 17 ? "udp" : "other"; }

std::string hex_bytes(const std::string& b) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    for (unsigned char c : b) {
        out.push_back(digits[c >> 4]);
        out.push_back(digits[c & 15]);
    }
    return out;
}

// "1-20,35,40-41" -> sorted, merged [first, last] ranges (frames count from 1).
bool parse_frame_ranges(const std::string& spec, std::vector<std::pair<uint64_t, uint64_t>>& out) {
    out.clear();
    size_t pos = 0;
    while (pos < spec.size()) {
        size_t end = spec.find(',', pos);
        if (end == std::string::npos) end = spec.size();
        std::string part = spec.substr(pos, end - pos);
        unsigned long long a = 0, b = 0;
        int used = 0;
        if (std::sscanf(part.c_str(), "%llu-%llu%n", &a, &b, &used) == 2 && used == static_cast<int>(part.size())) {
        } else if (std::sscanf(part.c_str(), "%llu%n", &a, &used) == 1 && used == static_cast<int>(part.size())) {
            b = a;
        } else {
            return false;
        }
        if (a == 0 || b < a || out.size() >= 1'000'000) return false;
        out.emplace_back(a, b);
        pos = end + 1;
    }
    std::sort(out.begin(), out.end());
    std::vector<std::pair<uint64_t, uint64_t>> merged;
    for (const auto& r : out) {
        if (!merged.empty() && r.first <= merged.back().second + 1) merged.back().second = std::max(merged.back().second, r.second);
        else merged.push_back(r);
    }
    out.swap(merged);
    return !out.empty();
}

std::string serialize(const Flow& f, bool final, const std::string& capture_path) {
    JsonWriter w;
    w.begin_object();
    w.kv("type", "session");
    w.kv("final", final);
    w.kv("flow_id", f.id);
    w.kv("proto", proto_name(f.proto));
    w.kv("src_ip", f.client_ip.str());
    w.kv("src_port", static_cast<unsigned>(f.client_port));
    w.kv("dst_ip", f.server_ip.str());
    w.kv("dst_port", static_cast<unsigned>(f.server_port));
    w.kv("start", static_cast<double>(f.first_ts) / 1e6);
    w.kv("end", static_cast<double>(f.last_ts) / 1e6);
    w.kv("capture", capture_path);
    if (f.evicted) w.kv("evicted", true);
    {  // The application, from the first bytes each side sent (DPI), else from the port.
        AppId app = identify_app(f.proto, f.head[0], f.head[1]);
        if (!*app.name && f.ftp_transfer) app = {"ftp-data", "FTP data"};
        const char* by_port = app_for_port(f.proto, f.server_port);
        bool payload = *app.name != 0;
        w.kv("app", payload ? app.name : by_port);
        if (payload) w.kv("app_label", app.label);
        w.kv("app_source", payload ? "payload" : *by_port ? "port" : "");
        if (payload && !app_fits_port(f.proto, f.server_port, app.name)) w.kv("app_expected", by_port);
    }

    static const char* dir_names[2] = {"c2s", "s2c"};
    for (int d = 0; d < 2; ++d) {
        w.key(dir_names[d]).begin_object();
        w.kv("packets", f.stats[d].packets);
        w.kv("bytes", f.stats[d].bytes);
        w.kv("payload_bytes", f.stats[d].payload_bytes);
        w.end_object();
    }

    if (f.proto == 6) {
        w.key("tcp").begin_object();
        w.kv("handshake", f.handshake_seen);
        w.kv("closed", f.closed);
        w.kv("rst", f.tcp[0].rst_seen || f.tcp[1].rst_seen);
        uint64_t retrans = 0, ooo = 0, gaps = 0, zero_win = 0;
        for (const auto& s : f.tcp) {
            retrans += s.retransmissions;
            ooo += s.out_of_order;
            gaps += s.gap_bytes;
            zero_win += s.zero_window;
        }
        w.kv("retransmissions", retrans);
        w.kv("out_of_order", ooo);
        w.kv("gap_bytes", gaps);
        w.kv("zero_window", zero_win);
        w.kv("null_flags", f.null_flags);
        if (f.synack_ts) w.kv("syn_rtt_ms", static_cast<double>(f.synack_ts - f.syn_ts) / 1000.0);
        if (f.hs_ack_ts) w.kv("ack_rtt_ms", static_cast<double>(f.hs_ack_ts - f.synack_ts) / 1000.0);
        w.end_object();
    }

    if (!g_compact) {  // an index needs who, what and when, not the per-packet shape
        // Payload-bearing packets: [relative_ms, signed_len] where the sign is the
        // direction (+ client->server, - server->client). Compact and easy to plot.
        w.key("events").begin_array();
        for (const auto& e : f.events) {
            w.begin_array();
            w.value(static_cast<double>(e.ts_us - f.first_ts) / 1000.0);
            int64_t len = static_cast<int64_t>(e.len);
            w.value(e.dir == Dir::ClientToServer ? len : -len);
            w.end_array();
        }
        w.end_array();
        w.kv("events_dropped", f.events_dropped);

        // Shannon entropy (bits/byte) of the first bytes of each stream: ~8 means
        // encrypted or compressed, < 6 usually plaintext.
        w.key("payload_entropy").begin_object();
        for (int d = 0; d < 2; ++d) {
            w.key(dir_names[d]);
            if (f.entropy[d] >= 0) w.value(f.entropy[d]);
            else w.null_value();
        }
        w.kv("sample_bytes", static_cast<uint64_t>(std::max(f.entropy_sample[0], f.entropy_sample[1])));
        w.end_object();

        // Coarse throughput over the whole session (trailing empty buckets trimmed).
        size_t used = RateHistogram::kBuckets;
        while (used > 0 && f.rate.out[used - 1] == 0 && f.rate.in[used - 1] == 0) --used;
        w.key("rate").begin_object();
        w.kv("bucket_ms", static_cast<double>(f.rate.bucket_us) / 1000.0);
        w.key("out").begin_array();
        for (size_t i = 0; i < used; ++i) w.value(f.rate.out[i]);
        w.end_array();
        w.key("in").begin_array();
        for (size_t i = 0; i < used; ++i) w.value(f.rate.in[i]);
        w.end_array();
        w.end_object();
    }

    if (f.logins && !f.logins->logins.empty()) {  // logins sent in clear text: never the password
        w.key("logins").begin_array();
        for (const auto& l : f.logins->logins) {
            w.begin_object().kv("proto", l.proto).kv("method", l.method).kv("user", l.user);
            w.key("accepted");
            if (l.accepted < 0) w.null_value();
            else w.value(l.accepted == 1);
            if (l.anonymous) w.kv("anonymous", true);
            if (l.default_secret) w.kv("default_secret", true);
            w.kv("ts", static_cast<double>(l.ts) / 1e6);
            w.end_object();
        }
        w.end_array();
    }
    if (!f.dns.empty()) {
        w.key("dns").begin_array();
        for (const auto& m : f.dns) {
            w.begin_object();
            w.kv("qname", m.qname);
            w.kv("qtype", static_cast<unsigned>(m.qtype));
            w.kv("answered", m.is_response);
            w.kv("rcode", static_cast<unsigned>(m.rcode));
            w.kv("txt_bytes", m.txt_bytes);
            w.key("answers").begin_array();
            for (const auto& a : m.answers) w.value(a);
            w.end_array();
            w.end_object();
        }
        w.end_array();
    }
    if (!f.http.empty()) {
        w.key("http").begin_array();
        for (const auto& r : f.http) {
            w.begin_object();
            w.kv("method", r.method);
            w.kv("host", r.host);
            w.kv("uri", g_redact ? redact_uri(r.uri) : r.uri);
            w.kv("user_agent", r.user_agent);
            w.kv("content_length", r.content_length);
            w.end_object();
        }
        w.end_array();
    }
    if (f.h2 && f.h2->reader.frames()) w.kv("http2", true);  // its HTTP was HTTP/2
    if (f.http_response) {
        w.key("http_response").begin_object();
        w.kv("status", f.http_response->status);
        w.kv("server", f.http_response->server);
        w.kv("content_type", f.http_response->content_type);
        w.end_object();
    }
    if (f.http_bodies && !f.http_bodies->files.empty()) {
        w.key("http_files").begin_array();
        for (const auto& file : f.http_bodies->files) {
            const HttpRequest* req = file.response < f.http.size() ? &f.http[file.response] : nullptr;
            w.begin_object();
            if (req) {
                w.kv("method", req->method);
                w.kv("host", req->host);
                w.kv("uri", g_redact ? redact_uri(req->uri) : req->uri);
                w.kv("user_agent", req->user_agent);
            }
            w.kv("n", static_cast<uint64_t>(file.response));  // which response: names it for --object
            w.kv("status", file.status);
            w.kv("content_type", file.content_type);
            if (!file.content_encoding.empty()) w.kv("content_encoding", file.content_encoding);
            if (!file.filename.empty()) w.kv("filename", file.filename);
            if (file.length_known) w.kv("declared_length", file.declared_length);
            w.kv("size", file.size);
            if (file.decoded) w.kv("encoded_size", file.encoded_size);
            w.kv("magic", hex_bytes(file.magic));
            w.kv("sha256", file.sha256);
            w.kv("complete", file.complete);
            w.kv("ts", static_cast<double>(file.ts) / 1e6);
            w.end_object();
        }
        w.end_array();
    }
    if (f.ftp_control) {
        w.key("ftp").begin_object();
        w.kv("user", f.ftp_control->user);
        w.kv("tls_refused", f.ftp_control->tls_refused);
        w.key("commands").begin_array();
        for (const auto& c : f.ftp_control->commands) w.value(c);
        w.end_array();
        w.end_object();
    }
    if (f.ftp_transfer && f.ftp_data) {
        const FtpTransfer& t = *f.ftp_transfer;
        // The file's direction: uploads go from the FTP client, which is the data
        // connection's client in passive mode and its server in active mode.
        int side;
        if (!t.command.empty()) side = (t.upload() != t.active) ? 0 : 1;
        else side = f.ftp_data[0].bytes >= f.ftp_data[1].bytes ? 0 : 1;
        const FtpDataSide& d = f.ftp_data[side];
        bool text = d.bytes > 0 && d.bytes == d.head.size();
        size_t printable = 0;
        for (unsigned char c : d.head) printable += (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t';
        text = text && d.head.find('\0') == std::string::npos && printable * 100 >= d.head.size() * 95;
        w.key("ftp_data").begin_object();
        w.kv("command", t.command);
        w.kv("name", t.name);
        w.kv("user", t.user);
        w.kv("upload", t.upload());
        w.kv("active", t.active);
        w.kv("tls_refused", t.tls_refused);
        w.kv("side", static_cast<uint64_t>(side));
        w.kv("control", t.control);
        w.kv("reply", t.reply);
        w.kv("size", d.bytes);
        w.kv("magic", hex_bytes(d.head.substr(0, 16)));
        w.kv("sha256", d.bytes ? d.hash.hex() : std::string());
        w.kv("complete", f.tcp[side].gap_bytes == 0 && (t.reply.empty() || t.reply[0] == '2'));
        if (text && !g_redact) w.kv("text", d.head);  // a small text file whole (configurations name devices)
        w.end_object();
    }
    if (f.smb && (!f.smb->files().empty() || f.smb->encrypted())) {
        if (f.smb->encrypted()) w.kv("smb_encrypted", true);
        w.key("smb_files").begin_array();
        for (const auto& file : f.smb->files()) {
            w.begin_object();
            w.kv("name", file.name);
            w.kv("share", file.share);
            w.kv("op", file.written ? "write" : "read");
            w.kv("n", file.seq);
            w.kv("size", file.size);
            if (file.end_of_file) w.kv("end_of_file", file.end_of_file);
            w.kv("magic", hex_bytes(file.magic));
            w.kv("sha256", file.sha256);
            w.kv("complete", file.complete);
            w.kv("ts", static_cast<double>(file.ts) / 1e6);
            w.end_object();
        }
        w.end_array();
    }
    if (f.proto == 6 && (!f.head[0].empty() || !f.head[1].empty())) {
        w.key("stream_head").begin_object();
        w.kv("c2s", hex_bytes(f.head[0].substr(0, 16))).kv("s2c", hex_bytes(f.head[1].substr(0, 16)));
        w.kv("c2s_from_start", f.head_from_start[0]).kv("s2c_from_start", f.head_from_start[1]);
        w.kv("first", f.first_speaker == 0 ? "client" : f.first_speaker == 1 ? "server" : "");
        w.end_object();
    }
    if (f.tls) {
        w.key("tls").begin_object();
        w.kv("sni", f.tls->sni);
        w.kv("ja3", f.tls->ja3_hash);
        w.kv("ja3_string", f.tls->ja3);
        w.kv("ja4", f.tls->ja4);
        w.key("alpn").begin_array();
        for (const auto& a : f.tls->alpn) w.value(a);
        w.end_array();
        if (f.tls_server) {
            w.kv("server_version", static_cast<unsigned>(f.tls_server->version));
            w.kv("server_cipher", static_cast<unsigned>(f.tls_server->cipher));
            w.kv("ja3s", f.tls_server->ja3s_hash);
            w.kv("ja3s_string", f.tls_server->ja3s);
            w.kv("ja4s", f.tls_server->ja4s);
        }
        if (f.tls_plain && f.tls_plain->dec.decrypting()) w.kv("decrypted", true);  // read with the user's key log
        w.end_object();
    }
    w.end_object();
    return w.str();
}

// Packet viewer back end: page through capture files (with BPF, flow and
// Wireshark display filters) printing one JSON summary per frame, or decode one
// frame in full.
struct PacketQuery {
    std::vector<uint64_t> bases;
    std::vector<std::string> flows;
    std::string bpf;
    std::string dfilter;              // Wireshark display filter
    std::vector<std::string> colors;  // coloring rules (filters), first match wins
    uint64_t from = 1;
    uint64_t limit = 500;
    bool count = false;
    int64_t detail = -1;
    bool single_pass = false;  // the live-capture view: no look-ahead cross-references
    std::vector<std::string> fields;  // add these fields' values to each summary ("tcp.analysis.*" = a prefix)
    std::string save;          // write the selected frames to this pcap instead of listing them
    std::vector<std::pair<uint64_t, uint64_t>> frames;  // only these frame ranges (sorted, merged)
    std::string keylog;        // a TLS key log (SSLKEYLOGFILE format) for decrypting the user's own TLS
    // Find Packet: text in the packet list's columns (or, with find_details, anywhere in the
    // detail tree), case-insensitive; `last` answers with the last match only (Find Previous).
    std::string find_text;
    bool find_details = false;
    bool last = false;
    // A share-safe copy (with save): stand-in addresses, contents cut; the address key to this file.
    bool sanitize = false;
    SanitizeOptions sanitize_opts;
    std::string sanitize_key;
};

// Whether a decoded frame shows `needle` (lower-case) in its columns, or its detail tree.
bool text_in_frame(const DecodedFrame& d, const std::string& needle, bool details) {
    auto has = [&](const std::string& s) {
        if (s.size() < needle.size()) return false;
        auto it = std::search(s.begin(), s.end(), needle.begin(), needle.end(), [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) == b;
        });
        return it != s.end();
    };
    if (has(d.src) || has(d.dst) || has(d.protocol) || has(d.info)) return true;
    if (!details) return false;
    for (const auto& l : d.layers) {
        if (has(l.name)) return true;
        for (const auto& f : l.fields)
            if (has(f.name) || has(f.value)) return true;
    }
    return false;
}

// The requested fields of a decoded frame (like tshark -T fields), plus its expert
// items: what the connection explainer reads instead of the Info text.
std::string summary_with_fields(const std::string& summary, const DecodedFrame& d, const FrameFields& ff,
                                const std::vector<std::string>& wanted) {
    // Every occurrence, in order: an ICMP error carries the quoted packet's addresses
    // after its own, and a DNS answer has several addresses.
    // Presence-only items (tcp.analysis.retransmission, protocols) come out with "" as
    // their value, as in the packet detail.
    std::vector<std::pair<const char*, std::vector<std::string>>> found;
    auto wants = [&](const char* field) {
        for (const auto& name : wanted) {
            if (!name.empty() && name.back() == '*' ? std::strncmp(field, name.c_str(), name.size() - 1) == 0
                                                    : name == field)
                return true;
        }
        return false;
    };
    auto add = [&](const char* name, std::string value) {
        auto it = std::find_if(found.begin(), found.end(), [&](const auto& e) { return std::strcmp(e.first, name) == 0; });
        if (it == found.end()) it = found.insert(found.end(), {name, {}});
        if (it->second.size() < 64) it->second.push_back(std::move(value));
    };
    for (const auto& p : ff.protos)
        if (wants(p.name)) add(p.name, "");
    for (const auto& f : ff.fields)
        if (wants(f.name)) add(f.name, f.value.type == FieldValue::kString ? f.value.s : filter_literal(f.value));
    JsonWriter w;
    w.begin_object();
    for (const auto& [name, values] : found) {
        w.key(name).begin_array();
        for (const auto& v : values) w.value(v);
        w.end_array();
    }
    w.end_object();
    JsonWriter x;
    x.begin_array();
    if (!d.expert.empty()) x.value(d.expert);
    for (const auto& note : d.notes) x.value(note.summary);
    x.end_array();
    // The summary is one JSON object: add the two keys before its closing brace.
    return summary.substr(0, summary.size() - 1) + ",\"f\":" + w.str() + ",\"x\":" + x.str() + "}";
}

// Wireshark's File > Export Specified Packets: the frames a query selects (frame
// numbers, flows, BPF, a display filter judged on the same two-pass view as the
// packet list) copied into a new pcap.
int run_save(const std::vector<std::string>& inputs, const PacketQuery& q) {
    std::vector<FlowKey> wanted;
    for (const auto& spec : q.flows) {
        FlowKey k;
        if (!parse_flow_spec(spec, k)) {
            std::fprintf(stderr, "anta-engine: bad flow spec '%s'\n", spec.c_str());
            return 2;
        }
        wanted.push_back(k);
    }
    std::string error;
    std::unique_ptr<DisplayFilter> dfilter;
    if (!q.dfilter.empty()) {
        dfilter = DisplayFilter::compile(q.dfilter, error);
        if (!dfilter) {
            std::fprintf(stderr, "anta-engine: display filter: %s\n", error.c_str());
            return 2;
        }
    }
    auto in_frames = [&](uint64_t n) {
        if (q.frames.empty()) return true;
        auto it = std::upper_bound(q.frames.begin(), q.frames.end(), std::make_pair(n, UINT64_MAX));
        return it != q.frames.begin() && std::prev(it)->second >= n;
    };
    auto in_flows = [&](LinkType link, const RawPacket& p) {
        if (wanted.empty()) return true;
        PacketInfo info;
        if (dissect(link, p.data, p.caplen, info) != DissectResult::Ok) return false;
        bool dummy;
        FlowKey k = FlowKey::from_packet(info, dummy);
        return std::find(wanted.begin(), wanted.end(), k) != wanted.end();
    };
    TlsKeyLog keylog;
    if (!q.keylog.empty()) keylog.load(q.keylog);
    const TlsKeyLog* kl = keylog.empty() ? nullptr : &keylog;
    InspectorAnnotations ann;
    bool two_pass = dfilter && !q.single_pass;
    if (two_pass) {  // look-ahead cross-references first, as the packet list has them
        Inspector recorder(&ann, nullptr);
        recorder.set_keylog(kl);
        if (!for_each_frame(inputs, q.bases, q.bpf, [&](uint64_t n, const RawPacket& p, LinkType link, bool) {
                recorder.observe(link, p.data, p.caplen, n, p.ts_us);
                return true;
            }, error)) {
            std::fprintf(stderr, "anta-engine: %s\n", error.c_str());
            return 2;
        }
        ann.complete = true;
    }
    Inspector inspector(nullptr, two_pass ? &ann : nullptr);
    inspector.set_keylog(kl);
    FrameFields ff;
    PcapFileWriter out(q.save);
    std::unique_ptr<Sanitizer> sanitizer;
    if (q.sanitize) sanitizer = std::make_unique<Sanitizer>(q.sanitize_opts);
    std::vector<uint8_t> clean;
    uint64_t first = 0, last = 0;
    std::string write_error;
    bool ok = for_each_frame(inputs, q.bases, q.bpf, [&](uint64_t n, const RawPacket& p, LinkType link, bool bpf_ok) {
        bool chosen = bpf_ok && in_frames(n) && in_flows(link, p);
        if (dfilter) {
            if (!chosen) {
                inspector.observe(link, p.data, p.caplen, n, p.ts_us);
                return true;
            }
            inspector.decode(link, p.data, p.caplen, n, p.ts_us, &ff, p.wire_len);
            if (!dfilter->match(ff)) return true;
        } else if (!chosen) {
            return true;
        }
        if (sanitizer) {
            if (!sanitizer->frame(link, p.data, p.caplen, clean)) return true;  // (a link type it can't clean)
            RawPacket safe{sanitizer->time(p.ts_us), static_cast<uint32_t>(clean.size()), p.wire_len, clean.data()};
            if (!out.write(link, safe, write_error)) return false;
        } else if (!out.write(link, p, write_error)) {
            return false;
        }
        if (!first) first = n;
        last = n;
        return true;
    }, error);
    if (!write_error.empty()) {
        std::fprintf(stderr, "anta-engine: %s\n", write_error.c_str());
        return 2;
    }
    if (!ok) {
        std::fprintf(stderr, "anta-engine: %s\n", error.c_str());
        return 2;
    }
    JsonWriter w;
    w.begin_object().kv("type", "saved").kv("packets", out.written()).kv("first", first).kv("last", last)
        .kv("skipped_link_type", out.skipped() + (sanitizer ? sanitizer->frames_unsupported() : 0));
    if (sanitizer) {
        uint64_t v4 = 0, v6 = 0, macs = 0;
        for (const auto& e : sanitizer->key()) (e.kind == "ipv4" ? v4 : e.kind == "ipv6" ? v6 : macs)++;
        w.key("sanitized").begin_object().kv("ipv4", v4).kv("ipv6", v6).kv("mac", macs)
            .kv("bytes_cut", sanitizer->bytes_cut()).kv("unsupported", sanitizer->frames_unsupported())
            .kv("keep_payload", q.sanitize_opts.keep_payload).kv("shift_time", q.sanitize_opts.shift_time).end_object();
        if (!q.sanitize_key.empty()) {  // the address key: real -> stand-in, owner-only (umask 077)
            std::FILE* key = std::fopen(q.sanitize_key.c_str(), "w");
            if (!key) {
                std::fprintf(stderr, "anta-engine: cannot write %s\n", q.sanitize_key.c_str());
                return 2;
            }
            std::fprintf(key, "kind,real,stand_in\n");
            for (const auto& e : sanitizer->key())
                std::fprintf(key, "%s,%s,%s\n", e.kind.c_str(), e.real.c_str(), e.stand_in.c_str());
            if (std::fclose(key) != 0) {
                std::fprintf(stderr, "anta-engine: cannot write %s\n", q.sanitize_key.c_str());
                return 2;
            }
        }
    }
    w.end_object();
    std::printf("%s\n", w.str().c_str());
    return 0;
}

// Every session of a capture (several rotated files, in order) as compact final
// records, for the file list and indicator searches; or, given a target, one
// transferred file written out as the capture is read again.
int run_index(const std::vector<std::string>& inputs, FlowTableOptions opts, ObjectTarget* object) {
    g_compact = true;
    opts.object = object;
    opts.update_interval_us = 1ULL << 60;  // final records only
    uint64_t packets = 0, sessions = 0;
    std::string capture_path = absolute_path(inputs.back());
    std::string error;
    bool ok;
    {
        FlowTable table(opts, [&](const Flow& f, bool final) {
            if (!final) return;
            ++sessions;
            if (!object) std::printf("%s\n", serialize(f, true, capture_path).c_str());
        });
        ok = for_each_frame(inputs, {}, "", [&](uint64_t, const RawPacket& raw, LinkType link, bool) {
            PacketInfo info;
            info.ts_us = raw.ts_us;
            info.wire_len = raw.wire_len;
            if (dissect(link, raw.data, raw.caplen, info) != DissectResult::Ok) return true;
            ++packets;
            table.on_packet(info);
            return true;
        }, error);
    }  // the table finishes the flows still open when it goes
    if (!ok) {
        std::fprintf(stderr, "anta-engine: %s\n", error.c_str());
        return 2;
    }
    JsonWriter w;
    if (object) {
        w.begin_object().kv("type", "object").kv("found", object->found).kv("written", object->written).end_object();
    } else {
        w.begin_object().kv("type", "index_done").kv("packets", packets).kv("sessions", sessions).end_object();
    }
    std::printf("%s\n", w.str().c_str());
    return object && !object->found ? 1 : 0;
}

int run_packets(const std::vector<std::string>& inputs, const PacketQuery& q) {
    if (!q.save.empty()) return run_save(inputs, q);
    std::vector<FlowKey> wanted;
    for (const auto& spec : q.flows) {
        FlowKey k;
        if (!parse_flow_spec(spec, k)) {
            std::fprintf(stderr, "anta-engine: bad flow spec '%s'\n", spec.c_str());
            return 2;
        }
        wanted.push_back(k);
    }
    std::string error;
    std::unique_ptr<DisplayFilter> dfilter;
    std::string needle;
    for (char c : q.find_text) needle.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    // (finding text needs every frame decoded, as a display filter does: "frame" matches them all)
    const std::string filter_text = q.dfilter.empty() && !needle.empty() ? "frame" : q.dfilter;
    if (!filter_text.empty()) {
        dfilter = DisplayFilter::compile(filter_text, error);
        if (!dfilter) {
            std::fprintf(stderr, "anta-engine: display filter: %s\n", error.c_str());
            return 2;
        }
    }
    std::vector<std::unique_ptr<DisplayFilter>> colors;
    for (size_t i = 0; i < q.colors.size(); ++i) {
        colors.push_back(DisplayFilter::compile(q.colors[i], error));
        if (!colors.back()) {
            std::fprintf(stderr, "anta-engine: coloring rule %zu: %s\n", i + 1, error.c_str());
            return 2;
        }
    }
    auto color_of = [&](const FrameFields& ff) {
        for (size_t i = 0; i < colors.size(); ++i)
            if (colors[i]->match(ff)) return static_cast<int>(i);
        return -1;
    };
    auto in_scope = [&](LinkType link, const RawPacket& p, bool bpf_ok) {
        if (!bpf_ok) return false;
        if (wanted.empty()) return true;
        PacketInfo info;
        if (dissect(link, p.data, p.caplen, info) != DissectResult::Ok) return false;
        bool dummy;
        FlowKey k = FlowKey::from_packet(info, dummy);
        for (const auto& w : wanted)
            if (k == w) return true;
        return false;
    };

    uint64_t returned = 0, matched = 0, before = 0, last_frame = 0, first_ts = 0;
    int64_t next = -1;
    bool found = false;
    std::string last_line;  // --last: the last matching frame's summary
    // Wireshark-style columns depend on other frames, so decoding takes two passes
    // like Wireshark's: pass 1 runs every frame through an Inspector that records
    // look-ahead cross-references (which frame completes a reassembled message,
    // which reply answers a ping), continuing a little past the last displayed
    // frame; pass 2 replays from the start and formats the displayed frames.
    // A display filter is evaluated in pass 2, on the same view Wireshark filters.
    constexpr uint64_t kLookahead = 20'000;
    TlsKeyLog keylog;
    if (!q.keylog.empty()) keylog.load(q.keylog);
    const TlsKeyLog* kl = keylog.empty() ? nullptr : &keylog;
    InspectorAnnotations ann;
    std::vector<uint64_t> shown;  // frames to display, in order
    uint64_t stop_after = q.detail >= 0 ? static_cast<uint64_t>(q.detail) : 0;
    bool stopped = false;
    {
        Inspector recorder(q.single_pass ? nullptr : &ann, nullptr);
        recorder.set_keylog(kl);
        bool ok = for_each_frame(inputs, q.bases, q.bpf, [&](uint64_t n, const RawPacket& p, LinkType link, bool bpf_ok) {
            bool page_done = q.detail >= 0 || (!dfilter && returned >= q.limit && next >= 0);
            if (page_done && stop_after && n > stop_after + kLookahead && !q.count) {
                stopped = true;
                return false;
            }
            last_frame = n;
            recorder.observe(link, p.data, p.caplen, n, p.ts_us);
            if (q.detail >= 0) {
                if (n == static_cast<uint64_t>(q.detail)) found = true;
                return true;
            }
            if (dfilter) return true;  // which frames match is only known in pass 2
            if (!in_scope(link, p, bpf_ok)) return true;
            ++matched;
            if (n < q.from) {
                ++before;
                return true;
            }
            if (returned < q.limit) {
                shown.push_back(n);
                ++returned;
                stop_after = n;
            } else if (next < 0) {
                next = static_cast<int64_t>(n);
            }
            return true;
        }, error, &first_ts);
        if (!ok) {
            std::fprintf(stderr, "anta-engine: %s\n", error.c_str());
            return 2;
        }
        ann.complete = !stopped;
    }
    if (q.detail >= 0 && !found) {
        std::fprintf(stderr, "anta-engine: frame %lld not found\n", static_cast<long long>(q.detail));
        return 1;
    }
    Inspector inspector(nullptr, q.single_pass ? nullptr : &ann);
    inspector.set_keylog(kl);
    FrameFields ff;
    if (dfilter && q.detail < 0) {
        bool ok = for_each_frame(inputs, q.bases, q.bpf, [&](uint64_t n, const RawPacket& p, LinkType link, bool bpf_ok) {
            if (!in_scope(link, p, bpf_ok)) {
                inspector.observe(link, p.data, p.caplen, n, p.ts_us);
                return true;
            }
            DecodedFrame d = inspector.decode(link, p.data, p.caplen, n, p.ts_us, &ff, p.wire_len);
            if (!dfilter->match(ff)) return true;
            if (!needle.empty() && !text_in_frame(d, needle, q.find_details)) return true;
            ++matched;
            if (n < q.from) {
                ++before;
                return true;
            }
            if (q.last) {  // only the last match is wanted: keep the latest
                JsonWriter w;
                write_packet_summary(w, d, n, p.ts_us, p.wire_len, p.caplen, color_of(ff));
                last_line = q.fields.empty() ? w.str() : summary_with_fields(w.str(), d, ff, q.fields);
                return true;
            }
            if (returned < q.limit) {
                JsonWriter w;
                write_packet_summary(w, d, n, p.ts_us, p.wire_len, p.caplen, color_of(ff));
                std::string line = q.fields.empty() ? w.str() : summary_with_fields(w.str(), d, ff, q.fields);
                std::printf("%s\n", line.c_str());
                ++returned;
            } else if (next < 0) {
                next = static_cast<int64_t>(n);
            }
            return next < 0 || q.count;
        }, error);
        if (!ok) {
            std::fprintf(stderr, "anta-engine: %s\n", error.c_str());
            return 2;
        }
    } else {
        if (q.detail >= 0) shown.assign(1, static_cast<uint64_t>(q.detail));
        if (!shown.empty()) {
            size_t i = 0;
            bool fields = q.detail >= 0 || !colors.empty() || !q.fields.empty();
            bool ok = for_each_frame(inputs, q.bases, q.bpf, [&](uint64_t n, const RawPacket& p, LinkType link, bool) {
                if (n != shown[i]) {
                    inspector.observe(link, p.data, p.caplen, n, p.ts_us);
                    return true;
                }
                JsonWriter w;
                DecodedFrame d = inspector.decode(link, p.data, p.caplen, n, p.ts_us, fields ? &ff : nullptr, p.wire_len);
                if (q.detail >= 0) write_packet_detail(w, d, n, p.ts_us, p.wire_len, p.data, p.caplen, &ff);
                else write_packet_summary(w, d, n, p.ts_us, p.wire_len, p.caplen, fields ? color_of(ff) : -1);
                std::string line = q.fields.empty() || q.detail >= 0 ? w.str() : summary_with_fields(w.str(), d, ff, q.fields);
                std::printf("%s\n", line.c_str());
                return ++i < shown.size();
            }, error);
            if (!ok) {
                std::fprintf(stderr, "anta-engine: %s\n", error.c_str());
                return 2;
            }
        }
    }
    if (q.detail >= 0) return 0;
    if (!last_line.empty()) {
        std::printf("%s\n", last_line.c_str());
        returned = 1;
    }
    JsonWriter w;
    w.begin_object().kv("type", "page").kv("from", q.from).kv("returned", returned).key("next");
    if (next >= 0) w.value(next);
    else w.null_value();
    w.key("matched_total");
    if (q.count || (dfilter && next < 0)) w.value(matched);
    else w.null_value();
    w.kv("matched_before", before).kv("last_frame", last_frame);
    w.kv("first_ts", static_cast<double>(first_ts) / 1e6).end_object();
    std::printf("%s\n", w.str().c_str());
    return 0;
}

// Validate display filters for an editor: one JSON line per filter.
int run_check_filters(const std::vector<std::string>& filters) {
    for (const auto& f : filters) {
        std::string error;
        bool ok = static_cast<bool>(DisplayFilter::compile(f, error));
        JsonWriter w;
        w.begin_object().kv("type", "filter_check").kv("filter", f).kv("ok", ok);
        if (!ok) w.kv("error", error);
        w.end_object();
        std::printf("%s\n", w.str().c_str());
    }
    return 0;
}

int run_filter_fields() {
    for (const auto& line : filter_field_catalog()) {
        size_t a = line.find('\t'), b = line.find('\t', a + 1);
        JsonWriter w;
        w.begin_object()
            .kv("type", "field")
            .kv("name", line.substr(0, a))
            .kv("kind", line.substr(a + 1, b - a - 1))
            .kv("desc", line.substr(b + 1))
            .end_object();
        std::printf("%s\n", w.str().c_str());
    }
    return 0;
}

void usage() {
    std::fprintf(stderr,
                 "anta-engine %s - packet capture and TCP reassembly for ANTA\n\n"
                 "Capture:\n"
                 "  -i, --interface IFACE   live capture (needs root / BPF access)\n"
                 "  -r, --read FILE         read a pcap/pcapng file\n"
                 "  -f, --filter EXPR       BPF filter, e.g. \"net 10.0.0.0/8 and not port 22\"\n"
                 "  -w, --write FILE        record captured frames, owner-only (enables per-stream export)\n"
                 "      --write-max-mb N    rotate the recording to FILE.1 past N MiB (default 1024, 0 = never)\n"
                 "      --write-keep N      keep N older segments, FILE.1 (newest) to FILE.N (default 1)\n"
                 "      --ring              Linux: use AF_PACKET TPACKET_V3 zero-copy ring\n"
                 "      --buffer-mb N       kernel capture buffer size (default 64)\n"
                 "      --no-promisc        don't put the interface in promiscuous mode\n"
                 "  -Z, --user NAME         drop root to NAME after opening the device (default: the sudo/pkexec user)\n"
                 "      --parent-pid PID    stop cleanly once process PID has exited (the app that started us)\n"
                 "      --list-interfaces   print capture devices as JSON and exit\n"
                 "      --check-capture IF  exit 0 if IF can be opened for capture (3 = permission denied)\n\n"
                 "Output:\n"
                 "  -u, --output ENDPOINT   stdout (default) | zmq+ipc://PATH | zmq+tcp://HOST:PORT | unix:PATH\n"
                 "      --dump-streams DIR  write each reassembled TCP direction to DIR/flow<id>_<dir>.bin\n"
                 "      --update-secs N     re-emit long-lived sessions every N seconds (default 30)\n"
                 "      --max-memory-mb N   flow-state budget; oldest flows are finished early past it (default 512)\n"
                 "      --redact            strip query strings from HTTP URIs in emitted metadata\n"
                 "      --print-packets     print one line per packet header to stderr (debug)\n"
                 "      --stop-on-stdin-eof stop cleanly when stdin closes (for parent processes)\n\n"
                 "Packet viewer:\n"
                 "      --packet-feed PPS   also emit per-packet summaries (rate-limited to PPS) for a live view\n"
                 "  --packets -r IN [-r IN2 ...] [--frame-base N ...] [--from N] [--limit N] [--count]\n"
                 "            [-f BPF] [--flow SPEC ...]   print packet summaries (frames numbered from 1)\n"
                 "  --packet-detail N -r IN [...]          decode frame N: layers, fields, hex\n"
                 "      --single-pass       decode in one pass, as a live capture shows it (no look-ahead)\n"
                 "      --keylog FILE       a TLS key log (SSLKEYLOGFILE) for your own TLS sessions: decrypted in\n"
                 "                          the packet view, and HTTP inside them analysed, indexed and\n"
                 "                          extracted (--index/--object/-r) like plain HTTP\n"
                 "  -Y, --display-filter F  only frames matching a Wireshark display filter\n"
                 "      --find-text T       only frames showing T (any case) in their columns (Find Packet)\n"
                 "      --find-in WHERE     list (the columns, default) or details (the whole detail tree)\n"
                 "      --last              only the last matching frame (Find Previous: with -Y frame.number < N)\n"
                 "      --color-rule F      coloring rule (repeatable; first match is reported as \"color\")\n"
                 "      --check-filter F    validate display filters (repeatable), one JSON line each\n"
                 "      --filter-fields     list the display-filter fields as JSON lines\n"
                 "  --stats -r IN [...]     capture statistics as one JSON object (Statistics / Network Map)\n"
                 "      --io-interval S     I/O graph bin size in seconds (default: from the duration)\n"
                 "      --io-series F       extra I/O graph series counting frames matching F (up to 8)\n"
                 "      --count-filter F    count the frames matching F over the whole capture (up to 256)\n"
                 "  --follow tcp,N -r IN    a TCP (or udp,N UDP) stream's payload in order, like Follow Stream\n"
                 "  --follow tls,N -r IN --keylog FILE      TCP stream N's decrypted TLS application data\n"
                 "  --follow http2,N,ID -r IN [--keylog FILE]  HTTP/2 stream ID of TCP stream N: headers and body\n\n"
                 "Export:\n"
                 "  --extract SPEC -r IN [-r IN2] -w OUT   copy only matching flows; SPEC = proto,ipA,portA,ipB,portB\n"
                 "                                         (repeatable; matches both directions)\n"
                 "  --packets ... --fields A,B,tcp.analysis.*   add those fields' values (and expert items) to each row\n"
                 "  --packets -r IN [...] --save OUT [-Y F] [--frames 1-20,35] [--flow SPEC]\n"
                 "                          write the selected frames to a new pcap (Export Specified Packets)\n"
                 "  -Y FILTER | --display-filter-file FILE  (a long filter, such as a selection, read from FILE)\n"
                 "      --sanitize          ... as a share-safe copy: stand-in addresses (consistent, subnets kept),\n"
                 "                          packet contents cut, checksums fixed; --sanitize-keep-payload keeps the\n"
                 "                          contents, --sanitize-shift-time starts it at 2000-01-01, --sanitize-key\n"
                 "                          FILE writes the address key (real -> stand-in, CSV)\n"
                 "  --index -r IN [-r IN2 ...]             every session as a compact final record (files, DNS, TLS…)\n"
                 "  --object FLOW:h|s|f:N --object-out OUT -r IN [...]\n"
                 "                          write one transferred file: HTTP response N, SMB open N or FTP\n"
                 "                          data direction N of flow FLOW (ids as --index prints them)\n",
                 kVersion);
}

}  // namespace

int main(int argc, char** argv) {
    platform_init();
#ifndef _WIN32
    // Everything we create (recordings, stream dumps) holds raw traffic: owner-only.
    // (On Windows, files under the user's profile inherit owner-only ACLs.)
    umask(077);
#endif

    CaptureOptions cap;
    cap.write_max_bytes = 1024ull << 20;
    FlowTableOptions table_opts;
    std::string endpoint = "stdout";
    std::string run_as;
    std::vector<std::string> read_files;
    std::vector<std::string> extract_specs;
    bool print_packets = false;
    bool stop_on_stdin_eof = false;
    long parent_pid = 0;
    bool packets_mode = false;
    bool stats_mode = false;
    bool follow_udp = false;
    int64_t follow_stream = -1;
    FollowQuery::Kind follow_kind = FollowQuery::Transport;
    uint32_t follow_h2 = 0;
    double io_interval = 0;  // 0: pick one from the capture's duration
    std::vector<std::string> check_filters, io_series, count_filters;
    PacketQuery query;
    bool index_mode = false;
    ObjectTarget object;
    std::string object_out;
    double feed_pps = 0;

    enum {
        OPT_IFACE = 1, OPT_READ, OPT_FILTER, OPT_WRITE, OPT_OUTPUT, OPT_USER, OPT_HELP, OPT_RING, OPT_BUFFER,
        OPT_NOPROMISC, OPT_DUMP, OPT_UPDATE, OPT_PRINT, OPT_EXTRACT, OPT_WRITE_MAX, OPT_MEMORY, OPT_REDACT,
        OPT_LIST, OPT_CHECK, OPT_STDIN_EOF, OPT_VERSION, OPT_PACKETS, OPT_COUNT, OPT_FROM, OPT_LIMIT,
        OPT_FRAME_BASE, OPT_FLOW, OPT_DETAIL, OPT_FEED, OPT_SINGLE_PASS, OPT_DFILTER, OPT_COLOR, OPT_CHECK_FILTER,
        OPT_FILTER_FIELDS, OPT_STATS, OPT_IO_INTERVAL, OPT_IO_SERIES, OPT_FOLLOW, OPT_PARENT,
        OPT_SAVE, OPT_FRAMES, OPT_INDEX, OPT_OBJECT, OPT_OBJECT_OUT, OPT_FIELDS, OPT_WRITE_KEEP, OPT_KEYLOG,
        OPT_FIND_TEXT, OPT_FIND_IN, OPT_LAST, OPT_SANITIZE, OPT_SANITIZE_KEEP, OPT_SANITIZE_TIME, OPT_SANITIZE_KEY,
        OPT_DFILTER_FILE, OPT_COUNT_FILTER
    };
    const std::vector<OptSpec> specs = {
        {'i', "interface", true, OPT_IFACE},     {'r', "read", true, OPT_READ},
        {'f', "filter", true, OPT_FILTER},       {'w', "write", true, OPT_WRITE},
        {'u', "output", true, OPT_OUTPUT},       {0, "socket", true, OPT_OUTPUT},  // backwards-compatible alias
        {'Z', "user", true, OPT_USER},           {'h', "help", false, OPT_HELP},
        {0, "ring", false, OPT_RING},            {0, "buffer-mb", true, OPT_BUFFER},
        {0, "no-promisc", false, OPT_NOPROMISC}, {0, "dump-streams", true, OPT_DUMP},
        {0, "update-secs", true, OPT_UPDATE},    {0, "print-packets", false, OPT_PRINT},
        {0, "extract", true, OPT_EXTRACT},       {0, "write-max-mb", true, OPT_WRITE_MAX},
        {0, "max-memory-mb", true, OPT_MEMORY},  {0, "redact", false, OPT_REDACT},
        {0, "list-interfaces", false, OPT_LIST}, {0, "check-capture", true, OPT_CHECK},
        {0, "stop-on-stdin-eof", false, OPT_STDIN_EOF}, {0, "version", false, OPT_VERSION},
        {0, "parent-pid", true, OPT_PARENT},
        {0, "packets", false, OPT_PACKETS},      {0, "count", false, OPT_COUNT},
        {0, "from", true, OPT_FROM},             {0, "limit", true, OPT_LIMIT},
        {0, "frame-base", true, OPT_FRAME_BASE}, {0, "flow", true, OPT_FLOW},
        {0, "packet-detail", true, OPT_DETAIL},  {0, "packet-feed", true, OPT_FEED},
        {0, "single-pass", false, OPT_SINGLE_PASS},
        {'Y', "display-filter", true, OPT_DFILTER}, {0, "color-rule", true, OPT_COLOR},
        {0, "check-filter", true, OPT_CHECK_FILTER}, {0, "filter-fields", false, OPT_FILTER_FIELDS},
        {0, "stats", false, OPT_STATS},          {0, "io-interval", true, OPT_IO_INTERVAL},
        {0, "io-series", true, OPT_IO_SERIES},  {0, "follow", true, OPT_FOLLOW},
        {0, "count-filter", true, OPT_COUNT_FILTER},
        {0, "save", true, OPT_SAVE},             {0, "frames", true, OPT_FRAMES},
        {0, "index", false, OPT_INDEX},          {0, "object", true, OPT_OBJECT},
        {0, "object-out", true, OPT_OBJECT_OUT}, {0, "fields", true, OPT_FIELDS},
        {0, "find-text", true, OPT_FIND_TEXT},   {0, "find-in", true, OPT_FIND_IN}, {0, "last", false, OPT_LAST},
        {0, "write-keep", true, OPT_WRITE_KEEP},
        {0, "keylog", true, OPT_KEYLOG},
        {0, "sanitize", false, OPT_SANITIZE},    {0, "sanitize-keep-payload", false, OPT_SANITIZE_KEEP},
        {0, "sanitize-shift-time", false, OPT_SANITIZE_TIME}, {0, "sanitize-key", true, OPT_SANITIZE_KEY},
        {0, "display-filter-file", true, OPT_DFILTER_FILE},
    };

    // long long, not long: long is 32-bit on Windows.
    auto positive = [](const std::string& arg, const char* what, long long max) -> long long {
        char* end = nullptr;
        long long v = std::strtoll(arg.c_str(), &end, 10);
        if (arg.empty() || !end || *end || v < 0 || v > max) {
            std::fprintf(stderr, "anta-engine: invalid %s '%s'\n", what, arg.c_str());
            std::exit(2);
        }
        return v;
    };

    int i = 1, id = 0;
    std::string optval;
    while (next_option(argc, argv, i, specs, id, optval)) {
        switch (id) {
            case OPT_IFACE: cap.iface = optval; break;
            case OPT_READ: read_files.push_back(optval); break;
            case OPT_FILTER: cap.bpf = optval; break;
            case OPT_WRITE: cap.write_file = optval; break;
            case OPT_OUTPUT: endpoint = optval; break;
            case OPT_USER: run_as = optval; break;
            case OPT_RING: cap.use_ring = true; break;
            case OPT_BUFFER: cap.buffer_mb = static_cast<int>(positive(optval, "--buffer-mb", 4096)); break;
            case OPT_NOPROMISC: cap.promiscuous = false; break;
            case OPT_DUMP: table_opts.dump_dir = optval; break;
            case OPT_UPDATE:
                table_opts.update_interval_us = static_cast<uint64_t>(positive(optval, "--update-secs", 86400)) * 1'000'000;
                break;
            case OPT_PRINT: print_packets = true; break;
            case OPT_EXTRACT: extract_specs.push_back(optval); break;
            case OPT_WRITE_KEEP: cap.write_keep = static_cast<uint32_t>(positive(optval, "--write-keep", 1000)); break;
            case OPT_WRITE_MAX:
                cap.write_max_bytes = static_cast<uint64_t>(positive(optval, "--write-max-mb", 1 << 20)) << 20;
                break;
            case OPT_MEMORY: {
                char* end = nullptr;
                double mb = std::strtod(optval.c_str(), &end);
                if (optval.empty() || !end || *end || !(mb > 0) || mb > 1048576) {
                    std::fprintf(stderr, "anta-engine: invalid --max-memory-mb '%s'\n", optval.c_str());
                    return 2;
                }
                table_opts.memory_budget = static_cast<size_t>(mb * 1048576.0);
                break;
            }
            case OPT_REDACT: g_redact = true; break;
            case OPT_STDIN_EOF: stop_on_stdin_eof = true; break;
            case OPT_PARENT: parent_pid = static_cast<long>(positive(optval, "--parent-pid", INT_MAX)); break;
            case OPT_PACKETS: packets_mode = true; break;
            case OPT_COUNT: query.count = true; break;
            case OPT_FIND_TEXT:
                if (optval.empty() || optval.size() > 1024) {
                    std::fprintf(stderr, "anta-engine: --find-text needs 1 to 1024 characters\n");
                    return 2;
                }
                query.find_text = optval;
                break;
            case OPT_FIND_IN:
                if (optval != "list" && optval != "details") {
                    std::fprintf(stderr, "anta-engine: --find-in is list or details\n");
                    return 2;
                }
                query.find_details = optval == "details";
                break;
            case OPT_LAST: query.last = true; break;
            case OPT_FROM: query.from = static_cast<uint64_t>(positive(optval, "--from", 0x7fffffffffffffffLL)); break;
            case OPT_LIMIT: query.limit = static_cast<uint64_t>(positive(optval, "--limit", 100000)); break;
            case OPT_FRAME_BASE:
                query.bases.push_back(static_cast<uint64_t>(positive(optval, "--frame-base", 0x7fffffffffffffffLL)));
                break;
            case OPT_FLOW: query.flows.push_back(optval); break;
            case OPT_DETAIL:
                query.detail = positive(optval, "--packet-detail", 0x7fffffffffffffffLL);
                packets_mode = true;
                break;
            case OPT_SINGLE_PASS: query.single_pass = true; break;
            case OPT_KEYLOG: query.keylog = optval; break;
            case OPT_DFILTER: query.dfilter = optval; break;
            case OPT_DFILTER_FILE: {  // a filter too long for a command line (a selection of many packets)
                std::FILE* fh = std::fopen(optval.c_str(), "rb");
                if (!fh) {
                    std::fprintf(stderr, "anta-engine: cannot read %s\n", optval.c_str());
                    return 2;
                }
                std::string text;
                char buf[65536];
                size_t got;
                while ((got = std::fread(buf, 1, sizeof buf, fh)) > 0 && text.size() <= (16u << 20)) text.append(buf, got);
                std::fclose(fh);
                if (text.size() > (16u << 20)) {
                    std::fprintf(stderr, "anta-engine: the display filter file is too large\n");
                    return 2;
                }
                while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
                query.dfilter = text;
                break;
            }
            case OPT_COLOR: query.colors.push_back(optval); break;
            case OPT_CHECK_FILTER: check_filters.push_back(optval); break;
            case OPT_FILTER_FIELDS: return run_filter_fields();
            case OPT_STATS: stats_mode = true; break;
            case OPT_SAVE: query.save = optval; break;
            case OPT_SANITIZE: query.sanitize = true; break;
            case OPT_SANITIZE_KEEP: query.sanitize_opts.keep_payload = true; break;
            case OPT_SANITIZE_TIME: query.sanitize_opts.shift_time = true; break;
            case OPT_SANITIZE_KEY: query.sanitize_key = optval; break;
            case OPT_FRAMES:
                if (!parse_frame_ranges(optval, query.frames)) {
                    std::fprintf(stderr, "anta-engine: invalid --frames '%s' (expected e.g. 1-20,35,40-41)\n", optval.c_str());
                    return 2;
                }
                break;
            case OPT_INDEX: index_mode = true; break;
            case OPT_OBJECT: {
                unsigned long long flow = 0, n = 0;
                char kind = 0;
                int used = 0;
                if (std::sscanf(optval.c_str(), "%llu:%c:%llu%n", &flow, &kind, &n, &used) != 3 ||
                    used != static_cast<int>(optval.size()) || (kind != 'h' && kind != 's' && kind != 'f')) {
                    std::fprintf(stderr, "anta-engine: invalid --object '%s' (expected FLOW:h|s|f:N)\n", optval.c_str());
                    return 2;
                }
                object.flow_id = flow;
                object.kind = kind;
                object.n = n;
                break;
            }
            case OPT_OBJECT_OUT: object_out = optval; break;
            case OPT_FIELDS:
                for (size_t a = 0; a <= optval.size();) {
                    size_t b = optval.find(',', a);
                    if (b == std::string::npos) b = optval.size();
                    if (b > a && query.fields.size() < 256) query.fields.push_back(optval.substr(a, b - a));
                    a = b + 1;
                }
                break;
            case OPT_FOLLOW: {
                // tcp,N  udp,N  tls,N (decrypted, with --keylog)  http2,N,ID (HTTP/2 stream ID of TCP stream N)
                size_t comma = optval.find(',');
                std::string kind = optval.substr(0, comma);
                if (comma == std::string::npos || (kind != "tcp" && kind != "udp" && kind != "tls" && kind != "http2")) {
                    std::fprintf(stderr, "--follow takes tcp,STREAM  udp,STREAM  tls,STREAM or http2,STREAM,ID\n");
                    return 2;
                }
                follow_udp = kind == "udp";
                follow_kind = kind == "tls" ? FollowQuery::Tls : kind == "http2" ? FollowQuery::Http2 : FollowQuery::Transport;
                std::string rest = optval.substr(comma + 1);
                if (follow_kind == FollowQuery::Http2) {
                    size_t c2 = rest.find(',');
                    if (c2 == std::string::npos) {
                        std::fprintf(stderr, "--follow http2 takes STREAM,ID\n");
                        return 2;
                    }
                    follow_h2 = static_cast<uint32_t>(positive(rest.substr(c2 + 1), "--follow", 0x7fffffff));
                    rest = rest.substr(0, c2);
                }
                follow_stream = static_cast<int64_t>(positive(rest, "--follow", 0x7fffffffffffffffLL));
                break;
            }
            case OPT_COUNT_FILTER:
                if (count_filters.size() >= 256) {
                    std::fprintf(stderr, "at most 256 --count-filter\n");
                    return 2;
                }
                count_filters.push_back(optval);
                break;
            case OPT_IO_SERIES:
                if (io_series.size() >= 8) {
                    std::fprintf(stderr, "at most 8 --io-series\n");
                    return 2;
                }
                io_series.push_back(optval);
                break;
            case OPT_IO_INTERVAL: {
                char* end = nullptr;
                io_interval = std::strtod(optval.c_str(), &end);
                if (!end || *end || !(io_interval >= 0.000001 && io_interval <= 86400)) {
                    std::fprintf(stderr, "--io-interval must be between 0.000001 and 86400 seconds\n");
                    return 2;
                }
                break;
            }
            case OPT_FEED: feed_pps = static_cast<double>(positive(optval, "--packet-feed", 100000)); break;
            case OPT_LIST: return print_interfaces();
            case OPT_CHECK: {
                std::string error;
                if (check_capture(optval, error)) return 0;
                std::fprintf(stderr, "anta-engine: cannot capture on %s: %s\n", optval.c_str(), error.c_str());
                return error == "permission denied" ? 3 : 1;
            }
            case OPT_VERSION: std::printf("anta-engine %s\n", kVersion); return 0;
            case OPT_HELP: usage(); return 0;
            default: usage(); return 2;
        }
    }
    if (table_opts.update_interval_us == 0) table_opts.update_interval_us = 1'000'000;
    // The user's own TLS secrets (--keylog): sessions they hold keys for are analysed
    // decrypted, so HTTP inside them is read like plain HTTP.
    TlsKeyLog flow_keylog;
    auto use_keylog = [&] {
        if (!query.keylog.empty()) {  // (an empty file too: a browser may be about to write to it)
            flow_keylog.load(query.keylog);
            table_opts.keylog = &flow_keylog;
        }
    };

    if (!extract_specs.empty()) {
        if (read_files.empty() || cap.write_file.empty()) {
            std::fprintf(stderr, "--extract needs -r INPUT and -w OUTPUT\n");
            return 2;
        }
        uint64_t written = 0;
        std::string error;
        if (!extract_flows(read_files, cap.write_file, extract_specs, written, error)) {
            std::fprintf(stderr, "extract failed: %s\n", error.c_str());
            return 1;
        }
        std::fprintf(stderr, "wrote %llu packets to %s\n", static_cast<unsigned long long>(written),
                     cap.write_file.c_str());
        return 0;
    }

    if (index_mode || object.kind) {
        if (read_files.empty() || (object.kind && object_out.empty())) {
            std::fprintf(stderr, "--index needs -r INPUT; --object also needs --object-out FILE\n");
            return 2;
        }
        use_keylog();
        if (!object.kind) return run_index(read_files, table_opts, nullptr);
        object.out = std::fopen(object_out.c_str(), "wb");
        if (!object.out) {
            std::fprintf(stderr, "anta-engine: cannot write %s: %s\n", object_out.c_str(), std::strerror(errno));
            return 2;
        }
        int rc = run_index(read_files, table_opts, &object);
        if (std::fclose(object.out) != 0 && rc == 0) rc = 2;
        return rc;
    }

    if (!check_filters.empty()) return run_check_filters(check_filters);
    if (follow_stream >= 0) {
        if (read_files.empty()) {
            std::fprintf(stderr, "--follow needs -r INPUT\n");
            return 2;
        }
        FollowQuery fq;
        fq.inputs = read_files;
        fq.bases = query.bases;
        fq.udp = follow_udp;
        fq.stream = static_cast<uint64_t>(follow_stream);
        fq.kind = follow_kind;
        fq.h2_stream = follow_h2;
        fq.keylog = query.keylog;
        return run_follow(fq);
    }
    if (stats_mode) {
        if (read_files.empty()) {
            std::fprintf(stderr, "--stats needs -r INPUT\n");
            return 2;
        }
        StatsQuery sq;
        sq.inputs = read_files;
        sq.bases = query.bases;
        sq.bpf = cap.bpf;
        sq.dfilter = query.dfilter;
        sq.io_series = io_series;
        sq.counts = count_filters;
        sq.io_interval = io_interval;
        sq.single_pass = query.single_pass;
        return run_stats(sq);
    }
    if (query.sanitize && (query.save.empty() || !packets_mode)) {
        std::fprintf(stderr, "anta-engine: --sanitize goes with --packets ... --save OUT\n");
        return 2;
    }
    if (packets_mode) {
        if (read_files.empty()) {
            std::fprintf(stderr, "--packets/--packet-detail need -r INPUT\n");
            return 2;
        }
        query.bpf = cap.bpf;
        return run_packets(read_files, query);
    }

    if (read_files.size() > 1) {
        std::fprintf(stderr, "anta-engine: only one -r input is analysed at a time\n");
        return 2;
    }
    if (!read_files.empty()) cap.read_file = read_files[0];
    if (cap.iface.empty() == cap.read_file.empty()) {
        usage();
        return 2;
    }

    std::string error;
    auto transport = make_transport(endpoint, error);
    if (!transport) {
        std::fprintf(stderr, "anta-engine: %s\n", error.c_str());
        return 2;
    }
    // Tell the analyzer when the recording rotates so frame numbers keep mapping to files.
    cap.on_rotate = [](uint64_t base, uint64_t previous_base) {
        Emitter* em = g_emitter.load();
        if (!em) return;
        JsonWriter w;
        w.begin_object().kv("type", "capture_rotated").kv("base", base).kv("previous_base", previous_base).end_object();
        em->line(w.str());
    };
    auto source = open_source(cap, error);
    if (!source) {
        std::fprintf(stderr, "anta-engine: %s\n", error.c_str());
        return 1;
    }
    if (!drop_privileges(run_as, {cap.write_file})) return 1;

    g_source = source.get();
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
#ifndef _WIN32
    if (parent_pid > 0) {
        // An engine started through the OS password prompt isn't our child, so it can't
        // see the app's stdin close: it watches the app's process instead, and stops
        // capturing when the app is gone rather than recording for nobody. It also
        // watches the session's socket, which the app removes when the user stops the
        // capture: that stops it even if the app's stop signal never arrives.
        std::string sock;
        if (endpoint.rfind("zmq+ipc://", 0) == 0) sock = endpoint.substr(10);
        else if (endpoint.rfind("unix:", 0) == 0) sock = endpoint.substr(5);
        std::thread([pid = static_cast<pid_t>(parent_pid), sock] {
            bool seen = false;
            for (;;) {
                if (kill(pid, 0) != 0 && errno != EPERM) {
                    std::fprintf(stderr, "anta-engine: the app that started this capture has exited; stopping\n");
                    break;
                }
                if (!sock.empty()) {
                    struct stat st;
                    if (lstat(sock.c_str(), &st) == 0) {
                        seen = true;
                    } else if (seen && errno == ENOENT) {
                        std::fprintf(stderr, "anta-engine: the app stopped this capture; stopping\n");
                        break;
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
            }
            for (;;) {  // keep at it: the source and emitter may not exist yet
                if (PacketSource* src = g_source.load()) src->stop();
                if (Emitter* em = g_emitter.load()) em->abort();  // nobody is left to receive records
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }).detach();
    }
#else
    (void)parent_pid;  // Windows has no elevated capture: --stop-on-stdin-eof covers our children
#endif
    if (stop_on_stdin_eof) {
        // The parent holds our stdin open; closing it (or dying) asks for a clean stop.
        // Portable replacement for signals, which Windows can't deliver to a child.
        std::thread([] {
            while (std::fgetc(stdin) != EOF) {
            }
            if (PacketSource* src = g_source.load()) src->stop();
        }).detach();
    }

    // The capture file the analyzer can slice exports from.
    std::string capture_path = absolute_path(!cap.write_file.empty() ? cap.write_file : cap.read_file);

    // Offline input must not lose records, so it waits for the analyzer; live
    // capture sheds records instead of stalling the capture loop.
    Emitter emitter(std::move(transport), !source->is_live());
    g_emitter = &emitter;
    {
        JsonWriter hello;
        hello.begin_object()
            .kv("type", "hello")
            .kv("version", kVersion)
            .kv("source", source->is_live() ? cap.iface : cap.read_file)
            .kv("pid", process_id())
            .kv("live", source->is_live())
            .kv("capture", capture_path)
            .kv("capture_rotates", !cap.write_file.empty() && cap.write_max_bytes > 0)
            .kv("filter", cap.bpf)
            .kv("redacted", g_redact)
            .end_object();
        emitter.line(hello.str());
    }

    uint64_t sessions = 0;
    use_keylog();
    FlowTable table(table_opts, [&](const Flow& f, bool final) {
        if (final) ++sessions;
        emitter.line(serialize(f, final, capture_path));
    });

    uint64_t packets = 0, not_ip = 0, truncated = 0, fragments = 0, other_l4 = 0;
    const LinkType link = source->link_type();
    // Which hardware addresses claimed each IPv4 address over ARP; an IP with more
    // than one is cache poisoning (a LAN man-in-the-middle). Bounded, so a flood of
    // spoofed addresses can't grow it without limit.
    std::map<uint32_t, std::set<std::string>> arp_claims;
    auto record_arp = [&](const RawPacket& raw) {
        ArpClaim c;
        if (!parse_arp(link, raw.data, raw.caplen, c) || c.ipv4 == 0 || c.ipv4 == 0xFFFFFFFFu)
            return;
        bool bcast = true, zero = true;
        for (int i = 0; i < 6; ++i) { bcast &= c.mac[i] == 0xFF; zero &= c.mac[i] == 0; }
        if (bcast || zero)
            return;
        auto it = arp_claims.find(c.ipv4);
        if (it == arp_claims.end()) {
            if (arp_claims.size() >= 4096) return;
            it = arp_claims.emplace(c.ipv4, std::set<std::string>{}).first;
        }
        if (it->second.size() >= 8) return;
        char buf[18];
        std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                      c.mac[0], c.mac[1], c.mac[2], c.mac[3], c.mac[4], c.mac[5]);
        it->second.insert(buf);
    };
    // Live packet view: token bucket over capture time so a flood can't swamp the analyzer.
    // The inspector sees every packet (dropped ones too) so its TCP/SSH/FTP state stays right.
    Inspector feed_inspector;
    double feed_tokens = feed_pps;
    uint64_t feed_last_us = 0, feed_dropped = 0;
    uint64_t last_pkt_ts = 0, last_housekeeping = 0;

    auto emit_stats = [&](bool final) {
        CaptureStats cs = source->stats();
        JsonWriter w;
        w.begin_object()
            .kv("type", "stats")
            .kv("final", final)
            .kv("ts", static_cast<double>(source->is_live() ? wall_us() : last_pkt_ts) / 1e6)
            .kv("packets", packets)
            .kv("kernel_received", cs.received)
            .kv("kernel_dropped", cs.dropped)
            .kv("if_dropped", cs.if_dropped)
            .kv("non_ip", not_ip)
            .kv("truncated", truncated)
            .kv("fragments", fragments)
            .kv("other_l4", other_l4)
            .kv("active_flows", static_cast<uint64_t>(table.active()))
            .kv("flow_memory", static_cast<uint64_t>(table.memory()))
            .kv("peak_flow_memory", static_cast<uint64_t>(table.peak_memory()))
            .kv("evicted_flows", table.evicted())
            .kv("sessions", sessions)
            .kv("ipc_dropped", emitter.dropped())
            .kv("feed_dropped", feed_dropped);
        if (final) {  // only in the closing record: usually empty, so the live stream stays light
            w.key("arp_conflicts").begin_array();
            for (const auto& [ip, macs] : arp_claims) {
                if (macs.size() < 2) continue;
                uint8_t b[4];
                std::memcpy(b, &ip, 4);
                char dotted[16];
                std::snprintf(dotted, sizeof(dotted), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
                w.begin_object().kv("ip", dotted).key("macs").begin_array();
                for (const auto& m : macs) w.value(m);
                w.end_array().end_object();
            }
            w.end_array();
        }
        w.end_object();
        emitter.line(w.str());
    };

    auto on_packet = [&](const RawPacket& raw) {
        if ((++packets & 0x3FF) == 0 && emitter.broken()) source->stop();  // downstream reader is gone
        if (feed_pps > 0) {
            if (feed_last_us) feed_tokens += static_cast<double>(raw.ts_us - std::min(raw.ts_us, feed_last_us)) / 1e6 * feed_pps;
            feed_tokens = std::min(feed_tokens, feed_pps);
            feed_last_us = raw.ts_us;
            if (feed_tokens >= 1.0) {
                feed_tokens -= 1.0;
                JsonWriter w;
                write_packet_summary(w, feed_inspector.decode(link, raw.data, raw.caplen, packets, raw.ts_us), packets,
                                     raw.ts_us, raw.wire_len, raw.caplen);
                emitter.line(w.str());
            } else {
                feed_inspector.observe(link, raw.data, raw.caplen, packets, raw.ts_us);
                ++feed_dropped;
            }
        }
        PacketInfo info;
        info.ts_us = raw.ts_us;
        info.wire_len = raw.wire_len;
        switch (dissect(link, raw.data, raw.caplen, info)) {
            case DissectResult::Ok: break;
            case DissectResult::NotIp: ++not_ip; record_arp(raw); return;
            case DissectResult::Truncated: ++truncated; return;
            case DissectResult::Fragment: ++fragments; return;
            case DissectResult::UnsupportedL4: ++other_l4; return;
        }
        last_pkt_ts = raw.ts_us;
        if (print_packets) {
            std::fprintf(stderr, "%.6f %s %s:%u -> %s:%u len=%u flags=0x%02x seq=%u ack=%u win=%u\n",
                         static_cast<double>(raw.ts_us) / 1e6, proto_name(info.proto), info.src.str().c_str(),
                         info.sport, info.dst.str().c_str(), info.dport, info.payload_len, info.tcp_flags,
                         info.seq, info.ack, info.window);
        }
        table.on_packet(info);
    };

    auto on_idle = [&]() {
        if (!source->is_live()) return;
        uint64_t now = wall_us();
        if (now < last_housekeeping + 1'000'000) return;
        last_housekeeping = now;
        table.sweep(now);  // live timestamps are wall clock, so timeouts still fire when quiet
        static uint64_t last_stats = 0;
        if (now >= last_stats + 5'000'000) {
            last_stats = now;
            emit_stats(false);
        }
    };

    std::fprintf(stderr, "anta-engine: %s %s%s\n", source->is_live() ? "capturing on" : "reading",
                 source->is_live() ? cap.iface.c_str() : cap.read_file.c_str(),
                 cap.bpf.empty() ? "" : (" filter: " + cap.bpf).c_str());
    bool ok = source->run(on_packet, on_idle);
    table.flush_all();
    emit_stats(true);
    emitter.close();
    g_emitter.store(nullptr);

    CaptureStats cs = source->stats();
    g_source.store(nullptr);
    std::fprintf(stderr,
                 "anta-engine: %llu packets, %llu sessions, kernel drops %llu, non-ip %llu, truncated %llu, "
                 "fragments %llu, ipc dropped %llu\n",
                 static_cast<unsigned long long>(packets), static_cast<unsigned long long>(sessions),
                 static_cast<unsigned long long>(cs.dropped), static_cast<unsigned long long>(not_ip),
                 static_cast<unsigned long long>(truncated), static_cast<unsigned long long>(fragments),
                 static_cast<unsigned long long>(emitter.dropped()));
    if (!ok) {
        std::fprintf(stderr, "anta-engine: capture error: %s\n", source->error().c_str());
        return 1;
    }
    return 0;
}
