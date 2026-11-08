// Fuzz harness for everything that touches attacker-controlled bytes:
// L2-L4 dissection, flow tracking/reassembly and the DNS/HTTP/TLS parsers.
//
// Two modes:
//  * libFuzzer (Linux clang): build with -DANTA_LIBFUZZER -fsanitize=fuzzer,address,undefined
//  * standalone (any clang, used by `make fuzz`): a seeded mutation fuzzer that
//    takes real frames from pcaps, corrupts them, and runs them under ASan/UBSan.
//
// Input format for one test case: a sequence of [u16 length][frame bytes].

#include <pcap/pcap.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "../src/dfilter.h"
#include "../src/dpi.h"
#include "../src/tlsdecrypt.h"
#include "../src/tlskeys.h"
#include "../src/tlsstream.h"
#include "../src/flow.h"
#include "../src/ftpfiles.h"
#include "../src/http2.h"
#include "../src/inflate.h"
#include "../src/inspect.h"
#include "../src/packet.h"
#include "../src/proto.h"
#include "../src/sanitize.h"

using namespace anta;

namespace {

volatile size_t g_sink = 0;  // keep results observable so nothing is optimised away

// A key log for the seed captures' TLS sessions (seed.keys beside a seed): with it the
// decrypted-HTTP paths run on records that open, and mutated ones exercise the failures.
TlsKeyLog g_keylog;
const TlsKeyLog* keylog() { return g_keylog.empty() ? nullptr : &g_keylog; }

// Everything the decoder emits goes to the browser as JSON: it must always be
// valid UTF-8 with no raw control characters, whatever bytes were on the wire.
void check_json_text(const std::string& s) {
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x20) __builtin_trap();
        if (c < 0x80) continue;
        size_t n = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC2 ? 2 : 0;
        if (n == 0 || i + n > s.size()) __builtin_trap();
        for (size_t k = 1; k < n; ++k)
            if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80) __builtin_trap();
        i += n - 1;
    }
}

Inspector g_inspector;  // stateful, like a long capture: state must stay consistent under garbage

void exercise_viewer(LinkType link, const std::vector<uint8_t>& frame) {
    static uint64_t n = 0;
    if (n == 0) g_inspector.set_keylog(keylog());
    ++n;
    g_inspector.observe(link, frame.data(), frame.size(), n, n * 1000);
    ++n;
    DecodedFrame d = g_inspector.decode(link, frame.data(), frame.size(), n, n * 1000);
    for (const auto& l : d.layers) {  // every highlighted range must lie inside the captured bytes
        if (l.offset > frame.size() || l.length > frame.size() - l.offset) __builtin_trap();
        for (const auto& f : l.fields)
            if (f.offset > frame.size() || f.length > frame.size() - f.offset) __builtin_trap();
    }
    JsonWriter w;
    write_packet_detail(w, d, 1, 0, static_cast<uint32_t>(frame.size()), frame.data(),
                        static_cast<uint32_t>(frame.size()));
    check_json_text(w.str());
    g_sink += w.str().size();
}

void check_decoded(const DecodedFrame& d, const std::vector<uint8_t>& frame) {
    for (const auto& l : d.layers) {  // highlights must lie inside the captured bytes
        if (l.offset > frame.size() || l.length > frame.size() - l.offset) __builtin_trap();
        for (const auto& f : l.fields)
            if (f.offset > frame.size() || f.length > frame.size() - f.offset) __builtin_trap();
    }
    JsonWriter w;
    write_packet_summary(w, d, 1, 0, static_cast<uint32_t>(frame.size()), static_cast<uint32_t>(frame.size()));
    check_json_text(w.str());
    g_sink += w.str().size();
}

// Display filters the viewer, the coloring rules and the statistics run on every
// frame: each kind of comparison, slices, regexes and the expert fields.
const char* const kFilters[] = {
    "tcp.analysis.flags && !tcp.analysis.window_update",
    "ip.addr == 10.0.0.0/8 || ipv6.addr == fe80::/10",
    "tcp.port in {80, 443, 8000..8100} && tcp.len > 0",
    "frame contains \"GET\" || http.request.uri matches \"(?i)admin\"",
    "eth[0] & 1 || tcp[13] & 0x12 == 0x12 || ip[0:2] == 45:00",
    "dns.qry.name contains \"a\" && dns.time > 0.1 || dns.retransmit_request || dns.response_missing",
    "tls.handshake.type == 1 && tls.handshake.legacy_version || tls.malformed.buffer_too_small",
    "tcp.analysis.partial_ack || tcp.analysis.ambiguous_ack || tcp.analysis.acks_frame > 3",
    "ip.ttl.too_small || ip.ttl.lncb || ip.bogus_ip_length || udp.length.bad || icmp.type.error",
    "_ws.expert && !_ws.malformed && frame.len >= 60 && udp.stream < 4",
};

const std::vector<std::unique_ptr<DisplayFilter>>& compiled_filters() {
    static std::vector<std::unique_ptr<DisplayFilter>> out = [] {
        std::vector<std::unique_ptr<DisplayFilter>> v;
        for (const char* f : kFilters) {
            std::string err;
            auto c = DisplayFilter::compile(f, err);
            if (!c) {
                std::fprintf(stderr, "harness filter does not compile: %s: %s\n", f, err.c_str());
                __builtin_trap();
            }
            v.push_back(std::move(c));
        }
        return v;
    }();
    return out;
}

// The fields a frame produced must describe its own bytes. (Their text reaches the
// browser through the JSON writer, which write_packet_detail checks below.)
void check_fields(const FrameFields& ff, const std::vector<uint8_t>& frame) {
    for (const auto& p : ff.protos)
        if (p.offset > frame.size() || p.length > frame.size() - p.offset) __builtin_trap();
    for (const auto& f : ff.fields) g_sink += filter_literal(f.value).size();
    for (const auto& flt : compiled_filters()) g_sink += flt->match(ff);
}

// The filter language itself: mutated filter text must compile or fail cleanly.
void exercise_filter_parser(std::mt19937_64& rng, const FrameFields& ff) {
    std::string f = kFilters[rng() % (sizeof(kFilters) / sizeof(kFilters[0]))];
    static const char pieces[] = "()[]{}!&|=<>~:.,\"\\-0123456789abcfx/ ";
    for (int k = 1 + static_cast<int>(rng() % 6); k > 0 && !f.empty(); --k) {
        size_t i = rng() % f.size();
        switch (rng() % 3) {
            case 0: f[i] = pieces[rng() % (sizeof(pieces) - 1)]; break;
            case 1: f.erase(i, 1 + rng() % 4); break;
            default: f.insert(i, 1, static_cast<char>(rng() % 256)); break;
        }
    }
    std::string err;
    if (auto c = DisplayFilter::compile(f, err)) g_sink += c->match(ff);
    else check_json_text(err);
}

// The file view: a recording pass collects look-ahead cross-references (TCP
// message boundaries, ICMP replies, IP fragments), a second pass uses them.
void exercise_two_pass(const std::vector<std::vector<uint8_t>>& frames) {
    InspectorAnnotations ann;
    {
        Inspector recorder(&ann, nullptr);
        recorder.set_keylog(keylog());
        for (size_t i = 0; i < frames.size(); ++i)
            recorder.observe(LinkType::Ethernet, frames[i].data(), frames[i].size(), i + 1, (i + 1) * 50'000);
    }
    ann.complete = true;
    Inspector viewer(nullptr, &ann);
    viewer.set_keylog(keylog());
    FrameFields ff;
    std::mt19937_64 rng(frames.size());
    for (size_t i = 0; i < frames.size(); ++i) {
        if (i % 3 == 2) {  // pages skip frames: observed, not displayed
            viewer.observe(LinkType::Ethernet, frames[i].data(), frames[i].size(), i + 1, (i + 1) * 50'000);
            continue;
        }
        // Filtering and the statistics decode with fields, sometimes with a wire
        // length larger than what was captured.
        uint32_t wire = static_cast<uint32_t>(frames[i].size() + (i % 4 == 1 ? 100 : 0));
        DecodedFrame d = viewer.decode(LinkType::Ethernet, frames[i].data(), frames[i].size(), i + 1,
                                       (i + 1) * 50'000, &ff, wire);
        check_decoded(d, frames[i]);
        check_fields(ff, frames[i]);
        for (const auto& note : d.notes) check_json_text(note.summary);
        if (i % 7 == 0) {
            JsonWriter w;
            write_packet_detail(w, d, i + 1, 0, wire, frames[i].data(), static_cast<uint32_t>(frames[i].size()), &ff);
            check_json_text(w.str());
            exercise_filter_parser(rng, ff);
        }
    }
}

// Compressed HTTP bodies: any gzip stream inside a frame (mutated or not) goes
// through the decoder, with a small output cap so bombs stop early.
void exercise_inflate(const uint8_t* data, size_t len) {
    for (size_t i = 0; i + 3 <= len; ++i) {
        if (data[i] != 0x1f || data[i + 1] != 0x8b) continue;
        std::string in(reinterpret_cast<const char*>(data + i), len - i), out;
        g_sink += http_decode_body(in, "gzip", out, 1u << 20) ? out.size() : 1;
        if (in.size() > 10) g_sink += http_decode_body(in.substr(10), "deflate", out, 1u << 20) ? out.size() : 1;
        if (out.size() > (1u << 20)) __builtin_trap();
        return;
    }
}

// QUIC: header parsing, Initial decryption (garbage fails the AEAD tag, so the
// frame parser also gets the raw bytes) and CRYPTO stream reassembly.
void exercise_quic(const uint8_t* data, size_t len) {
    QuicLongHeader h;
    if (quic_parse_long_header(data, len, h) && quic_known_version(h.version) && h.length <= len) {
        QuicKeys k;
        uint64_t pn = 0;
        std::string payload;
        if (quic_initial_keys(h.version, h.dcid, false, k) && quic_open(data, h, k, -1, pn, payload))
            g_sink += payload.size();
    }
    std::string raw(reinterpret_cast<const char*>(data), len);
    QuicFrames frames = quic_frames(raw);
    QuicCryptoStream crypto;
    for (const auto& c : frames.crypto) crypto.add(c.first, c.second);
    bool complete = false;
    if (auto ch = quic_client_hello(crypto.head(), complete)) g_sink += ch->sni.size();
    QuicHelloReader reader;
    g_sink += reader.on_client_datagram(data, len);
}

// SMB2 file copies: the payload as either side's stream, split at a varying point.
void exercise_smb_files(const uint8_t* data, size_t len) {
    SmbFileTracker t;
    size_t cut = len / 3;
    t.on_data(true, data, cut, 1);
    t.on_data(false, data + cut, len - cut, 2);
    t.on_data(false, data, len, 3);
    t.finish();
    for (const auto& f : t.files()) g_sink += f.size + f.sha256.size();
}

// FTP control text both ways (replies and commands), split mid-line, plus the
// data-side accounting a file passes through.
void exercise_ftp(const uint8_t* data, size_t len) {
    IpAddr a, b;
    a.family = b.family = 4;
    a.bytes[0] = 10;
    b.bytes[0] = 172;
    FtpControl c(a, 50000, b, 21);
    std::vector<FtpExpect> expect;
    size_t cut = len / 2;
    c.on_data(true, data, cut, expect);
    c.on_data(false, data + cut, len - cut, expect);
    c.on_data(false, data, cut, expect);
    c.on_data(true, data + cut, len - cut, expect);
    FtpDataSide side;
    side.add(data, len);
    g_sink += expect.size() + c.commands.size() + c.user.size() + side.bytes + side.head.size();
    for (const auto& e : expect) g_sink += e.port + e.transfer->name.size();
}

void exercise_parsers(const uint8_t* data, size_t len) {
    exercise_inflate(data, len);
    exercise_quic(data, len);
    exercise_smb_files(data, len);
    exercise_ftp(data, len);
    if (auto d = parse_dns(data, len)) g_sink += d->qname.size() + d->answers.size();
    std::string s(reinterpret_cast<const char*>(data), len);
    if (auto ch = parse_tls_client_hello(s)) g_sink += ch->ja3.size() + ch->ja4.size();
    if (auto sh = parse_tls_server_hello(s)) g_sink += sh->cipher;
    g_sink += parse_http_requests(s, 16).size();
    if (auto r = parse_http_response(s)) g_sink += static_cast<size_t>(r->status);
    // TLS 1.3 and 1.2 record decryption on mutated secrets and record bytes, every
    // supported suite (authentication normally fails; the failure paths are what run).
    if (len >= 48) {
        std::vector<uint8_t> out(len);
        for (uint16_t cs : {uint16_t{0x1301}, uint16_t{0x1302}, uint16_t{0x1303}}) {
            TlsRecordKeys rk = tls13_record_keys(data, cs == 0x1302 ? 48 : 32, cs);
            long n = tls13_open(rk, data[0], data, data + 5, len - 5, out.data());
            if (n > 0) g_sink += out[0];
        }
        for (uint16_t cs : {uint16_t{0xC02F}, uint16_t{0xC030}, uint16_t{0xCCA8}}) {
            Tls12Keys k = tls12_keys(data, data, data + 16, cs);
            long n = tls12_open(k, data[1] & 1, data[2], 23, 0x0303, data + 8, len - 8, out.data());
            if (n > 0) g_sink += out[0];
        }
    }
    // The analysis path's stream decryptor: the bytes as both sides' streams, cut at
    // varying points so records split across calls.
    {
        TlsStreamDecryptor dec(keylog());
        std::string plain;
        size_t cut = len ? data[0] % (len + 1) : 0;
        dec.feed(0, data, cut, plain);
        dec.feed(1, data + cut, len - cut, plain);
        dec.feed(0, data + cut, len - cut, plain);
        dec.feed(1, data, cut, plain);
        g_sink += plain.size() + dec.buffered() + dec.records();
    }
    // HTTP/2: HPACK blocks whole and in fragments, Huffman strings, and the frame reader
    // over both sides' streams cut at varying points.
    {
        struct Count : Http2Handler {
            size_t n = 0;
            void h2_headers(int, uint32_t, const Http2Headers& h, bool, bool) override { n += h.size(); }
            void h2_data(int, uint32_t, const uint8_t*, size_t len) override { n += len; }
            void h2_end(int, uint32_t) override { ++n; }
            void h2_reset(uint32_t) override { ++n; }
        } count;
        Hpack whole, pieces;
        Http2Headers h;
        std::vector<HpackRepr> reprs;
        std::vector<uint32_t> updates;
        g_sink += whole.decode(data, len, h, &reprs, &updates);
        size_t used = 0, cut = len ? data[len - 1] % (len + 1) : 0;
        if (pieces.decode(data, cut, h, nullptr, nullptr, &used) && used <= cut) {
            std::string rest(reinterpret_cast<const char*>(data + used), len - used);
            g_sink += pieces.decode(reinterpret_cast<const uint8_t*>(rest.data()), rest.size(), h);
        }
        std::string huff;
        g_sink += hpack_huffman_decode(data, len, huff) + huff.size() + h.size();
        for (bool preface : {false, true}) {
            Http2Reader r(preface);
            size_t c2 = len ? data[0] % (len + 1) : 0;
            r.feed(0, data, c2, count);
            r.feed(1, data + c2, len - c2, count);
            r.feed(0, data + c2, len - c2, count);
            r.feed(1, data, c2, count);
            g_sink += r.frames() + r.buffered();
        }
        g_sink += count.n;
    }
    // Application identification from each side's first bytes, both ways round.
    size_t half = len / 2;
    std::string a = s.substr(0, std::min<size_t>(half, kDpiHead)), b = s.substr(half, kDpiHead);
    for (uint8_t proto : {uint8_t{6}, uint8_t{17}}) {
        AppId x = identify_app(proto, a, b), y = identify_app(proto, b, a), z = identify_app(proto, s.substr(0, kDpiHead), "");
        g_sink += std::strlen(x.name) + std::strlen(y.name) + std::strlen(z.name);
        uint16_t port = len >= 2 ? static_cast<uint16_t>((data[0] << 8) | data[1]) : 0;
        if (app_for_port(proto, port)[0]) g_sink += app_fits_port(proto, port, x.name);
    }
}

void run_case(const uint8_t* data, size_t size) {
    FlowTableOptions opts;
    opts.memory_budget = 4u << 20;  // small budget so eviction paths run too
    opts.max_flows = 64;
    opts.pending_limit = 64 * 1024;
    opts.update_interval_us = 1'000'000;
    opts.keylog = keylog();  // HTTPS read with the key log: decrypted, then parsed as HTTP
    // Export Objects: write one of the first flows' files out as it streams past
    // (which kind and object vary with the input, so every writer path runs).
    static std::FILE* sink = std::tmpfile();
    ObjectTarget target;
    target.flow_id = 1 + (size ? data[0] % 4 : 0);
    target.kind = "hsf"[size > 1 ? data[1] % 3 : 0];
    target.n = size > 2 ? data[2] % 2 : 0;
    target.out = sink;
    if (sink) {
        std::rewind(sink);
        opts.object = &target;
    }
    FlowTable table(opts, [](const Flow& f, bool) {
        g_sink += f.events.size() + f.dns.size() + f.http.size() + (f.tls ? f.tls->ja3.size() : 0);
    });
    // Share-safe copies, contents cut and kept: every rewriter path on the same bytes.
    static const uint8_t kKey[32] = {1, 2, 3};
    Sanitizer cut({false, false}, kKey), keep({true, true}, kKey);
    std::vector<uint8_t> clean;

    size_t off = 0;
    uint64_t ts = 1'700'000'000'000'000ULL;
    std::vector<std::vector<uint8_t>> all;
    while (off + 2 <= size) {
        size_t len = static_cast<size_t>(data[off] | (data[off + 1] << 8));
        off += 2;
        if (len > size - off) len = size - off;
        // Copy into an exactly-sized heap buffer so ASan flags any overread.
        std::vector<uint8_t> frame(data + off, data + off + len);
        off += len;
        all.push_back(frame);
        ts += 50'000;

        PacketInfo info;
        info.ts_us = ts;
        info.wire_len = static_cast<uint32_t>(len);
        for (LinkType lt : {LinkType::Ethernet, LinkType::Raw, LinkType::Null, LinkType::LinuxSll, LinkType::LinuxSll2,
                            LinkType::Ieee80211, LinkType::Radiotap, LinkType::Pktap, LinkType::Nflog, LinkType::Ppp,
                            LinkType::Ppi}) {
            exercise_viewer(lt, frame);
            for (Sanitizer* z : {&cut, &keep}) {
                if (z->frame(lt, frame.data(), frame.size(), clean)) {
                    if (clean.size() > frame.size()) __builtin_trap();  // a copy never grows
                    PacketInfo again;  // and still reads
                    g_sink += clean.size() + static_cast<size_t>(dissect(lt, clean.data(), clean.size(), again));
                }
            }
            PacketInfo probe = info;
            if (dissect(lt, frame.data(), frame.size(), probe) == DissectResult::Ok && lt == LinkType::Ethernet) {
                table.on_packet(probe);
                if (probe.payload_len) exercise_parsers(probe.payload, probe.payload_len);
            }
            ArpClaim ac;  // the analysis-path ARP parser, on the same untrusted bytes
            if (parse_arp(lt, frame.data(), frame.size(), ac)) g_sink += ac.ipv4;
        }
        exercise_parsers(frame.data(), frame.size());
    }
    table.flush_all();
    exercise_two_pass(all);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    run_case(data, size);
    return 0;
}

#ifndef ANTA_LIBFUZZER

namespace {

std::vector<std::vector<uint8_t>> load_frames(const char* path) {
    std::vector<std::vector<uint8_t>> frames;
    char err[PCAP_ERRBUF_SIZE];
    pcap_t* p = pcap_open_offline(path, err);
    if (!p) {
        std::fprintf(stderr, "seed %s: %s\n", path, err);
        return frames;
    }
    pcap_pkthdr* h;
    const u_char* d;
    while (pcap_next_ex(p, &h, &d) == 1 && frames.size() < 200'000) frames.emplace_back(d, d + h->caplen);
    pcap_close(p);
    return frames;
}

void mutate(std::vector<uint8_t>& f, std::mt19937_64& rng) {
    static const uint8_t interesting[] = {0x00, 0x01, 0x05, 0x0f, 0x10, 0x3f, 0x40, 0x7f, 0x80, 0xc0, 0xfe, 0xff};
    std::uniform_int_distribution<int> op(0, 9);
    int rounds = 1 + static_cast<int>(rng() % 4);
    for (int r = 0; r < rounds; ++r) {
        if (f.empty()) f.push_back(0);
        size_t i = rng() % f.size();
        switch (op(rng)) {
            case 0: f[i] ^= static_cast<uint8_t>(1u << (rng() % 8)); break;
            case 1: f[i] = interesting[rng() % sizeof(interesting)]; break;
            case 2: f.resize(rng() % (f.size() + 1)); break;                       // truncate
            case 3: for (int k = 0; k < 16; ++k) f.push_back(static_cast<uint8_t>(rng())); break;
            case 4: if (i + 1 < f.size()) { f[i] = 0xff; f[i + 1] = 0xff; } break;  // max a 16-bit field
            case 5: if (f.size() > 14) f[14] = interesting[rng() % sizeof(interesting)]; break;  // IP ver/IHL
            case 6: if (f.size() > 46) f[46] = interesting[rng() % sizeof(interesting)]; break;  // TCP data offset
            case 7: if (f.size() > 17) { f[16] = static_cast<uint8_t>(rng()); f[17] = static_cast<uint8_t>(rng()); } break;
            case 8: if (f.size() > 54) f[54 + rng() % (f.size() - 54)] = static_cast<uint8_t>(rng()); break;  // payload
            default: f.insert(f.begin() + static_cast<std::ptrdiff_t>(i), static_cast<uint8_t>(rng())); break;
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s SECONDS seed.pcap [seed.pcap...]\n", argv[0]);
        return 2;
    }
    double seconds = std::atof(argv[1]);
    std::vector<std::vector<uint8_t>> seeds;
    for (int i = 2; i < argc; ++i) {
        std::string keys = argv[i];  // seed.pcap's TLS secrets, if seed.keys is beside it
        keys = keys.substr(0, keys.rfind('.')) + ".keys";
        if (std::FILE* k = std::fopen(keys.c_str(), "r")) {
            std::fclose(k);
            std::fprintf(stderr, "key log %s: %zu secrets\n", keys.c_str(), g_keylog.load(keys));
        }
        auto f = load_frames(argv[i]);
        seeds.insert(seeds.end(), f.begin(), f.end());
    }
    if (seeds.empty()) return 2;

    uint64_t seed = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    std::mt19937_64 rng(seed);
    std::fprintf(stderr, "fuzzing %zu seed frames for %.0fs (rng seed %llu)\n", seeds.size(), seconds,
                 static_cast<unsigned long long>(seed));
    auto deadline = std::chrono::steady_clock::now() + std::chrono::duration<double>(seconds);
    uint64_t cases = 0, frames = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        // Take a run of consecutive frames (so handshakes and streams stay mostly
        // coherent), corrupt some of them, and shuffle a few into new orders.
        size_t start = rng() % seeds.size();
        size_t n = 1 + rng() % 96;
        std::vector<uint8_t> input;
        for (size_t k = 0; k < n; ++k) {
            std::vector<uint8_t> f = seeds[(start + k) % seeds.size()];
            if (rng() % 3 == 0) mutate(f, rng);
            if (f.size() > 0xffff) f.resize(0xffff);
            input.push_back(static_cast<uint8_t>(f.size() & 0xff));
            input.push_back(static_cast<uint8_t>(f.size() >> 8));
            input.insert(input.end(), f.begin(), f.end());
            if (rng() % 16 == 0) {  // duplicate frame (retransmission-like)
                input.push_back(static_cast<uint8_t>(f.size() & 0xff));
                input.push_back(static_cast<uint8_t>(f.size() >> 8));
                input.insert(input.end(), f.begin(), f.end());
            }
        }
        run_case(input.data(), input.size());
        ++cases;
        frames += n;
    }
    std::fprintf(stderr, "ok: %llu cases, %llu frames, no sanitizer findings\n", static_cast<unsigned long long>(cases),
                 static_cast<unsigned long long>(frames));
    return 0;
}

#endif
