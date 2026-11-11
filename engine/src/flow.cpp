#include "flow.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <cstring>

#include "headers.h"
#include "dpi.h"
#include "inflate.h"

namespace anta {

namespace {
// Approximate heap cost of one buffered out-of-order segment (map node + vector).
// Counting it means a flood of 1-byte segments hits the cap as fast as large ones.
constexpr size_t kSegmentOverhead = 96;
}  // namespace

using wire::TCP_ACK;
using wire::TCP_FIN;
using wire::TCP_RST;
using wire::TCP_SYN;

// ------------------------------------------------------------------ FlowKey

FlowKey FlowKey::from_packet(const PacketInfo& p, bool& a_to_b) {
    FlowKey k;
    k.proto = p.proto;
    bool src_first = p.src < p.dst || (p.src == p.dst && p.sport <= p.dport);
    if (src_first) {
        k.a = p.src; k.port_a = p.sport;
        k.b = p.dst; k.port_b = p.dport;
    } else {
        k.a = p.dst; k.port_a = p.dport;
        k.b = p.src; k.port_b = p.sport;
    }
    a_to_b = src_first;
    return k;
}

size_t FlowKeyHash::operator()(const FlowKey& k) const {
    // FNV-1a over the canonical tuple.
    uint64_t h = 1469598103934665603ULL;
    auto mix = [&h](const uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            h ^= p[i];
            h *= 1099511628211ULL;
        }
    };
    size_t addr_len = k.a.family == 6 ? 16 : 4;
    mix(k.a.bytes.data(), addr_len);
    mix(k.b.bytes.data(), addr_len);
    mix(reinterpret_cast<const uint8_t*>(&k.port_a), 2);
    mix(reinterpret_cast<const uint8_t*>(&k.port_b), 2);
    mix(&k.proto, 1);
    return static_cast<size_t>(h);
}

// ---------------------------------------------------------------- TcpStream

TcpStream::SegmentKind TcpStream::on_segment(uint32_t seq, uint8_t flags, const uint8_t* data, size_t len,
                                             size_t pending_limit, const Sink& sink) {
    if (flags & TCP_RST) rst_seen = true;
    if (flags & TCP_SYN) {
        syn_seen = true;
        if (!initialized_) {
            next_seq_ = seq + 1;  // SYN consumes one sequence number
            initialized_ = true;
        }
        return SegmentKind::Empty;  // ignore TFO data on SYN
    }
    if (len == 0) {
        if (flags & TCP_FIN) fin_seen = true;
        return SegmentKind::Empty;
    }
    if (!initialized_) {  // joined mid-stream: trust the first data segment
        next_seq_ = seq;
        initialized_ = true;
    }
    if (flags & TCP_FIN) fin_seen = true;

    // Signed distance handles 32-bit sequence wraparound.
    int32_t delta = static_cast<int32_t>(seq - next_seq_);
    if (delta == 0) {
        deliver(data, len, sink);
        drain(sink);
        return SegmentKind::InOrder;
    }
    if (delta < 0) {
        size_t overlap = static_cast<size_t>(-static_cast<int64_t>(delta));
        ++retransmissions;
        if (overlap >= len) return SegmentKind::Retransmission;
        deliver(data + overlap, len - overlap, sink);
        drain(sink);
        return SegmentKind::PartialOverlap;
    }

    uint64_t offset = delivered_ + static_cast<uint64_t>(delta);
    auto it = pending_.find(offset);
    if (it != pending_.end()) {
        if (it->second.size() >= len) {
            ++retransmissions;
            return SegmentKind::Retransmission;
        }
        pending_bytes_ -= it->second.size() + kSegmentOverhead;
    }
    pending_[offset].assign(data, data + len);
    pending_bytes_ += len + kSegmentOverhead;
    ++out_of_order;

    // Memory pressure: give up on the oldest hole rather than buffer forever.
    while (pending_bytes_ > pending_limit && !pending_.empty()) {
        uint64_t hole = pending_.begin()->first - delivered_;
        gap_bytes += static_cast<uint32_t>(hole);
        next_seq_ += static_cast<uint32_t>(hole);
        delivered_ += hole;
        drain(sink);
    }
    return SegmentKind::OutOfOrder;
}

void TcpStream::deliver(const uint8_t* data, size_t len, const Sink& sink) {
    sink(data, len);
    next_seq_ += static_cast<uint32_t>(len);
    delivered_ += len;
}

void TcpStream::drain(const Sink& sink) {
    while (!pending_.empty()) {
        auto it = pending_.begin();
        if (it->first > delivered_) break;
        const auto& seg = it->second;
        size_t skip = static_cast<size_t>(delivered_ - it->first);
        if (skip < seg.size()) deliver(seg.data() + skip, seg.size() - skip, sink);
        pending_bytes_ -= seg.size() + kSegmentOverhead;
        pending_.erase(it);
    }
}

void TcpStream::flush(const Sink& sink) {
    while (!pending_.empty()) {
        uint64_t hole = pending_.begin()->first - delivered_;
        gap_bytes += static_cast<uint32_t>(hole);
        next_seq_ += static_cast<uint32_t>(hole);
        delivered_ += hole;
        drain(sink);
    }
}

// ---------------------------------------------------------------- FlowTable

namespace {

bool is_well_known_server_port(uint16_t port) {
    switch (port) {
        case 53: case 80: case 123: case 443: case 853: case 5353: case 8080: case 8443:
            return true;
        default:
            return port < 1024;
    }
}

bool is_dns_port(uint16_t port) { return port == 53 || port == 5353 || port == 5355; }

}  // namespace

Flow& FlowTable::lookup(const PacketInfo& p, bool& is_c2s, bool& created) {
    bool a_to_b = false;
    FlowKey key = FlowKey::from_packet(p, a_to_b);
    created = false;

    auto it = flows_.find(key);
    bool fresh_syn = p.proto == wire::IPPROTO_TCP_ && (p.tcp_flags & TCP_SYN) && !(p.tcp_flags & TCP_ACK);
    if (it != flows_.end() && it->second->closed && fresh_syn) {
        // Port reuse: the old connection is done, start a new session.
        finish(*it->second);
        total_mem_ -= it->second->mem;
        flows_.erase(it);
        it = flows_.end();
    }
    if (it == flows_.end()) {
        auto f = std::make_unique<Flow>();
        f->id = next_id_++;
        f->proto = p.proto;
        f->first_ts = p.ts_us;

        // Decide who initiated the conversation.
        bool sender_is_client = true;
        if (p.proto == wire::IPPROTO_TCP_ && (p.tcp_flags & TCP_SYN)) {
            sender_is_client = !(p.tcp_flags & TCP_ACK);
        } else if (is_well_known_server_port(p.sport) != is_well_known_server_port(p.dport)) {
            sender_is_client = is_well_known_server_port(p.dport);
        } else if (p.proto == wire::IPPROTO_TCP_) {
            sender_is_client = p.sport > p.dport;  // mid-stream join: ephemeral port is the client
        }
        f->client_is_a = (sender_is_client == a_to_b);
        if (sender_is_client) {
            f->client_ip = p.src; f->client_port = p.sport;
            f->server_ip = p.dst; f->server_port = p.dport;
        } else {
            f->client_ip = p.dst; f->client_port = p.dport;
            f->server_ip = p.src; f->server_port = p.sport;
        }
        if (p.proto == wire::IPPROTO_TCP_ && !ftp_expect_.empty()) {  // an FTP data connection?
            auto e = ftp_expect_.find({f->server_ip, f->server_port, f->client_ip});
            if (e != ftp_expect_.end()) {
                auto transfer = e->second.first;
                if (p.ts_us < e->second.second + 600'000'000) {
                    f->ftp_transfer = transfer;
                    f->ftp_data = std::make_unique<FtpDataSide[]>(2);
                }
                // One connection per announcement: drop its other address (NAT) too.
                for (auto x = ftp_expect_.begin(); x != ftp_expect_.end();)
                    x = x->second.first == transfer ? ftp_expect_.erase(x) : std::next(x);
            }
        }
        it = flows_.emplace(key, std::move(f)).first;
        created = true;
    }
    Flow& f = *it->second;
    is_c2s = (a_to_b == f.client_is_a);
    return f;
}

void FlowTable::on_packet(const PacketInfo& p) {
    bool is_c2s = false, created = false;
    Flow& f = lookup(p, is_c2s, created);
    Dir dir = is_c2s ? Dir::ClientToServer : Dir::ServerToClient;
    auto d = static_cast<size_t>(dir);

    f.stats[d].packets++;
    f.stats[d].bytes += p.wire_len;
    f.last_ts = p.ts_us;
    f.dirty = true;
    if (created) f.last_emit_ts = p.ts_us;

    if (p.proto == wire::IPPROTO_TCP_) handle_tcp(f, p, dir);
    else handle_udp(f, p, dir);
    account(f);

    // `f` must not be used past this point: eviction may finish and free it.
    if (total_mem_ > opts_.memory_budget || flows_.size() > opts_.max_flows)
        evict_oldest(std::max<size_t>(1, flows_.size() / 10));
    sweep(p.ts_us);
}

void FlowTable::account(Flow& f) {
    size_t m = sizeof(Flow) + f.events.capacity() * sizeof(PayloadEvent) + f.app_buf[0].capacity() +
               f.app_buf[1].capacity() + f.tcp[0].buffered() + f.tcp[1].buffered() +
               f.dns.capacity() * (sizeof(DnsMessage) + 128) + f.http.capacity() * (sizeof(HttpRequest) + 256) +
               (f.ftp_data ? f.ftp_data[0].head.capacity() + f.ftp_data[1].head.capacity() : 0) +
               (f.tls_plain ? sizeof(TlsPlain) + f.tls_plain->req.capacity() + f.tls_plain->resp.capacity() +
                                  f.tls_plain->held[0].capacity() + f.tls_plain->held[1].capacity() +
                                  f.tls_plain->dec.buffered() : 0) +
               (f.h2 ? sizeof(H2State) + f.h2->reader.buffered() + f.h2->streams.size() * sizeof(H2Stream) : 0);
    total_mem_ = total_mem_ + m - f.mem;
    f.mem = m;
    if (total_mem_ > peak_mem_) peak_mem_ = total_mem_;
}

void FlowTable::evict_oldest(size_t count) {
    // Finish the least recently active flows early (they are emitted, not lost).
    std::vector<std::pair<uint64_t, const FlowKey*>> by_age;
    by_age.reserve(flows_.size());
    for (auto& [key, f] : flows_) by_age.emplace_back(f->last_ts, &key);
    count = std::min(count, by_age.size());
    std::nth_element(by_age.begin(), by_age.begin() + static_cast<std::ptrdiff_t>(count), by_age.end());
    std::vector<FlowKey> victims;
    victims.reserve(count);
    for (size_t i = 0; i < count; ++i) victims.push_back(*by_age[i].second);
    for (const auto& key : victims) {
        auto it = flows_.find(key);
        if (it == flows_.end()) continue;
        it->second->evicted = true;
        finish(*it->second);
        total_mem_ -= it->second->mem;
        flows_.erase(it);
        ++evicted_;
    }
}

void FlowTable::handle_tcp(Flow& f, const PacketInfo& p, Dir dir) {
    auto d = static_cast<size_t>(dir);
    TcpStream& stream = f.tcp[d];
    if (p.window == 0 && !(p.tcp_flags & (TCP_RST | TCP_SYN))) stream.zero_window++;
    if (p.tcp_flags == 0) f.null_flags++;  // no stack sends these: crafted packets, NULL scans
    {  // The handshake's timing: the first SYN, the SYN/ACK that answers it, the ACK after that.
        const uint8_t fl = p.tcp_flags;
        if (dir == Dir::ClientToServer && (fl & TCP_SYN) && !(fl & TCP_ACK) && !f.syn_ts) {
            f.syn_ts = p.ts_us;
            f.syn_seq = p.seq;
        } else if (dir == Dir::ServerToClient && (fl & TCP_SYN) && (fl & TCP_ACK) && f.syn_ts && !f.synack_ts &&
                   p.ack == f.syn_seq + 1 && p.ts_us >= f.syn_ts) {
            f.synack_ts = p.ts_us;
        } else if (dir == Dir::ClientToServer && (fl & TCP_ACK) && !(fl & (TCP_SYN | TCP_RST)) && f.synack_ts &&
                   !f.hs_ack_ts && p.ts_us >= f.synack_ts) {
            f.hs_ack_ts = p.ts_us;
        }
    }

    auto kind = stream.on_segment(p.seq, p.tcp_flags, p.payload, p.payload_len, opts_.pending_limit,
                                  [&](const uint8_t* data, size_t len) { on_stream_data(f, dir, data, len); });

    if (p.payload_len > 0 && kind != TcpStream::SegmentKind::Retransmission) record_event(f, p, dir);
    if (f.tcp[0].syn_seen && f.tcp[1].syn_seen) f.handshake_seen = true;

    if (!f.closed && (stream.rst_seen || (f.tcp[0].fin_seen && f.tcp[1].fin_seen))) {
        f.closed = true;
        f.closed_ts = p.ts_us;
    }
}

void FlowTable::handle_udp(Flow& f, const PacketInfo& p, Dir dir) {
    auto d = static_cast<size_t>(dir);
    f.stats[d].payload_bytes += p.payload_len;
    if (p.payload_len > 0) record_event(f, p, dir);
    if (p.payload_len > 0 && f.head[d].empty()) {  // each direction's first datagram, for DPI
        f.head[d].assign(reinterpret_cast<const char*>(p.payload), std::min<size_t>(p.payload_len, kDpiHead));
        if (f.first_speaker < 0) f.first_speaker = static_cast<int8_t>(d);
    }

    // QUIC: the Client Hello (server name, fingerprints) rides in Initial packets.
    if (f.server_port == 443 && dir == Dir::ClientToServer && p.payload_len > 0 && !f.quic_done) {
        if (!f.quic) f.quic = std::make_unique<QuicHelloReader>();
        if (f.quic->on_client_datagram(p.payload, p.payload_len)) {
            if (f.quic->hello) f.tls = std::move(f.quic->hello);
            f.quic.reset();
            f.quic_done = true;
        }
    }

    // DTLS: the hellos are plaintext handshake records, fragmented to fit datagrams.
    if (p.payload_len >= 13 && !f.dtls_done && (f.dtls || (p.payload[0] == 22 && p.payload[1] == 0xfe))) {
        if (!f.dtls) f.dtls = std::make_unique<DtlsHelloReader>();
        bool done = f.dtls->on_datagram(p.payload, p.payload_len, dir == Dir::ClientToServer);
        if (f.dtls->hello && !f.tls) f.tls = f.dtls->hello;
        if (f.dtls->server_hello && !f.tls_server) f.tls_server = f.dtls->server_hello;
        if (done) {
            f.dtls.reset();
            f.dtls_done = true;
        }
    }

    // SNMP v1/v2c: the community string travels in clear text (it is never kept).
    if ((f.server_port == 161 || f.server_port == 162) && p.payload_len > 0 && p.payload[0] == 0x30) {
        if (!f.logins) f.logins = std::make_unique<LoginTracker>("SNMP");
        f.logins->snmp(p.payload, p.payload_len, p.ts_us);
    }

    if ((is_dns_port(f.server_port) || is_dns_port(f.client_port)) && p.payload_len > 0) {
        auto msg = parse_dns(p.payload, p.payload_len);
        if (!msg) return;
        if (msg->is_response) {
            for (auto& q : f.dns) {
                if (q.txid == msg->txid && !q.is_response) {
                    q.is_response = true;  // fold the answer into the matching query
                    q.rcode = msg->rcode;
                    q.answers = msg->answers;
                    q.txt_bytes = msg->txt_bytes;
                    q.answer_count = msg->answer_count;
                    return;
                }
            }
        }
        if (f.dns.size() < 64) f.dns.push_back(std::move(*msg));
    }
}

namespace {
constexpr size_t kHeadBytes = 16;
constexpr size_t kMaxHttpFiles = 64;
constexpr size_t kMaxHttpHeader = 16 * 1024;

bool header_value(const std::string& block, const char* name, std::string& out) {
    size_t n = std::strlen(name);
    for (size_t pos = block.find("\r\n"); pos != std::string::npos; pos = block.find("\r\n", pos + 2)) {
        size_t start = pos + 2;
        if (start + n + 1 > block.size()) break;
        bool match = block[start + n] == ':';
        for (size_t i = 0; match && i < n; ++i)
            match = std::tolower(static_cast<unsigned char>(block[start + i])) == name[i];
        if (!match) continue;
        size_t v = start + n + 1, e = block.find("\r\n", v);
        if (e == std::string::npos) e = block.size();
        while (v < e && (block[v] == ' ' || block[v] == '\t')) ++v;
        while (e > v && (block[e - 1] == ' ' || block[e - 1] == '\t')) --e;
        out = block.substr(v, std::min<size_t>(e - v, 512));
        return true;
    }
    return false;
}

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// filename="a b.exe" / filename=a.exe / filename*=UTF-8''a.exe
std::string disposition_filename(const std::string& v) {
    std::string lv = lower(v);
    size_t p = lv.find("filename*=");
    bool ext = p != std::string::npos;
    if (!ext) p = lv.find("filename=");
    if (p == std::string::npos) return "";
    p += ext ? 10 : 9;
    std::string name;
    if (p < v.size() && v[p] == '"') {
        size_t e = v.find('"', p + 1);
        name = v.substr(p + 1, e == std::string::npos ? std::string::npos : e - p - 1);
    } else {
        size_t e = v.find(';', p);
        name = v.substr(p, e == std::string::npos ? std::string::npos : e - p);
    }
    if (ext) {
        size_t q = name.find("''");
        if (q != std::string::npos) name = name.substr(q + 2);
    }
    return name.substr(0, 255);
}
}  // namespace

// The server side of an HTTP connection, response by response: each body is hashed
// as it streams past (Content-Length, chunked, or until the connection closes).
void FlowTable::http_body_data(Flow& f, const uint8_t* data, size_t len) {
    HttpBodyTracker& t = *f.http_bodies;
    auto feed = [&](const uint8_t* p, size_t n) { http_body_bytes(t, p, n); };
    auto finish_file = [&](bool complete) {
        http_file_done(f, t, complete);
        t.mode = HttpBodyTracker::Headers;
    };
    while (len && t.mode != HttpBodyTracker::Done) {
        switch (t.mode) {
            case HttpBodyTracker::Headers: {
                size_t old = t.pending.size();
                size_t take = std::min(len, kMaxHttpHeader + 4 - old);
                t.pending.append(reinterpret_cast<const char*>(data), take);
                size_t end = t.pending.find("\r\n\r\n", old >= 3 ? old - 3 : 0);
                if (end == std::string::npos) {
                    if (t.pending.size() > kMaxHttpHeader) t.mode = HttpBodyTracker::Done;  // not HTTP after all
                    data += take;
                    len -= take;
                    break;
                }
                size_t used = end + 4 - old;
                data += used;
                len -= used;
                std::string head = t.pending.substr(0, end + 2);
                t.pending.clear();
                if (head.compare(0, 5, "HTTP/") != 0 || head.size() < 12) {
                    t.mode = HttpBodyTracker::Done;
                    break;
                }
                int status = std::atoi(head.c_str() + 9);
                uint32_t index = static_cast<uint32_t>(t.responses++);
                if (status >= 100 && status < 200) break;  // interim response, the real one follows
                const std::string& requests = f.tls_plain ? f.tls_plain->req : f.app_buf[0];
                if (f.http.size() <= index && !requests.empty() && looks_like_http_request(requests))
                    f.http = parse_http_requests(requests, 16);
                bool head_request = index < f.http.size() && f.http[index].method == "HEAD";
                std::string cl, te;
                HttpFile file;
                file.status = status;
                file.response = index;
                file.ts = f.last_ts;
                header_value(head, "content-type", file.content_type);
                header_value(head, "content-encoding", file.content_encoding);
                std::string disp;
                if (header_value(head, "content-disposition", disp)) file.filename = disposition_filename(disp);
                if (header_value(head, "content-length", cl) && !cl.empty() && std::isdigit(static_cast<unsigned char>(cl[0]))) {
                    file.length_known = true;
                    file.declared_length = std::strtoull(cl.c_str(), nullptr, 10);
                }
                bool chunked = header_value(head, "transfer-encoding", te) && lower(te).find("chunked") != std::string::npos;
                if (head_request || status == 204 || status == 304) break;  // no body
                std::string enc = lower(file.content_encoding);
                t.collect = enc == "gzip" || enc == "x-gzip" || enc == "deflate";
                t.encoded.clear();
                t.current = std::move(file);
                t.hash = Sha256();
                {
                    ObjectTarget* o = opts_.object;
                    t.sink = o && o->kind == 'h' && o->flow_id == f.id && o->n == index ? o : nullptr;
                    if (t.sink) t.sink->found = true;
                }
                t.gaps_at_start = f.tcp[1].gap_bytes;
                if (chunked) {
                    t.mode = HttpBodyTracker::Chunked;
                    t.chunk = HttpBodyTracker::Size;
                } else if (t.current.length_known) {
                    t.remaining = t.current.declared_length;
                    t.mode = HttpBodyTracker::Length;
                    if (!t.remaining) finish_file(true);
                } else {
                    t.mode = HttpBodyTracker::UntilClose;
                }
                break;
            }
            case HttpBodyTracker::Length: {
                size_t take = static_cast<size_t>(std::min<uint64_t>(len, t.remaining));
                feed(data, take);
                data += take;
                len -= take;
                t.remaining -= take;
                if (!t.remaining) finish_file(true);
                break;
            }
            case HttpBodyTracker::UntilClose:
                feed(data, len);
                len = 0;
                break;
            case HttpBodyTracker::Chunked:
                if (t.chunk == HttpBodyTracker::Data) {
                    size_t take = static_cast<size_t>(std::min<uint64_t>(len, t.remaining));
                    feed(data, take);
                    data += take;
                    len -= take;
                    t.remaining -= take;
                    if (!t.remaining) t.chunk = HttpBodyTracker::DataEnd;
                    break;
                }
                {  // size lines, the CRLF after each chunk, and trailers: line by line
                    const uint8_t* nl = static_cast<const uint8_t*>(std::memchr(data, '\n', len));
                    size_t take = nl ? static_cast<size_t>(nl - data) + 1 : len;
                    if (t.pending.size() + take > 4096) {
                        t.mode = HttpBodyTracker::Done;
                        break;
                    }
                    t.pending.append(reinterpret_cast<const char*>(data), take);
                    data += take;
                    len -= take;
                    if (!nl) break;
                    std::string line = t.pending;
                    t.pending.clear();
                    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
                    if (t.chunk == HttpBodyTracker::DataEnd) {
                        t.chunk = HttpBodyTracker::Size;
                    } else if (t.chunk == HttpBodyTracker::Size) {
                        char* end = nullptr;
                        unsigned long long n = std::strtoull(line.c_str(), &end, 16);
                        if (end == line.c_str()) {
                            t.mode = HttpBodyTracker::Done;
                            break;
                        }
                        if (n == 0) {
                            t.chunk = HttpBodyTracker::Trailer;
                        } else {
                            t.remaining = n;
                            t.chunk = HttpBodyTracker::Data;
                        }
                    } else if (line.empty()) {  // the blank line after the trailers
                        finish_file(true);
                    }
                }
                break;
            case HttpBodyTracker::Done:
                break;
        }
    }
}

void FlowTable::http_body_end(Flow& f, bool stream_closed) {
    if (!f.http_bodies) return;
    HttpBodyTracker& t = *f.http_bodies;
    bool reading = t.mode == HttpBodyTracker::Length || t.mode == HttpBodyTracker::Chunked ||
                   t.mode == HttpBodyTracker::UntilClose;
    if (!reading) return;
    // A body read until close is whole once the server closed; the others were cut short.
    http_file_done(f, t, t.mode == HttpBodyTracker::UntilClose && stream_closed);
    t.mode = HttpBodyTracker::Done;
}

namespace {
constexpr size_t kMaxEncodedBody = 8u << 20;   // compressed bodies decoded up to this size
constexpr size_t kMaxDecodedBody = 64u << 20;  // and this much output
}  // namespace

void FlowTable::http_body_bytes(HttpBodyTracker& t, const uint8_t* p, size_t n) {
    if (t.collect && t.encoded.size() + n > kMaxEncodedBody) {  // too big to decode: hash it as sent
        t.hash.update(reinterpret_cast<const uint8_t*>(t.encoded.data()), t.encoded.size());
        if (t.sink) t.sink->write(t.encoded.data(), t.encoded.size());
        std::string().swap(t.encoded);
        t.collect = false;
    }
    if (t.collect) {
        t.encoded.append(reinterpret_cast<const char*>(p), n);
    } else {
        t.hash.update(p, n);
        if (t.sink) t.sink->write(p, n);
        if (t.current.magic.size() < kHeadBytes)
            t.current.magic.append(reinterpret_cast<const char*>(p), std::min(n, kHeadBytes - t.current.magic.size()));
    }
    t.current.size += n;
}

void FlowTable::http_file_done(Flow& f, HttpBodyTracker& t, bool complete) {
    HttpFile& file = t.current;
    if (t.collect) {
        std::string decoded;
        if (complete && http_decode_body(t.encoded, file.content_encoding, decoded, kMaxDecodedBody)) {
            file.encoded_size = file.size;
            file.size = decoded.size();
            file.decoded = true;
            t.hash = Sha256();
            t.hash.update(reinterpret_cast<const uint8_t*>(decoded.data()), decoded.size());
            if (t.sink) t.sink->write(decoded.data(), decoded.size());
            file.magic = decoded.substr(0, kHeadBytes);
        } else {  // cut short or not valid gzip/deflate: hash what was sent
            t.hash.update(reinterpret_cast<const uint8_t*>(t.encoded.data()), t.encoded.size());
            if (t.sink) t.sink->write(t.encoded.data(), t.encoded.size());
            file.magic = t.encoded.substr(0, kHeadBytes);
        }
        std::string().swap(t.encoded);
        t.collect = false;
    }
    file.sha256 = t.hash.hex();
    file.complete = complete && f.tcp[1].gap_bytes == t.gaps_at_start;
    t.sink = nullptr;
    if (file.size && t.files.size() < kMaxHttpFiles) t.files.push_back(std::move(file));
    file = HttpFile();
}

void FlowTable::on_stream_data(Flow& f, Dir dir, const uint8_t* data, size_t len) {
    auto d = static_cast<size_t>(dir);
    f.stats[d].payload_bytes += len;
    // Logins sent in clear text: on the ports of the protocols that send them, and HTTP on any port.
    if (!f.logins_decided && len) {
        if (const char* proto = LoginTracker::proto_for_port(f.server_port)) {
            f.logins = std::make_unique<LoginTracker>(proto);
            f.logins_decided = true;
        } else if (dir == Dir::ClientToServer) {
            f.logins_decided = true;
            if (looks_like_http_request(std::string(reinterpret_cast<const char*>(data), std::min<size_t>(len, 16))))
                f.logins = std::make_unique<LoginTracker>("HTTP");
        }
    }
    if (f.logins) f.logins->data(dir == Dir::ClientToServer, data, len, f.last_ts);
    size_t had = f.head[d].size();
    if (had < kDpiHead) {  // enough of each direction to recognise the application (DPI)
        if (!had) {
            f.head_from_start[d] = f.tcp[d].syn_seen;
            if (f.first_speaker < 0) f.first_speaker = static_cast<int8_t>(d);
        }
        f.head[d].append(reinterpret_cast<const char*>(data), std::min(len, kDpiHead - had));
    }
    // A TLS connection opening with a ClientHello, when the user gave a key log: its
    // secrets (if the log has them) are looked up by the hello's random.
    if (opts_.keylog && f.proto == wire::IPPROTO_TCP_ && dir == Dir::ClientToServer && !had && !f.tls_plain &&
        len >= 3 && data[0] == 0x16 && data[1] == 3)
        f.tls_plain = std::make_unique<TlsPlain>(opts_.keylog);
    if (f.tls_plain) tls_plain_data(f, dir, data, len);
    // Cleartext HTTP/2 with prior knowledge (h2c): the client opens with the connection preface.
    if (f.proto == wire::IPPROTO_TCP_ && dir == Dir::ClientToServer && !had && !f.tls_plain && !f.h2 && len >= 3 &&
        std::memcmp(data, Http2Reader::kPreface, 3) == 0)
        f.h2 = std::make_unique<H2State>(true);
    if (f.h2 && !f.tls_plain) h2_feed(f, dir, data, len);
    if (f.proto == wire::IPPROTO_TCP_ && f.server_port == 21) {  // FTP control: commands, data ports
        if (!f.ftp_control)
            f.ftp_control = std::make_unique<FtpControl>(f.client_ip, f.client_port, f.server_ip, f.server_port);
        std::vector<FtpExpect> expect;
        f.ftp_control->on_data(dir == Dir::ClientToServer, data, len, expect);
        for (auto& e : expect) {
            if (ftp_expect_.size() >= 4096) ftp_expect_.erase(ftp_expect_.begin());
            ftp_expect_[{e.ip, e.port, e.peer}] = {std::move(e.transfer), f.last_ts};
        }
    }
    if (f.ftp_data) {
        f.ftp_data[d].add(data, len);
        ObjectTarget* o = opts_.object;
        if (o && o->kind == 'f' && o->flow_id == f.id && o->n == d) {
            o->found = true;
            o->write(data, len);
        }
    }
    if (f.proto == wire::IPPROTO_TCP_ && (f.server_port == 445 || f.server_port == 139)) {
        if (!f.smb) {
            f.smb = std::make_unique<SmbFileTracker>();
            if (opts_.object && opts_.object->kind == 's' && opts_.object->flow_id == f.id) f.smb->set_target(opts_.object);
        }
        if (f.tcp[d].gap_bytes != f.smb_gaps[d]) {  // a hole: that direction's framing is gone
            f.smb_gaps[d] = f.tcp[d].gap_bytes;
            f.smb->on_gap(dir == Dir::ClientToServer);
        }
        f.smb->on_data(dir == Dir::ClientToServer, data, len, f.last_ts);
    }
    if (dir == Dir::ServerToClient && !f.tls_plain) {  // (decrypted TLS feeds the tracker itself)
        if (!f.http_bodies && had < 5 && f.head[d].size() >= 5 && f.head[d].compare(0, 5, "HTTP/") == 0 &&
            f.head_from_start[d]) {
            f.http_bodies = std::make_unique<HttpBodyTracker>();
            if (had) http_body_data(f, reinterpret_cast<const uint8_t*>(f.head[d].data()), had);
        }
        if (f.http_bodies) http_body_data(f, data, len);
    }
    std::string& buf = f.app_buf[d];
    size_t limit = f.app_limit[d] == SIZE_MAX ? opts_.app_buf_limit : f.app_limit[d];
    if (buf.size() < limit) {
        size_t take = std::min(len, limit - buf.size());
        buf.append(reinterpret_cast<const char*>(data), take);
        if (f.app_limit[d] == SIZE_MAX) classify(f, dir);
        // TLS hellos are parsed as soon as they are complete so the buffer can go.
        if (looks_like_tls(buf)) {
            if (dir == Dir::ClientToServer && !f.tls) f.tls = parse_tls_client_hello(buf);
            if (dir == Dir::ServerToClient && !f.tls_server) f.tls_server = parse_tls_server_hello(buf);
            if (dir == Dir::ClientToServer ? f.tls.has_value() : f.tls_server.has_value()) release_app_buf(f, dir);
        } else if (buf.size() >= f.app_limit[d]) {
            if (f.app_limit[d] <= 2048) release_app_buf(f, dir);  // unrecognised protocol: keep only the entropy
        }
    }
    if (!opts_.dump_dir.empty()) {
        if (!f.dump[d]) {
            std::string path = opts_.dump_dir + "/flow" + std::to_string(f.id) + (d == 0 ? "_c2s.bin" : "_s2c.bin");
            f.dump[d] = std::fopen(path.c_str(), "wb");
        }
        if (f.dump[d]) std::fwrite(data, 1, len, f.dump[d]);
    }
}

// What decrypted bytes carry, from the first of them: 1 HTTP/1.x, 2 HTTP/2, 3 something
// else, 0 can't tell yet. The client's first bytes decide; with only the server's secret
// known, the server's do (an HTTP/1.x status line, or HTTP/2's opening SETTINGS frame).
namespace {
uint8_t plain_app_kind(const std::string& c, const std::string& s) {
    if (!c.empty()) {
        size_t k = std::min(c.size(), Http2Reader::kPrefaceLen);
        if (c.compare(0, k, Http2Reader::kPreface, k) == 0) return c.size() >= Http2Reader::kPrefaceLen ? 2 : 0;
        if (looks_like_http_request(c)) return 1;
        return c.size() >= 16 ? 3 : 0;
    }
    if (s.size() >= 5 && s.compare(0, 5, "HTTP/") == 0) return 1;
    if (s.size() >= 9) {
        uint32_t len = (static_cast<uint8_t>(s[0]) << 16) | (static_cast<uint8_t>(s[1]) << 8) | static_cast<uint8_t>(s[2]);
        bool settings = s[3] == 4 && !(s[4] & 1) && len % 6 == 0 && s.compare(5, 4, std::string(4, '\0')) == 0;
        return settings ? 2 : 3;
    }
    return 0;
}
}  // namespace

// The decrypted side of a TLS connection, handed on as plain HTTP/1.x or HTTP/2 is, so
// files downloaded over HTTPS are hashed, typed and extracted like HTTP ones.
void FlowTable::tls_plain_data(Flow& f, Dir dir, const uint8_t* data, size_t len) {
    TlsPlain& t = *f.tls_plain;
    auto d = static_cast<size_t>(dir);
    if (f.tcp[d].gap_bytes != t.gaps[d]) {  // bytes never captured: decryption picks up at the next record
        t.dec.gap(static_cast<int>(d), f.tcp[d].gap_bytes - t.gaps[d]);
        t.gaps[d] = f.tcp[d].gap_bytes;
    }
    std::string plain;
    t.dec.feed(static_cast<int>(d), data, len, plain);
    if (t.dec.take_discontinuity(static_cast<int>(d))) plain_gap(f, dir);
    if (plain.empty()) return;
    if (t.app == 0) {
        if (t.held[d].size() < 64 * 1024) t.held[d] += plain;
        t.app = plain_app_kind(t.held[0], t.held[1]);
        if (t.app == 0) {
            if (t.held[d].size() < 64 * 1024) return;
            t.app = 3;
        }
        if (t.app == 2) f.h2 = std::make_unique<H2State>(true);
        std::string held[2];
        held[0].swap(t.held[0]);
        held[1].swap(t.held[1]);
        for (int k : {0, 1})  // the client's first: requests before the responses that answer them
            if (!held[k].empty()) plain_app(f, static_cast<Dir>(k), held[k]);
        return;
    }
    plain_app(f, dir, plain);
}

// The decrypted stream has a hole (bytes were never captured). HTTP/1.x drops the
// message the hole cut and reads on from the next one; HTTP/2 can't (HPACK's table is
// lost with the bytes), so that side of it stops.
void FlowTable::plain_gap(Flow& f, Dir dir) {
    TlsPlain& t = *f.tls_plain;
    auto d = static_cast<size_t>(dir);
    t.held[d].clear();
    if (f.h2) f.h2->reader.stop(static_cast<int>(d));
    if (t.app != 1) return;
    t.resync[d] = true;
    if (dir == Dir::ServerToClient && f.http_bodies) http_body_end(f, false);  // the response it cut
}

void FlowTable::plain_app(Flow& f, Dir dir, const std::string& plain) {
    TlsPlain& t = *f.tls_plain;
    auto d = static_cast<size_t>(dir);
    if (t.app == 2) {
        h2_feed(f, dir, reinterpret_cast<const uint8_t*>(plain.data()), plain.size());
        return;
    }
    if (t.app != 1) return;
    if (dir == Dir::ClientToServer) {
        if (t.resync[d]) {  // past a hole: from the next request line on
            if (!looks_like_http_request(plain)) return;
            t.resync[d] = false;
            if (!t.req.empty()) t.req += "\r\n\r\n";  // ends the request the hole cut
        }
        if (t.req.size() < opts_.app_buf_limit)
            t.req.append(plain, 0, std::min(plain.size(), opts_.app_buf_limit - t.req.size()));
        return;
    }
    if (t.resync[d]) {  // past a hole: from the next status line on
        if (plain.compare(0, 7, "HTTP/1.") != 0) return;
        t.resync[d] = false;
        if (f.http_bodies) {
            f.http_bodies->mode = HttpBodyTracker::Headers;
            f.http_bodies->pending.clear();
            http_body_data(f, reinterpret_cast<const uint8_t*>(plain.data()), plain.size());
            return;
        }
    }
    size_t held = t.s2c_seen ? 0 : t.resp.size();  // earlier bytes not yet given to the body tracker
    if (t.resp.size() < 4096) t.resp.append(plain, 0, std::min(plain.size(), 4096 - t.resp.size()));
    if (!t.s2c_seen) {
        if (t.resp.size() < 5) return;  // too little to tell yet
        t.s2c_seen = true;
        if (t.resp.compare(0, 5, "HTTP/") != 0) return;
        f.http_bodies = std::make_unique<HttpBodyTracker>();
        if (held) http_body_data(f, reinterpret_cast<const uint8_t*>(t.resp.data()), held);
    }
    if (f.http_bodies) http_body_data(f, reinterpret_cast<const uint8_t*>(plain.data()), plain.size());
}

// ------------------------------------------------------------------- HTTP/2

namespace {
constexpr size_t kMaxH2Streams = 256;   // open streams followed at once
constexpr size_t kMaxH2Requests = 64;   // requests kept per connection

const std::string* h2_header(const Http2Headers& h, const char* name) {
    for (const auto& kv : h)
        if (kv.first == name) return &kv.second;
    return nullptr;
}
}  // namespace

struct FlowTable::H2Events : Http2Handler {
    FlowTable& table;
    Flow& f;
    H2Events(FlowTable& t, Flow& fl) : table(t), f(fl) {}

    void h2_headers(int dir, uint32_t sid, const Http2Headers& h, bool end_stream, bool push) override {
        H2State& s = *f.h2;
        auto it = s.streams.find(sid);
        if (it == s.streams.end()) {
            if (s.streams.size() >= kMaxH2Streams) return;
            it = s.streams.emplace(sid, H2Stream()).first;
        }
        H2Stream& st = it->second;
        if (dir == 0 || push) {  // a request, or the request a server push promises
            if (st.request >= 0 || f.http.size() >= kMaxH2Requests) return;  // (trailers, or too many)
            HttpRequest r;
            for (const auto& [name, value] : h) {
                if (name == ":method") r.method = value.substr(0, 32);
                else if (name == ":path") r.uri = value.substr(0, 2048);
                else if (name == ":authority" || (name == "host" && r.host.empty())) r.host = value.substr(0, 256);
                else if (name == "user-agent") r.user_agent = value.substr(0, 512);
                else if (name == "content-type") r.content_type = value.substr(0, 256);
                else if (name == "content-length") r.content_length = std::strtoull(value.c_str(), nullptr, 10);
            }
            if (r.method.empty() && r.uri.empty()) return;
            st.request = static_cast<int>(f.http.size());
            f.http.push_back(std::move(r));
            return;
        }
        const std::string* status = h2_header(h, ":status");
        int code = status ? std::atoi(status->c_str()) : 0;
        if (st.response) {  // trailers after the body; they may end the stream
            if (end_stream) end(sid, true);
            return;
        }
        if (code < 200) return;  // an interim 1xx: the real response follows
        if (!f.http_response) {
            HttpResponse resp;
            resp.status = code;
            if (const std::string* v = h2_header(h, "server")) resp.server = v->substr(0, 256);
            if (const std::string* v = h2_header(h, "content-type")) resp.content_type = v->substr(0, 256);
            if (const std::string* v = h2_header(h, "x-powered-by")) resp.powered_by = v->substr(0, 128);
            f.http_response = std::move(resp);
        }
        st.response = true;
        HttpBodyTracker& t = st.body;
        HttpFile& file = t.current;
        file = HttpFile();
        file.status = code;
        file.response = st.request >= 0 ? static_cast<uint32_t>(st.request) : kH2NoRequest + s.responses++;
        file.ts = f.last_ts;
        if (const std::string* v = h2_header(h, "content-type")) file.content_type = v->substr(0, 512);
        if (const std::string* v = h2_header(h, "content-encoding")) file.content_encoding = v->substr(0, 512);
        if (const std::string* v = h2_header(h, "content-disposition")) file.filename = disposition_filename(*v);
        if (const std::string* v = h2_header(h, "content-length"); v && !v->empty() && std::isdigit(static_cast<unsigned char>((*v)[0]))) {
            file.length_known = true;
            file.declared_length = std::strtoull(v->c_str(), nullptr, 10);
        }
        std::string enc = lower(file.content_encoding);
        t.collect = enc == "gzip" || enc == "x-gzip" || enc == "deflate";
        t.encoded.clear();
        t.hash = Sha256();
        ObjectTarget* o = table.opts_.object;
        t.sink = o && o->kind == 'h' && o->flow_id == f.id && o->n == file.response ? o : nullptr;
        if (t.sink) t.sink->found = true;
        t.gaps_at_start = f.tcp[1].gap_bytes;
        if (end_stream) end(sid, true);  // no body (a HEAD, 204 or 304)
    }

    void h2_data(int dir, uint32_t sid, const uint8_t* p, size_t n) override {
        if (dir != 1) return;  // request bodies (uploads) aren't followed, as for HTTP/1.x
        auto it = f.h2->streams.find(sid);
        if (it != f.h2->streams.end() && it->second.response) table.http_body_bytes(it->second.body, p, n);
    }
    void h2_end(int dir, uint32_t sid) override {
        if (dir == 1) end(sid, true);
    }
    void h2_reset(uint32_t sid) override { end(sid, false); }

    // The response is over (END_STREAM), cut off (RST_STREAM) or the connection ended.
    void end(uint32_t sid, bool complete) {
        auto it = f.h2->streams.find(sid);
        if (it == f.h2->streams.end()) return;
        H2Stream& st = it->second;
        if (st.response) {
            table.http_file_done(f, st.body, complete);
            if (!st.body.files.empty()) {
                if (!f.http_bodies) {
                    f.http_bodies = std::make_unique<HttpBodyTracker>();
                    f.http_bodies->mode = HttpBodyTracker::Done;  // HTTP/2 fills it; no HTTP/1.x reads it
                }
                auto& files = f.http_bodies->files;
                for (auto& file : st.body.files)
                    if (files.size() < kMaxHttpFiles) files.push_back(std::move(file));
            }
        }
        f.h2->streams.erase(it);
    }
};

void FlowTable::h2_feed(Flow& f, Dir dir, const uint8_t* data, size_t len) {
    H2State& s = *f.h2;
    auto d = static_cast<size_t>(dir);
    if (!f.tls_plain && f.tcp[d].gap_bytes != s.gaps[d]) {  // cleartext h2c: a hole loses the framing
        s.gaps[d] = f.tcp[d].gap_bytes;
        s.reader.stop(static_cast<int>(d));
    }
    H2Events events(*this, f);
    s.reader.feed(static_cast<int>(d), data, len, events);
}

void FlowTable::h2_finish(Flow& f) {
    if (!f.h2) return;
    H2Events events(*this, f);
    std::vector<uint32_t> open;
    for (const auto& [sid, st] : f.h2->streams)
        if (st.response) open.push_back(sid);
    for (uint32_t sid : open) events.end(sid, false);  // the connection ended before END_STREAM
}

void FlowTable::classify(Flow& f, Dir dir) {
    auto d = static_cast<size_t>(dir);
    const std::string& buf = f.app_buf[d];
    size_t limit;
    if (looks_like_tls(buf)) limit = opts_.app_buf_limit;                       // until the hello parses
    else if (dir == Dir::ClientToServer && looks_like_http_request(buf)) limit = opts_.app_buf_limit;
    else if (dir == Dir::ServerToClient && buf.compare(0, 5, "HTTP/") == 0) limit = 4096;
    else if (is_dns_port(f.server_port)) limit = opts_.app_buf_limit;
    else limit = 2048;                                                          // entropy sample only
    f.app_limit[d] = std::min(limit, opts_.app_buf_limit);
    if (f.app_buf[d].size() > f.app_limit[d]) f.app_buf[d].resize(f.app_limit[d]);
}

namespace {
double shannon_bits_per_byte(const std::string& buf) {
    if (buf.empty()) return -1.0;
    uint32_t counts[256] = {0};
    for (unsigned char c : buf) counts[c]++;
    double h = 0, n = static_cast<double>(buf.size());
    for (uint32_t c : counts)
        if (c) h -= (c / n) * std::log2(c / n);
    return h;
}
}  // namespace

void FlowTable::release_app_buf(Flow& f, Dir dir) {
    auto d = static_cast<size_t>(dir);
    if (f.entropy[d] < 0 && !f.app_buf[d].empty()) {
        f.entropy[d] = shannon_bits_per_byte(f.app_buf[d]);
        f.entropy_sample[d] = static_cast<uint32_t>(f.app_buf[d].size());
    }
    std::string().swap(f.app_buf[d]);
    f.app_limit[d] = 0;
}

void FlowTable::record_event(Flow& f, const PacketInfo& p, Dir dir) {
    f.rate.add(p.ts_us - f.first_ts, p.payload_len, dir == Dir::ClientToServer);
    if (f.events.size() < opts_.max_events) {
        f.events.push_back({p.ts_us, p.payload_len, dir});
    } else {
        f.events_dropped++;
    }
}

void FlowTable::parse_app(Flow& f, Dir dir) {
    if (f.proto != wire::IPPROTO_TCP_) return;
    auto d = static_cast<size_t>(dir);
    const std::string& buf = f.app_buf[d];
    if (buf.empty()) return;
    if (f.entropy[d] < 0 || f.entropy_sample[d] < buf.size()) {
        f.entropy[d] = shannon_bits_per_byte(buf);
        f.entropy_sample[d] = static_cast<uint32_t>(buf.size());
    }

    if (dir == Dir::ClientToServer) {
        if (!f.tls && looks_like_tls(buf)) f.tls = parse_tls_client_hello(buf);
        if (looks_like_http_request(buf)) f.http = parse_http_requests(buf, 16);
        if (is_dns_port(f.server_port) && f.dns.empty()) {
            // DNS over TCP: 2-byte length-prefixed messages.
            size_t pos = 0;
            while (pos + 2 <= buf.size() && f.dns.size() < 64) {
                size_t n = (static_cast<uint8_t>(buf[pos]) << 8) | static_cast<uint8_t>(buf[pos + 1]);
                if (pos + 2 + n > buf.size()) break;
                if (auto m = parse_dns(reinterpret_cast<const uint8_t*>(buf.data() + pos + 2), n))
                    f.dns.push_back(std::move(*m));
                pos += 2 + n;
            }
        }
    } else {
        if (!f.tls_server && looks_like_tls(buf)) f.tls_server = parse_tls_server_hello(buf);
        if (!f.http_response) f.http_response = parse_http_response(buf);
    }
}

void FlowTable::finish(Flow& f) {
    for (size_t d = 0; d < 2; ++d) {
        Dir dir = static_cast<Dir>(d);
        f.tcp[d].flush([&](const uint8_t* data, size_t len) { on_stream_data(f, dir, data, len); });
        parse_app(f, dir);
        if (f.dump[d]) {
            std::fclose(f.dump[d]);
            f.dump[d] = nullptr;
        }
    }
    if (f.tls_plain) {  // HTTP inside TLS the user holds the keys for
        const TlsPlain& t = *f.tls_plain;
        if (looks_like_http_request(t.req)) f.http = parse_http_requests(t.req, 16);
        if (!f.http_response && t.resp.compare(0, 5, "HTTP/") == 0) f.http_response = parse_http_response(t.resp);
    }
    h2_finish(f);
    http_body_end(f, f.tcp[1].fin_seen || f.tcp[1].rst_seen);
    if (f.smb) f.smb->finish();
    emit_(f, true);
}

void FlowTable::sweep(uint64_t now_us) {
    if (now_us < last_sweep_ + 1'000'000) return;
    last_sweep_ = now_us;

    for (auto it = flows_.begin(); it != flows_.end();) {
        Flow& f = *it->second;
        uint64_t idle_limit = f.proto == wire::IPPROTO_TCP_ ? opts_.tcp_idle_us : opts_.udp_idle_us;
        if (f.proto == wire::IPPROTO_TCP_ && !f.handshake_seen && f.stats[0].payload_bytes + f.stats[1].payload_bytes == 0)
            idle_limit = std::min(idle_limit, opts_.half_open_idle_us);  // scans / SYN floods
        uint64_t idle = now_us > f.last_ts ? now_us - f.last_ts : 0;
        bool expired = idle >= idle_limit || (f.closed && now_us >= f.closed_ts + opts_.close_linger_us);
        if (expired) {
            finish(f);
            total_mem_ -= f.mem;
            it = flows_.erase(it);
            continue;
        }
        if (f.dirty && now_us >= f.last_emit_ts + opts_.update_interval_us) {
            parse_app(f, Dir::ClientToServer);
            parse_app(f, Dir::ServerToClient);
            emit_(f, false);
            f.last_emit_ts = now_us;
            f.dirty = false;
        }
        ++it;
    }
}

void FlowTable::flush_all() {
    for (auto& [key, f] : flows_) finish(*f);
    flows_.clear();
    total_mem_ = 0;
}

}  // namespace anta
