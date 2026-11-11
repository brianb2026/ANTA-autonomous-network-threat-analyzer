#include "stats.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>

#include "capture.h"
#include "dfilter.h"
#include "inspect.h"
#include "json.h"
#include "tlskeys.h"

namespace anta {

namespace {

// ------------------------------------------------------------ helpers

bool pseudo(const char* name) { return std::strchr(name, '.') || name[0] == '_'; }

const char* proto_title(const std::string& a) {
    static const std::map<std::string, const char*> names = {
        {"frame", "Frame"}, {"eth", "Ethernet"}, {"sll", "Linux cooked-mode capture"},
        {"vlan", "802.1Q Virtual LAN"}, {"mpls", "MultiProtocol Label Switching"},
        {"pppoes", "PPP-over-Ethernet Session"}, {"ppp", "Point-to-Point Protocol"},
        {"llc", "Logical-Link Control"}, {"wlan", "IEEE 802.11 wireless LAN"}, {"radiotap", "Radiotap Header"},
        {"nflog", "Linux Netfilter NFLOG"}, {"arp", "Address Resolution Protocol"},
        {"ip", "Internet Protocol Version 4"}, {"ipv6", "Internet Protocol Version 6"},
        {"tcp", "Transmission Control Protocol"}, {"udp", "User Datagram Protocol"},
        {"icmp", "Internet Control Message Protocol"}, {"icmpv6", "Internet Control Message Protocol v6"},
        {"igmp", "Internet Group Management Protocol"}, {"gre", "Generic Routing Encapsulation"},
        {"erspan", "Encapsulated Remote Switch Packet ANalysis"}, {"vxlan", "Virtual eXtensible Local Area Network"},
        {"geneve", "Generic Network Virtualization Encapsulation"}, {"dns", "Domain Name System"},
        {"mdns", "Multicast Domain Name System"}, {"llmnr", "Link-local Multicast Name Resolution"},
        {"dhcp", "Dynamic Host Configuration Protocol"}, {"dhcpv6", "DHCPv6"}, {"ntp", "Network Time Protocol"},
        {"nbns", "NetBIOS Name Service"}, {"ssdp", "Simple Service Discovery Protocol"},
        {"tftp", "Trivial File Transfer Protocol"}, {"syslog", "Syslog message"}, {"quic", "QUIC IETF"},
        {"http", "Hypertext Transfer Protocol"}, {"tls", "Transport Layer Security"}, {"ssh", "SSH Protocol"},
        {"ftp", "File Transfer Protocol (FTP)"}, {"ftp-data", "FTP Data"}, {"smtp", "Simple Mail Transfer Protocol"},
        {"pop", "Post Office Protocol"}, {"imap", "Internet Message Access Protocol"}, {"telnet", "Telnet"},
        {"data", "Data"}, {"stp", "Spanning Tree Protocol"}, {"lldp", "Link Layer Discovery Protocol"},
        {"ocsp", "Online Certificate Status Protocol"}, {"json", "JavaScript Object Notation"},
        {"xml", "eXtensible Markup Language"}};
    auto it = names.find(a);
    return it == names.end() ? nullptr : it->second;
}

std::string addr_text(const FieldValue& v) {
    if (v.type == FieldValue::kString) return v.s;
    return filter_literal(v);
}

struct Counts {
    uint64_t tx_p = 0, tx_b = 0, rx_p = 0, rx_b = 0;
};

struct Endpoint {
    std::string addr;
    uint32_t port = 0;
    bool has_port = false;
    Counts c;
};

struct Conversation {
    std::string a, b;
    uint32_t pa = 0, pb = 0;
    bool ports = false;
    uint64_t ab_p = 0, ab_b = 0, ba_p = 0, ba_b = 0;
    double first = 0, last = 0;
    int64_t stream = -1;
    std::map<std::string, uint64_t> apps;  // deepest protocol -> bytes (IP conversations)
};

struct Expert {
    std::string severity, group, protocol, summary;
    uint64_t count = 0;
    std::vector<uint64_t> frames;
};

struct LenBin {
    uint64_t count = 0, sum = 0, min = ~0ULL, max = 0;
};

struct Host {
    std::string addr;
    bool v6 = false;
    Counts c;
    double first = 0, last = 0;
    std::map<std::string, std::string> names;  // name -> how we learned it
    std::map<std::string, uint64_t> macs;      // source MACs this address used
    std::map<uint32_t, uint64_t> tcp_serves, tcp_uses, udp_serves, udp_uses;
    std::set<std::string> peers;
    std::map<std::string, uint64_t> roles;     // evidence: "dns-server", "dhcp-server", "router", ...
    uint32_t ttl_max = 0;
    std::set<std::string> user_agents, dhcp_vendor;
    std::set<std::string> users, domains;  // Kerberos user accounts and realms seen for this client
    std::string windows_version;           // from its Windows browser announcements
    // Passive OS fingerprints: the first SYN it sent (TTL, window, MSS, scale, option
    // order, as p0f reads them) and the options its DHCP client asks for.
    bool syn_seen = false;
    uint32_t syn_ttl = 0, syn_win = 0;
    int syn_mss = -1, syn_ws = -1;
    std::string syn_opts, dhcp_prl;
    std::set<std::string> mdns_services;   // service types it announces over mDNS (_googlecast._tcp ...)
};

struct MacInfo {
    std::string vendor;
    std::set<std::string> src_ips, arp_ips;
    // When each address was used from this MAC (first and last frame), so a device's change of
    // address shows as one span ending and the next beginning.
    std::map<std::string, std::pair<double, double>> ip_spans;
    uint64_t frames = 0;
};

constexpr const char* kSev[] = {"Chat", "Note", "Warning", "Error"};

bool udp_service_port(uint32_t p) {
    switch (p) {
        case 53: case 67: case 69: case 123: case 137: case 138: case 161: case 162: case 389: case 443:
        case 500: case 514: case 520: case 853: case 1194: case 1812: case 1813: case 1900: case 3478:
        case 4500: case 5060: case 5353: case 5355: case 51820:
            return true;
        default: return p < 1024;
    }
}

class Collector {
public:
    explicit Collector(const StatsQuery& q) : q_(q) {}

    std::vector<std::unique_ptr<DisplayFilter>> series;
    // Display filters counted over the whole capture, with the first frames each matched.
    struct Count {
        std::unique_ptr<DisplayFilter> filter;
        uint64_t count = 0;
        std::vector<uint64_t> frames;
    };
    std::vector<Count> counts;
    double first_cap = 0, last_cap = 0;  // whole capture (pass 1)
    double interval = 1;

    void frame(uint64_t n, double ts, uint32_t len, const FrameFields& ff, const DecodedFrame& d) {
        ++frames_;
        bytes_ += len;
        if (!frames_seen_) {
            first_ = ts;
            frames_seen_ = true;
        }
        last_ = std::max(last_, ts);
        first_ = std::min(first_, ts);

        // Protocol hierarchy (frames and whole-frame bytes, like Wireshark)
        std::vector<std::string> stack;
        for (size_t i = 0; i < ff.protos.size() && i < ff.outer_protos; ++i) {
            const auto& p = ff.protos[i];
            if (!pseudo(p.name) && (stack.empty() || stack.back() != p.name)) stack.emplace_back(p.name);
        }
        std::string path;
        for (size_t i = 0; i < stack.size(); ++i) {
            path += (i ? "/" : "") + stack[i];
            auto& node = phs_[path];
            node.first += 1;
            node.second += len;
            if (i + 1 == stack.size()) {
                auto& e = phs_end_[path];
                e.first += 1;
                e.second += len;
            }
        }
        std::string deepest = stack.empty() ? "frame" : stack.back();
        if (deepest == "data" && stack.size() > 1) deepest = stack[stack.size() - 2];

        // Lengths
        static const uint32_t edges[] = {20, 40, 80, 160, 320, 640, 1280, 2560, 5120};
        size_t bin = 0;
        while (bin < 9 && len >= edges[bin]) ++bin;
        auto& lb = lens_[bin];
        lb.count++;
        lb.sum += len;
        lb.min = std::min<uint64_t>(lb.min, len);
        lb.max = std::max<uint64_t>(lb.max, len);

        // I/O graph
        size_t slot = ts >= first_cap ? static_cast<size_t>((ts - first_cap) / interval) : 0;
        if (slot < kMaxBins) {
            if (io_.size() <= slot) io_.resize(slot + 1);
            auto& b = io_[slot];
            b.packets++;
            b.bytes += len;
            bool bad = ff.has_outer_proto("tcp.analysis.flags") && !ff.has_outer_proto("tcp.analysis.window_update") &&
                       !ff.has_outer_proto("tcp.analysis.keep_alive") && !ff.has_outer_proto("tcp.analysis.keep_alive_ack");
            if (bad) b.errors++;
            if (b.series.size() < series.size()) b.series.resize(series.size());
            for (size_t i = 0; i < series.size(); ++i)
                if (series[i]->match(ff)) b.series[i]++;
        }
        for (auto& c : counts)
            if (c.filter->match(ff)) {
                c.count++;
                if (c.frames.size() < 20) c.frames.push_back(n);
            }

        // Addresses
        const FieldValue *esrc = nullptr, *edst = nullptr, *isrc = nullptr, *idst = nullptr, *sllsrc = nullptr;
        bool v6 = false;
        uint32_t sport = 0, dport = 0;
        bool tcp = false, udp = false;
        int64_t stream = -1;
        uint32_t ttl = 0;
        for (size_t fi = 0; fi < ff.fields.size() && fi < ff.outer_fields; ++fi) {
            const auto& f = ff.fields[fi];
            const char* nm = f.name;
            if (!esrc && std::strcmp(nm, "eth.src") == 0) esrc = &f.value;
            else if (!sllsrc && std::strcmp(nm, "sll.src.eth") == 0) sllsrc = &f.value;
            else if (!edst && std::strcmp(nm, "eth.dst") == 0) edst = &f.value;
            else if (std::strcmp(nm, "ip.src") == 0 || std::strcmp(nm, "ipv6.src") == 0) {  // innermost wins
                isrc = &f.value;
                v6 = nm[2] == 'v';
            } else if (std::strcmp(nm, "ip.dst") == 0 || std::strcmp(nm, "ipv6.dst") == 0) {
                idst = &f.value;
            } else if (std::strcmp(nm, "ip.ttl") == 0 || std::strcmp(nm, "ipv6.hlim") == 0) {
                ttl = static_cast<uint32_t>(f.value.u);
            } else if (std::strcmp(nm, "tcp.srcport") == 0) {
                sport = static_cast<uint32_t>(f.value.u);
                tcp = true;
            } else if (std::strcmp(nm, "tcp.dstport") == 0) {
                dport = static_cast<uint32_t>(f.value.u);
            } else if (std::strcmp(nm, "udp.srcport") == 0 && !tcp) {
                sport = static_cast<uint32_t>(f.value.u);
                udp = true;
            } else if (std::strcmp(nm, "udp.dstport") == 0 && !tcp) {
                dport = static_cast<uint32_t>(f.value.u);
            } else if (std::strcmp(nm, "tcp.stream") == 0) {
                stream = static_cast<int64_t>(f.value.u);
            }
        }
        if (esrc && edst) {
            std::string s = addr_text(*esrc), t = addr_text(*edst);
            endpoint(eth_, s, 0, false, len, true);
            endpoint(eth_, t, 0, false, len, false);
            conversation(eth_conv_, s, t, 0, 0, false, ts, len, -1, nullptr);
            macs_[s].frames++;
        }
        if (isrc && idst) {
            std::string s = addr_text(*isrc), t = addr_text(*idst);
            auto& eps = v6 ? ip6_ : ip4_;
            endpoint(eps, s, 0, false, len, true);
            endpoint(eps, t, 0, false, len, false);
            conversation(v6 ? ip6_conv_ : ip4_conv_, s, t, 0, 0, false, ts, len, -1, &deepest);
            Host& hs = host(s, v6, ts);
            Host& hd = host(t, v6, ts);
            hs.c.tx_p++;
            hs.c.tx_b += len;
            hd.c.rx_p++;
            hd.c.rx_b += len;
            if (hs.peers.size() < 5000) hs.peers.insert(t);
            if (hd.peers.size() < 5000) hd.peers.insert(s);
            hs.ttl_max = std::max(hs.ttl_max, ttl);
            if (tcp && !hs.syn_seen) {
                const FieldValue* syn = ff.first_outer("tcp.flags.syn");
                const FieldValue* ack = ff.first_outer("tcp.flags.ack");
                if (syn && syn->u && ack && !ack->u) {
                    hs.syn_seen = true;
                    hs.syn_ttl = ttl;
                    if (const FieldValue* w = ff.first_outer("tcp.window_size_value")) hs.syn_win = static_cast<uint32_t>(w->u);
                    if (const FieldValue* m = ff.first_outer("tcp.options.mss_val")) hs.syn_mss = static_cast<int>(m->u);
                    if (const FieldValue* x = ff.first_outer("tcp.options.wscale.shift")) hs.syn_ws = static_cast<int>(x->u);
                    for (size_t fi = 0; fi < ff.fields.size() && fi < ff.outer_fields; ++fi)
                        if (std::strcmp(ff.fields[fi].name, "tcp.option_kind") == 0 && hs.syn_opts.size() < 64)
                            hs.syn_opts += (hs.syn_opts.empty() ? "" : ",") + std::to_string(ff.fields[fi].value.u);
                }
            }
            if (udp && sport == 5353 && hs.mdns_services.size() < 16) {
                const FieldValue* resp = ff.first_outer("dns.flags.response");
                if (resp && resp->u) {
                    for (size_t fi = 0; fi < ff.fields.size() && fi < ff.outer_fields; ++fi) {
                        const auto& f = ff.fields[fi];
                        if (std::strcmp(f.name, "dns.resp.name") != 0 && std::strcmp(f.name, "dns.ptr.domain_name") != 0) continue;
                        const std::string& n = f.value.s;
                        size_t at = n.find("._tcp.");
                        if (at == std::string::npos) at = n.find("._udp.");
                        if (at == std::string::npos) continue;
                        size_t start = n.rfind("._", at - 1);
                        start = start == std::string::npos ? 0 : start + 1;
                        if (start < at && n[start] == '_' && hs.mdns_services.size() < 16)
                            hs.mdns_services.insert(n.substr(start, at + 5 - start));
                    }
                }
            }
            const FieldValue* smac = esrc ? esrc : sllsrc;
            if (smac && hs.macs.size() < 8) hs.macs[addr_text(*smac)]++;
            if (smac) {
                auto& mi = macs_[addr_text(*smac)];
                if (!esrc) mi.frames++;
                if (const FieldValue* v = ff.first_outer(esrc ? "eth.src.oui_resolved" : "sll.src.oui_resolved"))
                    mi.vendor = v->s;
                if (mi.src_ips.size() < 64) mi.src_ips.insert(s);
                auto sp = mi.ip_spans.find(s);
                if (sp != mi.ip_spans.end()) {
                    sp->second.first = std::min(sp->second.first, ts);
                    sp->second.second = std::max(sp->second.second, ts);
                } else if (mi.ip_spans.size() < 64) {
                    mi.ip_spans.emplace(s, std::make_pair(ts, ts));
                }
            }
            if (tcp || udp) {
                auto& eps4 = tcp ? tcp_ : udp_;
                endpoint(eps4, s, sport, true, len, true);
                endpoint(eps4, t, dport, true, len, false);
                conversation(tcp ? tcp_conv_ : udp_conv_, s, t, sport, dport, true, ts, len, stream, nullptr);
            }
            if (tcp) tcp_roles(ff, s, t, sport, dport, stream, hs, hd);
            if (udp) {
                bool sk = udp_service_port(sport), dk = udp_service_port(dport);
                if (sport == 67 && dport == 68) {
                    hs.udp_serves[67]++;
                    hs.roles["dhcp-server"]++;
                } else if (sport == dport) {
                    // Same port both ways (Windows time sync uses 123 to 123): the
                    // direction doesn't say who serves, so neither side is credited.
                } else if (sk && (!dk || sport < dport)) {
                    hs.udp_serves[sport]++;
                    hd.udp_uses[sport]++;
                } else if (dk) {
                    hd.udp_serves[dport]++;
                    hs.udp_uses[dport]++;
                }
            }
            app_evidence(ff, s, t, hs, hd);
        }
        arp_evidence(ff);
        expert(n, ff, d, sport, dport);
    }

    void write(JsonWriter& w, uint64_t frames_total) {
        double duration = frames_ ? last_ - first_ : 0;
        w.begin_object().kv("type", "stats");
        // ---- properties
        w.key("properties").begin_object();
        w.kv("frames", frames_).kv("frames_total", frames_total).kv("bytes", bytes_);
        w.kv("first", first_).kv("last", last_).kv("duration", duration);
        w.kv("filter", q_.dfilter).kv("bpf", q_.bpf);
        w.key("files").begin_array();
        for (const auto& f : q_.inputs) w.value(f);
        w.end_array();
        w.end_object();
        // ---- protocol hierarchy
        w.key("protocols").begin_array();
        for (const auto& [path, fb] : phs_) {
            size_t slash = path.rfind('/');
            std::string abbr = slash == std::string::npos ? path : path.substr(slash + 1);
            const char* title = proto_title(abbr);
            auto e = phs_end_.find(path);
            w.begin_object()
                .kv("path", path)
                .kv("abbr", abbr)
                .kv("name", title ? title : abbr.c_str())
                .kv("frames", fb.first)
                .kv("bytes", fb.second)
                .kv("end_frames", e == phs_end_.end() ? uint64_t{0} : e->second.first)
                .kv("end_bytes", e == phs_end_.end() ? uint64_t{0} : e->second.second)
                .end_object();
        }
        w.end_array();
        // ---- endpoints and conversations
        w.key("endpoints").begin_object();
        write_endpoints(w, "eth", eth_);
        write_endpoints(w, "ipv4", ip4_);
        write_endpoints(w, "ipv6", ip6_);
        write_endpoints(w, "tcp", tcp_);
        write_endpoints(w, "udp", udp_);
        w.end_object();
        w.key("conversations").begin_object();
        write_conversations(w, "eth", eth_conv_);
        write_conversations(w, "ipv4", ip4_conv_);
        write_conversations(w, "ipv6", ip6_conv_);
        write_conversations(w, "tcp", tcp_conv_);
        write_conversations(w, "udp", udp_conv_);
        w.end_object();
        // ---- I/O graph
        w.key("io").begin_object();
        w.kv("interval", interval).kv("start", first_cap);
        w.key("series").begin_array();
        for (const auto& s : q_.io_series) w.value(s);
        w.end_array();
        w.key("bins").begin_array();
        for (const auto& b : io_) {
            w.begin_array().value(b.packets).value(b.bytes).value(b.errors);
            for (size_t i = 0; i < series.size(); ++i) w.value(i < b.series.size() ? b.series[i] : uint64_t{0});
            w.end_array();
        }
        w.end_array();
        w.kv("truncated", io_.size() >= kMaxBins);
        w.end_object();
        // ---- packet lengths
        static const char* labels[] = {"0-19", "20-39", "40-79", "80-159", "160-319", "320-639", "640-1279",
                                       "1280-2559", "2560-5119", "5120 and greater"};
        w.key("lengths").begin_array();
        for (int i = 0; i < 10; ++i) {
            const auto& b = lens_[i];
            w.begin_object().kv("range", labels[i]).kv("count", b.count);
            if (b.count) w.kv("min", b.min).kv("max", b.max).kv("avg", static_cast<double>(b.sum) / b.count);
            w.end_object();
        }
        w.end_array();
        // ---- expert info
        std::vector<const Expert*> ex;
        for (const auto& [k, e] : experts_) ex.push_back(&e);
        std::sort(ex.begin(), ex.end(), [](const Expert* a, const Expert* b) {
            int sa = static_cast<int>(std::find(std::begin(kSev), std::end(kSev), a->severity) - std::begin(kSev));
            int sb = static_cast<int>(std::find(std::begin(kSev), std::end(kSev), b->severity) - std::begin(kSev));
            if (sa != sb) return sa > sb;
            return a->count > b->count;
        });
        if (!counts.empty()) {
            w.key("counts").begin_array();
            for (const auto& c : counts) {
                w.begin_object().kv("count", c.count).key("frames").begin_array();
                for (uint64_t f : c.frames) w.value(f);
                w.end_array().end_object();
            }
            w.end_array();
        }
        w.key("expert").begin_array();
        for (const Expert* e : ex) {
            w.begin_object()
                .kv("severity", e->severity)
                .kv("group", e->group)
                .kv("protocol", e->protocol)
                .kv("summary", e->summary)
                .kv("count", e->count);
            w.key("frames").begin_array();
            for (uint64_t f : e->frames) w.value(f);
            w.end_array().end_object();
        }
        w.end_array();
        // ---- DNS / HTTP / TLS
        w.key("dns").begin_object();
        w.kv("queries", dns_queries_).kv("responses", dns_responses_).kv("retransmissions", dns_retransmissions_);
        if (!dns_times_.empty()) {
            std::vector<double> v = dns_times_;
            std::sort(v.begin(), v.end());
            double sum = 0;
            for (double x : v) sum += x;
            auto pct = [&](double p) { return v[std::min(v.size() - 1, static_cast<size_t>(p * (v.size() - 1) + 0.5))]; };
            w.key("response_time").begin_object();
            w.kv("count", static_cast<uint64_t>(v.size())).kv("min", v.front()).kv("avg", sum / v.size());
            w.kv("median", pct(0.5)).kv("p95", pct(0.95)).kv("max", v.back());
            w.end_object();
        }
        std::sort(dns_slowest_.begin(), dns_slowest_.end(),
                  [](const DnsTiming& a, const DnsTiming& b) { return a.seconds > b.seconds; });
        w.key("slowest").begin_array();
        for (size_t i = 0; i < dns_slowest_.size() && i < 100; ++i) {
            const auto& d = dns_slowest_[i];
            w.begin_object().kv("seconds", d.seconds).kv("name", d.name).kv("server", d.server)
                .kv("client", d.client).kv("frame", d.frame).end_object();
        }
        w.end_array();
        write_counts(w, "names", dns_names_, 2000);
        write_counts(w, "types", dns_types_, 100);
        write_counts(w, "rcodes", dns_rcodes_, 100);
        w.end_object();
        w.key("http").begin_object();
        w.kv("requests", http_requests_).kv("responses", http_responses_);
        write_counts(w, "hosts", http_hosts_, 2000);
        write_counts(w, "uris", http_uris_, 2000);
        write_counts(w, "methods", http_methods_, 100);
        write_counts(w, "status", http_status_, 100);
        write_counts(w, "user_agents", http_agents_, 500);
        write_counts(w, "content_types", http_ctypes_, 200);
        w.end_object();
        w.key("tls").begin_object();
        w.kv("client_hellos", tls_hellos_);
        write_counts(w, "server_names", tls_sni_, 2000);
        write_counts(w, "ja3", tls_ja3_, 500);
        write_counts(w, "ja4", tls_ja4_, 500);
        w.end_object();
        // ---- hosts and MACs (evidence for the network map)
        std::vector<const Host*> hosts;
        for (const auto& [k, h] : hosts_) hosts.push_back(&h);
        std::sort(hosts.begin(), hosts.end(), [](const Host* a, const Host* b) {
            return a->c.tx_b + a->c.rx_b > b->c.tx_b + b->c.rx_b;
        });
        if (hosts.size() > q_.max_rows) hosts.resize(q_.max_rows);
        w.key("hosts").begin_array();
        for (const Host* h : hosts) {
            w.begin_object().kv("addr", h->addr).kv("v6", h->v6);
            w.kv("tx_packets", h->c.tx_p).kv("tx_bytes", h->c.tx_b).kv("rx_packets", h->c.rx_p).kv("rx_bytes", h->c.rx_b);
            w.kv("first", h->first).kv("last", h->last).kv("peers", static_cast<uint64_t>(h->peers.size()));
            w.kv("ttl", static_cast<uint64_t>(h->ttl_max));
            w.key("names").begin_array();
            for (const auto& [n, src] : h->names) w.begin_array().value(n).value(src).end_array();
            w.end_array();
            w.key("macs").begin_array();
            for (const auto& [m, cnt] : h->macs) w.value(m);
            w.end_array();
            write_ports(w, "tcp_serves", h->tcp_serves);
            write_ports(w, "tcp_uses", h->tcp_uses);
            write_ports(w, "udp_serves", h->udp_serves);
            write_ports(w, "udp_uses", h->udp_uses);
            w.key("roles").begin_object();
            for (const auto& [r, cnt] : h->roles) w.kv(r.c_str(), cnt);
            w.end_object();
            w.key("user_agents").begin_array();
            for (const auto& u : h->user_agents) w.value(u);
            w.end_array();
            w.key("dhcp_vendor").begin_array();
            for (const auto& u : h->dhcp_vendor) w.value(u);
            w.end_array();
            w.key("users").begin_array();
            for (const auto& u : h->users) w.value(u);
            w.end_array();
            w.key("domains").begin_array();
            for (const auto& d : h->domains) w.value(d);
            w.end_array();
            if (!h->windows_version.empty()) w.kv("windows_version", h->windows_version);
            if (h->syn_seen) {
                w.key("syn").begin_object().kv("ttl", static_cast<uint64_t>(h->syn_ttl)).kv("win", static_cast<uint64_t>(h->syn_win));
                if (h->syn_mss >= 0) w.kv("mss", static_cast<uint64_t>(h->syn_mss));
                if (h->syn_ws >= 0) w.kv("ws", static_cast<uint64_t>(h->syn_ws));
                w.kv("opts", h->syn_opts).end_object();
            }
            if (!h->dhcp_prl.empty()) w.kv("dhcp_prl", h->dhcp_prl);
            if (!h->mdns_services.empty()) {
                w.key("mdns_services").begin_array();
                for (const auto& sv : h->mdns_services) w.value(sv);
                w.end_array();
            }
            w.end_object();
        }
        w.end_array();
        w.key("macs").begin_array();
        size_t written = 0;
        for (const auto& [m, mi] : macs_) {
            if (++written > q_.max_rows) break;
            w.begin_object().kv("mac", m).kv("vendor", mi.vendor).kv("frames", mi.frames);
            w.kv("src_ip_count", static_cast<uint64_t>(mi.src_ips.size()));
            w.key("src_ips").begin_array();
            size_t k = 0;
            for (const auto& ip : mi.src_ips) {
                if (++k > 16) break;
                w.value(ip);
            }
            w.end_array();
            w.key("arp_ips").begin_array();
            for (const auto& ip : mi.arp_ips) w.value(ip);
            w.end_array();
            w.key("ip_spans").begin_array();  // [address, first, last]
            k = 0;
            for (const auto& [ip, span] : mi.ip_spans) {
                if (++k > 16) break;
                w.begin_array().value(ip).value(span.first).value(span.second).end_array();
            }
            w.end_array().end_object();
        }
        w.end_array();
        w.end_object();
    }

private:
    static constexpr size_t kMaxBins = 100'000;
    struct Bin {
        uint64_t packets = 0, bytes = 0, errors = 0;
        std::vector<uint64_t> series;
    };

    const StatsQuery& q_;
    uint64_t frames_ = 0, bytes_ = 0;
    bool frames_seen_ = false;
    double first_ = 0, last_ = 0;
    std::map<std::string, std::pair<uint64_t, uint64_t>> phs_, phs_end_;
    LenBin lens_[10];
    std::vector<Bin> io_;
    std::unordered_map<std::string, Endpoint> eth_, ip4_, ip6_, tcp_, udp_;
    std::unordered_map<std::string, Conversation> eth_conv_, ip4_conv_, ip6_conv_, tcp_conv_, udp_conv_;
    std::map<std::string, Expert> experts_;
    std::unordered_map<std::string, Host> hosts_;
    std::map<std::string, MacInfo> macs_;
    std::unordered_map<int64_t, std::pair<std::string, uint32_t>> stream_server_;  // tcp.stream -> server side
    uint64_t dns_queries_ = 0, dns_responses_ = 0, http_requests_ = 0, http_responses_ = 0, tls_hellos_ = 0;
    uint64_t dns_retransmissions_ = 0;
    struct DnsTiming {
        double seconds;
        std::string name, server, client;
        uint64_t frame;
    };
    std::vector<double> dns_times_;
    std::vector<DnsTiming> dns_slowest_;
    std::map<std::string, uint64_t> dns_names_, dns_types_, dns_rcodes_, http_hosts_, http_uris_, http_methods_,
        http_status_, http_agents_, http_ctypes_, tls_sni_, tls_ja3_, tls_ja4_;

    Host& host(const std::string& addr, bool v6, double ts) {
        auto [it, fresh] = hosts_.try_emplace(addr);
        Host& h = it->second;
        if (fresh) {
            h.addr = addr;
            h.v6 = v6;
        }
        if (ts > 0) {  // 0: known only from a name lookup or DHCP, no traffic yet
            if (!h.first || ts < h.first) h.first = ts;
            h.last = std::max(h.last, ts);
        }
        return h;
    }

    static void endpoint(std::unordered_map<std::string, Endpoint>& m, const std::string& addr, uint32_t port,
                         bool has_port, uint32_t len, bool tx) {
        std::string key = has_port ? addr + "|" + std::to_string(port) : addr;
        auto& e = m[key];
        e.addr = addr;
        e.port = port;
        e.has_port = has_port;
        if (tx) {
            e.c.tx_p++;
            e.c.tx_b += len;
        } else {
            e.c.rx_p++;
            e.c.rx_b += len;
        }
    }

    static void conversation(std::unordered_map<std::string, Conversation>& m, const std::string& s,
                             const std::string& d, uint32_t sp, uint32_t dp, bool ports, double ts, uint32_t len,
                             int64_t stream, const std::string* app) {
        std::string ks = ports ? s + "|" + std::to_string(sp) : s, kd = ports ? d + "|" + std::to_string(dp) : d;
        std::string key = ks < kd ? ks + "#" + kd : kd + "#" + ks;
        if (stream >= 0) key += "#" + std::to_string(stream);
        auto [it, fresh] = m.try_emplace(key);
        Conversation& c = it->second;
        if (fresh) {  // A is whoever sent the first packet, as in Wireshark
            c.a = s;
            c.b = d;
            c.pa = sp;
            c.pb = dp;
            c.ports = ports;
            c.first = ts;
            c.stream = stream;
        }
        c.last = std::max(c.last, ts);
        bool ab = c.a == s && (!ports || c.pa == sp);
        if (ab) {
            c.ab_p++;
            c.ab_b += len;
        } else {
            c.ba_p++;
            c.ba_b += len;
        }
        if (app) c.apps[*app] += len;
    }

    void tcp_roles(const FrameFields& ff, const std::string& s, const std::string& t, uint32_t sp, uint32_t dp,
                   int64_t stream, Host& hs, Host& hd) {
        const FieldValue* syn = ff.first_outer("tcp.flags.syn");
        const FieldValue* ack = ff.first_outer("tcp.flags.ack");
        if (stream < 0 || stream_server_.count(stream)) return;
        // Who is the server: the target of a SYN, the sender of a SYN/ACK, else the well-known port.
        std::string server, client;
        uint32_t port = 0;
        if (syn && syn->u && !(ack && ack->u)) {
            server = t;
            client = s;
            port = dp;
        } else if (syn && syn->u) {
            server = s;
            client = t;
            port = sp;
        } else if (sp < 1024 && dp >= 1024) {
            server = s;
            client = t;
            port = sp;
        } else if (dp < 1024 && sp >= 1024) {
            server = t;
            client = s;
            port = dp;
        } else {
            return;  // decide on a later packet of this stream
        }
        stream_server_[stream] = {server, port};
        Host& hsrv = server == hs.addr ? hs : hd;
        Host& hcli = server == hs.addr ? hd : hs;
        (void)client;
        hsrv.tcp_serves[port]++;
        hcli.tcp_uses[port]++;
    }

    void app_evidence(const FrameFields& ff, const std::string& s, const std::string& t, Host& hs, Host& hd) {
        // The DHCP client's parameter request list, in order, for its MAC.
        if (ff.first_outer("dhcp.option.request_list_item")) {
            std::string prl;
            for (size_t fi = 0; fi < ff.fields.size() && fi < ff.outer_fields; ++fi)
                if (std::strcmp(ff.fields[fi].name, "dhcp.option.request_list_item") == 0 && prl.size() < 200)
                    prl += (prl.empty() ? "" : ",") + std::to_string(ff.fields[fi].value.u);
            if (const FieldValue* m = ff.first_outer("dhcp.hw.mac_addr")) dhcp_prl_[addr_text(*m)] = prl;
        }
        bool response = false;
        std::string qname;
        double dns_time = -1;
        int64_t krb_type = -1;
        std::vector<std::string> krb_names, krb_realms, krb_crealms;
        std::string krb_netbios;
        uint64_t browse_cmd = 0, os_major = 0, os_minor = 0;
        bool browse_dc = false;
        std::string browse_name;
        std::string ntlm_user, ntlm_domain, ntlm_host, dc_name, dc_forest, dc_nb_domain, smb_tree;
        bool smb_response = false;
        for (size_t fi = 0; fi < ff.fields.size() && fi < ff.outer_fields; ++fi) {
            const auto& f = ff.fields[fi];
            const char* nm = f.name;
            if (std::strncmp(nm, "kerberos.", 9) == 0) {
                if (std::strcmp(nm, "kerberos.msg_type") == 0 && krb_type < 0) krb_type = static_cast<int64_t>(f.value.u);
                else if (std::strcmp(nm, "kerberos.CNameString") == 0 && krb_names.size() < 8) krb_names.push_back(f.value.s);
                else if (std::strcmp(nm, "kerberos.realm") == 0 && krb_realms.size() < 4)
                    krb_realms.push_back(f.value.s);
                else if (std::strcmp(nm, "kerberos.crealm") == 0 && krb_crealms.size() < 4)
                    krb_crealms.push_back(f.value.s);
                else if (std::strcmp(nm, "kerberos.addr_nb") == 0) krb_netbios = f.value.s;
                continue;
            }
            if (std::strncmp(nm, "browser.", 8) == 0) {
                if (std::strcmp(nm, "browser.command") == 0) browse_cmd = f.value.u;
                else if (std::strcmp(nm, "browser.server") == 0 || std::strcmp(nm, "browser.response_computer_name") == 0)
                    browse_name = f.value.s;
                else if (std::strcmp(nm, "browser.os_major") == 0) os_major = f.value.u;
                else if (std::strcmp(nm, "browser.os_minor") == 0) os_minor = f.value.u;
                else if (std::strcmp(nm, "browser.server_type.domain_controller") == 0) browse_dc = f.value.u;
                continue;
            }
            if (std::strncmp(nm, "ntlmssp.auth.", 13) == 0) {  // an NTLM logon names the user and the machine
                if (std::strcmp(nm + 13, "username") == 0) ntlm_user = f.value.s;
                else if (std::strcmp(nm + 13, "domain") == 0) ntlm_domain = f.value.s;
                else if (std::strcmp(nm + 13, "hostname") == 0) ntlm_host = f.value.s;
                continue;
            }
            if (std::strncmp(nm, "mscldap.", 8) == 0) {  // a domain controller's answer to a DC ping
                // (mscldap.domain names the partition pinged, e.g. DomainDnsZones: not the domain)
                if (std::strcmp(nm, "mscldap.nb_hostname") == 0) dc_name = f.value.s;
                else if (std::strcmp(nm, "mscldap.forest") == 0) dc_forest = f.value.s;
                else if (std::strcmp(nm, "mscldap.nb_domain") == 0) dc_nb_domain = f.value.s;
                continue;
            }
            if (std::strcmp(nm, "smb2.tree") == 0) {
                smb_tree = f.value.s;
                continue;
            }
            if (std::strcmp(nm, "smb2.flags.response") == 0) {
                smb_response = f.value.u;
                continue;
            }
            if (std::strcmp(nm, "dns.time") == 0) {
                dns_time = f.value.d;
            } else if (std::strcmp(nm, "dns.retransmit_request_in") == 0 ||
                       std::strcmp(nm, "dns.retransmit_response_in") == 0) {
                ++dns_retransmissions_;
            } else if (std::strcmp(nm, "dns.flags.response") == 0) {
                response = f.value.u;
                (response ? dns_responses_ : dns_queries_)++;
                // mDNS and LLMNR replies come from every device that answers for its own name.
                if (response && !ff.has_proto("mdns") && !ff.has_proto("llmnr")) hs.roles["dns-server"]++;
            } else if (std::strcmp(nm, "dns.qry.name") == 0) {
                qname = f.value.s;
                if (!response) dns_names_[qname]++;
            } else if (std::strcmp(nm, "dns.qry.type") == 0 && !response) {
                dns_types_[dns_type_name(static_cast<uint16_t>(f.value.u))]++;
            } else if (std::strcmp(nm, "dns.flags.rcode") == 0) {
                static const char* rc[] = {"No error", "Format error", "Server failure", "No such name",
                                           "Not implemented", "Refused"};
                dns_rcodes_[f.value.u < 6 ? rc[f.value.u] : "Other"]++;
            } else if (std::strcmp(nm, "_anta.dns_answer") == 0) {
                size_t tab = f.value.s.find('\t');
                if (tab != std::string::npos) {
                    std::string name = f.value.s.substr(0, tab), addr = f.value.s.substr(tab + 1);
                    bool v6 = addr.find(':') != std::string::npos;
                    auto it = hosts_.find(addr);
                    Host& h = it != hosts_.end() ? it->second : host(addr, v6, 0);
                    if (!name.empty() && h.names.size() < 16)
                        h.names.emplace(name, ff.has_outer_proto("mdns") ? "mDNS" : ff.has_outer_proto("llmnr") ? "LLMNR" : "DNS");
                }
            } else if (std::strcmp(nm, "tls.handshake.extensions_server_name") == 0) {
                tls_sni_[f.value.s]++;
                if (hd.names.size() < 16) hd.names.emplace(f.value.s, "TLS SNI");
            } else if (std::strcmp(nm, "tls.handshake.ja3_hash") == 0) {
                tls_ja3_[f.value.s]++;
                ++tls_hellos_;
            } else if (std::strcmp(nm, "tls.handshake.ja4") == 0) {
                tls_ja4_[f.value.s]++;
            } else if (std::strcmp(nm, "http.request.method") == 0) {
                ++http_requests_;
                http_methods_[f.value.s]++;
            } else if (std::strcmp(nm, "http.response.code") == 0) {
                ++http_responses_;
                http_status_[std::to_string(f.value.u)]++;
            } else if (std::strcmp(nm, "http.host") == 0) {
                http_hosts_[f.value.s]++;
                std::string host_only = f.value.s;
                size_t colon = host_only.rfind(':');
                if (colon != std::string::npos && host_only.find(']') == std::string::npos &&
                    host_only.find(':') == colon)
                    host_only = host_only.substr(0, colon);
                if (hd.names.size() < 16) hd.names.emplace(host_only, "HTTP Host");
                if (const FieldValue* u = ff.first_outer("http.request.uri")) http_uris_[f.value.s + u->s]++;
            } else if (std::strcmp(nm, "http.user_agent") == 0) {
                http_agents_[f.value.s]++;
                if (hs.user_agents.size() < 4) hs.user_agents.insert(f.value.s);
            } else if (std::strcmp(nm, "http.content_type") == 0) {
                http_ctypes_[f.value.s]++;
            } else if (std::strcmp(nm, "dhcp.option.router") == 0) {
                Host& r = host(addr_text(f.value), false, 0);
                r.roles["router"]++;
            } else if (std::strcmp(nm, "dhcp.option.domain_name_server") == 0) {
                Host& r = host(addr_text(f.value), false, 0);
                r.roles["dns-server-advertised"]++;
            } else if (std::strcmp(nm, "dhcp.option.hostname") == 0) {
                if (hs.names.size() < 16 && s != "0.0.0.0") hs.names.emplace(f.value.s, "DHCP");
                if (const FieldValue* m = ff.first_outer("dhcp.hw.mac_addr")) dhcp_names_[addr_text(*m)] = f.value.s;
            } else if (std::strcmp(nm, "dhcp.option.vendor_class_id") == 0) {
                if (const FieldValue* m = ff.first_outer("dhcp.hw.mac_addr")) dhcp_vendor_[addr_text(*m)] = f.value.s;
            } else if (std::strcmp(nm, "dhcp.ip.your") == 0) {
                // The address a DHCP server hands out, for the client's MAC.
                const FieldValue* m = ff.first_outer("dhcp.hw.mac_addr");
                std::string yi = addr_text(f.value);
                if (m && yi != "0.0.0.0") dhcp_leases_[addr_text(*m)] = yi;
            } else if (std::strcmp(nm, "nbns.name") == 0) {
                // NetBIOS registrations announce the sender's own name.
                std::string n = f.value.s;
                size_t lt = n.find('<');
                if (lt != std::string::npos) n = n.substr(0, lt);
                if (!n.empty() && n != "*" && hs.names.size() < 16 && s != "0.0.0.0" && !response)
                    nb_names_[s].insert(n);
            }
        }
        if (krb_type >= 0) {
            // Requests come from the client; replies and errors go to it. A name ending
            // in $ is the machine's own account; anything else is a person's.
            Host* client = (krb_type == 10 || krb_type == 12) ? &hs
                           : (krb_type == 11 || krb_type == 13 || krb_type == 30) ? &hd : nullptr;
            if (krb_type == 11 || krb_type == 13 || krb_type == 30) hs.roles["kdc"]++;
            if (client) {
                for (const auto& n : krb_names) {
                    if (n.empty()) continue;
                    if (n.back() == '$') {
                        std::string host = n.substr(0, n.size() - 1);
                        for (auto& ch : host) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
                        if (client->names.size() < 16) client->names.emplace(host, "Kerberos");
                    } else if (client->users.size() < 16) {
                        client->users.insert(n);
                    }
                }
                // The client's own realm: replies and errors say so; an AS-REQ's realm is the
                // client's too, but a TGS-REQ's names the service's (possibly another domain).
                const auto& own = !krb_crealms.empty() ? krb_crealms : krb_type == 10 ? krb_realms : krb_crealms;
                for (const auto& r : own) {
                    std::string realm = r;
                    for (auto& ch : realm) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
                    if (!realm.empty() && client->domains.size() < 4) client->domains.insert(realm);
                }
                if (!krb_netbios.empty() && client->names.size() < 16) client->names.emplace(krb_netbios, "Kerberos");
            }
        }
        auto upper = [](std::string v) {
            for (auto& ch : v) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
            return v;
        };
        if (!ntlm_user.empty() || !ntlm_host.empty()) {  // sent by the client
            if (!ntlm_user.empty() && ntlm_user.back() != '$' && hs.users.size() < 16) hs.users.insert(ntlm_user);
            if (!ntlm_domain.empty() && hs.domains.size() < 4) hs.domains.insert(upper(ntlm_domain));
            if (!ntlm_host.empty() && hs.names.size() < 16) hs.names.emplace(upper(ntlm_host), "NTLM");
        }
        if (!dc_name.empty() && dc_name != "<Root>") {
            if (hs.names.size() < 16) hs.names.emplace(dc_name, "CLDAP");
            for (const auto& d : {dc_nb_domain, dc_forest})
                if (!d.empty() && d != "<Root>" && hs.domains.size() < 4) hs.domains.insert(upper(d));
            hs.roles["domain-controller"]++;
        }
        if (smb_tree.size() > 2 && smb_tree[0] == '\\' && smb_tree[1] == '\\') {  // \\server\share names the server
            std::string server = smb_tree.substr(2, smb_tree.find('\\', 2) - 2);
            Host& srv = smb_response ? hs : hd;
            bool ip = !server.empty() && server.find_first_not_of("0123456789.:[]") == std::string::npos;
            if (!server.empty() && !ip && srv.names.size() < 16) srv.names.emplace(server, "SMB share");
        }
        if (browse_cmd) {
            // Host and local-master announcements, elections and announcement requests name
            // the sender; workgroup announcements name the workgroup.
            if (!browse_name.empty() && browse_cmd != 0x0c && hs.names.size() < 16) hs.names.emplace(browse_name, "Browser");
            if (browse_cmd == 0x0c && !browse_name.empty() && hs.domains.size() < 4) hs.domains.insert(browse_name);
            if ((browse_cmd == 0x01 || browse_cmd == 0x0f) && os_major)
                hs.windows_version = std::to_string(os_major) + "." + std::to_string(os_minor);
            if (browse_dc) hs.roles["domain-controller"]++;
        }
        if (dns_time >= 0 && response) {  // request-to-response time, as in Wireshark's DNS statistics
            if (dns_times_.size() < 500'000) dns_times_.push_back(dns_time);
            const FieldValue* fn = ff.first_outer("frame.number");
            dns_slowest_.push_back({dns_time, qname, s, t, fn ? fn->u : 0});
            if (dns_slowest_.size() > 400) {
                std::nth_element(dns_slowest_.begin(), dns_slowest_.begin() + 100, dns_slowest_.end(),
                                 [](const DnsTiming& a, const DnsTiming& b) { return a.seconds > b.seconds; });
                dns_slowest_.resize(100);
            }
        }
        (void)t;
    }

    void arp_evidence(const FrameFields& ff) {
        const FieldValue* sha = ff.first_outer("arp.src.hw_mac");
        const FieldValue* spa = ff.first_outer("arp.src.proto_ipv4");
        if (sha && spa) {
            std::string ip = addr_text(*spa);
            if (ip != "0.0.0.0") {
                auto& mi = macs_[addr_text(*sha)];
                if (mi.arp_ips.size() < 16) mi.arp_ips.insert(ip);
            }
        }
    }

    // Expert information as Wireshark's expert tap counts it: the outer packet's
    // items only, with Wireshark's severity, group, protocol and summary.
    void expert(uint64_t n, const FrameFields& ff, const DecodedFrame& d, uint32_t sport, uint32_t dport) {
        enum { kChat, kNote, kWarn, kError };
        static const struct {
            const char* field;
            int sev;
            const char* group;
            const char* summary;
        } tcp_items[] = {
            {"tcp.analysis.retransmission", kNote, "Sequence", "This frame is a (suspected) retransmission"},
            {"tcp.analysis.fast_retransmission", kNote, "Sequence", "This frame is a (suspected) fast retransmission"},
            {"tcp.analysis.spurious_retransmission", kNote, "Sequence",
             "This frame is a (suspected) spurious retransmission"},
            {"tcp.analysis.out_of_order", kWarn, "Sequence", "This frame is a (suspected) out-of-order segment"},
            {"tcp.analysis.lost_segment", kWarn, "Sequence", "Previous segment(s) not captured (common at capture start)"},
            {"tcp.analysis.ack_lost_segment", kWarn, "Sequence",
             "ACKed segment that wasn't captured (common at capture start)"},
            {"tcp.analysis.window_update", kChat, "Sequence", "TCP window update"},
            {"tcp.analysis.window_full", kWarn, "Sequence", "TCP window specified by the receiver is now completely full"},
            {"tcp.analysis.zero_window", kWarn, "Sequence", "TCP Zero Window segment"},
            {"tcp.analysis.zero_window_probe", kNote, "Sequence", "TCP Zero Window Probe"},
            {"tcp.analysis.zero_window_probe_ack", kNote, "Sequence", "TCP Zero Window Probe Ack"},
            {"tcp.analysis.keep_alive", kNote, "Sequence", "TCP keep-alive segment"},
            {"tcp.analysis.keep_alive_ack", kNote, "Sequence", "ACK to a TCP keep-alive segment"},
            {"tcp.analysis.reused_ports", kNote, "Sequence",
             "A new tcp session is started with the same ports as an earlier session in this trace"},
            {"tcp.analysis.partial_ack", kNote, "Sequence", "Partial Acknowledgement of a segment"},
            {"tcp.analysis.ambiguous_ack", kNote, "Sequence", "Ambiguous ACK following Karn's definition"},
            {"tcp.options.sack.dsack", kWarn, "Sequence", "D-SACK Sequence"},
            {"tcp.connection.fin", kChat, "Sequence", "Connection finish (FIN)"},
            {"tcp.connection.fin_active", kNote, "Sequence", "This frame initiates the connection closing"},
            {"tcp.connection.fin_passive", kNote, "Sequence", "This frame undergoes the connection closing"},
            {"tcp.connection.rst", kWarn, "Sequence", "Connection reset (RST)"},
            {"tcp.ack.nonzero", kNote, "Protocol",
             "The acknowledgment number field is nonzero while the ACK flag is not set"},
            {"tcp.options.mss.absent", kNote, "Protocol", "The SYN packet does not contain a MSS option"},
            {"tcp.options.sack_perm.absent", kNote, "Protocol", "The SYN packet does not contain a SACK PERM option"},
        };
        char buf[160];
        if (ff.has_outer_proto("tcp")) {
            for (const auto& t : tcp_items)
                if (ff.has_outer_proto(t.field)) add_expert(t.sev, t.group, "TCP", t.summary, n);
            if (ff.has_outer_proto("tcp.analysis.duplicate_ack")) {
                const FieldValue* num = ff.first_outer("tcp.analysis.duplicate_ack_num");
                std::snprintf(buf, sizeof buf, "Duplicate ACK (#%llu)", static_cast<unsigned long long>(num ? num->u : 1));
                add_expert(kNote, "Sequence", "TCP", buf, n);
            }
            if (ff.has_outer_proto("tcp.connection.syn")) {
                std::snprintf(buf, sizeof buf, "Connection establish request (SYN): server port %u", dport);
                add_expert(kChat, "Sequence", "TCP", buf, n);
            } else if (ff.has_outer_proto("tcp.connection.synack")) {
                std::snprintf(buf, sizeof buf, "Connection establish acknowledge (SYN+ACK): server port %u", sport);
                add_expert(kChat, "Sequence", "TCP", buf, n);
            }
            if (d.exceeds_mss)
                add_expert(kNote, "Protocol", "TCP",
                           "This packet's length exceeds MSS (common with TSO or incomplete conversations)", n);
        }
        if (ff.has_outer_proto("ip.ttl.too_small")) {
            const FieldValue* ttl = ff.first_outer("ip.ttl");
            std::snprintf(buf, sizeof buf, "\"Time To Live\" only %llu",
                          static_cast<unsigned long long>(ttl ? ttl->u : 0));
            add_expert(kNote, "Sequence", "IPv4", buf, n);
        }
        if (ff.has_outer_proto("ip.ttl.lncb")) {
            const FieldValue* dst = ff.first_outer("ip.dst");
            uint8_t last = dst && dst->s.size() == 4 ? static_cast<uint8_t>(dst->s[3]) : 0;
            std::snprintf(buf, sizeof buf,
                          "\"Time To Live\" != %d for a packet sent to the Local Network Control Block (see RFC 3171)",
                          last == 18 || last == 102 || last == 251 ? 255 : 1);
            add_expert(kNote, "Sequence", "IPv4", buf, n);
        }
        if (ff.has_outer_proto("icmp.type.error")) add_expert(kNote, "Response", "ICMP", "Type indicates an error", n);
        if (ff.has_outer_proto("icmp.type.deprecated")) add_expert(kNote, "Deprecated", "ICMP", "Type is deprecated", n);
        if (ff.has_outer_proto("icmp.resp_not_found"))
            add_expert(kWarn, "Sequence", "ICMP", "No response seen to ICMP request", n);
        // DNS retransmissions arrive as notes, labelled DNS, mDNS or LLMNR.
        if (ff.has_outer_proto("dhcp.secs_le"))
            add_expert(kNote, "Protocol", "DHCP/BOOTP", "Seconds elapsed appears to be encoded as little-endian", n);
        // One per Hello, and a record can carry several.
        size_t protos = std::min(ff.protos.size(), ff.outer_protos);
        for (size_t i = 0; i < protos; ++i)
            if (std::strcmp(ff.protos[i].name, "tls.handshake.legacy_version") == 0)
                add_expert(kChat, "Deprecated", "TLS",
                           "This legacy_version field MUST be ignored. The supported_versions extension is present "
                           "and MUST be used instead.",
                           n);
        for (const auto& note : d.notes) add_expert(note.severity, note.group, note.protocol, note.summary, n);
        if (d.malformed) add_expert(kError, "Malformed", d.protocol, "Malformed Packet (Exception occurred)", n);
    }

    void add_expert(int sev, const char* group, const std::string& proto, const std::string& summary, uint64_t n) {
        std::string key = std::to_string(sev) + "|" + group + "|" + proto + "|" + summary;
        if (experts_.size() > 5000 && !experts_.count(key)) return;
        Expert& e = experts_[key];
        if (!e.count) {
            e.severity = kSev[sev];
            e.group = group;
            e.protocol = proto;
            e.summary = summary;
        }
        e.count++;
        if (e.frames.size() < 500) e.frames.push_back(n);
    }

    static std::string dns_type_name(uint16_t t) {
        switch (t) {
            case 1: return "A";
            case 2: return "NS";
            case 5: return "CNAME";
            case 6: return "SOA";
            case 12: return "PTR";
            case 15: return "MX";
            case 16: return "TXT";
            case 28: return "AAAA";
            case 33: return "SRV";
            case 41: return "OPT";
            case 64: return "SVCB";
            case 65: return "HTTPS";
            case 255: return "ANY";
            default: return "TYPE" + std::to_string(t);
        }
    }

    void write_endpoints(JsonWriter& w, const char* name, const std::unordered_map<std::string, Endpoint>& m) {
        std::vector<const Endpoint*> v;
        v.reserve(m.size());
        for (const auto& [k, e] : m) v.push_back(&e);
        std::sort(v.begin(), v.end(), [](const Endpoint* a, const Endpoint* b) {
            return a->c.tx_b + a->c.rx_b > b->c.tx_b + b->c.rx_b;
        });
        w.key(name).begin_object().kv("total", static_cast<uint64_t>(v.size()));
        if (v.size() > q_.max_rows) v.resize(q_.max_rows);
        w.key("rows").begin_array();
        for (const Endpoint* e : v) {
            w.begin_array().value(e->addr);
            if (e->has_port) w.value(static_cast<uint64_t>(e->port));
            else w.null_value();
            w.value(e->c.tx_p).value(e->c.tx_b).value(e->c.rx_p).value(e->c.rx_b).end_array();
        }
        w.end_array().end_object();
    }

    void write_conversations(JsonWriter& w, const char* name,
                             const std::unordered_map<std::string, Conversation>& m) {
        std::vector<const Conversation*> v;
        v.reserve(m.size());
        for (const auto& [k, c] : m) v.push_back(&c);
        std::sort(v.begin(), v.end(), [](const Conversation* a, const Conversation* b) {
            return a->ab_b + a->ba_b > b->ab_b + b->ba_b;
        });
        w.key(name).begin_object().kv("total", static_cast<uint64_t>(v.size()));
        if (v.size() > q_.max_rows) v.resize(q_.max_rows);
        w.key("rows").begin_array();
        for (const Conversation* c : v) {
            w.begin_array().value(c->a);
            if (c->ports) w.value(static_cast<uint64_t>(c->pa));
            else w.null_value();
            w.value(c->b);
            if (c->ports) w.value(static_cast<uint64_t>(c->pb));
            else w.null_value();
            w.value(c->ab_p).value(c->ab_b).value(c->ba_p).value(c->ba_b);
            w.value(c->first - first_cap).value(c->last - c->first);
            if (c->stream >= 0) w.value(c->stream);
            else w.null_value();
            w.begin_object();
            std::vector<std::pair<std::string, uint64_t>> apps(c->apps.begin(), c->apps.end());
            std::sort(apps.begin(), apps.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
            for (size_t i = 0; i < apps.size() && i < 6; ++i) w.kv(apps[i].first.c_str(), apps[i].second);
            w.end_object();
            w.end_array();
        }
        w.end_array().end_object();
    }

    static void write_counts(JsonWriter& w, const char* name, const std::map<std::string, uint64_t>& m, size_t cap) {
        std::vector<std::pair<std::string, uint64_t>> v(m.begin(), m.end());
        std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        w.key(name).begin_array();
        for (size_t i = 0; i < v.size() && i < cap; ++i) w.begin_array().value(v[i].first).value(v[i].second).end_array();
        w.end_array();
    }

    static void write_ports(JsonWriter& w, const char* name, const std::map<uint32_t, uint64_t>& m) {
        w.key(name).begin_object();
        for (const auto& [p, cnt] : m) w.kv(std::to_string(p).c_str(), cnt);
        w.end_object();
    }

public:
    // Names learned from DHCP/NetBIOS are tied to MACs and addresses; attach them at the end.
    void finish() {
        for (auto& [mac, ip] : dhcp_leases_) {
            auto it = hosts_.find(ip);
            if (it == hosts_.end()) continue;
            auto n = dhcp_names_.find(mac);
            if (n != dhcp_names_.end() && it->second.names.size() < 16) it->second.names.emplace(n->second, "DHCP");
            auto v = dhcp_vendor_.find(mac);
            if (v != dhcp_vendor_.end()) it->second.dhcp_vendor.insert(v->second);
            auto p = dhcp_prl_.find(mac);
            if (p != dhcp_prl_.end()) it->second.dhcp_prl = p->second;
        }
        for (auto& [ip, names] : nb_names_) {
            auto it = hosts_.find(ip);
            if (it == hosts_.end()) continue;
            for (const auto& n : names)
                if (it->second.names.size() < 16) it->second.names.emplace(n, "NetBIOS");
        }
        for (auto& [k, h] : hosts_)
            for (const auto& [mac, cnt] : h.macs) {
                auto v = dhcp_vendor_.find(mac);
                if (v != dhcp_vendor_.end()) h.dhcp_vendor.insert(v->second);
                auto p = dhcp_prl_.find(mac);
                if (p != dhcp_prl_.end() && h.dhcp_prl.empty()) h.dhcp_prl = p->second;
            }
    }

private:
    std::map<std::string, std::string> dhcp_names_, dhcp_vendor_, dhcp_leases_, dhcp_prl_;
    std::map<std::string, std::set<std::string>> nb_names_;
};

}  // namespace

int run_stats(const StatsQuery& q) {
    std::string error;
    std::unique_ptr<DisplayFilter> dfilter;
    if (!q.dfilter.empty()) {
        dfilter = DisplayFilter::compile(q.dfilter, error);
        if (!dfilter) {
            std::fprintf(stderr, "anta-engine: display filter: %s\n", error.c_str());
            return 2;
        }
    }
    Collector col(q);
    for (size_t i = 0; i < q.io_series.size(); ++i) {
        col.series.push_back(DisplayFilter::compile(q.io_series[i], error));
        if (!col.series.back()) {
            std::fprintf(stderr, "anta-engine: I/O graph filter %zu: %s\n", i + 1, error.c_str());
            return 2;
        }
    }
    for (size_t i = 0; i < q.counts.size(); ++i) {
        Collector::Count c;
        c.filter = DisplayFilter::compile(q.counts[i], error);
        if (!c.filter) {
            std::fprintf(stderr, "anta-engine: count filter %zu: %s\n", i + 1, error.c_str());
            return 2;
        }
        col.counts.push_back(std::move(c));
    }
    // Pass 1: look-ahead cross-references and the capture's time span.
    InspectorAnnotations ann;
    uint64_t total = 0;
    double first = 0, last = 0;
    bool any = false;
    {
        Inspector recorder(q.single_pass ? nullptr : &ann, nullptr);
        bool ok = for_each_frame(q.inputs, q.bases, q.bpf, [&](uint64_t n, const RawPacket& p, LinkType link, bool) {
            recorder.observe(link, p.data, p.caplen, n, p.ts_us);
            double ts = static_cast<double>(p.ts_us) / 1e6;
            if (!any) first = last = ts;
            any = true;
            first = std::min(first, ts);
            last = std::max(last, ts);
            ++total;
            return true;
        }, error);
        if (!ok) {
            std::fprintf(stderr, "anta-engine: %s\n", error.c_str());
            return 2;
        }
        ann.complete = true;
    }
    col.first_cap = first;
    col.last_cap = last;
    double span = last - first;
    if (q.io_interval > 0) {
        col.interval = q.io_interval;
    } else {  // about 100-500 bins
        static const double steps[] = {0.001, 0.01, 0.1, 1, 10, 60, 600, 3600, 86400};
        col.interval = steps[8];
        for (double s : steps)
            if (span / s <= 500) {
                col.interval = s;
                break;
            }
    }
    // Pass 2: decode everything in scope with fields, as the viewer shows it.
    Inspector inspector(nullptr, q.single_pass ? nullptr : &ann);
    FrameFields ff;
    bool ok = for_each_frame(q.inputs, q.bases, q.bpf, [&](uint64_t n, const RawPacket& p, LinkType link, bool bpf_ok) {
        if (!bpf_ok) {
            inspector.observe(link, p.data, p.caplen, n, p.ts_us);
            return true;
        }
        DecodedFrame d = inspector.decode(link, p.data, p.caplen, n, p.ts_us, &ff, p.wire_len);
        if (dfilter && !dfilter->match(ff)) return true;
        col.frame(n, static_cast<double>(p.ts_us) / 1e6, p.wire_len, ff, d);
        return true;
    }, error);
    if (!ok) {
        std::fprintf(stderr, "anta-engine: %s\n", error.c_str());
        return 2;
    }
    col.finish();
    JsonWriter w;
    col.write(w, total);
    std::fwrite(w.str().data(), 1, w.str().size(), stdout);
    std::fputc('\n', stdout);
    return 0;
}

}  // namespace anta

namespace anta {

namespace {
// Collects what one frame's decoding decrypted (Follow TLS) or decoded on the chosen
// HTTP/2 stream (Follow HTTP/2); the frame's addresses then say which side sent it.
struct FrameTap : FollowTap {
    FollowQuery::Kind kind;
    uint32_t h2_stream;
    std::vector<std::string> items;
    std::set<uint32_t> h2_streams;  // every HTTP/2 stream the connection carried
    FrameTap(FollowQuery::Kind k, uint32_t s) : kind(k), h2_stream(s) {}
    void tls_data(const uint8_t* p, size_t n) override {
        if (kind == FollowQuery::Tls) items.emplace_back(reinterpret_cast<const char*>(p), n);
    }
    void h2_block(uint32_t sid, const std::string& text) override {
        if (sid && h2_streams.size() < 100000) h2_streams.insert(sid);
        if (kind == FollowQuery::Http2 && sid == h2_stream) items.push_back(text);
    }
    void h2_data(uint32_t sid, const uint8_t* p, size_t n) override {
        if (sid && h2_streams.size() < 100000) h2_streams.insert(sid);
        if (kind == FollowQuery::Http2 && sid == h2_stream) items.emplace_back(reinterpret_cast<const char*>(p), n);
    }
};
}  // namespace

int run_follow(const FollowQuery& q) {
    std::string error;
    Inspector inspector;
    FrameFields ff;
    TlsKeyLog keylog;
    FrameTap tap(q.kind, q.h2_stream);
    if (q.kind != FollowQuery::Transport) {
        if (!q.keylog.empty()) keylog.load(q.keylog);
        inspector.set_keylog(q.keylog.empty() ? nullptr : &keylog);
        inspector.set_follow_tap(&tap);
    }
    bool saw_tls = false;
    const char* stream_field = q.udp ? "udp.stream" : "tcp.stream";
    std::string a_addr, b_addr;
    uint64_t a_port = 0, b_port = 0;
    bool known = false, truncated = false;
    size_t total = 0;
    uint64_t sent[2] = {0, 0}, frames = 0;
    struct Chunk {
        int dir;
        uint64_t frame;
        std::string data;
    };
    std::vector<Chunk> chunks;
    // TCP: bytes delivered per direction in sequence order; segments ahead of a gap wait.
    bool next_set[2] = {false, false};
    uint32_t next[2] = {0, 0};
    std::map<uint32_t, std::pair<uint64_t, std::string>> held[2];
    auto emit = [&](int dir, uint64_t frame, std::string data) {
        if (data.empty()) return;
        if (total + data.size() > q.max_bytes) {
            data.resize(q.max_bytes - std::min(total, q.max_bytes));
            truncated = true;
        }
        total += data.size();
        sent[dir] += data.size();
        if (!chunks.empty() && chunks.back().dir == dir) chunks.back().data += data;
        else if (!data.empty()) chunks.push_back({dir, frame, std::move(data)});
    };
    auto deliver = [&](int dir, uint64_t frame, uint32_t seq, std::string data) {
        if (!next_set[dir]) {
            next_set[dir] = true;
            next[dir] = seq;
        }
        int32_t ahead = static_cast<int32_t>(seq - next[dir]);
        if (ahead > 0) {  // a gap: hold it until the missing bytes arrive
            if (held[dir].size() < 4096) held[dir][seq] = {frame, std::move(data)};
            return;
        }
        size_t skip = static_cast<size_t>(-ahead);
        if (skip >= data.size()) return;  // all seen already (a retransmission)
        emit(dir, frame, data.substr(skip));
        next[dir] = seq + static_cast<uint32_t>(data.size());
        for (auto it = held[dir].begin(); it != held[dir].end();) {
            int32_t d = static_cast<int32_t>(it->first - next[dir]);
            if (d > 0) break;
            size_t s = static_cast<size_t>(-d);
            if (s < it->second.second.size()) {
                emit(dir, it->second.first, it->second.second.substr(s));
                next[dir] = it->first + static_cast<uint32_t>(it->second.second.size());
            }
            it = held[dir].erase(it);
        }
    };
    bool ok = for_each_frame(q.inputs, q.bases, "", [&](uint64_t n, const RawPacket& p, LinkType link, bool) {
        if (truncated) return false;
        tap.items.clear();
        inspector.decode(link, p.data, p.caplen, n, p.ts_us, &ff, p.wire_len);
        const FieldValue* s = ff.first_outer(stream_field);
        if (!s || s->u != q.stream) return true;
        if (ff.has_proto("tls")) saw_tls = true;
        const FieldValue* src = ff.first_outer("ip.src");
        const FieldValue* dst = ff.first_outer("ip.dst");
        if (!src) {
            src = ff.first_outer("ipv6.src");
            dst = ff.first_outer("ipv6.dst");
        }
        const FieldValue* sp = ff.first_outer(q.udp ? "udp.srcport" : "tcp.srcport");
        const FieldValue* dp = ff.first_outer(q.udp ? "udp.dstport" : "tcp.dstport");
        if (!src || !dst || !sp || !dp) return true;
        std::string sa = filter_literal(*src), da = filter_literal(*dst);
        if (!known) {
            a_addr = sa;
            b_addr = da;
            a_port = sp->u;
            b_port = dp->u;
            known = true;
        }
        int dir = (sa == a_addr && sp->u == a_port) ? 0 : 1;
        ++frames;
        if (q.kind != FollowQuery::Transport) {  // decrypted or decoded: what the tap collected
            for (auto& item : tap.items) emit(dir, n, std::move(item));
            return true;
        }
        // The payload: the transport layer's bytes after its header.
        const FrameFields::Proto* tp = nullptr;
        for (size_t i = 0; i < ff.protos.size() && i < ff.outer_protos; ++i)
            if (std::strcmp(ff.protos[i].name, q.udp ? "udp" : "tcp") == 0) tp = &ff.protos[i];
        if (!tp) return true;
        size_t hl = q.udp ? 8 : 0;
        if (!q.udp) {
            const FieldValue* h = ff.first_outer("tcp.hdr_len");
            hl = h ? static_cast<size_t>(h->u) : 20;
        }
        size_t start = tp->offset + hl, end = std::min<size_t>(tp->offset + tp->length, p.caplen);
        if (start >= end) return true;
        std::string data(reinterpret_cast<const char*>(p.data) + start, end - start);
        if (q.udp) {
            emit(dir, n, std::move(data));
        } else {
            const FieldValue* seq = ff.first_outer("tcp.seq");
            const FieldValue* syn = ff.first_outer("tcp.flags.syn");
            uint32_t sq = static_cast<uint32_t>(seq ? seq->u : 0) + ((syn && syn->u) ? 1u : 0u);
            deliver(dir, n, sq, std::move(data));
        }
        return true;
    }, error);
    if (!ok) {
        std::fprintf(stderr, "anta-engine: %s\n", error.c_str());
        return 2;
    }
    for (int dir = 0; dir < 2; ++dir)  // whatever still waits behind a gap that never filled
        for (auto& [seq, held_data] : held[dir]) emit(dir, held_data.first, held_data.second);
    static const char* hex = "0123456789abcdef";
    JsonWriter w;
    const char* proto = q.kind == FollowQuery::Tls ? "tls" : q.kind == FollowQuery::Http2 ? "http2" : q.udp ? "udp" : "tcp";
    w.begin_object().kv("type", "follow").kv("proto", proto).kv("stream", q.stream);
    if (q.kind == FollowQuery::Http2) w.kv("h2_stream", static_cast<uint64_t>(q.h2_stream));
    w.kv("found", known).kv("frames", frames).kv("truncated", truncated);
    if (!q.udp) w.kv("tls", saw_tls);  // (a TCP stream carrying TLS: it can be followed decrypted)
    if (!tap.h2_streams.empty()) {     // the HTTP/2 streams inside, for Follow HTTP/2 Stream
        w.key("h2_streams").begin_array();
        for (uint32_t sid : tap.h2_streams) w.value(static_cast<uint64_t>(sid));
        w.end_array();
    }
    if (known) {
        w.kv("a", a_addr).kv("a_port", a_port).kv("b", b_addr).kv("b_port", b_port);
        w.kv("a_bytes", sent[0]).kv("b_bytes", sent[1]);
    }
    w.key("chunks").begin_array();
    for (const auto& c : chunks) {
        std::string h;
        h.reserve(c.data.size() * 2);
        for (unsigned char ch : c.data) {
            h.push_back(hex[ch >> 4]);
            h.push_back(hex[ch & 15]);
        }
        w.begin_object().kv("dir", c.dir).kv("frame", c.frame).kv("hex", h).end_object();
    }
    w.end_array().end_object();
    std::fwrite(w.str().data(), 1, w.str().size(), stdout);
    std::fputc('\n', stdout);
    return 0;
}

}  // namespace anta
