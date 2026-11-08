#include "capture.h"

#include "platform.h"  // must precede pcap.h on Windows (winsock2 before windows.h)

#include <pcap/pcap.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#include "flow.h"

#include <functional>

#ifdef __linux__
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace anta {

namespace {

// Optional recorder so live captures can later be sliced into per-stream exports.
// Files are created owner-only (the process umask is 077) because they hold full
// packet payloads. Past `max_bytes` the file rotates to PATH.1, and older segments
// move down to PATH.2 ... PATH.<keep>: a rolling buffer of the most recent packets,
// bounding disk use while keeping recent history exportable.
class Recorder {
public:
    bool open(pcap_t* handle, const std::string& path, uint64_t max_bytes, uint32_t keep,
              std::function<void(uint64_t, uint64_t)> on_rotate, std::string& error) {
        if (path.empty()) return true;
        handle_ = handle;
        path_ = path;
        max_bytes_ = max_bytes;
        keep_ = std::max<uint32_t>(1, std::min<uint32_t>(keep, 1000));
        on_rotate_ = std::move(on_rotate);
        dumper_ = pcap_dump_open(handle, path.c_str());
        if (!dumper_) {
            error = std::string("cannot open capture output: ") + pcap_geterr(handle);
            return false;
        }
        return true;
    }
    void write(const RawPacket& p) {
        if (!dumper_) return;
        pcap_pkthdr hdr{};
        hdr.ts.tv_sec = static_cast<time_t>(p.ts_us / 1'000'000);
        hdr.ts.tv_usec = static_cast<decltype(hdr.ts.tv_usec)>(p.ts_us % 1'000'000);
        hdr.caplen = p.caplen;
        hdr.len = p.wire_len;
        pcap_dump(reinterpret_cast<u_char*>(dumper_), &hdr, p.data);
        ++frames_;
        bytes_ += sizeof(uint32_t) * 4 + p.caplen;
        if (++since_flush_ >= 256) flush();
        if (max_bytes_ && bytes_ >= max_bytes_) rotate();
    }
    void rotate() {
        pcap_dump_close(dumper_);
        dumper_ = nullptr;
        bytes_ = 0;
        // Shift the older segments down: .N falls off the end of the buffer.
        std::remove((path_ + "." + std::to_string(keep_)).c_str());
        for (uint32_t i = keep_; i > 1; --i) {
            std::string from = path_ + "." + std::to_string(i - 1), to = path_ + "." + std::to_string(i);
            std::rename(from.c_str(), to.c_str());  // a missing one is fine: the buffer is still filling
        }
        std::string old = path_ + ".1";
        std::remove(old.c_str());  // Windows rename() won't replace an existing file
        if (std::rename(path_.c_str(), old.c_str()) != 0) {
            std::fprintf(stderr, "anta-engine: cannot rotate %s (%s); recording stopped\n", path_.c_str(),
                         std::strerror(errno));
            return;
        }
        dumper_ = pcap_dump_open(handle_, path_.c_str());
        if (!dumper_) std::fprintf(stderr, "anta-engine: cannot reopen %s; recording stopped\n", path_.c_str());
        previous_base_ = base_;
        base_ = frames_;
        if (on_rotate_) on_rotate_(base_, previous_base_);
    }
    void flush() {
        if (dumper_) pcap_dump_flush(dumper_);
        since_flush_ = 0;
    }
    ~Recorder() {
        if (dumper_) pcap_dump_close(dumper_);
    }

private:
    pcap_t* handle_ = nullptr;
    std::string path_;
    uint64_t max_bytes_ = 0;
    uint32_t keep_ = 1;
    uint64_t frames_ = 0, base_ = 0, previous_base_ = 0;
    std::function<void(uint64_t, uint64_t)> on_rotate_;
    uint64_t bytes_ = 0;
    pcap_dumper_t* dumper_ = nullptr;
    int since_flush_ = 0;
};

// ------------------------------------------------------------- libpcap source

class PcapSource : public PacketSource {
public:
    ~PcapSource() override {
        if (handle_) pcap_close(handle_);
    }

    bool open(const CaptureOptions& opts, std::string& error) {
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        live_ = opts.read_file.empty();
        if (!live_) {
            handle_ = pcap_open_offline(opts.read_file.c_str(), errbuf);
            if (!handle_) {
                error = errbuf;
                return false;
            }
        } else {
            handle_ = pcap_create(opts.iface.c_str(), errbuf);
            if (!handle_) {
                error = errbuf;
                return false;
            }
            pcap_set_snaplen(handle_, opts.snaplen);
            pcap_set_promisc(handle_, opts.promiscuous ? 1 : 0);
            pcap_set_timeout(handle_, 250);
            pcap_set_immediate_mode(handle_, 1);
            pcap_set_buffer_size(handle_, opts.buffer_mb << 20);
            int rc = pcap_activate(handle_);
            if (rc < 0) {
                error = std::string("pcap_activate: ") + pcap_geterr(handle_);
                return false;
            }
        }
        if (!opts.bpf.empty()) {
            bpf_program prog{};
            if (pcap_compile(handle_, &prog, opts.bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
                error = std::string("bad BPF filter: ") + pcap_geterr(handle_);
                return false;
            }
            int rc = pcap_setfilter(handle_, &prog);
            pcap_freecode(&prog);
            if (rc < 0) {
                error = std::string("pcap_setfilter: ") + pcap_geterr(handle_);
                return false;
            }
        }
        link_ = static_cast<LinkType>(pcap_datalink(handle_));
        return recorder_.open(handle_, opts.write_file, opts.write_max_bytes, opts.write_keep, opts.on_rotate, error);
    }

    bool run(const Handler& on_packet, const IdleHandler& on_idle) override {
        handler_ = &on_packet;
        while (!stopping_) {
            int n = pcap_dispatch(handle_, -1, &PcapSource::trampoline, reinterpret_cast<u_char*>(this));
            if (n == PCAP_ERROR_BREAK) break;
            if (n < 0) {
                error_ = pcap_geterr(handle_);
                return false;
            }
            if (n == 0 && !live_) break;  // end of file
            if (live_) recorder_.flush();
            on_idle();
        }
        recorder_.flush();
        return true;
    }

    void stop() override {
        stopping_ = true;
        if (handle_) pcap_breakloop(handle_);
    }

    LinkType link_type() const override { return link_; }
    bool is_live() const override { return live_; }

    CaptureStats stats() override {
        CaptureStats s;
        pcap_stat ps{};
        if (live_ && pcap_stats(handle_, &ps) == 0) {
            s.received = ps.ps_recv;
            s.dropped = ps.ps_drop;
            s.if_dropped = ps.ps_ifdrop;
        } else {
            s.received = seen_;
        }
        return s;
    }

private:
    static void trampoline(u_char* user, const pcap_pkthdr* h, const u_char* bytes) {
        auto* self = reinterpret_cast<PcapSource*>(user);
        RawPacket p{static_cast<uint64_t>(h->ts.tv_sec) * 1'000'000 + static_cast<uint64_t>(h->ts.tv_usec),
                    h->caplen, h->len, bytes};
        self->seen_++;
        self->recorder_.write(p);
        (*self->handler_)(p);
    }

    pcap_t* handle_ = nullptr;
    LinkType link_ = LinkType::Ethernet;
    bool live_ = false;
    std::atomic<bool> stopping_{false};
    const Handler* handler_ = nullptr;
    Recorder recorder_;
    uint64_t seen_ = 0;
};

#ifdef __linux__
// --------------------------------------------- AF_PACKET TPACKET_V3 ring (Linux)
//
// The kernel writes frames straight into a memory-mapped ring of blocks shared
// with userspace. We walk each block in place (no copy, no syscall per packet),
// then hand the block back by flipping its status word to TP_STATUS_KERNEL.

class RingSource : public PacketSource {
public:
    ~RingSource() override {
        if (ring_ && ring_ != MAP_FAILED) munmap(ring_, ring_size_);
        if (fd_ >= 0) close(fd_);
        if (dead_) pcap_close(dead_);
    }

    bool open(const CaptureOptions& opts, std::string& error) {
        fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd_ < 0) return fail(error, "socket(AF_PACKET)");

        int version = TPACKET_V3;
        if (setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0)
            return fail(error, "PACKET_VERSION");

        block_size_ = 1u << 22;  // 4 MiB blocks
        block_count_ = std::max(2, opts.buffer_mb / 4);
        tpacket_req3 req{};
        req.tp_block_size = block_size_;
        req.tp_block_nr = block_count_;
        req.tp_frame_size = 2048;
        req.tp_frame_nr = (block_size_ * block_count_) / req.tp_frame_size;
        req.tp_retire_blk_tov = 50;  // ms before a partially filled block is handed to us
        req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
        if (setsockopt(fd_, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0)
            return fail(error, "PACKET_RX_RING");

        ring_size_ = static_cast<size_t>(block_size_) * block_count_;
        ring_ = static_cast<uint8_t*>(mmap(nullptr, ring_size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0));
        if (ring_ == MAP_FAILED) return fail(error, "mmap ring");

        unsigned ifindex = if_nametoindex(opts.iface.c_str());
        if (ifindex == 0) return fail(error, "unknown interface " + opts.iface);
        sockaddr_ll ll{};
        ll.sll_family = AF_PACKET;
        ll.sll_protocol = htons(ETH_P_ALL);
        ll.sll_ifindex = static_cast<int>(ifindex);
        if (bind(fd_, reinterpret_cast<sockaddr*>(&ll), sizeof(ll)) < 0) return fail(error, "bind");

        if (opts.promiscuous) {
            packet_mreq mr{};
            mr.mr_ifindex = static_cast<int>(ifindex);
            mr.mr_type = PACKET_MR_PROMISC;
            setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
        }

        // Compile the BPF expression with libpcap, then attach it to the raw socket
        // so filtering happens in the kernel before frames ever reach the ring.
        dead_ = pcap_open_dead(DLT_EN10MB, opts.snaplen);
        if (!opts.bpf.empty()) {
            bpf_program prog{};
            if (pcap_compile(dead_, &prog, opts.bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
                error = std::string("bad BPF filter: ") + pcap_geterr(dead_);
                return false;
            }
            sock_fprog fprog{};
            fprog.len = static_cast<unsigned short>(prog.bf_len);
            fprog.filter = reinterpret_cast<sock_filter*>(prog.bf_insns);
            int rc = setsockopt(fd_, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
            pcap_freecode(&prog);
            if (rc < 0) return fail(error, "SO_ATTACH_FILTER");
        }
        return recorder_.open(dead_, opts.write_file, opts.write_max_bytes, opts.write_keep, opts.on_rotate, error);
    }

    bool run(const Handler& on_packet, const IdleHandler& on_idle) override {
        unsigned block = 0;
        pollfd pfd{fd_, POLLIN | POLLERR, 0};
        while (!stopping_) {
            auto* desc = reinterpret_cast<tpacket_block_desc*>(ring_ + static_cast<size_t>(block) * block_size_);
            if (!(__atomic_load_n(&desc->hdr.bh1.block_status, __ATOMIC_ACQUIRE) & TP_STATUS_USER)) {
                recorder_.flush();
                on_idle();
                poll(&pfd, 1, 250);
                continue;
            }
            uint32_t count = desc->hdr.bh1.num_pkts;
            auto* hdr = reinterpret_cast<tpacket3_hdr*>(reinterpret_cast<uint8_t*>(desc) +
                                                         desc->hdr.bh1.offset_to_first_pkt);
            for (uint32_t i = 0; i < count; ++i) {
                RawPacket p{static_cast<uint64_t>(hdr->tp_sec) * 1'000'000 + hdr->tp_nsec / 1000,
                            hdr->tp_snaplen, hdr->tp_len, reinterpret_cast<uint8_t*>(hdr) + hdr->tp_mac};
                recorder_.write(p);
                on_packet(p);
                hdr = reinterpret_cast<tpacket3_hdr*>(reinterpret_cast<uint8_t*>(hdr) + hdr->tp_next_offset);
            }
            __atomic_store_n(&desc->hdr.bh1.block_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE);
            block = (block + 1) % block_count_;
            on_idle();  // let the caller run its (rate-limited) housekeeping
        }
        recorder_.flush();
        return true;
    }

    void stop() override { stopping_ = true; }
    LinkType link_type() const override { return LinkType::Ethernet; }
    bool is_live() const override { return true; }

    CaptureStats stats() override {
        tpacket_stats_v3 st{};
        socklen_t len = sizeof(st);
        if (getsockopt(fd_, SOL_PACKET, PACKET_STATISTICS, &st, &len) == 0) {
            // The kernel resets these counters on every read; accumulate.
            totals_.received += st.tp_packets;
            totals_.dropped += st.tp_drops;
        }
        return totals_;
    }

private:
    bool fail(std::string& error, const std::string& what) {
        error = what + ": " + std::strerror(errno);
        return false;
    }

    int fd_ = -1;
    uint8_t* ring_ = nullptr;
    size_t ring_size_ = 0;
    unsigned block_size_ = 0;
    unsigned block_count_ = 0;
    pcap_t* dead_ = nullptr;
    std::atomic<bool> stopping_{false};
    Recorder recorder_;
    CaptureStats totals_;
};
#endif  // __linux__


}  // namespace

bool list_interfaces(std::vector<InterfaceInfo>& out, std::string& error) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* devs = nullptr;
    if (pcap_findalldevs(&devs, errbuf) != 0) {
        error = errbuf;
        return false;
    }
    for (pcap_if_t* d = devs; d; d = d->next) {
        InterfaceInfo info;
        info.name = d->name ? d->name : "";
        info.description = d->description ? d->description : "";
        info.loopback = (d->flags & PCAP_IF_LOOPBACK) != 0;
#ifdef PCAP_IF_UP
        info.up = (d->flags & PCAP_IF_UP) != 0;
        info.running = (d->flags & PCAP_IF_RUNNING) != 0;
#endif
#ifdef PCAP_IF_WIRELESS
        info.wireless = (d->flags & PCAP_IF_WIRELESS) != 0;
#endif
        for (pcap_addr_t* a = d->addresses; a; a = a->next) {
            if (!a->addr) continue;
            char buf[INET6_ADDRSTRLEN] = {0};
            if (a->addr->sa_family == AF_INET) {
                inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(a->addr)->sin_addr, buf, sizeof(buf));
            } else if (a->addr->sa_family == AF_INET6) {
                inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(a->addr)->sin6_addr, buf, sizeof(buf));
            } else {
                continue;
            }
            info.addresses.emplace_back(buf);
        }
        out.push_back(std::move(info));
    }
    pcap_freealldevs(devs);
    return true;
}

bool check_capture(const std::string& iface, std::string& error) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* p = pcap_create(iface.c_str(), errbuf);
    if (!p) {
        error = errbuf;
        return false;
    }
    int rc = pcap_activate(p);
    if (rc < 0) {
        error = rc == PCAP_ERROR_PERM_DENIED ? "permission denied" : pcap_geterr(p);
        pcap_close(p);
        return false;
    }
    pcap_close(p);
    return true;
}

bool parse_flow_spec(const std::string& spec, FlowKey& key) try {
    // proto,ipA,portA,ipB,portB
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t comma = spec.find(',', start);
        parts.push_back(spec.substr(start, comma - start));
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    if (parts.size() != 5) return false;

    PacketInfo p;
    p.proto = static_cast<uint8_t>(std::stoi(parts[0]));
    for (int side = 0; side < 2; ++side) {
        IpAddr& addr = side == 0 ? p.src : p.dst;
        const std::string& text = parts[side == 0 ? 1 : 3];
        if (inet_pton(AF_INET, text.c_str(), addr.bytes.data()) == 1) addr.family = 4;
        else if (inet_pton(AF_INET6, text.c_str(), addr.bytes.data()) == 1) addr.family = 6;
        else return false;
    }
    p.sport = static_cast<uint16_t>(std::stoi(parts[2]));
    p.dport = static_cast<uint16_t>(std::stoi(parts[4]));
    bool ignored;
    key = FlowKey::from_packet(p, ignored);
    return true;
}
catch (const std::exception&) {  // std::stoi on garbage
    return false;
}

std::unique_ptr<PacketSource> open_source(const CaptureOptions& opts, std::string& error) {
#ifdef __linux__
    if (opts.use_ring && opts.read_file.empty()) {
        auto src = std::make_unique<RingSource>();
        if (!src->open(opts, error)) return nullptr;
        return src;
    }
#else
    if (opts.use_ring) {
        error = "--ring requires Linux (AF_PACKET); use the default libpcap source on this platform";
        return nullptr;
    }
#endif
    auto src = std::make_unique<PcapSource>();
    if (!src->open(opts, error)) return nullptr;
    return src;
}

bool for_each_frame(const std::vector<std::string>& in_files, const std::vector<uint64_t>& bases,
                    const std::string& bpf, const FrameFn& fn, std::string& error, uint64_t* first_ts_us) {
    uint64_t frame = 0;
    for (size_t i = 0; i < in_files.size(); ++i) {
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_t* in = pcap_open_offline(in_files[i].c_str(), errbuf);
        if (!in) {
            error = in_files[i] + ": " + errbuf;
            return false;
        }
        if (i < bases.size()) frame = bases[i];
        bpf_program prog{};
        bool filtered = !bpf.empty();
        if (filtered && pcap_compile(in, &prog, bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
            error = std::string("bad filter: ") + pcap_geterr(in);
            pcap_close(in);
            return false;
        }
        auto link = static_cast<LinkType>(pcap_datalink(in));
        pcap_pkthdr* hdr = nullptr;
        const u_char* data = nullptr;
        bool keep_going = true;
        int rc;
        while (keep_going && (rc = pcap_next_ex(in, &hdr, &data)) == 1) {
            ++frame;
            if (first_ts_us && *first_ts_us == 0)
                *first_ts_us = static_cast<uint64_t>(hdr->ts.tv_sec) * 1'000'000 + static_cast<uint64_t>(hdr->ts.tv_usec);
            bool matched = !filtered || pcap_offline_filter(&prog, hdr, data) != 0;
            RawPacket p{static_cast<uint64_t>(hdr->ts.tv_sec) * 1'000'000 + static_cast<uint64_t>(hdr->ts.tv_usec),
                        hdr->caplen, hdr->len, data};
            keep_going = fn(frame, p, link, matched);
        }
        if (filtered) pcap_freecode(&prog);
        pcap_close(in);
        if (!keep_going) break;
        // rc == -1 at the tail of a file still being written is expected: stop quietly.
    }
    return true;
}

PcapFileWriter::~PcapFileWriter() {
    if (dumper_) pcap_dump_close(static_cast<pcap_dumper_t*>(dumper_));
    if (dead_) pcap_close(static_cast<pcap_t*>(dead_));
}

bool PcapFileWriter::write(LinkType link, const RawPacket& p, std::string& error) {
    if (!dumper_) {
        pcap_t* dead = pcap_open_dead(static_cast<int>(link), 262144);
        if (!dead) {
            error = "cannot create a capture for link type " + std::to_string(static_cast<int>(link));
            return false;
        }
        pcap_dumper_t* out = pcap_dump_open(dead, path_.c_str());
        if (!out) {
            error = pcap_geterr(dead);
            pcap_close(dead);
            return false;
        }
        dead_ = dead;
        dumper_ = out;
        link_ = static_cast<int>(link);
    }
    if (static_cast<int>(link) != link_) {
        ++skipped_;
        return true;
    }
    pcap_pkthdr h{};
    h.ts.tv_sec = static_cast<decltype(h.ts.tv_sec)>(p.ts_us / 1000000);
    h.ts.tv_usec = static_cast<decltype(h.ts.tv_usec)>(p.ts_us % 1000000);
    h.caplen = p.caplen;
    h.len = std::max<uint32_t>(p.wire_len, p.caplen);
    pcap_dump(static_cast<u_char*>(dumper_), &h, p.data);
    ++written_;
    return true;
}

bool extract_flows(const std::vector<std::string>& in_files, const std::string& out_file,
                   const std::vector<std::string>& flow_specs, uint64_t& written, std::string& error) {
    std::vector<FlowKey> wanted;
    for (const auto& spec : flow_specs) {
        FlowKey k;
        try {
            if (!parse_flow_spec(spec, k)) throw std::invalid_argument(spec);
        } catch (const std::exception&) {
            error = "bad flow spec '" + spec + "' (expected proto,ipA,portA,ipB,portB)";
            return false;
        }
        wanted.push_back(k);
    }
    if (in_files.empty()) {
        error = "no input files";
        return false;
    }

    written = 0;
    pcap_dumper_t* out = nullptr;
    pcap_t* first = nullptr;
    int out_link = -1;
    for (const auto& in_file : in_files) {
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_t* in = pcap_open_offline(in_file.c_str(), errbuf);
        if (!in) {
            error = errbuf;
            break;
        }
        int dlt = pcap_datalink(in);
        if (!out) {
            out = pcap_dump_open(in, out_file.c_str());
            if (!out) {
                error = pcap_geterr(in);
                pcap_close(in);
                break;
            }
            first = in;
            out_link = dlt;
        } else if (dlt != out_link) {
            std::fprintf(stderr, "anta-engine: skipping %s (link type %d differs from %d)\n", in_file.c_str(), dlt,
                         out_link);
            pcap_close(in);
            continue;
        }
        auto link = static_cast<LinkType>(dlt);
        pcap_pkthdr* hdr = nullptr;
        const u_char* data = nullptr;
        while (pcap_next_ex(in, &hdr, &data) == 1) {
            PacketInfo info;
            if (dissect(link, data, hdr->caplen, info) != DissectResult::Ok) continue;
            bool ignored;
            FlowKey k = FlowKey::from_packet(info, ignored);
            for (const auto& w : wanted) {
                if (k == w) {
                    pcap_dump(reinterpret_cast<u_char*>(out), hdr, data);
                    ++written;
                    break;
                }
            }
        }
        if (in != first) pcap_close(in);
    }
    if (out) pcap_dump_close(out);
    if (first) pcap_close(first);
    return error.empty();
}

}  // namespace anta
