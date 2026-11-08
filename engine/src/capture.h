// Packet sources: libpcap (live or file, all platforms) and, on Linux, a
// zero-copy AF_PACKET TPACKET_V3 memory-mapped ring.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "flow.h"
#include "packet.h"

namespace anta {

struct RawPacket {
    uint64_t ts_us;
    uint32_t caplen;
    uint32_t wire_len;
    const uint8_t* data;  // valid only for the duration of the callback
};

struct CaptureStats {
    uint64_t received = 0;  // frames the kernel handed us
    uint64_t dropped = 0;   // frames the kernel dropped (buffer full)
    uint64_t if_dropped = 0;
};

struct CaptureOptions {
    std::string iface;       // live capture device
    std::string read_file;   // offline pcap/pcapng
    std::string bpf;         // BPF filter expression
    std::string write_file;  // optionally record every captured frame here
    uint64_t write_max_bytes = 0;  // rotate write_file to write_file.1 past this size (0 = never)
    uint32_t write_keep = 1;       // older segments kept: FILE.1 (newest) ... FILE.N (the rolling buffer)
    // Called after a rotation with the global frame number base of the new file and
    // of the file now at write_file.1 (frame N lives in the file whose base < N).
    std::function<void(uint64_t base, uint64_t previous_base)> on_rotate;
    int snaplen = 65535;
    bool promiscuous = true;
    int buffer_mb = 64;
    bool use_ring = false;   // Linux only: AF_PACKET PACKET_RX_RING instead of libpcap
};

class PacketSource {
public:
    using Handler = std::function<void(const RawPacket&)>;
    using IdleHandler = std::function<void()>;

    virtual ~PacketSource() = default;
    // Runs until the source is exhausted or stop() is called. Returns false on error.
    virtual bool run(const Handler& on_packet, const IdleHandler& on_idle) = 0;
    virtual void stop() = 0;
    virtual LinkType link_type() const = 0;
    virtual CaptureStats stats() = 0;
    virtual bool is_live() const = 0;
    const std::string& error() const { return error_; }

protected:
    std::string error_;
};

struct InterfaceInfo {
    std::string name;
    std::string description;
    std::vector<std::string> addresses;
    bool loopback = false;
    bool up = false;
    bool running = false;
    bool wireless = false;
};

// Capture devices as libpcap/Npcap sees them.
bool list_interfaces(std::vector<InterfaceInfo>& out, std::string& error);

// Try to open IFACE for live capture without capturing anything (permission check).
bool check_capture(const std::string& iface, std::string& error);

// Returns nullptr and fills `error` on failure.
std::unique_ptr<PacketSource> open_source(const CaptureOptions& opts, std::string& error);

// Calls `fn(frame, packet, link)` for each frame of `in_files` in order.
// Frames are numbered from 1; `bases[i]` (if given) is the number of frames that
// precede in_files[i]. Every frame is passed (stateful decoders need them all);
// `matched` says whether it passes the `bpf` filter. Return false from `fn` to stop.
using FrameFn = std::function<bool(uint64_t frame, const RawPacket& packet, LinkType link, bool matched)>;
bool for_each_frame(const std::vector<std::string>& in_files, const std::vector<uint64_t>& bases,
                    const std::string& bpf, const FrameFn& fn, std::string& error, uint64_t* first_ts_us = nullptr);

// "proto,ipA,portA,ipB,portB" -> canonical (direction-independent) flow key.
bool parse_flow_spec(const std::string& spec, FlowKey& key);

// Writes chosen frames to a new pcap file, in the link type of the first frame
// (frames of another link type, possible in a pcapng file, are skipped and counted).
class PcapFileWriter {
public:
    explicit PcapFileWriter(std::string path) : path_(std::move(path)) {}
    ~PcapFileWriter();
    PcapFileWriter(const PcapFileWriter&) = delete;
    PcapFileWriter& operator=(const PcapFileWriter&) = delete;
    // False (with `error`) only if the file can't be created.
    bool write(LinkType link, const RawPacket& packet, std::string& error);
    uint64_t written() const { return written_; }
    uint64_t skipped() const { return skipped_; }

private:
    std::string path_;
    void* dead_ = nullptr;    // pcap_t*
    void* dumper_ = nullptr;  // pcap_dumper_t*
    int link_ = -1;
    uint64_t written_ = 0, skipped_ = 0;
};

// Copies the frames of the given flows out of `in_files` (in order) into `out_file`.
// Each flow spec is "proto,ipA,portA,ipB,portB" and matches both directions.
bool extract_flows(const std::vector<std::string>& in_files, const std::string& out_file,
                   const std::vector<std::string>& flow_specs, uint64_t& written, std::string& error);

}  // namespace anta
