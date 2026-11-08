// Delivery of JSON records to the analyzer.
//
// Records are queued by the capture thread and written by a dedicated writer
// thread, so a slow or restarting analyzer never stalls packet capture.
// Transports:
//   stdout                     newline-delimited JSON (pipe into `anta analyze`)
//   unix:PATH                  newline-delimited JSON over a Unix stream socket
//   zmq+ipc://PATH             ZeroMQ PUSH (ZMTP 3.0) over a Unix socket
//   zmq+tcp://HOST:PORT        ZeroMQ PUSH (ZMTP 3.0) over TCP
// The ZeroMQ side is a self-contained ZMTP 3.0 implementation (NULL mechanism),
// wire-compatible with libzmq/pyzmq PULL sockets, so the engine needs no libzmq.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace anta {

class Transport {
public:
    virtual ~Transport() = default;
    virtual bool connect(std::string& error) = 0;  // establish (or re-establish) the link
    virtual bool send(const std::string& record) = 0;
    virtual void disconnect() = 0;
    virtual std::string describe() const = 0;
};

// Parses an endpoint spec ("stdout", "unix:/path", "zmq+ipc:///path", "zmq+tcp://127.0.0.1:5555").
std::unique_ptr<Transport> make_transport(const std::string& endpoint, std::string& error);

class Emitter {
public:
    // blocking=true (offline input): never drop; the producer waits for space and
    // the writer waits for the analyzer. blocking=false (live capture): drop and
    // count rather than ever stall the capture loop.
    Emitter(std::unique_ptr<Transport> transport, bool blocking, size_t max_queue_bytes = 64u << 20);
    ~Emitter();

    void line(std::string record);
    // Deliver what is queued (bounded wait in live mode), then stop the writer.
    void close();
    // Async-signal-safe: give up on undelivered records (Ctrl-C while waiting).
    void abort() { abort_.store(true); }
    // True once the transport is permanently broken (e.g. stdout pipe closed).
    bool broken() const { return broken_.load(); }

    uint64_t dropped() const { return dropped_.load(); }

private:
    void run();

    std::unique_ptr<Transport> transport_;
    bool blocking_;
    size_t max_queue_bytes_;

    std::mutex mu_;
    std::condition_variable not_empty_, not_full_;
    std::deque<std::string> queue_;
    size_t queue_bytes_ = 0;
    bool closing_ = false;

    std::atomic<bool> abort_{false};
    std::atomic<bool> broken_{false};
    std::atomic<uint64_t> dropped_{0};
    std::thread writer_;
};

}  // namespace anta
