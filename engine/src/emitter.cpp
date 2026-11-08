#include "emitter.h"

#include "platform.h"

#ifndef _WIN32
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/un.h>
#endif

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>

namespace anta {

namespace {

#ifdef MSG_NOSIGNAL
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif

void configure_socket(socket_t fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    // A stalled analyzer must not wedge the writer thread forever.
#ifdef _WIN32
    DWORD snd = 2000, rcv = 5000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&snd), sizeof(snd));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&rcv), sizeof(rcv));
#else
    timeval tv{2, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    timeval rtv{5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
#endif
}

bool interrupted() {
#ifdef _WIN32
    return WSAGetLastError() == WSAEINTR;
#else
    return errno == EINTR;
#endif
}

bool send_all(socket_t fd, const void* data, size_t len) {
    const auto* p = static_cast<const char*>(data);
    while (len > 0) {
        int chunk = static_cast<int>(std::min<size_t>(len, 1u << 30));
        auto n = ::send(fd, p, chunk, kSendFlags);
        if (n < 0 && interrupted()) continue;
        if (n <= 0) return false;
        p += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

bool recv_all(socket_t fd, void* data, size_t len) {
    auto* p = static_cast<char*>(data);
    while (len > 0) {
        int chunk = static_cast<int>(std::min<size_t>(len, 1u << 30));
        auto n = ::recv(fd, p, chunk, 0);
        if (n < 0 && interrupted()) continue;
        if (n <= 0) return false;
        p += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

socket_t connect_unix(const std::string& path, std::string& error) {
#ifdef _WIN32
    error = "Unix-domain endpoints are not supported on Windows; use stdout or zmq+tcp://127.0.0.1:PORT";
    return kInvalidSocket;
#else
    sockaddr_un addr{};
    if (path.empty() || path.size() >= sizeof(addr.sun_path)) {
        error = "socket path too long (max " + std::to_string(sizeof(addr.sun_path) - 1) + " bytes): " + path;
        return kInvalidSocket;
    }
    socket_t fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        error = std::strerror(errno);
        return kInvalidSocket;
    }
    configure_socket(fd);
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        error = path + ": " + std::strerror(errno);
        close_socket(fd);
        return kInvalidSocket;
    }
    return fd;
#endif
}

socket_t connect_tcp(const std::string& host, const std::string& port, std::string& error) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (rc != 0) {
        error = host + ": " + gai_strerror(rc);
        return -1;
    }
    socket_t fd = kInvalidSocket;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == kInvalidSocket) continue;
        configure_socket(fd);
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
        if (::connect(fd, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) break;
        error = host + ":" + port + ": connection refused or unreachable";
        close_socket(fd);
        fd = kInvalidSocket;
    }
    freeaddrinfo(res);
    return fd;
}

// ------------------------------------------------------------------ stdout

class StdoutTransport : public Transport {
public:
    bool connect(std::string&) override { return !failed_; }
    bool send(const std::string& record) override {
        if (std::fwrite(record.data(), 1, record.size(), stdout) != record.size() || std::fputc('\n', stdout) == EOF ||
            std::fflush(stdout) != 0) {
            failed_ = true;  // reader went away (EPIPE); nothing to reconnect to
            return false;
        }
        return true;
    }
    void disconnect() override {}
    std::string describe() const override { return "stdout"; }
    bool failed_ = false;
};

// ----------------------------------------------- newline JSON over Unix socket

class UnixLineTransport : public Transport {
public:
    explicit UnixLineTransport(std::string path) : path_(std::move(path)) {}
    ~UnixLineTransport() override { disconnect(); }
    bool connect(std::string& error) override {
        disconnect();
        fd_ = connect_unix(path_, error);
        return fd_ != kInvalidSocket;
    }
    bool send(const std::string& record) override {
        return fd_ != kInvalidSocket && send_all(fd_, record.data(), record.size()) && send_all(fd_, "\n", 1);
    }
    void disconnect() override {
        if (fd_ != kInvalidSocket) close_socket(fd_);
        fd_ = kInvalidSocket;
    }
    std::string describe() const override { return "unix:" + path_; }

private:
    std::string path_;
    socket_t fd_ = kInvalidSocket;
};

// ------------------------------------------------------------- ZMTP 3.0 PUSH
//
// Greeting (64 bytes): signature FF 00*8 7F, version 03 00, mechanism "NULL"
// padded to 20 bytes, as-server 00, 31 bytes of filler. Then each side sends a
// READY command carrying its Socket-Type property, after which every record is
// one single-frame message: flags (0x00 short / 0x02 long) + size + body.

class ZmtpTransport : public Transport {
public:
    ZmtpTransport(std::string ipc_path, std::string host, std::string port)
        : ipc_path_(std::move(ipc_path)), host_(std::move(host)), port_(std::move(port)) {}
    ~ZmtpTransport() override { disconnect(); }

    bool connect(std::string& error) override {
        disconnect();
        fd_ = ipc_path_.empty() ? connect_tcp(host_, port_, error) : connect_unix(ipc_path_, error);
        if (fd_ == kInvalidSocket) return false;
        if (!handshake(error)) {
            disconnect();
            return false;
        }
        return true;
    }

    bool send(const std::string& record) override {
        if (fd_ == kInvalidSocket) return false;
        uint8_t header[9];
        size_t hlen;
        if (record.size() <= 255) {
            header[0] = 0x00;
            header[1] = static_cast<uint8_t>(record.size());
            hlen = 2;
        } else {
            header[0] = 0x02;  // LONG
            uint64_t n = record.size();
            for (int i = 0; i < 8; ++i) header[1 + i] = static_cast<uint8_t>(n >> (56 - 8 * i));
            hlen = 9;
        }
        return send_all(fd_, header, hlen) && send_all(fd_, record.data(), record.size());
    }

    void disconnect() override {
        if (fd_ != kInvalidSocket) close_socket(fd_);
        fd_ = kInvalidSocket;
    }

    std::string describe() const override {
        return ipc_path_.empty() ? "zmq+tcp://" + host_ + ":" + port_ : "zmq+ipc://" + ipc_path_;
    }

private:
    bool handshake(std::string& error) {
        uint8_t greeting[64] = {0};
        greeting[0] = 0xFF;
        greeting[9] = 0x7F;
        greeting[10] = 3;  // major
        greeting[11] = 0;  // minor
        std::memcpy(greeting + 12, "NULL", 4);
        if (!send_all(fd_, greeting, sizeof(greeting))) {
            error = "ZMTP greeting send failed";
            return false;
        }
        uint8_t peer[64];
        if (!recv_all(fd_, peer, sizeof(peer))) {
            error = "no ZMTP greeting from analyzer";
            return false;
        }
        if (peer[0] != 0xFF || (peer[9] & 0x01) != 0x01 || peer[10] < 3 || std::memcmp(peer + 12, "NULL", 5) != 0) {
            error = "peer is not a ZMTP 3.x NULL-mechanism endpoint";
            return false;
        }

        static const char kName[] = "Socket-Type";
        static const char kType[] = "PUSH";
        std::string body;
        body += static_cast<char>(5);
        body += "READY";
        body += static_cast<char>(sizeof(kName) - 1);
        body += kName;
        uint32_t vlen = sizeof(kType) - 1;
        for (int i = 3; i >= 0; --i) body += static_cast<char>((vlen >> (8 * i)) & 0xFF);
        body += kType;
        uint8_t cmd_header[2] = {0x04, static_cast<uint8_t>(body.size())};
        if (!send_all(fd_, cmd_header, 2) || !send_all(fd_, body.data(), body.size())) {
            error = "ZMTP READY send failed";
            return false;
        }

        uint8_t flags;
        if (!recv_all(fd_, &flags, 1) || !(flags & 0x04)) {
            error = "expected ZMTP command from analyzer";
            return false;
        }
        uint64_t size = 0;
        if (flags & 0x02) {
            uint8_t b[8];
            if (!recv_all(fd_, b, 8)) return false;
            for (uint8_t x : b) size = (size << 8) | x;
        } else {
            uint8_t b;
            if (!recv_all(fd_, &b, 1)) return false;
            size = b;
        }
        if (size == 0 || size > 4096) {
            error = "bad ZMTP command size";
            return false;
        }
        std::string cmd(size, '\0');
        if (!recv_all(fd_, cmd.data(), size)) return false;
        size_t name_len = static_cast<uint8_t>(cmd[0]);
        std::string name = cmd.substr(1, name_len);
        if (name == "ERROR") {
            error = "analyzer rejected connection";
            if (cmd.size() > 2 + name_len) error += ": " + cmd.substr(2 + name_len);
            return false;
        }
        if (name != "READY") {
            error = "unexpected ZMTP command " + name;
            return false;
        }
        // Check the peer is a PULL socket (PUSH may only talk to PULL).
        size_t pos = 1 + name_len;
        while (pos < cmd.size()) {
            size_t klen = static_cast<uint8_t>(cmd[pos]);
            if (pos + 1 + klen + 4 > cmd.size()) break;
            std::string key = cmd.substr(pos + 1, klen);
            pos += 1 + klen;
            uint32_t len = 0;
            for (int i = 0; i < 4; ++i) len = (len << 8) | static_cast<uint8_t>(cmd[pos + i]);
            pos += 4;
            if (pos + len > cmd.size()) break;
            std::string value = cmd.substr(pos, len);
            pos += len;
            if (key == "Socket-Type" && value != "PULL") {
                error = "analyzer socket type is " + value + ", expected PULL";
                return false;
            }
        }
        return true;
    }

    std::string ipc_path_, host_, port_;
    socket_t fd_ = kInvalidSocket;
};

uint64_t now_us() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count());
}

}  // namespace

std::unique_ptr<Transport> make_transport(const std::string& endpoint, std::string& error) {
    auto starts = [&](const char* p) { return endpoint.rfind(p, 0) == 0; };
    if (endpoint.empty() || endpoint == "stdout" || endpoint == "-") return std::make_unique<StdoutTransport>();
    if (starts("unix:")) return std::make_unique<UnixLineTransport>(endpoint.substr(5));

    std::string rest;
    if (starts("zmq+ipc://")) rest = "ipc://" + endpoint.substr(10);
    else if (starts("zmq+tcp://")) rest = "tcp://" + endpoint.substr(10);
    else if (starts("ipc://") || starts("tcp://")) rest = endpoint;
    else if (endpoint[0] == '/' || endpoint[0] == '.') return std::make_unique<UnixLineTransport>(endpoint);
    else {
        error = "unknown endpoint '" + endpoint + "' (use stdout, unix:PATH, zmq+ipc://PATH or zmq+tcp://HOST:PORT)";
        return nullptr;
    }

    if (rest.rfind("ipc://", 0) == 0) return std::make_unique<ZmtpTransport>(rest.substr(6), "", "");
    std::string hostport = rest.substr(6);
    size_t colon = hostport.rfind(':');
    if (colon == std::string::npos || colon + 1 == hostport.size()) {
        error = "tcp endpoint needs HOST:PORT";
        return nullptr;
    }
    std::string host = hostport.substr(0, colon);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
    return std::make_unique<ZmtpTransport>("", host, hostport.substr(colon + 1));
}

// ------------------------------------------------------------------ Emitter

Emitter::Emitter(std::unique_ptr<Transport> transport, bool blocking, size_t max_queue_bytes)
    : transport_(std::move(transport)), blocking_(blocking), max_queue_bytes_(max_queue_bytes) {
    writer_ = std::thread([this] { run(); });
}

Emitter::~Emitter() {
    if (writer_.joinable()) close();
}

void Emitter::line(std::string record) {
    std::unique_lock<std::mutex> lock(mu_);
    if (broken_.load() || abort_.load() || closing_) {
        dropped_++;
        return;
    }
    if (blocking_) {
        while (queue_bytes_ >= max_queue_bytes_ && !abort_.load() && !broken_.load())
            not_full_.wait_for(lock, std::chrono::milliseconds(200));
        if (abort_.load() || broken_.load()) {
            dropped_++;
            return;
        }
    } else if (queue_bytes_ + record.size() > max_queue_bytes_) {
        dropped_++;  // analyzer can't keep up: shed load instead of stalling capture
        return;
    }
    queue_bytes_ += record.size();
    queue_.push_back(std::move(record));
    lock.unlock();
    not_empty_.notify_one();
}

void Emitter::close() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        closing_ = true;
    }
    not_empty_.notify_all();
    if (!blocking_) {
        // Live mode: give the analyzer a moment to take the final records.
        uint64_t deadline = now_us() + 3'000'000;
        while (now_us() < deadline) {
            {
                std::lock_guard<std::mutex> lock(mu_);
                if (queue_.empty()) break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        abort_.store(true);
    }
    if (writer_.joinable()) writer_.join();
    std::lock_guard<std::mutex> lock(mu_);
    dropped_ += queue_.size();
    queue_.clear();
}

void Emitter::run() {
    bool connected = false;
    bool warned = false;
    uint64_t next_attempt = 0;

    while (!abort_.load()) {
        std::string record;
        {
            std::unique_lock<std::mutex> lock(mu_);
            not_empty_.wait_for(lock, std::chrono::milliseconds(200),
                                [&] { return !queue_.empty() || closing_ || abort_.load(); });
            if (abort_.load()) break;
            if (queue_.empty()) {
                if (closing_) break;
                continue;
            }
            record = std::move(queue_.front());
            queue_.pop_front();
            queue_bytes_ -= record.size();
        }
        not_full_.notify_all();

        while (!abort_.load()) {
            if (!connected) {
                uint64_t now = now_us();
                if (now >= next_attempt) {
                    std::string error;
                    connected = transport_->connect(error);
                    if (connected) {
                        std::fprintf(stderr, "anta-engine: connected to analyzer (%s)\n", transport_->describe().c_str());
                        warned = false;
                    } else {
                        next_attempt = now + (blocking_ ? 500'000 : 2'000'000);
                        if (!warned) {
                            std::fprintf(stderr, "anta-engine: analyzer unavailable (%s); %s\n", error.c_str(),
                                         blocking_ ? "waiting" : "dropping records until it returns");
                            warned = true;
                        }
                    }
                }
                if (!connected) {
                    if (!blocking_) {
                        dropped_++;
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
            }
            if (transport_->send(record)) break;
            transport_->disconnect();
            connected = false;
            if (auto* out = dynamic_cast<StdoutTransport*>(transport_.get()); out && out->failed_) {
                broken_.store(true);
                abort_.store(true);
                break;
            }
            std::fprintf(stderr, "anta-engine: lost connection to analyzer (%s)\n", transport_->describe().c_str());
            if (!blocking_) {
                dropped_++;
                break;
            }
        }
    }
    transport_->disconnect();
}

}  // namespace anta
