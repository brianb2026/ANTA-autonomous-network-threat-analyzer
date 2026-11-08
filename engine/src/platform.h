// Portability layer: one place for the socket/byte-order headers and the few
// POSIX vs. Windows differences the engine cares about.
#pragma once

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX  // keep std::min/std::max usable
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <BaseTsd.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#ifndef _SSIZE_T_DEFINED
#ifndef __MINGW32__
typedef SSIZE_T ssize_t;
#endif
#endif
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
inline int close_socket(socket_t s) { return closesocket(s); }
inline int process_id() { return _getpid(); }
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
inline int close_socket(socket_t s) { return ::close(s); }
inline int process_id() { return static_cast<int>(::getpid()); }
#endif

#include <string>

namespace anta {

// Absolute, symlink-resolved path (best effort: returns the input on failure).
std::string absolute_path(const std::string& path);

// One-time process setup: Winsock, Npcap DLL search path, binary stdout.
void platform_init();

}  // namespace anta
