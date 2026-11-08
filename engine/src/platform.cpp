#include "platform.h"

#include <climits>
#include <cstdio>
#include <cstdlib>

namespace anta {

std::string absolute_path(const std::string& path) {
    if (path.empty()) return path;
#ifdef _WIN32
    char buf[MAX_PATH * 4];
    if (_fullpath(buf, path.c_str(), sizeof(buf))) return buf;
#else
    char buf[PATH_MAX];
    if (realpath(path.c_str(), buf)) return buf;
#endif
    return path;
}

void platform_init() {
#ifdef _WIN32
    // Npcap installs wpcap.dll under System32\Npcap rather than System32. The
    // engine delay-loads wpcap.dll, so point the loader there before first use.
    char sysdir[MAX_PATH];
    UINT n = GetSystemDirectoryA(sysdir, MAX_PATH);
    if (n > 0 && n < MAX_PATH - 8) {
        std::string npcap = std::string(sysdir) + "\\Npcap";
        SetDllDirectoryA(npcap.c_str());
    }
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    // JSON records must not get \r\n translation.
    _setmode(_fileno(stdout), _O_BINARY);
#endif
}

}  // namespace anta
