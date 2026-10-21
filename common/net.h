/*
 * File    : net.h
 * Author  : Saksham Varshney
 * Roll No : 44300
 * Purpose : Tiny TCP socket wrapper that works on Windows (Winsock, built into
 *           Windows - nothing to install) and on Linux/macOS (POSIX sockets).
 *           Messages are text lines ending in '\n' (a very simple protocol).
 */
#ifndef NET_H
#define NET_H

#include <string>
#include <stdexcept>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <utility>          // std::move

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
  #define _WINSOCK_DEPRECATED_NO_WARNINGS   // we use the classic functions on purpose (work on every Windows compiler)
  #endif
  #include <winsock2.h>                     // only winsock2.h is needed (no ws2tcpip.h / getaddrinfo)
  #ifdef _MSC_VER
  #pragma comment(lib, "ws2_32.lib")   // MSVC links Winsock automatically (g++ needs -lws2_32)
  #endif
  typedef SOCKET sock_t;
  #define NET_INVALID INVALID_SOCKET
  #define NET_CLOSE(s) closesocket(s)
  static inline int netLastError() { return WSAGetLastError(); }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <errno.h>
  typedef int sock_t;
  #define NET_INVALID (-1)
  #define NET_CLOSE(s) ::close(s)
  static inline int netLastError() { return errno; }
#endif

#ifdef _WIN32
  #ifndef SO_EXCLUSIVEADDRUSE                // missing in some older MinGW headers
  #define SO_EXCLUSIVEADDRUSE ((int)(~SO_REUSEADDR))
  #endif
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0                 // Windows/macOS: flag does not exist
#endif

namespace net {

// Starts Winsock on Windows (no-op elsewhere). Called automatically by Socket.
inline void init() {
#ifdef _WIN32
    static bool done = false;
    if (!done) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) throw std::runtime_error("WSAStartup failed");
        done = true;
    }
#endif
}

// Ports must be 1..65535; otherwise the value would silently wrap around
inline void checkPort(int port) {
    if (port < 1 || port > 65535) throw std::invalid_argument("port must be between 1 and 65535");
}

inline std::string errText(const std::string &what) {
    return what + " (error code " + std::to_string(netLastError()) + ")";
}

class Socket {
public:
    Socket() : s_(NET_INVALID) { init(); }
    explicit Socket(sock_t s) : s_(s) { init(); }
    ~Socket() { close(); }

    // sockets cannot be copied, only moved
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;
    Socket(Socket &&o) : s_(o.s_), buf_(std::move(o.buf_)) { o.s_ = NET_INVALID; }
    Socket &operator=(Socket &&o) {
        if (this != &o) { close(); s_ = o.s_; buf_ = std::move(o.buf_); o.s_ = NET_INVALID; }
        return *this;
    }

    bool valid() const { return s_ != NET_INVALID; }

    void close() {
        if (s_ != NET_INVALID) { NET_CLOSE(s_); s_ = NET_INVALID; }
    }

    // ---- client side: connect to host (IPv4 address like "127.0.0.1" or a name like "localhost") ----
    void connectTo(const std::string &host, int port) {
        checkPort(port);
        close();

        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((unsigned short)port);

        // 1) dotted address? 2) otherwise look the name up
        uint32_t ip = (uint32_t)inet_addr(host.c_str());
        if (ip != (uint32_t)INADDR_NONE) {
            addr.sin_addr.s_addr = ip;
        } else {
            struct hostent *h = gethostbyname(host.c_str());
            if (!h || h->h_addrtype != AF_INET || !h->h_addr_list || !h->h_addr_list[0])
                throw std::runtime_error("cannot resolve host '" + host + "'");
            std::memcpy(&addr.sin_addr, h->h_addr_list[0], sizeof(addr.sin_addr));
        }

        s_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (s_ == NET_INVALID) throw std::runtime_error(errText("socket() failed"));
        if (::connect(s_, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            std::string e = errText("cannot connect to " + host + ":" + std::to_string(port) + " - is the server running?");
            close(); throw std::runtime_error(e);
        }
    }

    // ---- server side: listen on a port (all network interfaces) ----
    void listenOn(int port) {
        checkPort(port);
        close();
        s_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (s_ == NET_INVALID) throw std::runtime_error(errText("socket() failed"));
        int yes = 1;
#ifdef _WIN32
        // On Windows SO_REUSEADDR would let a second server steal the same port,
        // so use the exclusive option: a second server gets a clear "port in use" error.
        setsockopt(s_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&yes, sizeof(yes));
#else
        setsockopt(s_, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));  // allow quick restart
#endif
        struct sockaddr_in a;
        std::memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        a.sin_port = htons((unsigned short)port);
        if (::bind(s_, (struct sockaddr *)&a, sizeof(a)) != 0) {
            std::string e = errText("bind() failed on port " + std::to_string(port) + " (port already in use?)");
            close(); throw std::runtime_error(e);
        }
        if (::listen(s_, 5) != 0) { std::string e = errText("listen() failed"); close(); throw std::runtime_error(e); }
    }

    // waits for one client; returns the connected socket. peer = client's IP text.
    Socket acceptClient(std::string *peer = 0) {
        struct sockaddr_in a;
#ifdef _WIN32
        int len = sizeof(a);
#else
        socklen_t len = sizeof(a);
#endif
        sock_t c = ::accept(s_, (struct sockaddr *)&a, &len);
        if (c == NET_INVALID) throw std::runtime_error(errText("accept() failed"));
        if (peer) *peer = std::string(inet_ntoa(a.sin_addr)) + ":" + std::to_string(ntohs(a.sin_port));
        return Socket(c);
    }

    // ---- send one line (adds '\n'); loops until every byte is sent ----
    void sendLine(const std::string &line) {
        std::string data = line + "\n";
        size_t sent = 0;
        while (sent < data.size()) {
            int n = (int)::send(s_, data.data() + sent, (int)(data.size() - sent), MSG_NOSIGNAL);
            if (n <= 0) throw std::runtime_error(errText("send() failed"));
            sent += (size_t)n;
        }
    }

    // ---- receive one line (without '\n'). Returns false if the peer closed the connection. ----
    bool recvLine(std::string &out, size_t maxLen = 1000000) {
        for (;;) {
            size_t pos = buf_.find('\n');
            if (pos != std::string::npos) {
                if (pos > maxLen) throw std::runtime_error("received line too long");
                out = buf_.substr(0, pos);
                buf_.erase(0, pos + 1);
                if (!out.empty() && out[out.size() - 1] == '\r') out.erase(out.size() - 1);
                return true;
            }
            if (buf_.size() > maxLen) throw std::runtime_error("received line too long");
            char tmp[4096];
            int n = (int)::recv(s_, tmp, sizeof(tmp), 0);
            if (n == 0) return false;                  // orderly close
            if (n < 0) throw std::runtime_error(errText("recv() failed"));
            buf_.append(tmp, (size_t)n);
        }
    }

private:
    sock_t s_;
    std::string buf_;     // bytes received but not yet returned as a line
};

} // namespace net
#endif