#pragma once
// Listener — wraps a listening TCP socket and integrates with EventLoop.
// On each accept it builds a peer descriptor and invokes the user's
// on_accept callback. The callback owns the new fd and is responsible
// for registering it with the event loop or closing it.

#include <cstdint>
#include <functional>
#include <string>

#include "event_loop.hpp"

namespace securelink {

struct AcceptedPeer {
    int           fd;
    std::string   ip;
    std::uint16_t port;
};

using AcceptCallback = std::function<void(AcceptedPeer)>;

class Listener {
public:
    Listener(std::string bind_host, std::uint16_t port, int backlog = 64);
    ~Listener();

    Listener(const Listener&)            = delete;
    Listener& operator=(const Listener&) = delete;

    // Bind and start listening. Returns false on socket/bind/listen failure.
    bool start();

    // Attach to a running EventLoop. The on_accept callback runs on the
    // loop's thread whenever a new client connects.
    bool attach(EventLoop& loop, AcceptCallback on_accept);

    void stop();

    int fd()                    const { return fd_; }
    const std::string& host()   const { return host_; }
    std::uint16_t      port()   const { return port_; }
    std::uint64_t      accepts() const { return accepts_; }
    std::uint64_t      errors()  const { return errors_; }

private:
    std::string   host_;
    std::uint16_t port_;
    int           backlog_;
    int           fd_       = -1;
    EventLoop*    loop_     = nullptr;
    AcceptCallback on_accept_;
    std::uint64_t accepts_ = 0;
    std::uint64_t errors_  = 0;
};

}  // namespace securelink
