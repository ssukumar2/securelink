#include "listener.hpp"

#include "sl_socket.h"

namespace securelink {

Listener::Listener(std::string bind_host, std::uint16_t port, int backlog)
    : host_(std::move(bind_host)), port_(port), backlog_(backlog) {}

Listener::~Listener() { stop(); }

bool Listener::start() {
    fd_ = sl_sock_listen_tcp(host_.c_str(), port_, backlog_);
    if (fd_ < 0) return false;
    sl_sock_set_nonblocking(fd_, true);
    return true;
}

bool Listener::attach(EventLoop& loop, AcceptCallback on_accept) {
    if (fd_ < 0) return false;
    loop_      = &loop;
    on_accept_ = std::move(on_accept);
    return loop.add(fd_, kEvRead, [this](int, std::uint32_t) {
        for (;;) {
            char ip[64] = {0};
            std::uint16_t port = 0;
            int cfd = sl_sock_accept(fd_, ip, &port);
            if (cfd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                ++errors_;
                return;
            }
            ++accepts_;
            sl_sock_set_nonblocking(cfd, true);
            sl_sock_set_nodelay   (cfd, true);
            if (on_accept_) {
                AcceptedPeer p;
                p.fd   = cfd;
                p.ip   = ip;
                p.port = port;
                on_accept_(std::move(p));
            } else {
                sl_sock_close(cfd);
            }
        }
    });
}

void Listener::stop() {
    if (loop_ && fd_ >= 0) loop_->remove(fd_);
    if (fd_ >= 0) { sl_sock_close(fd_); fd_ = -1; }
    loop_ = nullptr;
}

}  // namespace securelink
