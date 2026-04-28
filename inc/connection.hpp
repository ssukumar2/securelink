#pragma once
#include <string>
#include <cstdint>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>

struct ConnectionConfig {
    int recv_timeout_sec = 10;
    int send_timeout_sec = 10;
    bool tcp_nodelay = true;
    bool keepalive = true;
    int keepalive_idle = 60;
    int keepalive_interval = 10;
    int keepalive_count = 3;
};

inline bool apply_socket_options(int fd, const ConnectionConfig& cfg) {
    struct timeval tv;

    tv.tv_sec = cfg.recv_timeout_sec;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        return false;

    tv.tv_sec = cfg.send_timeout_sec;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        return false;

    int flag = cfg.tcp_nodelay ? 1 : 0;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
        return false;

    if (cfg.keepalive) {
        int on = 1;
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &cfg.keepalive_idle, sizeof(int));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &cfg.keepalive_interval, sizeof(int));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cfg.keepalive_count, sizeof(int));
    }

    return true;
}
