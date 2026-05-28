#include "sl_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int sl_sock_listen_tcp(const char *host, uint16_t port, int backlog) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return -1;

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, p->ai_addr, p->ai_addrlen) == 0 &&
            listen(fd, backlog) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int sl_sock_set_nonblocking(int fd, bool nonblock) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (nonblock) flags |=  O_NONBLOCK;
    else          flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

int sl_sock_connect_tcp(const char *host, uint16_t port, uint32_t timeout_ms) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return -1;

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        int s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
        if (sl_sock_set_nonblocking(s, true) != 0) { close(s); continue; }

        int rc = connect(s, p->ai_addr, p->ai_addrlen);
        if (rc == 0) { fd = s; break; }
        if (errno != EINPROGRESS) { close(s); continue; }

        struct pollfd pfd = { .fd = s, .events = POLLOUT };
        int pr = poll(&pfd, 1, (int)timeout_ms);
        if (pr <= 0) { close(s); continue; }

        int err = 0; socklen_t elen = sizeof(err);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
            close(s);
            continue;
        }
        fd = s;
        break;
    }
    freeaddrinfo(res);
    if (fd >= 0) sl_sock_set_nonblocking(fd, false);
    return fd;
}

int sl_sock_accept(int listen_fd, char *peer_ip, uint16_t *peer_port) {
    struct sockaddr_storage sa;
    socklen_t slen = sizeof(sa);
    int fd = accept(listen_fd, (struct sockaddr *)&sa, &slen);
    if (fd < 0) return -1;

    if (peer_ip && peer_port) {
        if (sa.ss_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)&sa;
            inet_ntop(AF_INET, &in->sin_addr, peer_ip, 64);
            *peer_port = ntohs(in->sin_port);
        } else if (sa.ss_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&sa;
            inet_ntop(AF_INET6, &in6->sin6_addr, peer_ip, 64);
            *peer_port = ntohs(in6->sin6_port);
        } else {
            peer_ip[0] = '\0';
            *peer_port = 0;
        }
    }
    return fd;
}

int sl_sock_set_nodelay(int fd, bool on) {
    int v = on ? 1 : 0;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof(v));
}

int sl_sock_set_keepalive(int fd, bool on, int idle_sec, int interval_sec, int probes) {
    int v = on ? 1 : 0;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &v, sizeof(v)) != 0) return -1;
    if (!on) return 0;
#ifdef TCP_KEEPIDLE
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &idle_sec,     sizeof(idle_sec));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval_sec, sizeof(interval_sec));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &probes,       sizeof(probes));
#endif
    return 0;
}

int sl_sock_set_recv_timeout(int fd, uint32_t ms) {
    struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int sl_sock_set_send_timeout(int fd, uint32_t ms) {
    struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
    return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

void sl_sock_close(int fd) {
    if (fd < 0) return;
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

int sl_sock_read_n(int fd, void *buf, size_t n, uint32_t timeout_ms) {
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < n) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, (int)timeout_ms);
        if (pr <= 0) return -1;
        ssize_t r = recv(fd, p + got, n - got, 0);
        if (r == 0) return -1;
        if (r < 0)  { if (errno == EINTR) continue; return -1; }
        got += (size_t)r;
    }
    return 0;
}

int sl_sock_write_n(int fd, const void *buf, size_t n, uint32_t timeout_ms) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < n) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int pr = poll(&pfd, 1, (int)timeout_ms);
        if (pr <= 0) return -1;
        ssize_t w = send(fd, p + sent, n - sent, MSG_NOSIGNAL);
        if (w <= 0) { if (errno == EINTR) continue; return -1; }
        sent += (size_t)w;
    }
    return 0;
}
