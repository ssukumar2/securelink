#ifndef SECURELINK_SL_SOCKET_H
#define SECURELINK_SL_SOCKET_H

/* Thin C wrappers over BSD sockets. Each function returns 0 on success
 * (or a non-negative fd) and -1 on failure with errno preserved.
 *
 * Goals: hide repetitive setsockopt boilerplate, give the rest of the
 * codebase one place to enforce server defaults (NODELAY, REUSEADDR,
 * SO_RCVTIMEO, etc.), and provide a portable nonblocking connect. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Create a TCP socket and bind+listen on host:port. host may be NULL
 * for INADDR_ANY. Returns the listening fd or -1. */
int sl_sock_listen_tcp(const char *host, uint16_t port, int backlog);

/* Connect to host:port with a timeout (milliseconds). Returns connected
 * fd or -1. The returned fd is in blocking mode by default; toggle with
 * sl_sock_set_nonblocking() afterwards if needed. */
int sl_sock_connect_tcp(const char *host, uint16_t port,
                        uint32_t timeout_ms);

/* Accept one connection. Fills `peer_ip` (caller buffer >= 64 bytes) and
 * `peer_port`. Returns the new fd or -1. */
int sl_sock_accept(int listen_fd, char *peer_ip, uint16_t *peer_port);

/* Toggle nonblocking mode. */
int sl_sock_set_nonblocking(int fd, bool nonblock);

/* Common option helpers. */
int sl_sock_set_nodelay   (int fd, bool on);
int sl_sock_set_keepalive (int fd, bool on, int idle_sec, int interval_sec, int probes);
int sl_sock_set_recv_timeout(int fd, uint32_t ms);
int sl_sock_set_send_timeout(int fd, uint32_t ms);

/* Best-effort close: shutdown then close, swallow errors. */
void sl_sock_close(int fd);

/* Read/write exactly N bytes or fail. Returns 0 on success. */
int sl_sock_read_n (int fd, void *buf, size_t n, uint32_t timeout_ms);
int sl_sock_write_n(int fd, const void *buf, size_t n, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_SOCKET_H */
