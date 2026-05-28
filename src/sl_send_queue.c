#include "sl_send_queue.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

struct sl_send_queue {
    uint8_t *buf;
    size_t   cap;
    size_t   head;   /* next byte to send */
    size_t   tail;   /* next byte to write to */
    size_t   used;
};

sl_send_queue_t *sl_send_queue_new(size_t max_bytes) {
    if (max_bytes == 0) return NULL;
    sl_send_queue_t *q = (sl_send_queue_t *)calloc(1, sizeof(*q));
    if (!q) return NULL;
    q->buf = (uint8_t *)malloc(max_bytes);
    if (!q->buf) { free(q); return NULL; }
    q->cap  = max_bytes;
    return q;
}

void sl_send_queue_free(sl_send_queue_t *q) {
    if (!q) return;
    free(q->buf);
    free(q);
}

int sl_send_queue_enqueue(sl_send_queue_t *q, const uint8_t *data, size_t len) {
    if (!q || !data) return -1;
    if (len == 0) return 0;
    if (q->used + len > q->cap) return -1;

    const size_t first = (q->cap - q->tail < len) ? (q->cap - q->tail) : len;
    memcpy(q->buf + q->tail, data, first);
    if (len > first) memcpy(q->buf, data + first, len - first);
    q->tail  = (q->tail + len) % q->cap;
    q->used += len;
    return 0;
}

int sl_send_queue_flush(sl_send_queue_t *q, int fd) {
    if (!q) return -1;
    int total = 0;
    while (q->used > 0) {
        const size_t chunk = (q->cap - q->head < q->used)
                                 ? (q->cap - q->head)
                                 : q->used;
        ssize_t w = send(fd, q->buf + q->head, chunk, MSG_NOSIGNAL);
        if (w > 0) {
            q->head  = (q->head + (size_t)w) % q->cap;
            q->used -= (size_t)w;
            total   += (int)w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (w < 0 && errno == EINTR) continue;
        return -1;
    }
    return total;
}

size_t sl_send_queue_pending(const sl_send_queue_t *q) {
    return q ? q->used : 0;
}

bool sl_send_queue_empty(const sl_send_queue_t *q) {
    return q ? (q->used == 0) : true;
}
