#include "sl_recv_buf.h"

#include <stdlib.h>
#include <string.h>

int sl_recv_buf_init(sl_recv_buf_t *rb, size_t cap) {
    if (!rb || cap == 0) return -1;
    rb->buf = (uint8_t *)malloc(cap);
    if (!rb->buf) return -1;
    rb->cap  = cap;
    rb->used = 0;
    return 0;
}

void sl_recv_buf_free(sl_recv_buf_t *rb) {
    if (!rb) return;
    free(rb->buf);
    rb->buf = NULL;
    rb->cap = rb->used = 0;
}

int sl_recv_buf_push(sl_recv_buf_t *rb, const uint8_t *data, size_t len) {
    if (!rb || !data) return -1;
    if (rb->used + len > rb->cap) return -1;
    memcpy(rb->buf + rb->used, data, len);
    rb->used += len;
    return 0;
}

int sl_recv_buf_take(sl_recv_buf_t *rb, uint8_t *out, size_t out_cap) {
    if (!rb || !out) return -1;
    if (rb->used < SL_RECORD_HEADER_LEN) return 0;

    int expected = sl_record_peek_len(rb->buf);
    if (expected < 0) return -1;
    if ((size_t)expected > out_cap) return -1;
    if (rb->used < (size_t)expected) return 0;

    memcpy(out, rb->buf, (size_t)expected);
    /* Slide remaining bytes to the front. */
    const size_t leftover = rb->used - (size_t)expected;
    if (leftover > 0) {
        memmove(rb->buf, rb->buf + expected, leftover);
    }
    rb->used = leftover;
    return expected;
}

size_t sl_recv_buf_buffered(const sl_recv_buf_t *rb) {
    return rb ? rb->used : 0;
}
