#include "sl_ring.h"

#include <stdlib.h>
#include <string.h>

int sl_ring_init(sl_ring_t *r, size_t cap) {
    if (r == NULL || cap == 0) return -1;
    r->buf = (uint8_t *)malloc(cap);
    if (r->buf == NULL) return -1;
    r->cap  = cap;
    r->head = 0;
    r->tail = 0;
    r->used = 0;
    return 0;
}

void sl_ring_free(sl_ring_t *r) {
    if (r == NULL) return;
    free(r->buf);
    r->buf = NULL;
    r->cap = r->head = r->tail = r->used = 0;
}

void sl_ring_reset(sl_ring_t *r) {
    if (r == NULL) return;
    r->head = r->tail = r->used = 0;
}

size_t sl_ring_capacity (const sl_ring_t *r) { return r ? r->cap  : 0; }
size_t sl_ring_used     (const sl_ring_t *r) { return r ? r->used : 0; }
size_t sl_ring_free_space(const sl_ring_t *r) { return r ? (r->cap - r->used) : 0; }
bool   sl_ring_empty    (const sl_ring_t *r) { return r ? (r->used == 0)       : true; }
bool   sl_ring_full     (const sl_ring_t *r) { return r ? (r->used == r->cap)  : true; }

size_t sl_ring_push(sl_ring_t *r, const uint8_t *data, size_t len) {
    if (r == NULL || data == NULL) return 0;
    const size_t space = sl_ring_free_space(r);
    const size_t n = (len < space) ? len : space;
    if (n == 0) return 0;

    const size_t first = (r->cap - r->head < n) ? (r->cap - r->head) : n;
    memcpy(r->buf + r->head, data, first);
    if (n > first) {
        memcpy(r->buf, data + first, n - first);
    }
    r->head = (r->head + n) % r->cap;
    r->used += n;
    return n;
}

size_t sl_ring_pop(sl_ring_t *r, uint8_t *out, size_t len) {
    if (r == NULL || out == NULL) return 0;
    const size_t avail = r->used;
    const size_t n = (len < avail) ? len : avail;
    if (n == 0) return 0;

    const size_t first = (r->cap - r->tail < n) ? (r->cap - r->tail) : n;
    memcpy(out, r->buf + r->tail, first);
    if (n > first) {
        memcpy(out + first, r->buf, n - first);
    }
    r->tail = (r->tail + n) % r->cap;
    r->used -= n;
    return n;
}

size_t sl_ring_peek(const sl_ring_t *r, uint8_t *out, size_t len) {
    if (r == NULL || out == NULL) return 0;
    const size_t avail = r->used;
    const size_t n = (len < avail) ? len : avail;
    if (n == 0) return 0;

    const size_t first = (r->cap - r->tail < n) ? (r->cap - r->tail) : n;
    memcpy(out, r->buf + r->tail, first);
    if (n > first) {
        memcpy(out + first, r->buf, n - first);
    }
    return n;
}

size_t sl_ring_discard(sl_ring_t *r, size_t n) {
    if (r == NULL) return 0;
    const size_t k = (n < r->used) ? n : r->used;
    r->tail = (r->tail + k) % r->cap;
    r->used -= k;
    return k;
}
