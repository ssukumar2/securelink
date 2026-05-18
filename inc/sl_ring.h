#ifndef SECURELINK_SL_RING_H
#define SECURELINK_SL_RING_H

/* Fixed-capacity byte ring buffer. Single-producer / single-consumer
 * safe across one thread boundary if `head` and `tail` are read with
 * relaxed atomics — but this implementation is plain non-atomic; wrap
 * with a mutex if shared. Intended use: per-connection send/recv staging.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *buf;
    size_t   cap;        /* capacity in bytes (power of two recommended) */
    size_t   head;       /* write index */
    size_t   tail;       /* read index */
    size_t   used;       /* bytes currently stored */
} sl_ring_t;

int  sl_ring_init  (sl_ring_t *r, size_t cap);
void sl_ring_free  (sl_ring_t *r);
void sl_ring_reset (sl_ring_t *r);

size_t sl_ring_capacity (const sl_ring_t *r);
size_t sl_ring_used     (const sl_ring_t *r);
size_t sl_ring_free_space(const sl_ring_t *r);
bool   sl_ring_empty    (const sl_ring_t *r);
bool   sl_ring_full     (const sl_ring_t *r);

/* Push up to `len` bytes from `data`. Returns bytes actually pushed. */
size_t sl_ring_push(sl_ring_t *r, const uint8_t *data, size_t len);

/* Pop up to `len` bytes into `out`. Returns bytes actually popped. */
size_t sl_ring_pop(sl_ring_t *r, uint8_t *out, size_t len);

/* Peek without removing. */
size_t sl_ring_peek(const sl_ring_t *r, uint8_t *out, size_t len);

/* Discard `n` bytes from the tail. Returns bytes actually discarded. */
size_t sl_ring_discard(sl_ring_t *r, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_RING_H */
