#include "sl_packet_mutator.h"

#include <string.h>

void sl_mut_rng_seed(sl_mut_rng_t *r, uint64_t seed) {
    if (!r) return;
    r->state = seed ? seed : 0xA5A5A5A5A5A5A5A5ULL;
}

/* xorshift64* — small, fast, deterministic. Plenty for fuzzing. */
uint64_t sl_mut_rng_next(sl_mut_rng_t *r) {
    if (!r) return 0;
    uint64_t x = r->state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    r->state = x;
    return x * 2685821657736338717ULL;
}

static uint64_t bounded(sl_mut_rng_t *r, uint64_t upper) {
    if (upper == 0) return 0;
    return sl_mut_rng_next(r) % upper;
}

void sl_mut_flip_bit(sl_mut_rng_t *r, uint8_t *buf, size_t len) {
    if (!buf || len == 0) return;
    const uint64_t bit = bounded(r, (uint64_t)len * 8ULL);
    buf[bit / 8] ^= (uint8_t)(1U << (bit % 8));
}

void sl_mut_flip_bits(sl_mut_rng_t *r, uint8_t *buf, size_t len, size_t n) {
    for (size_t i = 0; i < n; ++i) sl_mut_flip_bit(r, buf, len);
}

int sl_mut_overwrite(sl_mut_rng_t *r, uint8_t *buf, size_t len,
                     size_t offset, size_t len_overwrite) {
    if (!buf) return -1;
    if (offset + len_overwrite > len) return -1;
    for (size_t i = 0; i < len_overwrite; ++i) {
        buf[offset + i] = (uint8_t)sl_mut_rng_next(r);
    }
    return 0;
}

size_t sl_mut_truncate(size_t len, size_t n) {
    return (n >= len) ? 0 : (len - n);
}

void sl_mut_extend(sl_mut_rng_t *r, uint8_t *buf_tail, size_t n) {
    if (!buf_tail) return;
    for (size_t i = 0; i < n; ++i) {
        buf_tail[i] = (uint8_t)sl_mut_rng_next(r);
    }
}

void sl_mut_swap_bytes(sl_mut_rng_t *r, uint8_t *buf, size_t len) {
    if (!buf || len < 2) return;
    const uint64_t a = bounded(r, (uint64_t)len);
    uint64_t b = bounded(r, (uint64_t)len);
    if (b == a) b = (b + 1) % len;
    const uint8_t tmp = buf[a];
    buf[a] = buf[b];
    buf[b] = tmp;
}
