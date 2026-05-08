#include "sl_mem.h"

#include <stddef.h>
#include <stdint.h>

void sl_secure_zero(void *p, size_t n) {
    if (p == NULL || n == 0) return;
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int sl_ct_equal(const void *a, const void *b, size_t n) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    /* Map nonzero -> 0, zero -> 1 without a branch. */
    return (int)((1U & ((uint32_t)diff - 1U) >> 8) & 1U);
}

void sl_xor_inplace(uint8_t *dst, const uint8_t *src, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        dst[i] ^= src[i];
    }
}

void sl_ct_copy(uint8_t *dst, const uint8_t *src, size_t n, int cond) {
    /* Convert cond to 0x00 / 0xFF mask. */
    const uint8_t mask = (uint8_t)(-(int8_t)(!!cond));
    for (size_t i = 0; i < n; ++i) {
        dst[i] = (uint8_t)((src[i] & mask) | (dst[i] & (uint8_t)~mask));
    }
}
