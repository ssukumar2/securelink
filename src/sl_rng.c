#include "sl_rng.h"

#include <openssl/rand.h>
#include <string.h>

int sl_rng_init(void) {
    /* OpenSSL >= 1.1 seeds itself; this call ensures the DRBG is ready
     * and gives us an early failure if /dev/urandom is unreachable. */
    unsigned char probe[1];
    if (RAND_bytes(probe, sizeof(probe)) != 1) {
        return -1;
    }
    return 0;
}

int sl_rng_bytes(uint8_t *buf, size_t len) {
    if (buf == NULL || len == 0) {
        return -1;
    }
    /* RAND_bytes accepts int; chunk for very large requests. */
    while (len > 0) {
        int chunk = (len > 1 << 20) ? (1 << 20) : (int)len;
        if (RAND_bytes(buf, chunk) != 1) {
            return -1;
        }
        buf += chunk;
        len -= (size_t)chunk;
    }
    return 0;
}

int sl_rng_u32(uint32_t *out) {
    if (out == NULL) return -1;
    uint8_t b[4];
    if (sl_rng_bytes(b, sizeof(b)) != 0) return -1;
    *out = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  |  (uint32_t)b[3];
    return 0;
}

int sl_rng_u64(uint64_t *out) {
    if (out == NULL) return -1;
    uint8_t b[8];
    if (sl_rng_bytes(b, sizeof(b)) != 0) return -1;
    *out = 0;
    for (int i = 0; i < 8; ++i) {
        *out = (*out << 8) | (uint64_t)b[i];
    }
    return 0;
}

int sl_rng_uniform(uint64_t upper, uint64_t *out) {
    if (upper == 0 || out == NULL) return -1;

    /* Rejection sampling: discard values >= floor(2^64 / upper) * upper. */
    const uint64_t limit = UINT64_MAX - (UINT64_MAX % upper);
    uint64_t r;
    for (;;) {
        if (sl_rng_u64(&r) != 0) return -1;
        if (r < limit) {
            *out = r % upper;
            return 0;
        }
    }
}
