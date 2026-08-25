#include "sl_hexstr.h"
#include "sl_mem.h"

#include <stddef.h>
#include <stdint.h>

int sl_hexstr_encode(const uint8_t *in, size_t len, char *out, size_t out_cap) {
    if ((!in && len > 0) || !out) return -1;
    if (out_cap < len * 2 + 1) return -1;
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[2 * i]     = d[(in[i] >> 4) & 0x0F];
        out[2 * i + 1] = d[in[i] & 0x0F];
    }
    out[len * 2] = '\0';
    return (int)(len * 2);
}

static int nibble(char c, uint8_t *out) {
    if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0');      return 0; }
    if (c >= 'a' && c <= 'f') { *out = (uint8_t)(c - 'a' + 10); return 0; }
    if (c >= 'A' && c <= 'F') { *out = (uint8_t)(c - 'A' + 10); return 0; }
    return -1;
}

int sl_hexstr_decode(const char *in, uint8_t *out, size_t expected_len) {
    if (!in || !out) return -1;
    for (size_t i = 0; i < expected_len; ++i) {
        uint8_t hi, lo;
        if (nibble(in[2 * i],     &hi) != 0) return -1;
        if (nibble(in[2 * i + 1], &lo) != 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (in[2 * expected_len] != '\0') return -1;
    return 0;
}

int sl_hexstr_ct_equal(const char *a, const char *b, size_t n) {
    if (!a || !b) return 0;
    /* Delegate to the one canonical constant-time compare instead of
     * keeping a second copy of the same branch-free bit trick -- two
     * independent copies of tricky security logic are how they quietly
     * drift out of sync over time. */
    return sl_ct_equal(a, b, n * 2);
}
