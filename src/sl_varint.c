#include "sl_varint.h"

int sl_varint_size_u64(uint64_t v) {
    int n = 1;
    while (v >= 0x80) { v >>= 7; ++n; }
    return n;
}

int sl_varint_encode_u64(uint64_t v, uint8_t *out, size_t out_cap) {
    if (!out) return -1;
    int n = 0;
    while (v >= 0x80) {
        if ((size_t)n >= out_cap) return -1;
        out[n++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    if ((size_t)n >= out_cap) return -1;
    out[n++] = (uint8_t)v;
    return n;
}

int sl_varint_decode_u64(const uint8_t *in, size_t in_len, uint64_t *out) {
    if (!in || !out) return -1;
    uint64_t result = 0;
    int      shift  = 0;
    for (size_t i = 0; i < in_len && i < SL_VARINT_MAX_LEN; ++i) {
        const uint8_t b = in[i];
        result |= ((uint64_t)(b & 0x7F)) << shift;
        if ((b & 0x80) == 0) {
            *out = result;
            return (int)i + 1;
        }
        shift += 7;
        if (shift > 63) return -1; /* overflow */
    }
    return -1;
}
