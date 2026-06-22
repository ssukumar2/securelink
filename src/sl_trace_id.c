#include "sl_trace_id.h"

#include <ctype.h>
#include <string.h>

#include "sl_rng.h"

static int from_hex_char(char c, uint8_t *out) {
    if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0'); return 0; }
    if (c >= 'a' && c <= 'f') { *out = (uint8_t)(10 + c - 'a'); return 0; }
    return -1;
}

static int hex_to_bytes(const char *hex, size_t hex_len,
                        uint8_t *out, size_t out_len) {
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; ++i) {
        uint8_t hi, lo;
        if (from_hex_char(hex[2 * i],     &hi) != 0) return -1;
        if (from_hex_char(hex[2 * i + 1], &lo) != 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int bytes_to_hex(const uint8_t *in, size_t in_len,
                        char *out, size_t out_cap) {
    static const char d[] = "0123456789abcdef";
    if (out_cap < in_len * 2 + 1) return -1;
    for (size_t i = 0; i < in_len; ++i) {
        out[2 * i]     = d[(in[i] >> 4) & 0x0F];
        out[2 * i + 1] = d[in[i] & 0x0F];
    }
    out[in_len * 2] = '\0';
    return (int)(in_len * 2);
}

int sl_trace_id_random(sl_trace_id_t *out) {
    if (!out) return -1;
    if (sl_rng_bytes(out->bytes, SL_TRACE_ID_LEN) != 0) return -1;
    /* Re-roll if we somehow get the reserved zero ID. */
    if (sl_trace_id_is_zero(out)) out->bytes[0] = 0x01;
    return 0;
}

int sl_span_id_random(sl_span_id_t *out) {
    if (!out) return -1;
    if (sl_rng_bytes(out->bytes, SL_SPAN_ID_LEN) != 0) return -1;
    if (sl_span_id_is_zero(out)) out->bytes[0] = 0x01;
    return 0;
}

bool sl_trace_id_is_zero(const sl_trace_id_t *id) {
    if (!id) return true;
    for (size_t i = 0; i < SL_TRACE_ID_LEN; ++i)
        if (id->bytes[i] != 0) return false;
    return true;
}

bool sl_span_id_is_zero(const sl_span_id_t *id) {
    if (!id) return true;
    for (size_t i = 0; i < SL_SPAN_ID_LEN; ++i)
        if (id->bytes[i] != 0) return false;
    return true;
}

int sl_trace_id_to_hex(const sl_trace_id_t *id, char *out, size_t out_cap) {
    if (!id || !out) return -1;
    return bytes_to_hex(id->bytes, SL_TRACE_ID_LEN, out, out_cap);
}

int sl_span_id_to_hex(const sl_span_id_t *id, char *out, size_t out_cap) {
    if (!id || !out) return -1;
    return bytes_to_hex(id->bytes, SL_SPAN_ID_LEN, out, out_cap);
}

int sl_trace_id_from_hex(const char *hex, size_t len, sl_trace_id_t *out) {
    if (!hex || !out) return -1;
    return hex_to_bytes(hex, len, out->bytes, SL_TRACE_ID_LEN);
}

int sl_span_id_from_hex(const char *hex, size_t len, sl_span_id_t *out) {
    if (!hex || !out) return -1;
    return hex_to_bytes(hex, len, out->bytes, SL_SPAN_ID_LEN);
}
