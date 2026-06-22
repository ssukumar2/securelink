#include "sl_trace_flags.h"

#include <stddef.h>

bool sl_trace_flag_is_set(sl_trace_flags_t f, sl_trace_flags_t bit) {
    return (f & bit) != 0;
}

sl_trace_flags_t sl_trace_flags_with(sl_trace_flags_t f, sl_trace_flags_t bit) {
    return (sl_trace_flags_t)((f | bit) & SL_TRACE_FLAGS_MASK);
}

sl_trace_flags_t sl_trace_flags_without(sl_trace_flags_t f, sl_trace_flags_t bit) {
    return (sl_trace_flags_t)(f & (sl_trace_flags_t)~bit & SL_TRACE_FLAGS_MASK);
}

static char nib_to_hex(uint8_t n) {
    return (char)((n < 10) ? ('0' + n) : ('a' + (n - 10)));
}

int sl_trace_flags_to_hex(sl_trace_flags_t f, char *out, size_t out_cap) {
    if (!out || out_cap < 3) return -1;
    out[0] = nib_to_hex((uint8_t)((f >> 4) & 0x0F));
    out[1] = nib_to_hex((uint8_t)( f       & 0x0F));
    out[2] = '\0';
    return 2;
}

static int from_hex_char(char c, uint8_t *out) {
    if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0'); return 0; }
    if (c >= 'a' && c <= 'f') { *out = (uint8_t)(10 + c - 'a'); return 0; }
    return -1;
}

int sl_trace_flags_from_hex(const char *hex, size_t len, sl_trace_flags_t *out) {
    if (!hex || !out || len != 2) return -1;
    uint8_t hi, lo;
    if (from_hex_char(hex[0], &hi) != 0) return -1;
    if (from_hex_char(hex[1], &lo) != 0) return -1;
    const uint8_t v = (uint8_t)((hi << 4) | lo);
    if ((v & ~SL_TRACE_FLAGS_MASK) != 0) return -1;
    *out = v;
    return 0;
}
