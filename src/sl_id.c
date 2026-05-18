#include "sl_id.h"

#include <stddef.h>

#include "sl_rng.h"

int sl_id_random_u64(uint64_t *out) {
    if (out == NULL) return -1;
    for (int i = 0; i < 8; ++i) {
        uint64_t v = 0;
        if (sl_rng_u64(&v) != 0) return -1;
        if (v != 0) {
            *out = v;
            return 0;
        }
    }
    return -1;
}

int sl_id_to_hex(uint64_t id, char buf[17]) {
    static const char d[] = "0123456789abcdef";
    if (buf == NULL) return -1;
    for (int i = 15; i >= 0; --i) {
        buf[i] = d[id & 0xF];
        id >>= 4;
    }
    buf[16] = '\0';
    return 0;
}

int sl_id_from_hex(const char *hex, uint64_t *out) {
    if (hex == NULL || out == NULL) return -1;
    uint64_t v = 0;
    for (int i = 0; i < 16; ++i) {
        char c = hex[i];
        uint64_t nibble;
        if      (c >= '0' && c <= '9') nibble = (uint64_t)(c - '0');
        else if (c >= 'a' && c <= 'f') nibble = (uint64_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') nibble = (uint64_t)(c - 'A' + 10);
        else return -1;
        v = (v << 4) | nibble;
    }
    if (hex[16] != '\0') return -1;
    *out = v;
    return 0;
}
