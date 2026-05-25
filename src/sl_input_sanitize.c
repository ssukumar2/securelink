#include "sl_input_sanitize.h"

#include <stddef.h>
#include <stdint.h>

bool sl_in_range_size(size_t len, size_t min, size_t max) {
    if (min > max) return false;
    return len >= min && len <= max;
}

bool sl_is_printable_ascii(const uint8_t *buf, size_t len) {
    if (!buf && len > 0) return false;
    for (size_t i = 0; i < len; ++i) {
        const uint8_t c = buf[i];
        if (c < 0x20 || c > 0x7E) return false;
    }
    return true;
}

bool sl_is_valid_utf8(const uint8_t *buf, size_t len) {
    if (!buf && len > 0) return false;
    size_t i = 0;
    while (i < len) {
        const uint8_t b0 = buf[i];
        if (b0 < 0x80) { i += 1; continue; }

        uint32_t cp = 0;
        size_t   extra = 0;
        if ((b0 & 0xE0) == 0xC0) { cp = b0 & 0x1F; extra = 1; }
        else if ((b0 & 0xF0) == 0xE0) { cp = b0 & 0x0F; extra = 2; }
        else if ((b0 & 0xF8) == 0xF0) { cp = b0 & 0x07; extra = 3; }
        else return false;

        if (i + extra >= len) return false;
        for (size_t k = 1; k <= extra; ++k) {
            const uint8_t bk = buf[i + k];
            if ((bk & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (bk & 0x3F);
        }

        /* Reject overlong encodings. */
        if (extra == 1 && cp < 0x80)    return false;
        if (extra == 2 && cp < 0x800)   return false;
        if (extra == 3 && cp < 0x10000) return false;

        /* Reject UTF-16 surrogates and out-of-range code points. */
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;
        if (cp > 0x10FFFF) return false;

        i += 1 + extra;
    }
    return true;
}

bool sl_has_metachars(const uint8_t *buf, size_t len) {
    if (!buf) return false;
    for (size_t i = 0; i < len; ++i) {
        switch (buf[i]) {
            case '\0': case '\n': case '\r': case '\t':
            case '\'': case '"':  case '`':  case '\\':
            case ';':  case '|':  case '&':  case '$':
            case '<':  case '>':  case '(':  case ')':
                return true;
            default: break;
        }
    }
    return false;
}

bool sl_size_add_safe(size_t a, size_t b, size_t *out) {
    if (b > SIZE_MAX - a) return false;
    if (out) *out = a + b;
    return true;
}

bool sl_size_mul_safe(size_t a, size_t b, size_t *out) {
    if (a != 0 && b > SIZE_MAX / a) return false;
    if (out) *out = a * b;
    return true;
}
