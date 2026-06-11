#include "sl_extensions.h"

#include <string.h>

static void pack_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint16_t unpack_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

void sl_extensions_init(sl_extensions_t *e) {
    if (!e) return;
    memset(e, 0, sizeof(*e));
}

int sl_extensions_add(sl_extensions_t *e,
                      sl_ext_type_t type,
                      const uint8_t *body, size_t body_len) {
    if (!e) return -1;
    if (e->count >= SL_EXT_MAX_COUNT) return -1;
    if (body_len > SL_EXT_MAX_BODY) return -1;
    if (body_len > 0 && !body) return -1;

    sl_extension_t *slot = &e->items[e->count++];
    slot->type = (uint16_t)type;
    slot->len  = (uint16_t)body_len;
    if (body_len > 0) memcpy(slot->body, body, body_len);
    return 0;
}

const sl_extension_t *sl_extensions_find(const sl_extensions_t *e,
                                         sl_ext_type_t type) {
    if (!e) return NULL;
    for (uint8_t i = 0; i < e->count; ++i) {
        if (e->items[i].type == (uint16_t)type) return &e->items[i];
    }
    return NULL;
}

int sl_extensions_encode(const sl_extensions_t *e,
                         uint8_t *out, size_t out_cap) {
    if (!e || !out) return -1;
    if (out_cap < 2) return -1;

    /* Compute inner length. */
    size_t inner = 0;
    for (uint8_t i = 0; i < e->count; ++i) {
        inner += 4 + (size_t)e->items[i].len;
        if (inner > 0xFFFFu) return -1;
    }
    if (out_cap < 2 + inner) return -1;

    pack_u16(out, (uint16_t)inner);
    size_t off = 2;
    for (uint8_t i = 0; i < e->count; ++i) {
        const sl_extension_t *x = &e->items[i];
        pack_u16(out + off,     x->type);
        pack_u16(out + off + 2, x->len);
        if (x->len > 0) memcpy(out + off + 4, x->body, x->len);
        off += 4 + (size_t)x->len;
    }
    return (int)off;
}

int sl_extensions_decode(const uint8_t *in, size_t in_len,
                         sl_extensions_t *out) {
    if (!in || !out) return -1;
    sl_extensions_init(out);
    if (in_len < 2) return -1;

    const uint16_t inner = unpack_u16(in);
    if ((size_t)inner + 2 > in_len) return -1;

    size_t off = 2;
    const size_t end = 2 + (size_t)inner;
    while (off + 4 <= end) {
        const uint16_t t = unpack_u16(in + off);
        const uint16_t L = unpack_u16(in + off + 2);
        if (off + 4 + (size_t)L > end) return -1;

        if (L <= SL_EXT_MAX_BODY && out->count < SL_EXT_MAX_COUNT) {
            sl_extension_t *slot = &out->items[out->count++];
            slot->type = t;
            slot->len  = L;
            if (L > 0) memcpy(slot->body, in + off + 4, L);
        }
        /* If too big or list full: skip silently (graceful evolution). */
        off += 4 + (size_t)L;
    }
    return 0;
}
