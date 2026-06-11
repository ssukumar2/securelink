#include "sl_version.h"

#include <string.h>

void sl_version_list_init(sl_version_list_t *l) {
    if (!l) return;
    memset(l, 0, sizeof(*l));
}

int sl_version_list_add(sl_version_list_t *l, uint16_t version) {
    if (!l) return -1;
    if (l->count >= sizeof(l->versions) / sizeof(l->versions[0])) return -1;
    for (uint8_t i = 0; i < l->count; ++i) {
        if (l->versions[i] == version) return 0;   /* dedupe */
    }
    l->versions[l->count++] = version;
    return 0;
}

bool sl_version_list_has(const sl_version_list_t *l, uint16_t version) {
    if (!l) return false;
    for (uint8_t i = 0; i < l->count; ++i) {
        if (l->versions[i] == version) return true;
    }
    return false;
}

int sl_version_list_encode(const sl_version_list_t *l,
                           uint8_t *out, size_t out_cap) {
    if (!l || !out) return -1;
    const size_t need = (size_t)1 + (size_t)l->count * 2;
    if (out_cap < need) return -1;
    out[0] = l->count;
    for (uint8_t i = 0; i < l->count; ++i) {
        out[1 + 2 * i]     = (uint8_t)(l->versions[i] >> 8);
        out[1 + 2 * i + 1] = (uint8_t)(l->versions[i] & 0xFF);
    }
    return (int)need;
}

int sl_version_list_decode(const uint8_t *in, size_t in_len,
                           sl_version_list_t *out) {
    if (!in || !out || in_len < 1) return -1;
    sl_version_list_init(out);
    const uint8_t count = in[0];
    const size_t  cap   = sizeof(out->versions) / sizeof(out->versions[0]);
    if (count > cap) return -1;
    if (in_len < (size_t)1 + (size_t)count * 2) return -1;
    for (uint8_t i = 0; i < count; ++i) {
        const uint16_t v = ((uint16_t)in[1 + 2 * i] << 8) |
                            (uint16_t)in[1 + 2 * i + 1];
        sl_version_list_add(out, v);
    }
    return 0;
}

uint16_t sl_version_choose(const sl_version_list_t *a,
                           const sl_version_list_t *b) {
    if (!a || !b) return 0;
    uint16_t best = 0;
    for (uint8_t i = 0; i < a->count; ++i) {
        const uint16_t v = a->versions[i];
        if (sl_version_list_has(b, v) && v > best) best = v;
    }
    return best;
}
