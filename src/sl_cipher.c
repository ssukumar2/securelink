#include "sl_cipher.h"

#include <string.h>

void sl_cipher_list_init(sl_cipher_list_t *l) {
    if (!l) return;
    memset(l, 0, sizeof(*l));
}

int sl_cipher_list_add(sl_cipher_list_t *l, uint16_t suite) {
    if (!l) return -1;
    if (l->count >= SL_CIPHER_LIST_MAX) return -1;
    for (uint8_t i = 0; i < l->count; ++i) {
        if (l->suites[i] == suite) return 0;
    }
    l->suites[l->count++] = suite;
    return 0;
}

bool sl_cipher_list_has(const sl_cipher_list_t *l, uint16_t suite) {
    if (!l) return false;
    for (uint8_t i = 0; i < l->count; ++i) {
        if (l->suites[i] == suite) return true;
    }
    return false;
}

int sl_cipher_list_encode(const sl_cipher_list_t *l,
                          uint8_t *out, size_t out_cap) {
    if (!l || !out) return -1;
    const size_t need = (size_t)1 + (size_t)l->count * 2;
    if (out_cap < need) return -1;
    out[0] = l->count;
    for (uint8_t i = 0; i < l->count; ++i) {
        out[1 + 2 * i]     = (uint8_t)(l->suites[i] >> 8);
        out[1 + 2 * i + 1] = (uint8_t)(l->suites[i] & 0xFF);
    }
    return (int)need;
}

int sl_cipher_list_decode(const uint8_t *in, size_t in_len,
                          sl_cipher_list_t *out) {
    if (!in || !out || in_len < 1) return -1;
    sl_cipher_list_init(out);
    const uint8_t count = in[0];
    if (count > SL_CIPHER_LIST_MAX) return -1;
    if (in_len < (size_t)1 + (size_t)count * 2) return -1;
    for (uint8_t i = 0; i < count; ++i) {
        const uint16_t s = ((uint16_t)in[1 + 2 * i] << 8) |
                            (uint16_t)in[1 + 2 * i + 1];
        sl_cipher_list_add(out, s);
    }
    return 0;
}

uint16_t sl_cipher_choose(const sl_cipher_list_t *server_pref,
                          const sl_cipher_list_t *client_offered) {
    if (!server_pref || !client_offered) return 0;
    for (uint8_t i = 0; i < server_pref->count; ++i) {
        const uint16_t s = server_pref->suites[i];
        if (sl_cipher_list_has(client_offered, s) && sl_cipher_is_supported(s)) {
            return s;
        }
    }
    return 0;
}

const char *sl_cipher_name(uint16_t suite) {
    switch (suite) {
        case SL_CIPHER_AES256_GCM_SHA256: return "AES256-GCM-SHA256";
        case SL_CIPHER_CHACHA20_POLY1305: return "CHACHA20-POLY1305";
        default:                          return "unknown";
    }
}

bool sl_cipher_is_supported(uint16_t suite) {
    /* AES256-GCM is the only one implemented today. */
    return suite == SL_CIPHER_AES256_GCM_SHA256;
}
