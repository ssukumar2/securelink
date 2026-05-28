#include "sl_record.h"

#include <string.h>

#include "sl_mem.h"
#include "sl_nonce.h"

static void pack_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint16_t unpack_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

int sl_record_peek_len(const uint8_t header[SL_RECORD_HEADER_LEN]) {
    if (!header) return -1;
    const uint16_t ver = unpack_u16(header + 1);
    if (ver != SL_RECORD_VERSION) return -1;
    const uint16_t ct_len = unpack_u16(header + 3);
    if (ct_len < SL_AEAD_TAG_LEN || ct_len > SL_RECORD_MAX_CIPHERTEXT) return -1;
    return (int)SL_RECORD_HEADER_LEN + (int)ct_len;
}

int sl_record_seal(sl_record_type_t type,
                   const uint8_t key[SL_AEAD_KEY_LEN],
                   const uint8_t static_iv[SL_AEAD_IV_LEN],
                   uint64_t seq,
                   const uint8_t *pt, size_t pt_len,
                   uint8_t *out, size_t out_cap) {
    if (!key || !static_iv || !out) return -1;
    if (pt_len > SL_RECORD_MAX_PLAINTEXT) return -1;
    const size_t need = SL_RECORD_HEADER_LEN + pt_len + SL_AEAD_TAG_LEN;
    if (out_cap < need) return -1;

    /* Header */
    out[0] = (uint8_t)type;
    pack_u16(out + 1, SL_RECORD_VERSION);
    pack_u16(out + 3, (uint16_t)(pt_len + SL_AEAD_TAG_LEN));

    uint8_t nonce[SL_AEAD_IV_LEN];
    sl_nonce_build(static_iv, seq, nonce);

    uint8_t *ct  = out + SL_RECORD_HEADER_LEN;
    uint8_t *tag = ct + pt_len;

    int rc = sl_aead_seal(key, nonce,
                          out, SL_RECORD_HEADER_LEN,
                          pt, pt_len,
                          ct, tag);
    sl_secure_zero(nonce, sizeof(nonce));
    return (rc == 0) ? (int)need : -1;
}

int sl_record_open(const uint8_t *wire, size_t wire_len,
                   const uint8_t key[SL_AEAD_KEY_LEN],
                   const uint8_t static_iv[SL_AEAD_IV_LEN],
                   uint64_t seq,
                   sl_record_type_t *type_out,
                   uint8_t *pt_out, size_t pt_cap, size_t *pt_len_out) {
    if (!wire || !key || !static_iv || !type_out || !pt_len_out) return -1;
    if (wire_len < SL_RECORD_HEADER_LEN + SL_AEAD_TAG_LEN) return -1;

    const int expected = sl_record_peek_len(wire);
    if (expected < 0 || (size_t)expected != wire_len) return -1;

    const uint16_t ct_len = unpack_u16(wire + 3);
    const size_t pt_len = (size_t)ct_len - SL_AEAD_TAG_LEN;
    if (pt_cap < pt_len) return -1;

    uint8_t nonce[SL_AEAD_IV_LEN];
    sl_nonce_build(static_iv, seq, nonce);

    const uint8_t *ct  = wire + SL_RECORD_HEADER_LEN;
    const uint8_t *tag = ct + pt_len;

    int rc = sl_aead_open(key, nonce,
                          wire, SL_RECORD_HEADER_LEN,
                          ct, pt_len,
                          tag, pt_out);
    sl_secure_zero(nonce, sizeof(nonce));
    if (rc != 0) {
        if (pt_len > 0) memset(pt_out, 0, pt_len);
        return -1;
    }
    *type_out   = (sl_record_type_t)wire[0];
    *pt_len_out = pt_len;
    return 0;
}
