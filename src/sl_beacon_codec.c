#include "sl_beacon_codec.h"

#include <string.h>

#include "sl_mem.h"
#include "sl_nonce.h"

size_t sl_beacon_wire_size(const sl_beacon_t *b) {
    if (b == NULL) return 0;
    return (size_t)SL_BEACON_HEADER_LEN + (size_t)b->payload_len + SL_AEAD_TAG_LEN;
}

int sl_beacon_seal(const sl_beacon_t *b,
                   const uint8_t      key[SL_AEAD_KEY_LEN],
                   const uint8_t      static_iv[SL_AEAD_IV_LEN],
                   uint64_t           seq,
                   uint8_t           *wire_out,
                   size_t            *wire_len_out) {
    if (b == NULL || key == NULL || static_iv == NULL ||
        wire_out == NULL || wire_len_out == NULL) {
        return -1;
    }
    if (sl_beacon_validate(b) != 0) return -1;

    /* 1. Header at offset 0 (also AAD). */
    if (sl_beacon_pack_header(b, wire_out) != 0) return -1;
    const uint8_t *aad = wire_out;
    const size_t   aad_len = SL_BEACON_HEADER_LEN;

    /* 2. Derive per-record nonce. */
    uint8_t nonce[SL_AEAD_IV_LEN];
    sl_nonce_build(static_iv, seq, nonce);

    /* 3. Encrypt payload in-place into wire_out after header. */
    uint8_t *ct  = wire_out + SL_BEACON_HEADER_LEN;
    uint8_t *tag = ct + b->payload_len;

    if (sl_aead_seal(key, nonce,
                     aad, aad_len,
                     b->payload, b->payload_len,
                     ct, tag) != 0) {
        sl_secure_zero(nonce, sizeof(nonce));
        return -1;
    }

    *wire_len_out = sl_beacon_wire_size(b);
    sl_secure_zero(nonce, sizeof(nonce));
    return 0;
}

int sl_beacon_open(const uint8_t *wire, size_t wire_len,
                   const uint8_t  key[SL_AEAD_KEY_LEN],
                   const uint8_t  static_iv[SL_AEAD_IV_LEN],
                   uint64_t       seq,
                   sl_beacon_t   *b) {
    if (wire == NULL || key == NULL || static_iv == NULL || b == NULL) {
        return -1;
    }
    if (wire_len < (size_t)SL_BEACON_HEADER_LEN + SL_AEAD_TAG_LEN) {
        return -1;
    }

    if (sl_beacon_unpack_header(wire, b) != 0) return -1;
    if (sl_beacon_validate(b) != 0) return -1;

    const size_t expected = sl_beacon_wire_size(b);
    if (wire_len != expected) return -1;

    const uint8_t *aad = wire;
    const size_t   aad_len = SL_BEACON_HEADER_LEN;
    const uint8_t *ct  = wire + SL_BEACON_HEADER_LEN;
    const uint8_t *tag = ct + b->payload_len;

    uint8_t nonce[SL_AEAD_IV_LEN];
    sl_nonce_build(static_iv, seq, nonce);

    int rc = sl_aead_open(key, nonce,
                          aad, aad_len,
                          ct, b->payload_len,
                          tag, b->payload);
    sl_secure_zero(nonce, sizeof(nonce));
    if (rc != 0) {
        /* Scrub any partial payload. */
        memset(b->payload, 0, sizeof(b->payload));
        return -1;
    }
    return 0;
}
