#include "sl_beacon_ack_codec.h"

#include <string.h>

#include "sl_mem.h"
#include "sl_nonce.h"

int sl_beacon_ack_seal(const sl_beacon_ack_t *a,
                       const uint8_t key[SL_AEAD_KEY_LEN],
                       const uint8_t static_iv[SL_AEAD_IV_LEN],
                       uint64_t seq,
                       uint8_t out[SL_BEACON_ACK_WIRE_LEN]) {
    if (a == NULL || key == NULL || static_iv == NULL || out == NULL) {
        return -1;
    }
    if (sl_beacon_ack_validate(a) != 0) return -1;

    if (sl_beacon_ack_pack(a, out) != 0) return -1;

    uint8_t nonce[SL_AEAD_IV_LEN];
    sl_nonce_build(static_iv, seq, nonce);

    uint8_t *tag = out + SL_BEACON_ACK_HEADER_LEN;
    int rc = sl_aead_seal(key, nonce,
                          out, SL_BEACON_ACK_HEADER_LEN,
                          NULL, 0,
                          NULL, tag);
    sl_secure_zero(nonce, sizeof(nonce));
    return rc;
}

int sl_beacon_ack_open(const uint8_t wire[SL_BEACON_ACK_WIRE_LEN],
                       const uint8_t key[SL_AEAD_KEY_LEN],
                       const uint8_t static_iv[SL_AEAD_IV_LEN],
                       uint64_t seq,
                       sl_beacon_ack_t *a) {
    if (wire == NULL || key == NULL || static_iv == NULL || a == NULL) {
        return -1;
    }
    if (sl_beacon_ack_unpack(wire, a) != 0) return -1;
    if (sl_beacon_ack_validate(a) != 0) return -1;

    const uint8_t *tag = wire + SL_BEACON_ACK_HEADER_LEN;
    uint8_t nonce[SL_AEAD_IV_LEN];
    sl_nonce_build(static_iv, seq, nonce);

    int rc = sl_aead_open(key, nonce,
                          wire, SL_BEACON_ACK_HEADER_LEN,
                          NULL, 0,
                          tag, NULL);
    sl_secure_zero(nonce, sizeof(nonce));
    if (rc != 0) {
        memset(a, 0, sizeof(*a));
        return -1;
    }
    return 0;
}
