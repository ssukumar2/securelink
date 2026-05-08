#include "sl_nonce.h"

#include <string.h>

void sl_nonce_build(const uint8_t iv[SL_AEAD_IV_LEN],
                    uint64_t      seq,
                    uint8_t       nonce_out[SL_AEAD_IV_LEN]) {
    /* Copy IV, then XOR seq into the trailing 8 bytes (big-endian). */
    memcpy(nonce_out, iv, SL_AEAD_IV_LEN);

    uint8_t seq_be[8];
    seq_be[0] = (uint8_t)(seq >> 56);
    seq_be[1] = (uint8_t)(seq >> 48);
    seq_be[2] = (uint8_t)(seq >> 40);
    seq_be[3] = (uint8_t)(seq >> 32);
    seq_be[4] = (uint8_t)(seq >> 24);
    seq_be[5] = (uint8_t)(seq >> 16);
    seq_be[6] = (uint8_t)(seq >>  8);
    seq_be[7] = (uint8_t)(seq);

    /* XOR into the last 8 bytes of the nonce (offset 4). */
    for (size_t i = 0; i < 8; ++i) {
        nonce_out[SL_AEAD_IV_LEN - 8 + i] ^= seq_be[i];
    }
}

int sl_nonce_next(const uint8_t iv[SL_AEAD_IV_LEN],
                  uint64_t     *seq_inout,
                  uint8_t       nonce_out[SL_AEAD_IV_LEN]) {
    if (seq_inout == NULL) return -1;

    /* Refuse to wrap back to 0; that would reuse the very first nonce. */
    if (*seq_inout == UINT64_MAX) {
        return -1;
    }
    sl_nonce_build(iv, *seq_inout, nonce_out);
    ++(*seq_inout);
    return 0;
}
