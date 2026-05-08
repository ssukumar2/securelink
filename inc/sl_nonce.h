#ifndef SECURELINK_SL_NONCE_H
#define SECURELINK_SL_NONCE_H

#include <stddef.h>
#include <stdint.h>

#include "sl_aead.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Build a per-record GCM nonce from a static 12-byte session IV and a
 * monotonically increasing 64-bit sequence number, following the
 * construction in RFC 8446 §5.3:
 *
 *   nonce = iv XOR pad8(seq)
 *
 * where pad8(seq) is the seq packed big-endian into the low 8 bytes
 * with the high 4 bytes zero.
 *
 * This keeps the nonce unique across the session as long as `seq`
 * is unique. Caller must enforce that. */
void sl_nonce_build(const uint8_t iv[SL_AEAD_IV_LEN],
                    uint64_t      seq,
                    uint8_t       nonce_out[SL_AEAD_IV_LEN]);

/* Convenience wrapper: increments `*seq_inout` by 1 after building.
 * Returns 0 on success, -1 if `*seq_inout` would overflow back to 0. */
int  sl_nonce_next(const uint8_t iv[SL_AEAD_IV_LEN],
                   uint64_t     *seq_inout,
                   uint8_t       nonce_out[SL_AEAD_IV_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_NONCE_H */
