#ifndef SECURELINK_SL_BEACON_CODEC_H
#define SECURELINK_SL_BEACON_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "sl_aead.h"
#include "sl_beacon.h"

#ifdef __cplusplus
extern "C" {
#endif

/* On-wire layout produced by sl_beacon_seal:
 *
 *   [32-byte header (AAD)] [payload_len bytes ciphertext] [16-byte tag]
 *
 * Total wire size = SL_BEACON_HEADER_LEN + b->payload_len + SL_AEAD_TAG_LEN.
 *
 * The header doubles as AAD: tampering with client_id / sequence / timestamp
 * fails authentication. The payload is encrypted to keep metadata private.
 */

/* Returns wire size that sl_beacon_seal would produce for `b`. */
size_t sl_beacon_wire_size(const sl_beacon_t *b);

/* Seal a beacon into `wire_out`. Caller-supplied buffer must be at least
 * sl_beacon_wire_size(b) bytes. `static_iv` (12 bytes) and `seq` are
 * combined into the per-record AEAD nonce. Returns 0 on success. */
int sl_beacon_seal(const sl_beacon_t *b,
                   const uint8_t      key[SL_AEAD_KEY_LEN],
                   const uint8_t      static_iv[SL_AEAD_IV_LEN],
                   uint64_t           seq,
                   uint8_t           *wire_out,
                   size_t            *wire_len_out);

/* Parse and authenticate a wire-format beacon. On success, fills `b`
 * (including decrypted payload). Returns 0 on success, -1 on any failure
 * including tag mismatch. */
int sl_beacon_open(const uint8_t *wire, size_t wire_len,
                   const uint8_t  key[SL_AEAD_KEY_LEN],
                   const uint8_t  static_iv[SL_AEAD_IV_LEN],
                   uint64_t       seq,
                   sl_beacon_t   *b);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_BEACON_CODEC_H */
