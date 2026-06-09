#ifndef SECURELINK_SL_REKEY_H
#define SECURELINK_SL_REKEY_H

/* In-session rekey: derive a fresh set of traffic keys from the existing
 * ones without going back through the full handshake.
 *
 * Triggered by a KeyUpdate record (sl_record SL_REC_KEY_UPDATE). The new
 * keys take effect immediately after the record that announces them,
 * which is why both sides MUST flush any pending plaintext first.
 *
 * Derivation:
 *   new_secret = HKDF-Expand(current_secret, "securelink v1 rekey")
 *   then the standard session-key labels off `new_secret`.
 *
 * The sequence number resets to 1 with the new keys to keep the
 * (key, nonce) space safely bounded across rotations. */

#include <stddef.h>
#include <stdint.h>

#include "sl_session_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Counter pair tracking how many rekeys each side has performed. The
 * application-level KeyUpdate record carries the counter so a stale
 * KeyUpdate replay can be rejected. */
typedef struct {
    uint32_t local_epoch;    /* how many times WE have rotated outbound */
    uint32_t peer_epoch;     /* how many times PEER has rotated outbound */
} sl_rekey_epochs_t;

/* Rotate the local outbound keys, returning the new traffic-secret in
 * `next_secret_out` so the caller can persist it if needed. */
int sl_rekey_advance(sl_session_keys_t *keys,
                     uint8_t            current_secret[32],
                     uint8_t            next_secret_out[32]);

/* Validate that a received KeyUpdate is monotonically newer than the
 * last one observed. Returns 0 if it should be accepted. */
int sl_rekey_check_peer_epoch(sl_rekey_epochs_t *e, uint32_t incoming);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_REKEY_H */
