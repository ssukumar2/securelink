#include "sl_rekey.h"

#include <string.h>

#include "sl_hkdf.h"
#include "sl_kdf_labels.h"
#include "sl_mem.h"

int sl_rekey_advance(sl_session_keys_t *keys,
                     uint8_t            current_secret[32],
                     uint8_t            next_secret_out[32]) {
    if (!keys || !current_secret || !next_secret_out) return -1;

    /* Derive the next traffic-secret. */
    if (sl_hkdf_sha256(current_secret, 32,
                       NULL, 0,
                       (const uint8_t *)SL_KDF_LABEL_REKEY,
                       SL_KDF_LABEL_LEN(SL_KDF_LABEL_REKEY),
                       next_secret_out, 32) != 0) return -1;

    /* Re-derive traffic keys from the new secret. We use the secret
     * itself as the salt for domain separation across rotations. */
    sl_session_keys_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    if (sl_session_keys_derive(next_secret_out, 32,
                               next_secret_out, &fresh) != 0) {
        sl_secure_zero(&fresh, sizeof(fresh));
        return -1;
    }

    sl_session_keys_clear(keys);
    memcpy(keys, &fresh, sizeof(*keys));
    sl_secure_zero(&fresh, sizeof(fresh));

    /* Caller is responsible for scrubbing the *old* secret; we hand
     * back the new one in `next_secret_out`. */
    sl_secure_zero(current_secret, 32);
    return 0;
}

int sl_rekey_check_peer_epoch(sl_rekey_epochs_t *e, uint32_t incoming) {
    if (!e) return -1;
    /* Monotonic strictly-increasing requirement: incoming must be
     * exactly peer_epoch+1. Skipping epochs would mean the attacker
     * tried to drop a key update record. */
    if (incoming != e->peer_epoch + 1) return -1;
    e->peer_epoch = incoming;
    return 0;
}
