#ifndef SECURELINK_SL_HANDSHAKE_SECRET_H
#define SECURELINK_SL_HANDSHAKE_SECRET_H

/* Handshake secret schedule.
 *
 * Inputs:  raw ECDH shared secret, current transcript hash
 * Outputs: master_secret, finished keys (per direction), session keys+IVs
 *
 * All derivations use HKDF-SHA256 with disjoint labels for domain
 * separation (see sl_kdf_labels.h for the v1 namespace). */

#include <stddef.h>
#include <stdint.h>

#include "sl_aead.h"
#include "sl_finished.h"
#include "sl_session_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SL_HS_MASTER_LEN 32

typedef struct {
    uint8_t master[SL_HS_MASTER_LEN];
    uint8_t client_finished_key[SL_FINISHED_LEN];
    uint8_t server_finished_key[SL_FINISHED_LEN];
    sl_session_keys_t app_keys;
} sl_handshake_secret_t;

int  sl_handshake_secret_derive(const uint8_t *ecdh_shared, size_t shared_len,
                                const uint8_t  transcript[32],
                                sl_handshake_secret_t *out);

void sl_handshake_secret_clear(sl_handshake_secret_t *s);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_HANDSHAKE_SECRET_H */
