#ifndef SECURELINK_SL_SESSION_KEYS_H
#define SECURELINK_SL_SESSION_KEYS_H

/* Directional AES-256-GCM traffic keys derived from a handshake secret.
 *
 * This header was referenced (#include "sl_session_keys.h") by both
 * sl_handshake_secret.h and sl_rekey.h, and by their .c files calling
 * sl_session_keys_derive() / sl_session_keys_clear(), but the header
 * itself never existed anywhere in the repository -- meaning neither
 * of those two files could ever compile, and nothing that depends on
 * them (the full handshake secret schedule, in-session rekeying) was
 * ever actually buildable, let alone tested.
 *
 * The shape here follows directly from how the callers already use it:
 * a struct with client_key/client_iv/server_key/server_iv (matching the
 * SL_KDF_LABEL_CLIENT_KEY / SL_KDF_LABEL_SERVER_KEY / ..._IV labels
 * already defined in sl_kdf_labels.h, which were otherwise unused
 * anywhere in the codebase), one derive function taking a master
 * secret and a salt, and one clear function.
 */

#include <stddef.h>
#include <stdint.h>

#include "sl_aead.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t client_key[SL_AEAD_KEY_LEN];
    uint8_t client_iv [SL_AEAD_IV_LEN];
    uint8_t server_key[SL_AEAD_KEY_LEN];
    uint8_t server_iv [SL_AEAD_IV_LEN];
} sl_session_keys_t;

/* Derive both directions' traffic keys from `master` (the handshake
 * master secret, or the freshly-rotated secret during a rekey) and
 * `salt` (the transcript hash during the initial handshake; the new
 * secret itself during a rekey, per sl_rekey.c). Domain-separated by
 * direction via the four distinct KDF labels. Returns 0 on success. */
int sl_session_keys_derive(const uint8_t *master, size_t master_len,
                           const uint8_t  salt[32],
                           sl_session_keys_t *out);

/* Securely zero all key material. Safe to call on an already-cleared
 * or zero-initialized struct. */
void sl_session_keys_clear(sl_session_keys_t *keys);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_SESSION_KEYS_H */
