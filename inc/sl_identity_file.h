#ifndef SECURELINK_SL_IDENTITY_FILE_H
#define SECURELINK_SL_IDENTITY_FILE_H

/* Persistent on-disk Ed25519 identity.
 *
 * File format (binary):
 *
 *   magic[4]  = "SLID"
 *   version   = u32 BE (1)
 *   priv      = 32 bytes
 *   pub       = 32 bytes
 *   crc       = u32 BE (CRC-32C over the above)
 *
 * The file is written atomically with mode 0600. */

#include <stdint.h>

#include "sl_ed25519.h"

#ifdef __cplusplus
extern "C" {
#endif

int sl_identity_file_save(const char *path,
                          const uint8_t priv[SL_ED25519_PRIVKEY_LEN],
                          const uint8_t pub [SL_ED25519_PUBKEY_LEN]);

int sl_identity_file_load(const char *path,
                          uint8_t priv[SL_ED25519_PRIVKEY_LEN],
                          uint8_t pub [SL_ED25519_PUBKEY_LEN]);

/* Generate a new identity if `path` does not exist, otherwise load it.
 * Returns 0 on success. On generation, sets *was_created to 1. */
int sl_identity_file_load_or_create(const char *path,
                                    uint8_t priv[SL_ED25519_PRIVKEY_LEN],
                                    uint8_t pub [SL_ED25519_PUBKEY_LEN],
                                    int *was_created);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_IDENTITY_FILE_H */
