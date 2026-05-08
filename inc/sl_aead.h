#ifndef SECURELINK_SL_AEAD_H
#define SECURELINK_SL_AEAD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_AEAD_KEY_LEN  32   /* AES-256 */
#define SL_AEAD_IV_LEN   12   /* GCM standard nonce */
#define SL_AEAD_TAG_LEN  16   /* GCM tag */

/* AES-256-GCM seal.
 *   key  : 32-byte symmetric key
 *   iv   : 12-byte nonce, MUST be unique per (key, message)
 *   aad  : optional additional authenticated data
 *   pt   : plaintext input
 *   ct   : ciphertext output buffer (must be at least pt_len bytes)
 *   tag  : 16-byte authentication tag output
 * Returns 0 on success, -1 on failure. */
int sl_aead_seal(const uint8_t  key[SL_AEAD_KEY_LEN],
                 const uint8_t  iv[SL_AEAD_IV_LEN],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *pt,  size_t pt_len,
                 uint8_t       *ct,
                 uint8_t        tag[SL_AEAD_TAG_LEN]);

/* AES-256-GCM open.
 *   ct, ct_len : ciphertext input
 *   tag        : 16-byte tag to verify
 *   pt         : plaintext output (must be at least ct_len bytes)
 * Returns 0 on success and ciphertext is authentic.
 * Returns -1 on tag mismatch or any failure; pt content unspecified. */
int sl_aead_open(const uint8_t  key[SL_AEAD_KEY_LEN],
                 const uint8_t  iv[SL_AEAD_IV_LEN],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ct,  size_t ct_len,
                 const uint8_t  tag[SL_AEAD_TAG_LEN],
                 uint8_t       *pt);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_AEAD_H */
