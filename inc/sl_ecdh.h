#ifndef SECURELINK_SL_ECDH_H
#define SECURELINK_SL_ECDH_H

/* Ephemeral ECDH key agreement over NIST P-256.
 *
 * Workflow:
 *   1. Each side calls sl_ecdh_keypair_new() to generate an ephemeral key.
 *   2. Each side serializes its public key with sl_ecdh_export_pubkey()
 *      and sends it to the peer.
 *   3. On receiving the peer's pubkey, call sl_ecdh_compute_shared() to
 *      derive a 32-byte shared secret.
 *   4. Always free the local keypair with sl_ecdh_keypair_free() — this
 *      securely zeroes the private scalar before releasing memory.
 *
 * The shared secret is the X-coordinate of the ECDH point in big-endian.
 * It MUST be passed through HKDF (sl_hkdf) before use — never used as a
 * key directly. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_ECDH_PUBKEY_LEN  65   /* uncompressed: 0x04 || X(32) || Y(32) */
#define SL_ECDH_SHARED_LEN  32

typedef struct sl_ecdh_keypair sl_ecdh_keypair_t;

sl_ecdh_keypair_t *sl_ecdh_keypair_new(void);
void               sl_ecdh_keypair_free(sl_ecdh_keypair_t *kp);

int sl_ecdh_export_pubkey(const sl_ecdh_keypair_t *kp,
                          uint8_t out[SL_ECDH_PUBKEY_LEN]);

/* Validate that `pub` lies on the P-256 curve and is not the point at
 * infinity. Returns 0 if the key is well-formed. */
int sl_ecdh_validate_pubkey(const uint8_t pub[SL_ECDH_PUBKEY_LEN]);

/* Compute the shared secret. Caller must check return value before use. */
int sl_ecdh_compute_shared(const sl_ecdh_keypair_t *kp,
                           const uint8_t peer_pub[SL_ECDH_PUBKEY_LEN],
                           uint8_t out[SL_ECDH_SHARED_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_ECDH_H */
