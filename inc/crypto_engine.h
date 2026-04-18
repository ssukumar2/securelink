#ifndef SECURELINK_CRYPTO_ENGINE_H
#define SECURELINK_CRYPTO_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ECC key pair handle. Opaque pointer — internal structure hidden.
 */
typedef struct ecc_keypair ecc_keypair_t;

/**
 * Generate a new ECC key pair on secp256r1.
 * Returns NULL on failure. Caller must free with ecc_keypair_free().
 */
ecc_keypair_t* ecc_keypair_create(void);

/**
 * Free a key pair.
 */
void ecc_keypair_free(ecc_keypair_t* kp);

/**
 * Get the raw public key (64 bytes: x || y, no 0x04 prefix).
 * out_buf must be at least 64 bytes.
 * Returns 0 on success, -1 on failure.
 */
int ecc_get_public_key(const ecc_keypair_t* kp, uint8_t* out_buf, size_t buf_len);

/**
 * Derive ECDH shared secret from our key pair and peer's raw public key.
 * peer_pub must be 64 bytes (x || y).
 * out_secret must be at least 32 bytes.
 * Returns the number of secret bytes written, or -1 on failure.
 */
int ecc_derive_shared_secret(const ecc_keypair_t* kp,
                             const uint8_t* peer_pub, size_t peer_pub_len,
                             uint8_t* out_secret, size_t secret_buf_len);



#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_CRYPTO_ENGINE_H */
