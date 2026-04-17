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


ecc_keypair_t* ecc_keypair_create(void);


void ecc_keypair_free(ecc_keypair_t* kp);



#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_CRYPTO_ENGINE_H */