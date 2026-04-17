#include "crypto_engine.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>

struct ecc_keypair 
{
    EVP_PKEY* pkey;
};

ecc_keypair_t* ecc_keypair_create(void) 
{
    ecc_keypair_t* kp = calloc(1, sizeof(ecc_keypair_t));
    if (!kp) return NULL;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) { free(kp); return NULL; }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        free(kp);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) 
    {
        EVP_PKEY_CTX_free(ctx);
        free(kp);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &kp->pkey) <= 0) 
    {
        EVP_PKEY_CTX_free(ctx);
        free(kp);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return kp;
}

void ecc_keypair_free(ecc_keypair_t* kp) 
{
    if (kp) 
    {
        if (kp->pkey) EVP_PKEY_free(kp->pkey);
        free(kp);
    }
}

