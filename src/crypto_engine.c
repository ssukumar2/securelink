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

    if (!kp) 
        return NULL;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) 
    { 
        free(kp); 
        return NULL; 
    }

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
        if (kp->pkey) 
            EVP_PKEY_free(kp->pkey);

        free(kp);
    }
}

int ecc_get_public_key(const ecc_keypair_t* kp, uint8_t* out_buf, size_t buf_len) 
{
    if (!kp || !kp->pkey || buf_len < 64) 
        return -1;

    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(kp->pkey);

    if (!ec) 
        return -1;

    const EC_POINT* pub = EC_KEY_get0_public_key(ec);
    const EC_GROUP* group = EC_KEY_get0_group(ec);

    uint8_t uncompressed[65];
    size_t len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                                     uncompressed, sizeof(uncompressed), NULL);
    EC_KEY_free(ec);

    if (len != 65) 
        return -1;

    /* Skip the 0x04 prefix, copy 64 bytes of x || y */
    memcpy(out_buf, uncompressed + 1, 64);

    return 0;
}

int ecc_derive_shared_secret(const ecc_keypair_t* kp, const uint8_t* peer_pub, size_t peer_pub_len,
                             uint8_t* out_secret, size_t secret_buf_len) 
{
    if (!kp || !kp->pkey || peer_pub_len != 64 || secret_buf_len < 32) 
        return -1;

    /* Reconstruct peer public key with 0x04 prefix */
    uint8_t full_key[65];
    full_key[0] = 0x04;
    memcpy(full_key + 1, peer_pub, 64);

    EC_KEY* peer_ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!peer_ec) 
        return -1;

    const EC_GROUP* group = EC_KEY_get0_group(peer_ec);
    EC_POINT* peer_point = EC_POINT_new(group);

    if (!EC_POINT_oct2point(group, peer_point, full_key, sizeof(full_key), NULL)) 
    {
        EC_POINT_free(peer_point);
        EC_KEY_free(peer_ec);
        return -1;
    }

    EC_KEY_set_public_key(peer_ec, peer_point);

    EVP_PKEY* peer_pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(peer_pkey, peer_ec);

    /* ECDH derive */
    EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(kp->pkey, NULL);
    if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx) <= 0) 
    {
        EVP_PKEY_free(peer_pkey);
        EC_POINT_free(peer_point);
        return -1;
    }

    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pkey) <= 0) 
    {
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(peer_pkey);
        EC_POINT_free(peer_point);
        return -1;
    }

    size_t slen = 0;
    EVP_PKEY_derive(derive_ctx, NULL, &slen);

    uint8_t raw_secret[64];
    if (slen > sizeof(raw_secret)) slen = sizeof(raw_secret);
    EVP_PKEY_derive(derive_ctx, raw_secret, &slen);

    /* Copy up to 32 bytes for AES-256 key */
    size_t copy_len = slen < 32 ? slen : 32;
    memcpy(out_secret, raw_secret, copy_len);

    if (copy_len < 32) 
        memset(out_secret + copy_len, 0, 32 - copy_len);

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(peer_pkey);
    EC_POINT_free(peer_point);

    return 32;
}

