#include "sl_ed25519.h"

#include <openssl/evp.h>
#include <string.h>

#include "sl_mem.h"

int sl_ed25519_keypair_new(uint8_t priv[SL_ED25519_PRIVKEY_LEN],
                           uint8_t pub [SL_ED25519_PUBKEY_LEN]) {
    if (!priv || !pub) return -1;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) return -1;

    int rc = -1;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto out;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto out;

    size_t plen = SL_ED25519_PRIVKEY_LEN;
    if (EVP_PKEY_get_raw_private_key(pkey, priv, &plen) <= 0) goto out;
    if (plen != SL_ED25519_PRIVKEY_LEN) goto out;

    size_t pulen = SL_ED25519_PUBKEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pulen) <= 0) goto out;
    if (pulen != SL_ED25519_PUBKEY_LEN) goto out;
    rc = 0;

out:
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx)  EVP_PKEY_CTX_free(ctx);
    return rc;
}

int sl_ed25519_derive_pub(const uint8_t priv[SL_ED25519_PRIVKEY_LEN],
                          uint8_t pub[SL_ED25519_PUBKEY_LEN]) {
    if (!priv || !pub) return -1;
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL, priv, SL_ED25519_PRIVKEY_LEN);
    if (!pkey) return -1;
    size_t pulen = SL_ED25519_PUBKEY_LEN;
    int rc = (EVP_PKEY_get_raw_public_key(pkey, pub, &pulen) > 0 &&
              pulen == SL_ED25519_PUBKEY_LEN) ? 0 : -1;
    EVP_PKEY_free(pkey);
    return rc;
}

int sl_ed25519_sign(const uint8_t priv[SL_ED25519_PRIVKEY_LEN],
                    const uint8_t *msg, size_t msg_len,
                    uint8_t sig[SL_ED25519_SIG_LEN]) {
    if (!priv || !sig || (!msg && msg_len > 0)) return -1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL, priv, SL_ED25519_PRIVKEY_LEN);
    if (!pkey) return -1;

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int rc = -1;
    if (!md) goto out;
    if (EVP_DigestSignInit(md, NULL, NULL, NULL, pkey) <= 0) goto out;
    size_t slen = SL_ED25519_SIG_LEN;
    if (EVP_DigestSign(md, sig, &slen, msg, msg_len) <= 0) goto out;
    if (slen != SL_ED25519_SIG_LEN) goto out;
    rc = 0;
out:
    if (md)   EVP_MD_CTX_free(md);
    EVP_PKEY_free(pkey);
    return rc;
}

int sl_ed25519_verify(const uint8_t pub[SL_ED25519_PUBKEY_LEN],
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t sig[SL_ED25519_SIG_LEN]) {
    if (!pub || !sig || (!msg && msg_len > 0)) return -1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, NULL, pub, SL_ED25519_PUBKEY_LEN);
    if (!pkey) return -1;

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int rc = -1;
    if (!md) goto out;
    if (EVP_DigestVerifyInit(md, NULL, NULL, NULL, pkey) <= 0) goto out;
    int v = EVP_DigestVerify(md, sig, SL_ED25519_SIG_LEN, msg, msg_len);
    rc = (v == 1) ? 0 : -1;
out:
    if (md) EVP_MD_CTX_free(md);
    EVP_PKEY_free(pkey);
    return rc;
}
