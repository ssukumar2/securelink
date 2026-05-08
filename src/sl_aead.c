#include "sl_aead.h"

#include <openssl/evp.h>
#include <string.h>

#include "sl_mem.h"

int sl_aead_seal(const uint8_t  key[SL_AEAD_KEY_LEN],
                 const uint8_t  iv[SL_AEAD_IV_LEN],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *pt,  size_t pt_len,
                 uint8_t       *ct,
                 uint8_t        tag[SL_AEAD_TAG_LEN]) {
    if (key == NULL || iv == NULL || tag == NULL) return -1;
    if (pt_len > 0 && (pt == NULL || ct == NULL))  return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return -1;

    int rc  = -1;
    int len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SL_AEAD_IV_LEN, NULL) != 1) goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto out;

    if (aad_len > 0 && aad != NULL) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto out;
    }
    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) goto out;
    }
    if (EVP_EncryptFinal_ex(ctx, ct + (pt_len > 0 ? pt_len : 0), &len) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SL_AEAD_TAG_LEN, tag) != 1) goto out;

    rc = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int sl_aead_open(const uint8_t  key[SL_AEAD_KEY_LEN],
                 const uint8_t  iv[SL_AEAD_IV_LEN],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ct,  size_t ct_len,
                 const uint8_t  tag[SL_AEAD_TAG_LEN],
                 uint8_t       *pt) {
    if (key == NULL || iv == NULL || tag == NULL) return -1;
    if (ct_len > 0 && (ct == NULL || pt == NULL))  return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return -1;

    int rc  = -1;
    int len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SL_AEAD_IV_LEN, NULL) != 1) goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto out;

    if (aad_len > 0 && aad != NULL) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto out;
    }
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len) != 1) goto out;
    }
    /* Set expected tag before final. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SL_AEAD_TAG_LEN,
                            (void *)tag) != 1) goto out;

    int final_rc = EVP_DecryptFinal_ex(ctx, pt + (ct_len > 0 ? ct_len : 0), &len);
    if (final_rc <= 0) {
        /* Tag mismatch — scrub any plaintext we may have produced. */
        if (ct_len > 0) sl_secure_zero(pt, ct_len);
        goto out;
    }
    rc = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}
