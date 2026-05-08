#include "sl_hkdf.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>

#include "sl_mem.h"

#define HKDF_HASH_LEN 32U  /* SHA-256 output size */

int sl_hkdf_extract_sha256(const uint8_t *ikm,  size_t ikm_len,
                           const uint8_t *salt, size_t salt_len,
                           uint8_t       prk_out[32]) {
    if (ikm == NULL || prk_out == NULL) return -1;

    static const uint8_t zero_salt[HKDF_HASH_LEN] = {0};
    if (salt == NULL || salt_len == 0) {
        salt     = zero_salt;
        salt_len = HKDF_HASH_LEN;
    }

    unsigned int out_len = 0;
    if (HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len,
             prk_out, &out_len) == NULL) {
        return -1;
    }
    if (out_len != HKDF_HASH_LEN) {
        return -1;
    }
    return 0;
}

int sl_hkdf_expand_sha256(const uint8_t prk[32],
                          const uint8_t *info, size_t info_len,
                          uint8_t       *out,  size_t out_len) {
    if (prk == NULL || out == NULL) return -1;
    if (out_len > 255U * HKDF_HASH_LEN) return -1;

    uint8_t  t[HKDF_HASH_LEN];
    size_t   t_len  = 0;
    size_t   done   = 0;
    uint8_t  ctr    = 1;
    int      rc     = -1;

    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL) return -1;

    while (done < out_len) {
        if (HMAC_Init_ex(ctx, prk, (int)HKDF_HASH_LEN, EVP_sha256(), NULL) != 1) {
            goto cleanup;
        }
        if (t_len > 0 && HMAC_Update(ctx, t, t_len) != 1) {
            goto cleanup;
        }
        if (info_len > 0 && info != NULL) {
            if (HMAC_Update(ctx, info, info_len) != 1) goto cleanup;
        }
        if (HMAC_Update(ctx, &ctr, 1) != 1) goto cleanup;

        unsigned int n = 0;
        if (HMAC_Final(ctx, t, &n) != 1) goto cleanup;
        t_len = n;

        const size_t take = (out_len - done < t_len) ? (out_len - done) : t_len;
        memcpy(out + done, t, take);
        done += take;
        ++ctr;
    }
    rc = 0;

cleanup:
    sl_secure_zero(t, sizeof(t));
    HMAC_CTX_free(ctx);
    return rc;
}

int sl_hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                   const uint8_t *salt, size_t salt_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t       *out,  size_t out_len) {
    uint8_t prk[HKDF_HASH_LEN];
    if (sl_hkdf_extract_sha256(ikm, ikm_len, salt, salt_len, prk) != 0) {
        sl_secure_zero(prk, sizeof(prk));
        return -1;
    }
    int rc = sl_hkdf_expand_sha256(prk, info, info_len, out, out_len);
    sl_secure_zero(prk, sizeof(prk));
    return rc;
}
