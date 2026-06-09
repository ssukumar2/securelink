#include "sl_exporter.h"

#include <openssl/sha.h>
#include <string.h>

#include "sl_hkdf.h"
#include "sl_kdf_labels.h"
#include "sl_mem.h"

int sl_exporter_init(const uint8_t  master_secret[SL_EXPORTER_SECRET_LEN],
                     uint8_t        out[SL_EXPORTER_SECRET_LEN]) {
    if (!master_secret || !out) return -1;
    return sl_hkdf_sha256(master_secret, SL_EXPORTER_SECRET_LEN,
                          NULL, 0,
                          (const uint8_t *)SL_KDF_LABEL_EXPORTER,
                          SL_KDF_LABEL_LEN(SL_KDF_LABEL_EXPORTER),
                          out, SL_EXPORTER_SECRET_LEN);
}

int sl_exporter_derive(const uint8_t  exporter_secret[SL_EXPORTER_SECRET_LEN],
                       const char    *label,
                       const uint8_t *context, size_t context_len,
                       uint8_t       *out,     size_t out_len) {
    if (!exporter_secret || !label || !out) return -1;
    if (out_len == 0 || out_len > 255 * 32) return -1;

    /* Hash the label and optional context into a fixed-size info block.
     * This prevents collisions between (label, context) pairs that
     * concatenate ambiguously. */
    uint8_t info[SHA256_DIGEST_LENGTH];
    SHA256_CTX h;
    if (SHA256_Init(&h) != 1) return -1;
    SHA256_Update(&h, label, strlen(label));
    if (context && context_len > 0) {
        SHA256_Update(&h, context, context_len);
    }
    if (SHA256_Final(info, &h) != 1) return -1;

    int rc = sl_hkdf_sha256(exporter_secret, SL_EXPORTER_SECRET_LEN,
                            NULL, 0,
                            info, sizeof(info),
                            out, out_len);
    sl_secure_zero(info, sizeof(info));
    return rc;
}
