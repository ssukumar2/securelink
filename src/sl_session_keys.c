#include "sl_session_keys.h"

#include <string.h>

#include "sl_hkdf.h"
#include "sl_kdf_labels.h"
#include "sl_mem.h"

int sl_session_keys_derive(const uint8_t *master, size_t master_len,
                           const uint8_t  salt[32],
                           sl_session_keys_t *out) {
    if (!master || !salt || !out) return -1;
    memset(out, 0, sizeof(*out));

    if (sl_hkdf_sha256(master, master_len, salt, 32,
                       (const uint8_t *)SL_KDF_LABEL_CLIENT_KEY,
                       SL_KDF_LABEL_LEN(SL_KDF_LABEL_CLIENT_KEY),
                       out->client_key, SL_AEAD_KEY_LEN) != 0) goto fail;

    if (sl_hkdf_sha256(master, master_len, salt, 32,
                       (const uint8_t *)SL_KDF_LABEL_CLIENT_IV,
                       SL_KDF_LABEL_LEN(SL_KDF_LABEL_CLIENT_IV),
                       out->client_iv, SL_AEAD_IV_LEN) != 0) goto fail;

    if (sl_hkdf_sha256(master, master_len, salt, 32,
                       (const uint8_t *)SL_KDF_LABEL_SERVER_KEY,
                       SL_KDF_LABEL_LEN(SL_KDF_LABEL_SERVER_KEY),
                       out->server_key, SL_AEAD_KEY_LEN) != 0) goto fail;

    if (sl_hkdf_sha256(master, master_len, salt, 32,
                       (const uint8_t *)SL_KDF_LABEL_SERVER_IV,
                       SL_KDF_LABEL_LEN(SL_KDF_LABEL_SERVER_IV),
                       out->server_iv, SL_AEAD_IV_LEN) != 0) goto fail;

    return 0;

fail:
    sl_session_keys_clear(out);
    return -1;
}

void sl_session_keys_clear(sl_session_keys_t *keys) {
    if (!keys) return;
    sl_secure_zero(keys, sizeof(*keys));
}
