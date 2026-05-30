#include "sl_handshake_secret.h"

#include <string.h>

#include "sl_hkdf.h"
#include "sl_kdf_labels.h"
#include "sl_mem.h"

#define LABEL_MASTER          "securelink v1 master"
#define LABEL_CLIENT_FINISHED "securelink v1 c2s finished"
#define LABEL_SERVER_FINISHED "securelink v1 s2c finished"

int sl_handshake_secret_derive(const uint8_t *ecdh_shared, size_t shared_len,
                               const uint8_t  transcript[32],
                               sl_handshake_secret_t *out) {
    if (!ecdh_shared || !transcript || !out) return -1;
    memset(out, 0, sizeof(*out));

    /* 1. master = HKDF(ecdh, salt=transcript, info="master") */
    if (sl_hkdf_sha256(ecdh_shared, shared_len,
                       transcript, 32,
                       (const uint8_t *)LABEL_MASTER, strlen(LABEL_MASTER),
                       out->master, SL_HS_MASTER_LEN) != 0) goto fail;

    /* 2. finished keys from master */
    if (sl_hkdf_sha256(out->master, SL_HS_MASTER_LEN,
                       NULL, 0,
                       (const uint8_t *)LABEL_CLIENT_FINISHED,
                       strlen(LABEL_CLIENT_FINISHED),
                       out->client_finished_key, SL_FINISHED_LEN) != 0) goto fail;

    if (sl_hkdf_sha256(out->master, SL_HS_MASTER_LEN,
                       NULL, 0,
                       (const uint8_t *)LABEL_SERVER_FINISHED,
                       strlen(LABEL_SERVER_FINISHED),
                       out->server_finished_key, SL_FINISHED_LEN) != 0) goto fail;

    /* 3. application traffic keys (delegated to sl_session_keys) */
    if (sl_session_keys_derive(out->master, SL_HS_MASTER_LEN,
                               transcript, &out->app_keys) != 0) goto fail;
    return 0;

fail:
    sl_handshake_secret_clear(out);
    return -1;
}

void sl_handshake_secret_clear(sl_handshake_secret_t *s) {
    if (!s) return;
    sl_session_keys_clear(&s->app_keys);
    sl_secure_zero(s, sizeof(*s));
}
