#include "sl_finished.h"

#include <openssl/hmac.h>
#include <string.h>

#include "sl_hkdf.h"
#include "sl_mem.h"

#define LABEL_CLIENT "securelink v1 c2s finished"
#define LABEL_SERVER "securelink v1 s2c finished"

int sl_finished_derive_key(const uint8_t *handshake_secret, size_t hs_len,
                           int is_server,
                           uint8_t out_key[SL_FINISHED_LEN]) {
    if (!handshake_secret || !out_key || hs_len == 0) return -1;

    const char *label = is_server ? LABEL_SERVER : LABEL_CLIENT;
    return sl_hkdf_sha256(handshake_secret, hs_len,
                          NULL, 0,
                          (const uint8_t *)label, strlen(label),
                          out_key, SL_FINISHED_LEN);
}

int sl_finished_compute(const uint8_t finished_key[SL_FINISHED_LEN],
                        const uint8_t transcript_hash[32],
                        uint8_t out_mac[SL_FINISHED_LEN]) {
    if (!finished_key || !transcript_hash || !out_mac) return -1;
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha256(),
              finished_key, SL_FINISHED_LEN,
              transcript_hash, 32,
              out_mac, &out_len)) return -1;
    return (out_len == SL_FINISHED_LEN) ? 0 : -1;
}

int sl_finished_verify(const uint8_t finished_key[SL_FINISHED_LEN],
                       const uint8_t transcript_hash[32],
                       const uint8_t received_mac[SL_FINISHED_LEN]) {
    uint8_t expected[SL_FINISHED_LEN];
    if (sl_finished_compute(finished_key, transcript_hash, expected) != 0) {
        return -1;
    }
    int eq = sl_ct_equal(expected, received_mac, SL_FINISHED_LEN);
    sl_secure_zero(expected, sizeof(expected));
    return eq ? 0 : -1;
}
