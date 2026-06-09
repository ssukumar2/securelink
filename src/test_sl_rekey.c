/* Tests for sl_rekey.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_rekey.c src/sl_rekey.c src/sl_session_keys.c \
 *       src/sl_hkdf.c src/sl_mem.c \
 *       -lcrypto -o test_sl_rekey
 */

#include <stdio.h>
#include <string.h>

#include "sl_rekey.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_advance_produces_new_secret_and_keys(void) {
    sl_session_keys_t keys;
    uint8_t secret[32];
    for (int i = 0; i < 32; ++i) secret[i] = (uint8_t)(i + 1);

    /* Seed initial keys from `secret`. */
    CHECK(sl_session_keys_derive(secret, 32, secret, &keys) == 0);

    uint8_t old_c2s[32];
    memcpy(old_c2s, keys.c2s_key, 32);

    uint8_t before[32]; memcpy(before, secret, 32);
    uint8_t after[32];
    CHECK(sl_rekey_advance(&keys, secret, after) == 0);

    /* New secret must differ from old. */
    CHECK(memcmp(before, after, 32) != 0);
    /* Old secret buffer must have been zeroed. */
    uint8_t zero[32] = {0};
    CHECK(memcmp(secret, zero, 32) == 0);
    /* Keys must have changed. */
    CHECK(memcmp(keys.c2s_key, old_c2s, 32) != 0);
    return 0;
}

static int test_epoch_check_accepts_monotonic(void) {
    sl_rekey_epochs_t e = {0, 0};
    CHECK(sl_rekey_check_peer_epoch(&e, 1) == 0);
    CHECK(sl_rekey_check_peer_epoch(&e, 2) == 0);
    CHECK(sl_rekey_check_peer_epoch(&e, 3) == 0);
    return 0;
}

static int test_epoch_check_rejects_skips_and_replays(void) {
    sl_rekey_epochs_t e = {0, 0};
    sl_rekey_check_peer_epoch(&e, 1);
    /* Repeat of same epoch -> reject. */
    CHECK(sl_rekey_check_peer_epoch(&e, 1) != 0);
    /* Skipping ahead -> reject. */
    CHECK(sl_rekey_check_peer_epoch(&e, 5) != 0);
    /* Continue normally. */
    CHECK(sl_rekey_check_peer_epoch(&e, 2) == 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_advance_produces_new_secret_and_keys();
    rc |= test_epoch_check_accepts_monotonic();
    rc |= test_epoch_check_rejects_skips_and_replays();
    if (rc == 0) puts("test_sl_rekey: OK");
    return rc;
}
