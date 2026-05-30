/* Tests for sl_ecdh.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_ecdh.c src/sl_ecdh.c src/sl_mem.c \
 *       -lcrypto -o test_sl_ecdh
 */

#include <stdio.h>
#include <string.h>

#include "sl_ecdh.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_keypair_export(void) {
    sl_ecdh_keypair_t *kp = sl_ecdh_keypair_new();
    CHECK(kp != NULL);
    uint8_t pub[SL_ECDH_PUBKEY_LEN];
    CHECK(sl_ecdh_export_pubkey(kp, pub) == 0);
    CHECK(pub[0] == 0x04);
    CHECK(sl_ecdh_validate_pubkey(pub) == 0);
    sl_ecdh_keypair_free(kp);
    return 0;
}

static int test_shared_secret_agreement(void) {
    sl_ecdh_keypair_t *a = sl_ecdh_keypair_new();
    sl_ecdh_keypair_t *b = sl_ecdh_keypair_new();
    CHECK(a && b);

    uint8_t pa[SL_ECDH_PUBKEY_LEN], pb[SL_ECDH_PUBKEY_LEN];
    CHECK(sl_ecdh_export_pubkey(a, pa) == 0);
    CHECK(sl_ecdh_export_pubkey(b, pb) == 0);

    uint8_t sa[SL_ECDH_SHARED_LEN], sb[SL_ECDH_SHARED_LEN];
    CHECK(sl_ecdh_compute_shared(a, pb, sa) == 0);
    CHECK(sl_ecdh_compute_shared(b, pa, sb) == 0);
    CHECK(memcmp(sa, sb, SL_ECDH_SHARED_LEN) == 0);

    sl_ecdh_keypair_free(a);
    sl_ecdh_keypair_free(b);
    return 0;
}

static int test_invalid_pubkey_rejected(void) {
    uint8_t bad[SL_ECDH_PUBKEY_LEN] = {0};
    bad[0] = 0x04;          /* claims uncompressed */
    /* All-zero X/Y is not on the curve. */
    CHECK(sl_ecdh_validate_pubkey(bad) != 0);

    /* Wrong leading byte. */
    bad[0] = 0x05;
    CHECK(sl_ecdh_validate_pubkey(bad) != 0);
    return 0;
}

static int test_keys_differ_per_session(void) {
    sl_ecdh_keypair_t *a = sl_ecdh_keypair_new();
    sl_ecdh_keypair_t *b = sl_ecdh_keypair_new();
    uint8_t pa[SL_ECDH_PUBKEY_LEN], pb[SL_ECDH_PUBKEY_LEN];
    sl_ecdh_export_pubkey(a, pa);
    sl_ecdh_export_pubkey(b, pb);
    CHECK(memcmp(pa, pb, SL_ECDH_PUBKEY_LEN) != 0);
    sl_ecdh_keypair_free(a);
    sl_ecdh_keypair_free(b);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_keypair_export();
    rc |= test_shared_secret_agreement();
    rc |= test_invalid_pubkey_rejected();
    rc |= test_keys_differ_per_session();
    if (rc == 0) puts("test_sl_ecdh: OK");
    return rc;
}
