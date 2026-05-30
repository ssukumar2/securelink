/* Tests for sl_ed25519.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_ed25519.c src/sl_ed25519.c src/sl_mem.c \
 *       -lcrypto -o test_sl_ed25519
 */

#include <stdio.h>
#include <string.h>

#include "sl_ed25519.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_sign_verify_roundtrip(void) {
    uint8_t priv[SL_ED25519_PRIVKEY_LEN], pub[SL_ED25519_PUBKEY_LEN];
    CHECK(sl_ed25519_keypair_new(priv, pub) == 0);

    const uint8_t msg[] = "transcript-snapshot-bytes";
    uint8_t sig[SL_ED25519_SIG_LEN];
    CHECK(sl_ed25519_sign(priv, msg, sizeof(msg), sig) == 0);
    CHECK(sl_ed25519_verify(pub, msg, sizeof(msg), sig) == 0);
    return 0;
}

static int test_wrong_message_fails(void) {
    uint8_t priv[SL_ED25519_PRIVKEY_LEN], pub[SL_ED25519_PUBKEY_LEN];
    sl_ed25519_keypair_new(priv, pub);

    const uint8_t a[] = "alpha";
    const uint8_t b[] = "alphb";
    uint8_t sig[SL_ED25519_SIG_LEN];
    CHECK(sl_ed25519_sign(priv, a, sizeof(a), sig) == 0);
    CHECK(sl_ed25519_verify(pub, b, sizeof(b), sig) != 0);
    return 0;
}

static int test_wrong_key_fails(void) {
    uint8_t priv1[SL_ED25519_PRIVKEY_LEN], pub1[SL_ED25519_PUBKEY_LEN];
    uint8_t priv2[SL_ED25519_PRIVKEY_LEN], pub2[SL_ED25519_PUBKEY_LEN];
    sl_ed25519_keypair_new(priv1, pub1);
    sl_ed25519_keypair_new(priv2, pub2);

    const uint8_t msg[] = "hi";
    uint8_t sig[SL_ED25519_SIG_LEN];
    CHECK(sl_ed25519_sign(priv1, msg, sizeof(msg), sig) == 0);
    CHECK(sl_ed25519_verify(pub2, msg, sizeof(msg), sig) != 0);
    return 0;
}

static int test_derive_pub_matches(void) {
    uint8_t priv[SL_ED25519_PRIVKEY_LEN], pub[SL_ED25519_PUBKEY_LEN];
    sl_ed25519_keypair_new(priv, pub);

    uint8_t derived[SL_ED25519_PUBKEY_LEN];
    CHECK(sl_ed25519_derive_pub(priv, derived) == 0);
    CHECK(memcmp(derived, pub, SL_ED25519_PUBKEY_LEN) == 0);
    return 0;
}

static int test_tampered_sig_fails(void) {
    uint8_t priv[SL_ED25519_PRIVKEY_LEN], pub[SL_ED25519_PUBKEY_LEN];
    sl_ed25519_keypair_new(priv, pub);
    const uint8_t msg[] = "msg";
    uint8_t sig[SL_ED25519_SIG_LEN];
    sl_ed25519_sign(priv, msg, sizeof(msg), sig);
    sig[10] ^= 0x01;
    CHECK(sl_ed25519_verify(pub, msg, sizeof(msg), sig) != 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_sign_verify_roundtrip();
    rc |= test_wrong_message_fails();
    rc |= test_wrong_key_fails();
    rc |= test_derive_pub_matches();
    rc |= test_tampered_sig_fails();
    if (rc == 0) puts("test_sl_ed25519: OK");
    return rc;
}
