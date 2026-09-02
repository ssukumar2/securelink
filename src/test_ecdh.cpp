// Verifies sl_ecdh_* -- the actual ECDH key agreement implementation
// (distinct from crypto_engine.c's simpler demo wrapper). Compiled
// fine on its own but was never exercised end to end by any test
// until now.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_ecdh.cpp src/sl_ecdh.c src/sl_mem.c \
//       -lcrypto -o test_ecdh

#include <stdio.h>
#include <string.h>
#include "sl_ecdh.h"

int main(void) {
    int fail = 0;

    sl_ecdh_keypair_t *alice = sl_ecdh_keypair_new();
    sl_ecdh_keypair_t *bob   = sl_ecdh_keypair_new();
    if (!alice || !bob) { printf("FAIL: keypair generation failed\n"); return 1; }

    uint8_t alice_pub[SL_ECDH_PUBKEY_LEN];
    uint8_t bob_pub[SL_ECDH_PUBKEY_LEN];
    if (sl_ecdh_export_pubkey(alice, alice_pub) != 0) { printf("FAIL: export alice\n"); return 1; }
    if (sl_ecdh_export_pubkey(bob, bob_pub) != 0) { printf("FAIL: export bob\n"); return 1; }

    uint8_t alice_secret[SL_ECDH_SHARED_LEN];
    uint8_t bob_secret[SL_ECDH_SHARED_LEN];
    if (sl_ecdh_compute_shared(alice, bob_pub, alice_secret) != 0) {
        printf("FAIL: alice compute_shared\n"); return 1;
    }
    if (sl_ecdh_compute_shared(bob, alice_pub, bob_secret) != 0) {
        printf("FAIL: bob compute_shared\n"); return 1;
    }

    if (memcmp(alice_secret, bob_secret, SL_ECDH_SHARED_LEN) != 0) {
        printf("FAIL: alice and bob derived DIFFERENT shared secrets -- ECDH is broken\n");
        fail = 1;
    } else {
        printf("PASS: both sides derive the identical shared secret\n");
    }

    sl_ecdh_keypair_t *carol = sl_ecdh_keypair_new();
    uint8_t carol_pub[SL_ECDH_PUBKEY_LEN];
    sl_ecdh_export_pubkey(carol, carol_pub);
    uint8_t alice_carol_secret[SL_ECDH_SHARED_LEN];
    sl_ecdh_compute_shared(alice, carol_pub, alice_carol_secret);
    if (memcmp(alice_secret, alice_carol_secret, SL_ECDH_SHARED_LEN) == 0) {
        printf("FAIL: shared secret with bob == shared secret with carol\n"); fail = 1;
    } else {
        printf("PASS: different peer produces a different shared secret\n");
    }

    if (sl_ecdh_validate_pubkey(alice_pub) != 0) {
        printf("FAIL: a genuinely valid pubkey was rejected\n"); fail = 1;
    } else {
        printf("PASS: valid pubkey accepted by validate_pubkey\n");
    }

    uint8_t zero_pub[SL_ECDH_PUBKEY_LEN];
    memset(zero_pub, 0, sizeof(zero_pub));
    if (sl_ecdh_validate_pubkey(zero_pub) == 0) {
        printf("FAIL: all-zero pubkey was accepted as valid\n"); fail = 1;
    } else {
        printf("PASS: all-zero pubkey correctly rejected\n");
    }

    uint8_t bad_tag_pub[SL_ECDH_PUBKEY_LEN];
    memcpy(bad_tag_pub, alice_pub, sizeof(bad_tag_pub));
    bad_tag_pub[0] = 0xFF;
    if (sl_ecdh_validate_pubkey(bad_tag_pub) == 0) {
        printf("FAIL: pubkey with corrupted tag byte was accepted\n"); fail = 1;
    } else {
        printf("PASS: pubkey with corrupted tag byte correctly rejected\n");
    }

    uint8_t junk_secret[SL_ECDH_SHARED_LEN];
    memset(junk_secret, 0xEE, sizeof(junk_secret));
    int rc = sl_ecdh_compute_shared(alice, zero_pub, junk_secret);
    if (rc == 0) {
        printf("FAIL: compute_shared succeeded with an all-zero peer pubkey\n"); fail = 1;
    } else {
        printf("PASS: compute_shared rejects a malformed peer pubkey too\n");
    }

    sl_ecdh_keypair_free(alice);
    sl_ecdh_keypair_free(bob);
    sl_ecdh_keypair_free(carol);
    sl_ecdh_keypair_free(NULL);

    printf(fail ? "\ntest_ecdh: FAIL\n" : "\ntest_ecdh: OK\n");
    return fail;
}
