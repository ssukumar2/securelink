// Verifies sl_ed25519_* -- the long-term identity signature scheme
// that gives the handshake authenticity (ECDH alone only gives
// confidentiality/integrity, not proof of who you're talking to).
// Compiled fine on its own but was never exercised end to end by any
// test until now.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_ed25519.cpp src/sl_ed25519.c \
//       -lcrypto -o test_ed25519

#include <stdio.h>
#include <string.h>
#include "sl_ed25519.h"

int main(void) {
    int fail = 0;

    uint8_t priv[SL_ED25519_PRIVKEY_LEN];
    uint8_t pub[SL_ED25519_PUBKEY_LEN];
    if (sl_ed25519_keypair_new(priv, pub) != 0) {
        printf("FAIL: keypair generation failed\n"); return 1;
    }

    const char *msg = "this is the handshake transcript hash, signed";
    uint8_t sig[SL_ED25519_SIG_LEN];
    if (sl_ed25519_sign(priv, (const uint8_t*)msg, strlen(msg), sig) != 0) {
        printf("FAIL: signing failed\n"); return 1;
    }

    if (sl_ed25519_verify(pub, (const uint8_t*)msg, strlen(msg), sig) != 0) {
        printf("FAIL: valid signature failed to verify\n"); fail = 1;
    } else {
        printf("PASS: valid signature verifies correctly\n");
    }

    const char *tampered_msg = "this is the handshake transcript hash, SIGNED";
    if (sl_ed25519_verify(pub, (const uint8_t*)tampered_msg, strlen(tampered_msg), sig) == 0) {
        printf("FAIL: signature verified against a DIFFERENT message\n"); fail = 1;
    } else {
        printf("PASS: signature correctly rejected for a tampered message\n");
    }

    uint8_t priv2[SL_ED25519_PRIVKEY_LEN];
    uint8_t pub2[SL_ED25519_PUBKEY_LEN];
    sl_ed25519_keypair_new(priv2, pub2);
    if (sl_ed25519_verify(pub2, (const uint8_t*)msg, strlen(msg), sig) == 0) {
        printf("FAIL: signature verified under a DIFFERENT peer's public key\n"); fail = 1;
    } else {
        printf("PASS: signature correctly rejected under the wrong public key\n");
    }

    uint8_t corrupted_sig[SL_ED25519_SIG_LEN];
    memcpy(corrupted_sig, sig, sizeof(sig));
    corrupted_sig[0] ^= 0x01;
    if (sl_ed25519_verify(pub, (const uint8_t*)msg, strlen(msg), corrupted_sig) == 0) {
        printf("FAIL: a single flipped bit in the signature still verified\n"); fail = 1;
    } else {
        printf("PASS: a single flipped signature bit correctly fails verification\n");
    }

    uint8_t derived_pub[SL_ED25519_PUBKEY_LEN];
    if (sl_ed25519_derive_pub(priv, derived_pub) != 0) {
        printf("FAIL: derive_pub failed\n"); fail = 1;
    } else if (memcmp(pub, derived_pub, SL_ED25519_PUBKEY_LEN) != 0) {
        printf("FAIL: derive_pub disagrees with the pubkey from keypair_new\n"); fail = 1;
    } else {
        printf("PASS: derive_pub agrees with the original public key\n");
    }

    if (memcmp(pub, pub2, SL_ED25519_PUBKEY_LEN) == 0) {
        printf("FAIL: two independently generated keypairs share a public key\n"); fail = 1;
    } else {
        printf("PASS: independently generated keypairs have different public keys\n");
    }

    printf(fail ? "\ntest_ed25519: FAIL\n" : "\ntest_ed25519: OK\n");
    return fail;
}
