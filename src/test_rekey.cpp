// Verifies sl_rekey_advance and sl_rekey_check_peer_epoch -- the
// in-session key rotation mechanism. This file compiled fine on its
// own (confirmed separately) but was never exercised end to end by
// any test until now.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_rekey.cpp src/sl_rekey.c \
//       src/sl_session_keys.c src/sl_hkdf.c src/sl_mem.c \
//       -lcrypto -o test_rekey

#include <stdio.h>
#include <string.h>
#include "sl_rekey.h"

static void fill(uint8_t *buf, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; ++i) buf[i] = (uint8_t)(seed + i);
}

int main(void) {
    int fail = 0;

    sl_session_keys_t keys;
    memset(&keys, 0, sizeof(keys));
    uint8_t original_client_key[SL_AEAD_KEY_LEN];
    fill(original_client_key, SL_AEAD_KEY_LEN, 0xAA);
    memcpy(keys.client_key, original_client_key, SL_AEAD_KEY_LEN);

    uint8_t secret[32];   fill(secret, 32, 0x10);
    uint8_t secret_copy[32];
    memcpy(secret_copy, secret, 32);
    uint8_t next[32];

    if (sl_rekey_advance(&keys, secret, next) != 0) {
        printf("FAIL: sl_rekey_advance returned error\n"); return 1;
    }

    if (memcmp(secret_copy, next, 32) == 0) {
        printf("FAIL: next_secret == current_secret (no actual rotation)\n"); fail = 1;
    } else {
        printf("PASS: rekey produces a genuinely different secret\n");
    }

    if (memcmp(keys.client_key, original_client_key, SL_AEAD_KEY_LEN) == 0) {
        printf("FAIL: session keys unchanged after rekey\n"); fail = 1;
    } else {
        printf("PASS: session keys actually rotated\n");
    }

    uint8_t zeros32[32] = {0};
    if (memcmp(secret, zeros32, 32) != 0) {
        printf("FAIL: old secret was not zeroed by sl_rekey_advance\n"); fail = 1;
    } else {
        printf("PASS: old secret is zeroed automatically after rekey\n");
    }

    uint8_t s1[32]; fill(s1, 32, 0x55);
    uint8_t s2[32]; fill(s2, 32, 0x55);
    uint8_t n1[32], n2[32];
    sl_session_keys_t k1, k2;
    memset(&k1, 0, sizeof(k1));
    memset(&k2, 0, sizeof(k2));
    sl_rekey_advance(&k1, s1, n1);
    sl_rekey_advance(&k2, s2, n2);
    if (memcmp(n1, n2, 32) != 0) {
        printf("FAIL: same starting secret produced different next secrets\n"); fail = 1;
    } else {
        printf("PASS: rekey is deterministic given the same starting secret\n");
    }

    sl_rekey_epochs_t e;
    e.local_epoch = 0;
    e.peer_epoch  = 0;

    if (sl_rekey_check_peer_epoch(&e, 1) != 0) {
        printf("FAIL: first valid epoch (1) rejected\n"); fail = 1;
    } else {
        printf("PASS: first valid epoch accepted\n");
    }

    if (sl_rekey_check_peer_epoch(&e, 1) == 0) {
        printf("FAIL: replayed epoch (1 again) was accepted\n"); fail = 1;
    } else {
        printf("PASS: replayed epoch correctly rejected\n");
    }

    if (sl_rekey_check_peer_epoch(&e, 5) == 0) {
        printf("FAIL: skipped-ahead epoch (5) was accepted\n"); fail = 1;
    } else {
        printf("PASS: skipped epoch correctly rejected\n");
    }

    if (sl_rekey_check_peer_epoch(&e, 2) != 0) {
        printf("FAIL: correct next epoch (2) rejected\n"); fail = 1;
    } else {
        printf("PASS: correct sequential epoch accepted\n");
    }

    printf(fail ? "\ntest_rekey: FAIL\n" : "\ntest_rekey: OK\n");
    return fail;
}
