// Verifies sl_finished_* -- the Finished MAC that proves both sides of
// a handshake saw the same transcript AND know the same secret. This
// is distinct from (and used by) sl_handshake_secret.c, but had never
// been exercised directly on its own by any test until now.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_finished.cpp src/sl_finished.c \
//       src/sl_hkdf.c src/sl_mem.c \
//       -lcrypto -o test_finished

#include <stdio.h>
#include <string.h>
#include "sl_finished.h"

static void fill(uint8_t *buf, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; ++i) buf[i] = (uint8_t)(seed + i);
}

int main(void) {
    int fail = 0;

    uint8_t secret[32];     fill(secret, 32, 0x30);
    uint8_t transcript[32]; fill(transcript, 32, 0x40);

    uint8_t client_key[SL_FINISHED_LEN];
    uint8_t server_key[SL_FINISHED_LEN];
    if (sl_finished_derive_key(secret, 32, 0, client_key) != 0) {
        printf("FAIL: derive client_key\n"); return 1;
    }
    if (sl_finished_derive_key(secret, 32, 1, server_key) != 0) {
        printf("FAIL: derive server_key\n"); return 1;
    }

    if (memcmp(client_key, server_key, SL_FINISHED_LEN) == 0) {
        printf("FAIL: client and server finished keys are identical\n"); fail = 1;
    } else {
        printf("PASS: client_key != server_key\n");
    }

    uint8_t mac[SL_FINISHED_LEN];
    if (sl_finished_compute(client_key, transcript, mac) != 0) {
        printf("FAIL: compute failed\n"); return 1;
    }

    if (sl_finished_verify(client_key, transcript, mac) != 0) {
        printf("FAIL: a correctly computed MAC failed to verify\n"); fail = 1;
    } else {
        printf("PASS: correct MAC verifies successfully\n");
    }

    if (sl_finished_verify(server_key, transcript, mac) == 0) {
        printf("FAIL: MAC verified under the WRONG finished key\n"); fail = 1;
    } else {
        printf("PASS: MAC correctly rejected under the wrong key\n");
    }

    uint8_t other_transcript[32]; fill(other_transcript, 32, 0x99);
    if (sl_finished_verify(client_key, other_transcript, mac) == 0) {
        printf("FAIL: MAC verified against a DIFFERENT transcript\n"); fail = 1;
    } else {
        printf("PASS: MAC correctly rejected for a different transcript\n");
    }

    uint8_t corrupted_mac[SL_FINISHED_LEN];
    memcpy(corrupted_mac, mac, sizeof(mac));
    corrupted_mac[SL_FINISHED_LEN - 1] ^= 0x01;
    if (sl_finished_verify(client_key, transcript, corrupted_mac) == 0) {
        printf("FAIL: a single flipped MAC bit still verified\n"); fail = 1;
    } else {
        printf("PASS: a single flipped MAC bit correctly fails verification\n");
    }

    uint8_t secret2[32]; fill(secret2, 32, 0x77);
    uint8_t client_key2[SL_FINISHED_LEN];
    sl_finished_derive_key(secret2, 32, 0, client_key2);
    if (memcmp(client_key, client_key2, SL_FINISHED_LEN) == 0) {
        printf("FAIL: different handshake secrets produced the same finished key\n"); fail = 1;
    } else {
        printf("PASS: different secrets produce different finished keys\n");
    }

    printf(fail ? "\ntest_finished: FAIL\n" : "\ntest_finished: OK\n");
    return fail;
}
