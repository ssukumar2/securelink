// Verifies sl_handshake_secret_derive/_clear -- the actual full
// handshake key schedule the README describes (ECDH shared secret +
// transcript -> master secret -> finished keys + session keys). This
// file compiled fine on its own (confirmed separately) but was never
// exercised end to end by any test until now.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_handshake_secret.cpp src/sl_handshake_secret.c \
//       src/sl_session_keys.c src/sl_hkdf.c src/sl_mem.c \
//       -lcrypto -o test_handshake_secret

#include <stdio.h>
#include <string.h>
#include "sl_handshake_secret.h"

static void fill(uint8_t *buf, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; ++i) buf[i] = (uint8_t)(seed + i);
}

int main(void) {
    int fail = 0;

    uint8_t ecdh[32];       fill(ecdh, 32, 0x01);
    uint8_t transcript[32]; fill(transcript, 32, 0x02);

    sl_handshake_secret_t a, b;

    if (sl_handshake_secret_derive(ecdh, 32, transcript, &a) != 0) {
        printf("FAIL: derive a\n"); return 1;
    }
    if (sl_handshake_secret_derive(ecdh, 32, transcript, &b) != 0) {
        printf("FAIL: derive b\n"); return 1;
    }

    if (memcmp(&a, &b, sizeof(a)) != 0) {
        printf("FAIL: same inputs produced different secrets\n"); fail = 1;
    } else {
        printf("PASS: deterministic\n");
    }

    if (memcmp(a.client_finished_key, a.server_finished_key, SL_FINISHED_LEN) == 0) {
        printf("FAIL: client_finished_key == server_finished_key\n"); fail = 1;
    } else {
        printf("PASS: client_finished_key != server_finished_key\n");
    }

    if (memcmp(a.master, a.client_finished_key, SL_HS_MASTER_LEN) == 0) {
        printf("FAIL: client_finished_key == master (not independently derived)\n"); fail = 1;
    } else {
        printf("PASS: client_finished_key independently derived from master\n");
    }

    uint8_t transcript2[32]; fill(transcript2, 32, 0x03);
    sl_handshake_secret_t c;
    if (sl_handshake_secret_derive(ecdh, 32, transcript2, &c) != 0) {
        printf("FAIL: derive c\n"); return 1;
    }
    if (memcmp(a.master, c.master, SL_HS_MASTER_LEN) == 0) {
        printf("FAIL: different transcript produced identical master secret\n"); fail = 1;
    } else {
        printf("PASS: different transcript changes the master secret\n");
    }
    if (memcmp(a.app_keys.client_key, c.app_keys.client_key, SL_AEAD_KEY_LEN) == 0) {
        printf("FAIL: different transcript produced identical app traffic keys\n"); fail = 1;
    } else {
        printf("PASS: different transcript changes the app traffic keys too\n");
    }

    sl_handshake_secret_clear(&a);
    uint8_t zeros[sizeof(a)] = {0};
    if (memcmp(&a, zeros, sizeof(a)) != 0) {
        printf("FAIL: clear() did not zero the full struct\n"); fail = 1;
    } else {
        printf("PASS: clear() zeroes master, finished keys, and app_keys\n");
    }

    if (sl_handshake_secret_derive(NULL, 32, transcript, &b) == 0) {
        printf("FAIL: NULL ecdh_shared accepted\n"); fail = 1;
    } else {
        printf("PASS: NULL ecdh_shared rejected\n");
    }

    printf(fail ? "\ntest_handshake_secret: FAIL\n" : "\ntest_handshake_secret: OK\n");
    return fail;
}
