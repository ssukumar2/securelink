// Verifies sl_session_keys_derive/_clear, which never compiled before --
// the header it needed (sl_session_keys.h) didn't exist anywhere in the
// repository until now, even though sl_handshake_secret.c and sl_rekey.c
// both depended on it.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_session_keys.cpp src/sl_session_keys.c \
//       src/sl_hkdf.c src/sl_mem.c \
//       -lcrypto -o test_session_keys

#include <stdio.h>
#include <string.h>
#include "sl_session_keys.h"

static void fill(uint8_t *buf, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; ++i) buf[i] = (uint8_t)(seed + i);
}

int main(void) {
    int fail = 0;

    uint8_t master[32]; fill(master, 32, 0x11);
    uint8_t salt[32];   fill(salt, 32, 0x22);

    sl_session_keys_t a, b;

    if (sl_session_keys_derive(master, 32, salt, &a) != 0) { printf("FAIL: derive a\n"); return 1; }
    if (sl_session_keys_derive(master, 32, salt, &b) != 0) { printf("FAIL: derive b\n"); return 1; }
    if (memcmp(&a, &b, sizeof(a)) != 0) {
        printf("FAIL: same inputs produced different keys (not deterministic)\n"); fail = 1;
    } else {
        printf("PASS: deterministic\n");
    }

    if (memcmp(a.client_key, a.server_key, SL_AEAD_KEY_LEN) == 0) {
        printf("FAIL: client_key == server_key\n"); fail = 1;
    } else {
        printf("PASS: client_key != server_key\n");
    }
    if (memcmp(a.client_iv, a.server_iv, SL_AEAD_IV_LEN) == 0) {
        printf("FAIL: client_iv == server_iv\n"); fail = 1;
    } else {
        printf("PASS: client_iv != server_iv\n");
    }

    uint8_t master2[32]; fill(master2, 32, 0x99);
    sl_session_keys_t c;
    if (sl_session_keys_derive(master2, 32, salt, &c) != 0) { printf("FAIL: derive c\n"); return 1; }
    if (memcmp(a.client_key, c.client_key, SL_AEAD_KEY_LEN) == 0) {
        printf("FAIL: different master secret produced identical client_key\n"); fail = 1;
    } else {
        printf("PASS: different master secret changes the derived keys\n");
    }

    sl_session_keys_clear(&a);
    uint8_t zeros[sizeof(a)] = {0};
    if (memcmp(&a, zeros, sizeof(a)) != 0) {
        printf("FAIL: clear() did not zero the struct\n"); fail = 1;
    } else {
        printf("PASS: clear() zeroes all key material\n");
    }

    if (sl_session_keys_derive(NULL, 32, salt, &a) == 0) {
        printf("FAIL: NULL master accepted\n"); fail = 1;
    } else {
        printf("PASS: NULL master rejected\n");
    }

    printf(fail ? "\ntest_session_keys: FAIL\n" : "\ntest_session_keys: OK\n");
    return fail;
}
