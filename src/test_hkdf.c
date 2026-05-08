/* HKDF-SHA256 test vectors from RFC 5869 Appendix A.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_hkdf.c src/sl_hkdf.c src/sl_mem.c \
 *       -lcrypto -o test_hkdf
 */

#include <stdio.h>
#include <string.h>

#include "sl_hkdf.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int eq(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

/* Test Case 1: basic 22-byte IKM. */
static int test_case_1(void) {
    const uint8_t ikm[22] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b
    };
    const uint8_t salt[13] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c
    };
    const uint8_t info[10] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
    };
    const uint8_t expected[42] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,
        0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,
        0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,
        0x58,0x65
    };
    uint8_t out[42];
    CHECK(sl_hkdf_sha256(ikm, sizeof(ikm),
                         salt, sizeof(salt),
                         info, sizeof(info),
                         out,  sizeof(out)) == 0);
    CHECK(eq(out, expected, sizeof(expected)));
    return 0;
}

/* Test Case 3: zero salt, empty info. */
static int test_case_3(void) {
    const uint8_t ikm[22] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b
    };
    const uint8_t expected[42] = {
        0x8d,0xa4,0xe7,0x75,0xa5,0x63,0xc1,0x8f,
        0x71,0x5f,0x80,0x2a,0x06,0x3c,0x5a,0x31,
        0xb8,0xa1,0x1f,0x5c,0x5e,0xe1,0x87,0x9e,
        0xc3,0x45,0x4e,0x5f,0x3c,0x73,0x8d,0x2d,
        0x9d,0x20,0x13,0x95,0xfa,0xa4,0xb6,0x1a,
        0x96,0xc8
    };
    uint8_t out[42];
    CHECK(sl_hkdf_sha256(ikm, sizeof(ikm),
                         NULL, 0,
                         NULL, 0,
                         out,  sizeof(out)) == 0);
    CHECK(eq(out, expected, sizeof(expected)));
    return 0;
}

static int test_zero_length_output(void) {
    const uint8_t ikm[8] = {1,2,3,4,5,6,7,8};
    uint8_t out[1] = {0xAA};
    CHECK(sl_hkdf_sha256(ikm, sizeof(ikm), NULL, 0, NULL, 0, out, 0) == 0);
    CHECK(out[0] == 0xAA);  /* untouched */
    return 0;
}

static int test_oversize_rejected(void) {
    uint8_t ikm[8]  = {0};
    uint8_t out[1];
    /* 256 * 32 = 8192 > 255 * 32. Must fail. */
    CHECK(sl_hkdf_sha256(ikm, sizeof(ikm),
                         NULL, 0, NULL, 0,
                         out, 8192) != 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_case_1();
    rc |= test_case_3();
    rc |= test_zero_length_output();
    rc |= test_oversize_rejected();
    if (rc == 0) puts("test_hkdf: OK");
    return rc;
}
