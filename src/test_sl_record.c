/* Round-trip and tamper tests for sl_record.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_record.c src/sl_record.c src/sl_aead.c \
 *       src/sl_mem.c src/sl_nonce.c src/sl_rng.c \
 *       -lcrypto -o test_sl_record
 */

#include <stdio.h>
#include <string.h>

#include "sl_record.h"
#include "sl_rng.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_roundtrip(void) {
    uint8_t key[SL_AEAD_KEY_LEN], iv[SL_AEAD_IV_LEN];
    sl_rng_init();
    sl_rng_bytes(key, sizeof(key));
    sl_rng_bytes(iv,  sizeof(iv));

    const char *msg = "hello securelink record layer";
    const size_t pt_len = strlen(msg);

    uint8_t wire[1024];
    int n = sl_record_seal(SL_REC_APP_DATA, key, iv, 7,
                           (const uint8_t *)msg, pt_len,
                           wire, sizeof(wire));
    CHECK(n > 0);
    CHECK((size_t)n == SL_RECORD_HEADER_LEN + pt_len + SL_AEAD_TAG_LEN);

    /* peek_len from just the header */
    CHECK(sl_record_peek_len(wire) == n);

    sl_record_type_t type = SL_REC_INVALID;
    uint8_t pt[256];
    size_t plen = 0;
    CHECK(sl_record_open(wire, (size_t)n, key, iv, 7,
                         &type, pt, sizeof(pt), &plen) == 0);
    CHECK(type == SL_REC_APP_DATA);
    CHECK(plen == pt_len);
    CHECK(memcmp(pt, msg, pt_len) == 0);
    return 0;
}

static int test_wrong_seq_fails(void) {
    uint8_t key[SL_AEAD_KEY_LEN] = {0};
    uint8_t iv [SL_AEAD_IV_LEN]  = {0};
    const char *msg = "x";
    uint8_t wire[64];
    int n = sl_record_seal(SL_REC_APP_DATA, key, iv, 1,
                           (const uint8_t *)msg, 1, wire, sizeof(wire));
    CHECK(n > 0);

    sl_record_type_t type;
    uint8_t pt[16];
    size_t plen = 0;
    CHECK(sl_record_open(wire, (size_t)n, key, iv, 2,
                         &type, pt, sizeof(pt), &plen) != 0);
    return 0;
}

static int test_header_tamper_fails(void) {
    uint8_t key[SL_AEAD_KEY_LEN] = {0};
    uint8_t iv [SL_AEAD_IV_LEN]  = {0};
    const char *msg = "secrets";
    uint8_t wire[64];
    int n = sl_record_seal(SL_REC_APP_DATA, key, iv, 1,
                           (const uint8_t *)msg, 7, wire, sizeof(wire));
    CHECK(n > 0);

    /* Flip the content_type byte: header is part of AAD, so AEAD must fail. */
    wire[0] ^= 0xFF;

    sl_record_type_t type;
    uint8_t pt[16];
    size_t plen = 0;
    CHECK(sl_record_open(wire, (size_t)n, key, iv, 1,
                         &type, pt, sizeof(pt), &plen) != 0);
    return 0;
}

static int test_peek_rejects_bad_version(void) {
    uint8_t header[SL_RECORD_HEADER_LEN] = {
        SL_REC_APP_DATA, 0x00, 0x00, 0x00, 0x20
    };
    CHECK(sl_record_peek_len(header) < 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_roundtrip();
    rc |= test_wrong_seq_fails();
    rc |= test_header_tamper_fails();
    rc |= test_peek_rejects_bad_version();
    if (rc == 0) puts("test_sl_record: OK");
    return rc;
}
