/* Round-trip and tamper-detection tests for sl_aead (AES-256-GCM).
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_aead.c src/sl_aead.c src/sl_mem.c src/sl_rng.c \
 *       -lcrypto -o test_aead
 */

#include <stdio.h>
#include <string.h>

#include "sl_aead.h"
#include "sl_rng.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_roundtrip_no_aad(void) {
    uint8_t key[SL_AEAD_KEY_LEN], iv[SL_AEAD_IV_LEN];
    CHECK(sl_rng_init() == 0);
    CHECK(sl_rng_bytes(key, sizeof(key)) == 0);
    CHECK(sl_rng_bytes(iv,  sizeof(iv))  == 0);

    const uint8_t pt[] = "hello securelink";
    const size_t  pt_len = sizeof(pt) - 1;
    uint8_t ct [sizeof(pt)];
    uint8_t pt2[sizeof(pt)];
    uint8_t tag[SL_AEAD_TAG_LEN];

    CHECK(sl_aead_seal(key, iv, NULL, 0, pt, pt_len, ct, tag) == 0);
    CHECK(sl_aead_open(key, iv, NULL, 0, ct, pt_len, tag, pt2) == 0);
    CHECK(memcmp(pt, pt2, pt_len) == 0);
    return 0;
}

static int test_roundtrip_with_aad(void) {
    uint8_t key[SL_AEAD_KEY_LEN] = {0};
    uint8_t iv [SL_AEAD_IV_LEN]  = {0};
    for (size_t i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(iv);  ++i) iv[i]  = (uint8_t)(0x80 | i);

    const uint8_t aad[] = "frame-header-bytes";
    const uint8_t pt[]  = "the quick brown fox jumps over the lazy dog";
    const size_t  pt_len = sizeof(pt) - 1;

    uint8_t ct [sizeof(pt)];
    uint8_t pt2[sizeof(pt)];
    uint8_t tag[SL_AEAD_TAG_LEN];

    CHECK(sl_aead_seal(key, iv, aad, sizeof(aad) - 1,
                       pt,  pt_len, ct, tag) == 0);
    CHECK(sl_aead_open(key, iv, aad, sizeof(aad) - 1,
                       ct,  pt_len, tag, pt2) == 0);
    CHECK(memcmp(pt, pt2, pt_len) == 0);
    return 0;
}

static int test_tampered_ciphertext_fails(void) {
    uint8_t key[SL_AEAD_KEY_LEN] = {0};
    uint8_t iv [SL_AEAD_IV_LEN]  = {0};
    const uint8_t pt[] = "secret payload data";
    const size_t  pt_len = sizeof(pt) - 1;

    uint8_t ct [sizeof(pt)];
    uint8_t pt2[sizeof(pt)];
    uint8_t tag[SL_AEAD_TAG_LEN];

    CHECK(sl_aead_seal(key, iv, NULL, 0, pt, pt_len, ct, tag) == 0);
    ct[0] ^= 0x01;  /* flip a bit */
    CHECK(sl_aead_open(key, iv, NULL, 0, ct, pt_len, tag, pt2) != 0);
    return 0;
}

static int test_tampered_aad_fails(void) {
    uint8_t key[SL_AEAD_KEY_LEN] = {0};
    uint8_t iv [SL_AEAD_IV_LEN]  = {0};
    const uint8_t aad1[] = "aad-A";
    const uint8_t aad2[] = "aad-B";
    const uint8_t pt[]   = "payload";
    const size_t  pt_len = sizeof(pt) - 1;

    uint8_t ct [sizeof(pt)];
    uint8_t pt2[sizeof(pt)];
    uint8_t tag[SL_AEAD_TAG_LEN];

    CHECK(sl_aead_seal(key, iv, aad1, sizeof(aad1) - 1,
                       pt, pt_len, ct, tag) == 0);
    CHECK(sl_aead_open(key, iv, aad2, sizeof(aad2) - 1,
                       ct, pt_len, tag, pt2) != 0);
    return 0;
}

static int test_wrong_key_fails(void) {
    uint8_t key1[SL_AEAD_KEY_LEN] = {0};
    uint8_t key2[SL_AEAD_KEY_LEN] = {0};
    key2[0] = 0x01;
    uint8_t iv[SL_AEAD_IV_LEN] = {0};
    const uint8_t pt[] = "data";
    const size_t  pt_len = sizeof(pt) - 1;

    uint8_t ct[sizeof(pt)], pt2[sizeof(pt)], tag[SL_AEAD_TAG_LEN];
    CHECK(sl_aead_seal(key1, iv, NULL, 0, pt, pt_len, ct, tag) == 0);
    CHECK(sl_aead_open(key2, iv, NULL, 0, ct, pt_len, tag, pt2) != 0);
    return 0;
}

static int test_empty_plaintext(void) {
    uint8_t key[SL_AEAD_KEY_LEN] = {0};
    uint8_t iv [SL_AEAD_IV_LEN]  = {0};
    uint8_t tag[SL_AEAD_TAG_LEN];
    /* Empty plaintext with AAD-only authenticated message. */
    const uint8_t aad[] = "header-only";
    CHECK(sl_aead_seal(key, iv, aad, sizeof(aad) - 1, NULL, 0, NULL, tag) == 0);
    CHECK(sl_aead_open(key, iv, aad, sizeof(aad) - 1, NULL, 0, tag, NULL) == 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_roundtrip_no_aad();
    rc |= test_roundtrip_with_aad();
    rc |= test_tampered_ciphertext_fails();
    rc |= test_tampered_aad_fails();
    rc |= test_wrong_key_fails();
    rc |= test_empty_plaintext();
    if (rc == 0) puts("test_aead: OK");
    return rc;
}
