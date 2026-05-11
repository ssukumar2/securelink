/* Round-trip + tamper tests for the beacon codec.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_beacon_codec.c src/sl_beacon.c src/sl_beacon_codec.c \
 *       src/sl_aead.c src/sl_mem.c src/sl_nonce.c src/sl_rng.c \
 *       -lcrypto -o test_beacon_codec
 */

#include <stdio.h>
#include <string.h>

#include "sl_beacon.h"
#include "sl_beacon_codec.h"
#include "sl_rng.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static void fill_beacon(sl_beacon_t *b) {
    memset(b, 0, sizeof(*b));
    b->client_id    = 0xDEADBEEFCAFEBABEULL;
    b->sequence     = 1;
    b->timestamp_ms = 1234567890000ULL;
    b->interval_ms  = 5000;
    b->flags        = SL_BEACON_FLAG_REQUEST_ACK;
    const char *p = "host=hp-laptop;pid=1234";
    b->payload_len  = (uint16_t)strlen(p);
    memcpy(b->payload, p, b->payload_len);
}

static int test_roundtrip(void) {
    uint8_t key[SL_AEAD_KEY_LEN], iv[SL_AEAD_IV_LEN];
    CHECK(sl_rng_init() == 0);
    CHECK(sl_rng_bytes(key, sizeof(key)) == 0);
    CHECK(sl_rng_bytes(iv,  sizeof(iv))  == 0);

    sl_beacon_t src;
    fill_beacon(&src);

    uint8_t wire[SL_BEACON_HEADER_LEN + SL_BEACON_MAX_PAYLOAD + SL_AEAD_TAG_LEN];
    size_t wire_len = 0;
    CHECK(sl_beacon_seal(&src, key, iv, src.sequence, wire, &wire_len) == 0);
    CHECK(wire_len == sl_beacon_wire_size(&src));

    sl_beacon_t dst;
    CHECK(sl_beacon_open(wire, wire_len, key, iv, src.sequence, &dst) == 0);
    CHECK(dst.client_id    == src.client_id);
    CHECK(dst.sequence     == src.sequence);
    CHECK(dst.timestamp_ms == src.timestamp_ms);
    CHECK(dst.interval_ms  == src.interval_ms);
    CHECK(dst.flags        == src.flags);
    CHECK(dst.payload_len  == src.payload_len);
    CHECK(memcmp(dst.payload, src.payload, src.payload_len) == 0);
    return 0;
}

static int test_header_tamper_fails(void) {
    uint8_t key[SL_AEAD_KEY_LEN] = {0};
    uint8_t iv [SL_AEAD_IV_LEN]  = {0};

    sl_beacon_t src;
    fill_beacon(&src);
    uint8_t wire[SL_BEACON_HEADER_LEN + SL_BEACON_MAX_PAYLOAD + SL_AEAD_TAG_LEN];
    size_t wire_len = 0;
    CHECK(sl_beacon_seal(&src, key, iv, src.sequence, wire, &wire_len) == 0);

    /* Flip a bit inside the client_id field. */
    wire[3] ^= 0x80;

    sl_beacon_t dst;
    CHECK(sl_beacon_open(wire, wire_len, key, iv, src.sequence, &dst) != 0);
    return 0;
}

static int test_wrong_sequence_fails(void) {
    uint8_t key[SL_AEAD_KEY_LEN] = {0};
    uint8_t iv [SL_AEAD_IV_LEN]  = {0};
    sl_beacon_t src;
    fill_beacon(&src);
    src.sequence = 42;

    uint8_t wire[SL_BEACON_HEADER_LEN + SL_BEACON_MAX_PAYLOAD + SL_AEAD_TAG_LEN];
    size_t wire_len = 0;
    CHECK(sl_beacon_seal(&src, key, iv, src.sequence, wire, &wire_len) == 0);

    sl_beacon_t dst;
    /* Open with the wrong seq -> different nonce -> tag fails. */
    CHECK(sl_beacon_open(wire, wire_len, key, iv, 43, &dst) != 0);
    return 0;
}

static int test_empty_payload(void) {
    uint8_t key[SL_AEAD_KEY_LEN] = {0};
    uint8_t iv [SL_AEAD_IV_LEN]  = {0};
    sl_beacon_t src;
    memset(&src, 0, sizeof(src));
    src.client_id   = 1;
    src.sequence    = 1;
    src.timestamp_ms = 1;
    src.interval_ms  = 0;
    src.flags        = 0;
    src.payload_len  = 0;

    uint8_t wire[SL_BEACON_HEADER_LEN + SL_AEAD_TAG_LEN];
    size_t wire_len = 0;
    CHECK(sl_beacon_seal(&src, key, iv, src.sequence, wire, &wire_len) == 0);
    CHECK(wire_len == SL_BEACON_HEADER_LEN + SL_AEAD_TAG_LEN);

    sl_beacon_t dst;
    CHECK(sl_beacon_open(wire, wire_len, key, iv, src.sequence, &dst) == 0);
    CHECK(dst.payload_len == 0);
    return 0;
}

static int test_validate_rejects_bad_flags(void) {
    sl_beacon_t b;
    memset(&b, 0, sizeof(b));
    b.client_id = 1;
    b.sequence  = 1;
    b.flags     = 0x8000;  /* unknown bit */
    CHECK(sl_beacon_validate(&b) != 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_roundtrip();
    rc |= test_header_tamper_fails();
    rc |= test_wrong_sequence_fails();
    rc |= test_empty_payload();
    rc |= test_validate_rejects_bad_flags();
    if (rc == 0) puts("test_beacon_codec: OK");
    return rc;
}
