/* Tests for sl_extensions.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_extensions.c src/sl_extensions.c \
 *       -o test_sl_extensions
 */

#include <stdio.h>
#include <string.h>

#include "sl_extensions.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_add_and_find(void) {
    sl_extensions_t e;
    sl_extensions_init(&e);
    const uint8_t body[] = {1, 2, 3, 4};
    CHECK(sl_extensions_add(&e, SL_EXT_VERSIONS, body, sizeof(body)) == 0);
    CHECK(sl_extensions_add(&e, SL_EXT_CIPHERS, NULL, 0) == 0);

    const sl_extension_t *v = sl_extensions_find(&e, SL_EXT_VERSIONS);
    CHECK(v != NULL);
    CHECK(v->len == 4);
    CHECK(memcmp(v->body, body, 4) == 0);

    const sl_extension_t *c = sl_extensions_find(&e, SL_EXT_CIPHERS);
    CHECK(c != NULL);
    CHECK(c->len == 0);

    CHECK(sl_extensions_find(&e, SL_EXT_HEARTBEAT) == NULL);
    return 0;
}

static int test_encode_decode_roundtrip(void) {
    sl_extensions_t a, b;
    sl_extensions_init(&a);
    const uint8_t body1[] = "v";
    const uint8_t body2[] = "abcdef";
    sl_extensions_add(&a, SL_EXT_VERSIONS, body1, sizeof(body1) - 1);
    sl_extensions_add(&a, SL_EXT_SERVER_NAME, body2, sizeof(body2) - 1);

    uint8_t wire[256];
    int n = sl_extensions_encode(&a, wire, sizeof(wire));
    CHECK(n > 0);

    CHECK(sl_extensions_decode(wire, (size_t)n, &b) == 0);
    CHECK(b.count == 2);
    CHECK(b.items[0].type == SL_EXT_VERSIONS);
    CHECK(b.items[0].len  == 1);
    CHECK(b.items[1].type == SL_EXT_SERVER_NAME);
    CHECK(b.items[1].len  == 6);
    return 0;
}

static int test_decode_skips_unknown_gracefully(void) {
    /* Manually crafted wire with one known (VERSIONS) and one unknown type. */
    uint8_t wire[] = {
        0x00, 0x0A,                  /* inner length = 10 */
        0x00, 0x01, 0x00, 0x01, 0xAA,   /* SL_EXT_VERSIONS, 1 byte */
        0xFF, 0xFE, 0x00, 0x01, 0xBB,   /* unknown 0xFFFE, 1 byte */
    };
    sl_extensions_t e;
    CHECK(sl_extensions_decode(wire, sizeof(wire), &e) == 0);
    CHECK(e.count == 2);   /* unknown stored but ignored by lookups */
    CHECK(sl_extensions_find(&e, SL_EXT_VERSIONS) != NULL);
    return 0;
}

static int test_truncated_decode_rejected(void) {
    uint8_t wire[] = {
        0x00, 0x05,                  /* claims 5 bytes inner */
        0x00, 0x01, 0x00, 0x05, 0xAA /* only 1 of 5 declared bytes present */
    };
    sl_extensions_t e;
    CHECK(sl_extensions_decode(wire, sizeof(wire), &e) != 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_add_and_find();
    rc |= test_encode_decode_roundtrip();
    rc |= test_decode_skips_unknown_gracefully();
    rc |= test_truncated_decode_rejected();
    if (rc == 0) puts("test_sl_extensions: OK");
    return rc;
}
