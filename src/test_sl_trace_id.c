/* Tests for sl_trace_id.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_trace_id.c src/sl_trace_id.c src/sl_rng.c \
 *       -lcrypto -o test_sl_trace_id
 */

#include <stdio.h>
#include <string.h>

#include "sl_trace_id.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_random_id_is_nonzero(void) {
    sl_trace_id_t t;
    sl_span_id_t  s;
    CHECK(sl_trace_id_random(&t) == 0);
    CHECK(sl_span_id_random(&s)  == 0);
    CHECK(!sl_trace_id_is_zero(&t));
    CHECK(!sl_span_id_is_zero(&s));
    return 0;
}

static int test_hex_roundtrip(void) {
    sl_trace_id_t a, b;
    sl_span_id_t  x, y;
    sl_trace_id_random(&a);
    sl_span_id_random(&x);

    char tbuf[SL_TRACE_ID_HEX_LEN + 1];
    char sbuf[SL_SPAN_ID_HEX_LEN  + 1];
    CHECK(sl_trace_id_to_hex(&a, tbuf, sizeof(tbuf)) > 0);
    CHECK(sl_span_id_to_hex (&x, sbuf, sizeof(sbuf)) > 0);

    CHECK(sl_trace_id_from_hex(tbuf, SL_TRACE_ID_HEX_LEN, &b) == 0);
    CHECK(sl_span_id_from_hex (sbuf, SL_SPAN_ID_HEX_LEN,  &y) == 0);
    CHECK(memcmp(&a, &b, sizeof(a)) == 0);
    CHECK(memcmp(&x, &y, sizeof(x)) == 0);
    return 0;
}

static int test_bad_hex_rejected(void) {
    sl_trace_id_t t;
    CHECK(sl_trace_id_from_hex("xxxx", 4, &t) != 0);
    CHECK(sl_trace_id_from_hex("0123456789abcdef0123456789abcde", 31, &t) != 0);
    CHECK(sl_trace_id_from_hex("0123456789ABCDEF0123456789abcdef", 32, &t) != 0);
    return 0;
}

static int test_zero_predicates(void) {
    sl_trace_id_t z = {0};
    sl_span_id_t  zs = {0};
    CHECK(sl_trace_id_is_zero(&z));
    CHECK(sl_span_id_is_zero(&zs));
    return 0;
}

static int test_short_buffer_rejected(void) {
    sl_trace_id_t t; sl_trace_id_random(&t);
    char small[4];
    CHECK(sl_trace_id_to_hex(&t, small, sizeof(small)) < 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_random_id_is_nonzero();
    rc |= test_hex_roundtrip();
    rc |= test_bad_hex_rejected();
    rc |= test_zero_predicates();
    rc |= test_short_buffer_rejected();
    if (rc == 0) puts("test_sl_trace_id: OK");
    return rc;
}
