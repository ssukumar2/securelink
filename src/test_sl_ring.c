/* Tests for sl_ring.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_ring.c src/sl_ring.c -o test_sl_ring
 */

#include <stdio.h>
#include <string.h>

#include "sl_ring.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_init_free(void) {
    sl_ring_t r;
    CHECK(sl_ring_init(&r, 16) == 0);
    CHECK(sl_ring_capacity(&r) == 16);
    CHECK(sl_ring_used(&r) == 0);
    CHECK(sl_ring_empty(&r));
    sl_ring_free(&r);
    CHECK(r.buf == NULL);
    return 0;
}

static int test_basic_push_pop(void) {
    sl_ring_t r;
    CHECK(sl_ring_init(&r, 8) == 0);

    const uint8_t in[] = {1, 2, 3, 4, 5};
    CHECK(sl_ring_push(&r, in, sizeof(in)) == sizeof(in));
    CHECK(sl_ring_used(&r) == 5);

    uint8_t out[5] = {0};
    CHECK(sl_ring_pop(&r, out, sizeof(out)) == sizeof(out));
    CHECK(memcmp(in, out, sizeof(in)) == 0);
    CHECK(sl_ring_empty(&r));
    sl_ring_free(&r);
    return 0;
}

static int test_wraparound(void) {
    sl_ring_t r;
    CHECK(sl_ring_init(&r, 8) == 0);

    /* Fill 6, pop 4, push 6 -> tail wraps */
    const uint8_t a[] = {1, 2, 3, 4, 5, 6};
    CHECK(sl_ring_push(&r, a, sizeof(a)) == 6);

    uint8_t tmp[4];
    CHECK(sl_ring_pop(&r, tmp, 4) == 4);
    CHECK(memcmp(tmp, "\x01\x02\x03\x04", 4) == 0);

    const uint8_t b[] = {10, 20, 30, 40, 50, 60};
    CHECK(sl_ring_push(&r, b, sizeof(b)) == sizeof(b));
    CHECK(sl_ring_used(&r) == 8);
    CHECK(sl_ring_full(&r));

    uint8_t out[8];
    CHECK(sl_ring_pop(&r, out, 8) == 8);
    const uint8_t expect[] = {5, 6, 10, 20, 30, 40, 50, 60};
    CHECK(memcmp(out, expect, 8) == 0);
    sl_ring_free(&r);
    return 0;
}

static int test_overflow_truncates(void) {
    sl_ring_t r;
    CHECK(sl_ring_init(&r, 4) == 0);
    const uint8_t in[] = {1, 2, 3, 4, 5, 6};
    CHECK(sl_ring_push(&r, in, sizeof(in)) == 4);
    CHECK(sl_ring_full(&r));
    sl_ring_free(&r);
    return 0;
}

static int test_peek_and_discard(void) {
    sl_ring_t r;
    CHECK(sl_ring_init(&r, 8) == 0);
    const uint8_t in[] = {9, 8, 7, 6, 5};
    sl_ring_push(&r, in, sizeof(in));

    uint8_t p[3];
    CHECK(sl_ring_peek(&r, p, 3) == 3);
    CHECK(p[0] == 9 && p[1] == 8 && p[2] == 7);
    CHECK(sl_ring_used(&r) == 5);  /* unchanged */

    CHECK(sl_ring_discard(&r, 2) == 2);
    uint8_t rest[3];
    CHECK(sl_ring_pop(&r, rest, 3) == 3);
    CHECK(rest[0] == 7 && rest[1] == 6 && rest[2] == 5);
    sl_ring_free(&r);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_init_free();
    rc |= test_basic_push_pop();
    rc |= test_wraparound();
    rc |= test_overflow_truncates();
    rc |= test_peek_and_discard();
    if (rc == 0) puts("test_sl_ring: OK");
    return rc;
}
