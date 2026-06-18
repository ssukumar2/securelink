/* Tests for sl_resume_map.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_resume_map.c src/sl_resume_map.c \
 *       -o test_sl_resume_map
 */

#include <stdio.h>
#include <string.h>

#include "sl_resume_map.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_set_and_has(void) {
    sl_resume_map_t r;
    CHECK(sl_resume_map_init(&r, 100) == 0);
    CHECK(!sl_resume_map_has(&r, 0));
    CHECK(sl_resume_map_set(&r, 5) == 0);
    CHECK(sl_resume_map_has(&r, 5));
    CHECK(!sl_resume_map_has(&r, 6));
    CHECK(r.received_chunks == 1);
    /* Re-set is idempotent. */
    CHECK(sl_resume_map_set(&r, 5) == 0);
    CHECK(r.received_chunks == 1);
    sl_resume_map_free(&r);
    return 0;
}

static int test_complete(void) {
    sl_resume_map_t r;
    sl_resume_map_init(&r, 10);
    for (uint32_t i = 0; i < 10; ++i) sl_resume_map_set(&r, i);
    CHECK(sl_resume_map_complete(&r));
    sl_resume_map_free(&r);
    return 0;
}

static int test_missing_list(void) {
    sl_resume_map_t r;
    sl_resume_map_init(&r, 8);
    sl_resume_map_set(&r, 0);
    sl_resume_map_set(&r, 1);
    sl_resume_map_set(&r, 7);

    uint32_t out[8];
    bool more = false;
    size_t n = sl_resume_map_missing(&r, out, 8, &more);
    CHECK(n == 5);
    CHECK(!more);
    CHECK(out[0] == 2 && out[1] == 3 && out[2] == 4 && out[3] == 5 && out[4] == 6);

    /* Small buffer: more should be true. */
    n = sl_resume_map_missing(&r, out, 2, &more);
    CHECK(n == 2);
    CHECK(more);
    sl_resume_map_free(&r);
    return 0;
}

static int test_serialize_deserialize(void) {
    sl_resume_map_t a, b;
    sl_resume_map_init(&a, 20);
    sl_resume_map_set(&a, 3);
    sl_resume_map_set(&a, 11);
    sl_resume_map_set(&a, 19);

    uint8_t buf[16];
    int n = sl_resume_map_serialize(&a, buf, sizeof(buf));
    CHECK(n > 0);

    CHECK(sl_resume_map_deserialize(&b, buf, (size_t)n, 20) == 0);
    CHECK(b.received_chunks == 3);
    CHECK(sl_resume_map_has(&b, 3));
    CHECK(sl_resume_map_has(&b, 11));
    CHECK(sl_resume_map_has(&b, 19));
    CHECK(!sl_resume_map_has(&b, 7));

    sl_resume_map_free(&a);
    sl_resume_map_free(&b);
    return 0;
}

static int test_out_of_range_rejected(void) {
    sl_resume_map_t r;
    sl_resume_map_init(&r, 5);
    CHECK(sl_resume_map_set(&r, 5) != 0);
    CHECK(sl_resume_map_set(&r, 999) != 0);
    sl_resume_map_free(&r);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_set_and_has();
    rc |= test_complete();
    rc |= test_missing_list();
    rc |= test_serialize_deserialize();
    rc |= test_out_of_range_rejected();
    if (rc == 0) puts("test_sl_resume_map: OK");
    return rc;
}
