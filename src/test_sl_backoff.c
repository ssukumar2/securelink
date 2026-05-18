/* Tests for sl_backoff.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_backoff.c src/sl_backoff.c src/sl_rng.c \
 *       -lcrypto -o test_sl_backoff
 */

#include <stdio.h>

#include "sl_backoff.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_init_rejects_bad(void) {
    sl_backoff_t b;
    CHECK(sl_backoff_init(&b, 0, 100) != 0);
    CHECK(sl_backoff_init(&b, 100, 50) != 0);
    CHECK(sl_backoff_init(&b, 100, 1000) == 0);
    return 0;
}

static int test_within_bounds(void) {
    sl_backoff_t b;
    CHECK(sl_backoff_init(&b, 100, 5000) == 0);
    for (int i = 0; i < 50; ++i) {
        const uint32_t d = sl_backoff_next(&b);
        CHECK(d >= 100);
        CHECK(d <= 5000);
    }
    CHECK(sl_backoff_attempt(&b) == 50);
    return 0;
}

static int test_reset_returns_to_base(void) {
    sl_backoff_t b;
    sl_backoff_init(&b, 100, 5000);
    for (int i = 0; i < 5; ++i) sl_backoff_next(&b);
    sl_backoff_reset(&b);
    CHECK(sl_backoff_attempt(&b) == 0);
    /* After reset, range is [100, min(cap, 300)) */
    const uint32_t d = sl_backoff_next(&b);
    CHECK(d >= 100);
    CHECK(d < 300);
    return 0;
}

static int test_eventually_hits_cap(void) {
    sl_backoff_t b;
    sl_backoff_init(&b, 10, 1000);
    /* Run enough iterations that we should see something near the cap. */
    uint32_t max_seen = 0;
    for (int i = 0; i < 200; ++i) {
        const uint32_t d = sl_backoff_next(&b);
        if (d > max_seen) max_seen = d;
    }
    /* Should get at least into the upper half of the cap range. */
    CHECK(max_seen > 500);
    CHECK(max_seen <= 1000);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_init_rejects_bad();
    rc |= test_within_bounds();
    rc |= test_reset_returns_to_base();
    rc |= test_eventually_hits_cap();
    if (rc == 0) puts("test_sl_backoff: OK");
    return rc;
}
