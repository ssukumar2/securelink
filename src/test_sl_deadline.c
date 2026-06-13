/* Tests for sl_deadline.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_deadline.c src/sl_deadline.c \
 *       -o test_sl_deadline
 */

#include <stdio.h>
#include <time.h>

#include "sl_deadline.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static void sleep_ms(uint32_t ms) {
    struct timespec ts = { .tv_sec = ms / 1000,
                           .tv_nsec = (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static int test_now_is_monotonic(void) {
    uint64_t a = sl_deadline_now_ms();
    sleep_ms(5);
    uint64_t b = sl_deadline_now_ms();
    CHECK(b >= a);
    CHECK(b - a >= 1);   /* at least 1ms passed */
    return 0;
}

static int test_future_deadline_not_expired(void) {
    uint64_t d = sl_deadline_in_ms(1000);
    CHECK(!sl_deadline_expired(d));
    uint32_t r = sl_deadline_remaining_ms(d);
    CHECK(r > 0);
    CHECK(r <= 1000);
    return 0;
}

static int test_expired_deadline(void) {
    uint64_t d = sl_deadline_in_ms(5);
    sleep_ms(20);
    CHECK(sl_deadline_expired(d));
    CHECK(sl_deadline_remaining_ms(d) == 0);
    return 0;
}

static int test_zero_timeout(void) {
    uint64_t d = sl_deadline_in_ms(0);
    sleep_ms(1);
    CHECK(sl_deadline_expired(d));
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_now_is_monotonic();
    rc |= test_future_deadline_not_expired();
    rc |= test_expired_deadline();
    rc |= test_zero_timeout();
    if (rc == 0) puts("test_sl_deadline: OK");
    return rc;
}
