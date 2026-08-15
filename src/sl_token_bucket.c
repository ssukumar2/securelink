/* clock_gettime and CLOCK_MONOTONIC are POSIX (POSIX.1-2008), not
 * standard C11 -- glibc hides them under strict -std=c11 unless this
 * feature-test macro is defined first. Same pattern as sl_lockout.c
 * and sl_dos_guard.c. */
#define _POSIX_C_SOURCE 200809L

#include "sl_token_bucket.h"

#include <time.h>

static uint64_t now_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static void refill(sl_token_bucket_t *tb) {
    const uint64_t now = now_us();
    if (tb->last_refill_us == 0) {
        tb->last_refill_us = now;
        return;
    }
    if (now <= tb->last_refill_us) return;

    const uint64_t elapsed_us = now - tb->last_refill_us;
    /* tokens += rate_bps * elapsed_us / 1e6  */
    const uint64_t add = (tb->rate_bps * elapsed_us) / 1000000ULL;
    if (add == 0) return;

    uint64_t sum = tb->tokens + add;
    if (sum > tb->capacity_bytes) sum = tb->capacity_bytes;
    tb->tokens          = sum;
    tb->last_refill_us  = now;
}

void sl_token_bucket_init(sl_token_bucket_t *tb,
                          uint64_t capacity_bytes,
                          uint64_t rate_bps) {
    if (!tb) return;
    tb->capacity_bytes = capacity_bytes;
    tb->rate_bps       = rate_bps;
    tb->tokens         = capacity_bytes;   /* start full */
    tb->last_refill_us = 0;
}

int sl_token_bucket_try_take(sl_token_bucket_t *tb, uint64_t bytes) {
    if (!tb) return -1;
    refill(tb);
    if (tb->tokens < bytes) return -1;
    tb->tokens -= bytes;
    return 0;
}

uint32_t sl_token_bucket_wait_ms(sl_token_bucket_t *tb, uint64_t bytes) {
    if (!tb || tb->rate_bps == 0) return 0;
    refill(tb);
    if (tb->tokens >= bytes) return 0;
    const uint64_t deficit = bytes - tb->tokens;
    const uint64_t ms = (deficit * 1000ULL + tb->rate_bps - 1ULL) / tb->rate_bps;
    return (ms > UINT32_MAX) ? UINT32_MAX : (uint32_t)ms;
}

void sl_token_bucket_set_rate(sl_token_bucket_t *tb, uint64_t rate_bps) {
    if (!tb) return;
    refill(tb);
    tb->rate_bps = rate_bps;
}

uint64_t sl_token_bucket_tokens(const sl_token_bucket_t *tb) {
    return tb ? tb->tokens : 0;
}
