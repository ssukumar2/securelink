#include "sl_backoff.h"

#include <stdint.h>

#include "sl_rng.h"

int sl_backoff_init(sl_backoff_t *b, uint32_t base_ms, uint32_t cap_ms) {
    if (b == NULL || base_ms == 0 || cap_ms < base_ms) return -1;
    b->base_ms = base_ms;
    b->cap_ms  = cap_ms;
    b->last_ms = base_ms;
    b->attempt = 0;
    return 0;
}

void sl_backoff_reset(sl_backoff_t *b) {
    if (b == NULL) return;
    b->last_ms = b->base_ms;
    b->attempt = 0;
}

uint32_t sl_backoff_attempt(const sl_backoff_t *b) {
    return b ? b->attempt : 0;
}

uint32_t sl_backoff_next(sl_backoff_t *b) {
    if (b == NULL) return 0;

    /* upper = min(cap, last * 3); range = [base, upper) */
    uint64_t upper = (uint64_t)b->last_ms * 3ULL;
    if (upper > (uint64_t)b->cap_ms) upper = b->cap_ms;
    if (upper <= b->base_ms) upper = b->base_ms + 1;

    const uint64_t span = upper - b->base_ms;
    uint64_t r = 0;
    if (sl_rng_uniform(span, &r) != 0) {
        r = 0;  /* fall back to base on RNG failure */
    }
    const uint32_t delay = b->base_ms + (uint32_t)r;
    b->last_ms = delay;
    ++b->attempt;
    return delay;
}
