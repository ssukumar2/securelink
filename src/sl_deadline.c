/* clock_gettime and CLOCK_MONOTONIC are POSIX, not standard C11 -- same
 * pattern as sl_lockout.c, sl_dos_guard.c, sl_token_bucket.c, sl_clock.c,
 * sl_event_log.c. */
#define _POSIX_C_SOURCE 200809L

#include "sl_deadline.h"

#include <time.h>

uint64_t sl_deadline_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

uint64_t sl_deadline_in_ms(uint32_t timeout_ms) {
    return sl_deadline_now_ms() + (uint64_t)timeout_ms;
}

bool sl_deadline_expired(uint64_t deadline_ms) {
    return sl_deadline_now_ms() >= deadline_ms;
}

uint32_t sl_deadline_remaining_ms(uint64_t deadline_ms) {
    const uint64_t now = sl_deadline_now_ms();
    if (now >= deadline_ms) return 0;
    const uint64_t r = deadline_ms - now;
    return (r > UINT32_MAX) ? UINT32_MAX : (uint32_t)r;
}
