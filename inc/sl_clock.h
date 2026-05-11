#ifndef SECURELINK_SL_CLOCK_H
#define SECURELINK_SL_CLOCK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Wall-clock time in milliseconds since Unix epoch. Suitable for the
 * beacon timestamp field — comparable across hosts (subject to skew). */
uint64_t sl_clock_wall_ms(void);

/* Monotonic time in milliseconds. Never goes backwards. Use for
 * scheduling, intervals, and timeouts — never for wire timestamps. */
uint64_t sl_clock_mono_ms(void);

/* Sleep for `ms` milliseconds. Returns 0 normally, -1 if interrupted. */
int sl_clock_sleep_ms(uint32_t ms);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_CLOCK_H */
