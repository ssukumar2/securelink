#ifndef SECURELINK_SL_DEADLINE_H
#define SECURELINK_SL_DEADLINE_H

/* Deadline computations using the monotonic clock.
 *
 * A deadline is an absolute time in milliseconds. Comparing deadlines
 * to "now" rather than tracking remaining time avoids drift when the
 * caller takes longer than expected on intermediate steps.
 *
 * Used by the RPC client to time out outstanding calls, by the
 * SessionManager for idle reaping, and by the handshake engine for
 * upper-bound handshake timeout. */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t sl_deadline_now_ms(void);

/* Compute a deadline `timeout_ms` into the future from now. */
uint64_t sl_deadline_in_ms(uint32_t timeout_ms);

bool     sl_deadline_expired(uint64_t deadline_ms);

/* How many ms remain until the deadline; 0 if already expired. */
uint32_t sl_deadline_remaining_ms(uint64_t deadline_ms);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_DEADLINE_H */
