#ifndef SECURELINK_SL_LOCKOUT_H
#define SECURELINK_SL_LOCKOUT_H

/* Per-key (peer ID / IP) failure lockout with exponential backoff.
 *
 * On each failure, the lockout window doubles up to a cap. While locked
 * out, all attempts return SL_LOCKOUT_BLOCKED regardless of correctness.
 * A success resets the failure count and clears the lockout.
 *
 * Intended uses:
 *   - Reject brute-force handshake attempts from one IP.
 *   - Throttle a single misbehaving client_id without affecting others.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SL_LOCKOUT_ALLOW    = 0,
    SL_LOCKOUT_BLOCKED  = 1,
} sl_lockout_status_t;

typedef struct sl_lockout sl_lockout_t;

sl_lockout_t *sl_lockout_new(uint32_t base_lockout_ms,
                             uint32_t cap_lockout_ms,
                             uint32_t fail_threshold);
void          sl_lockout_free(sl_lockout_t *L);

/* Check whether `key` is currently allowed to attempt. */
sl_lockout_status_t sl_lockout_check(sl_lockout_t *L, const char *key);

/* Record a failure for `key`. Returns the resulting status. */
sl_lockout_status_t sl_lockout_fail(sl_lockout_t *L, const char *key);

/* Record a success, clearing any failure state for `key`. */
void sl_lockout_succeed(sl_lockout_t *L, const char *key);

/* Number of keys currently tracked. */
size_t sl_lockout_size(const sl_lockout_t *L);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_LOCKOUT_H */
