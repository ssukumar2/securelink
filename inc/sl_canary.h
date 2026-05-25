#ifndef SECURELINK_SL_CANARY_H
#define SECURELINK_SL_CANARY_H

/* Manual stack/heap canary helpers for buffers passed to risky parsing code.
 *
 * Place a canary just before and after a buffer; call sl_canary_check() after
 * the operation to detect overflows even when ASan / -fstack-protector isn't
 * in play (e.g. release builds, embedded targets).
 *
 * Usage:
 *   uint64_t c1, c2;
 *   sl_canary_arm(&c1);
 *   uint8_t buf[256];
 *   sl_canary_arm(&c2);
 *   parse_something(buf, sizeof(buf));
 *   if (!sl_canary_check(&c1) || !sl_canary_check(&c2)) abort();
 */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the process-wide canary value from RNG. Call once at startup.
 * Returns 0 on success. After init, sl_canary_value() is stable. */
int      sl_canary_init(void);
uint64_t sl_canary_value(void);

/* Write the canary value into *slot. */
void     sl_canary_arm(uint64_t *slot);

/* Constant-time check that *slot still holds the canary value.
 * Returns true if intact. */
bool     sl_canary_check(const uint64_t *slot);

/* Wipe a slot (e.g. when done with the buffer) to make stale canaries
 * harder for an attacker to observe in core dumps. */
void     sl_canary_disarm(uint64_t *slot);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_CANARY_H */
