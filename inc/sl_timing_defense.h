#ifndef SECURELINK_SL_TIMING_DEFENSE_H
#define SECURELINK_SL_TIMING_DEFENSE_H

/* Mitigations for timing side-channel attacks.
 *
 * Even with constant-time crypto, an attacker can extract bits by measuring
 * how long the server takes to reject a bad request. This module provides:
 *
 *  - sl_timing_pad_to_floor(): sleep until at least `floor_us` has elapsed
 *    since `start_us`, smoothing out fast-fail paths.
 *  - sl_timing_random_jitter(): inject 0..max_us of jitter to obscure
 *    fine-grained timing channels.
 *  - sl_timing_dummy_work(): perform a fixed amount of fake work, so
 *    early-return code paths look like full-work code paths to a timer.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t sl_timing_now_us(void);

void     sl_timing_pad_to_floor(uint64_t start_us, uint32_t floor_us);
void     sl_timing_random_jitter(uint32_t max_us);

/* Dummy AEAD-shaped work: hashes `iterations * 64` bytes. Iterations is
 * chosen to roughly match a real AES-GCM verify on small inputs. */
void     sl_timing_dummy_work(uint32_t iterations);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_TIMING_DEFENSE_H */
