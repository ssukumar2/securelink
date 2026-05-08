#ifndef SECURELINK_SL_RNG_H
#define SECURELINK_SL_RNG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the RNG subsystem. Safe to call multiple times.
 * Returns 0 on success, -1 on failure. */
int sl_rng_init(void);

/* Fill `buf` with `len` cryptographically secure random bytes.
 * Returns 0 on success, -1 on failure. On failure, `buf` contents
 * are unspecified and MUST NOT be used as key material. */
int sl_rng_bytes(uint8_t *buf, size_t len);

/* Convenience: random uint32_t / uint64_t. Returns 0 on success. */
int sl_rng_u32(uint32_t *out);
int sl_rng_u64(uint64_t *out);

/* Random integer in [0, upper). Rejection-sampled to remove modulo bias.
 * `upper` must be > 0. Returns 0 on success. */
int sl_rng_uniform(uint64_t upper, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_RNG_H */
