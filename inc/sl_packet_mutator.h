#ifndef SECURELINK_SL_PACKET_MUTATOR_H
#define SECURELINK_SL_PACKET_MUTATOR_H

/* Packet mutation primitives for adversarial testing.
 *
 * Each mutator takes a buffer and applies one well-defined corruption:
 * bit flip, byte shuffle, truncation, header field overwrite. Tests can
 * compose them to simulate everything from random transport corruption
 * to targeted forged-field attacks.
 *
 * All mutators are deterministic given the same seed so failures are
 * reproducible. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t state;
} sl_mut_rng_t;

void sl_mut_rng_seed(sl_mut_rng_t *r, uint64_t seed);
uint64_t sl_mut_rng_next(sl_mut_rng_t *r);

/* Flip a single random bit in `buf`. */
void sl_mut_flip_bit(sl_mut_rng_t *r, uint8_t *buf, size_t len);

/* Flip up to `n` random bits in `buf`. */
void sl_mut_flip_bits(sl_mut_rng_t *r, uint8_t *buf, size_t len, size_t n);

/* Overwrite `len_overwrite` bytes starting at `offset` with random data.
 * Returns 0 on success, -1 if range exceeds the buffer. */
int  sl_mut_overwrite(sl_mut_rng_t *r, uint8_t *buf, size_t len,
                      size_t offset, size_t len_overwrite);

/* Truncate by chopping off the trailing `n` bytes. Returns new length. */
size_t sl_mut_truncate(size_t len, size_t n);

/* Extend by appending `n` random bytes (caller-owned space). */
void sl_mut_extend(sl_mut_rng_t *r, uint8_t *buf_tail, size_t n);

/* Swap two random byte positions. */
void sl_mut_swap_bytes(sl_mut_rng_t *r, uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_PACKET_MUTATOR_H */
