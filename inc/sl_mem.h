#ifndef SECURELINK_SL_MEM_H
#define SECURELINK_SL_MEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Zero `n` bytes at `p` in a way the compiler will not optimize away.
 * Use for scrubbing keys, IVs, plaintext after use. */
void sl_secure_zero(void *p, size_t n);

/* Constant-time equality. Returns 1 if equal, 0 otherwise.
 * Time is independent of the position of the first differing byte. */
int sl_ct_equal(const void *a, const void *b, size_t n);

/* XOR `n` bytes from `src` into `dst` in place: dst[i] ^= src[i]. */
void sl_xor_inplace(uint8_t *dst, const uint8_t *src, size_t n);

/* Constant-time conditional copy: if `cond` is nonzero, copy `n` bytes
 * from `src` to `dst`; otherwise leave `dst` unchanged. Branch-free. */
void sl_ct_copy(uint8_t *dst, const uint8_t *src, size_t n, int cond);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_MEM_H */
