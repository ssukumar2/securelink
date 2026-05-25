#ifndef SECURELINK_SL_POW_H
#define SECURELINK_SL_POW_H

/* Client puzzle / proof-of-work to raise the cost of connection floods.
 *
 * Server hands the client a random 16-byte challenge and a difficulty
 * (number of leading zero bits required). Client must find a nonce such
 * that SHA-256(challenge || nonce) has at least `difficulty` leading zero
 * bits. Solving cost grows exponentially with difficulty (~2^difficulty).
 *
 * Typical use: bump difficulty when ThreatScore for an IP rises, or when
 * DoS guard says the server is under load. Drops trivial floods at the
 * client's CPU cost.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_POW_CHALLENGE_LEN 16U
#define SL_POW_NONCE_LEN     8U   /* 64-bit nonce */

/* Fill `challenge_out` with cryptographic random bytes. Returns 0 on success. */
int sl_pow_make_challenge(uint8_t challenge_out[SL_POW_CHALLENGE_LEN]);

/* Verify that nonce is a valid solution for `challenge` at `difficulty`. */
bool sl_pow_verify(const uint8_t challenge[SL_POW_CHALLENGE_LEN],
                   const uint8_t nonce[SL_POW_NONCE_LEN],
                   uint32_t      difficulty_bits);

/* Solve a challenge. Useful for clients (and tests). Writes the winning
 * nonce to `nonce_out`. `max_iters` caps work; returns 0 on success or
 * -1 if no solution within the cap. */
int sl_pow_solve(const uint8_t challenge[SL_POW_CHALLENGE_LEN],
                 uint32_t      difficulty_bits,
                 uint64_t      max_iters,
                 uint8_t       nonce_out[SL_POW_NONCE_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_POW_H */
