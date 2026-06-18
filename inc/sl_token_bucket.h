#ifndef SECURELINK_SL_TOKEN_BUCKET_H
#define SECURELINK_SL_TOKEN_BUCKET_H

/* Token bucket for bandwidth throttling.
 *
 * Distinct from sl_rate_limiter / RateLimiter (which limits events/sec
 * per key): this one tracks BYTES and is used to pace file transfer
 * chunks so a single transfer can't saturate the link.
 *
 * Capacity:        bytes the bucket can hold (burst tolerance)
 * Refill rate:     bytes per second added continuously
 *
 * try_take() returns 0 if the bucket has enough tokens (consumes them);
 * otherwise -1 and the caller should retry after wait_ms(). */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t capacity_bytes;
    uint64_t rate_bps;
    uint64_t tokens;
    uint64_t last_refill_us;
} sl_token_bucket_t;

void sl_token_bucket_init(sl_token_bucket_t *tb,
                          uint64_t capacity_bytes,
                          uint64_t rate_bps);

int      sl_token_bucket_try_take(sl_token_bucket_t *tb, uint64_t bytes);
uint32_t sl_token_bucket_wait_ms (sl_token_bucket_t *tb, uint64_t bytes);

void     sl_token_bucket_set_rate(sl_token_bucket_t *tb, uint64_t rate_bps);
uint64_t sl_token_bucket_tokens  (const sl_token_bucket_t *tb);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_TOKEN_BUCKET_H */
