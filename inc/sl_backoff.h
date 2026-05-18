#ifndef SECURELINK_SL_BACKOFF_H
#define SECURELINK_SL_BACKOFF_H

/* Decorrelated-jitter exponential backoff. Each attempt picks a delay in
 *
 *     [base_ms, min(cap_ms, prev * 3))
 *
 * which avoids the thundering-herd pattern of pure exponential backoff
 * and the truncation artefacts of "exp +/- small jitter".
 *
 * Reference: AWS Architecture Blog, "Exponential Backoff and Jitter"
 * (the "decorrelated jitter" variant). */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t base_ms;
    uint32_t cap_ms;
    uint32_t last_ms;
    uint32_t attempt;
} sl_backoff_t;

int      sl_backoff_init (sl_backoff_t *b, uint32_t base_ms, uint32_t cap_ms);
uint32_t sl_backoff_next (sl_backoff_t *b);
void     sl_backoff_reset(sl_backoff_t *b);
uint32_t sl_backoff_attempt(const sl_backoff_t *b);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_BACKOFF_H */
