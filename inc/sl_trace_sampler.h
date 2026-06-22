#ifndef SECURELINK_SL_TRACE_SAMPLER_H
#define SECURELINK_SL_TRACE_SAMPLER_H

/* Probabilistic sampler driven by the trace ID itself, so the decision
 * is consistent across every service that sees this trace. The decision
 * is based on the first 8 bytes of the trace ID interpreted as a uint64,
 * compared against a threshold = ratio * UINT64_MAX.
 *
 * Edge cases:
 *   ratio <= 0   → never sample (returns false)
 *   ratio >= 1   → always sample (returns true)
 *   debug flag   → always sample regardless of ratio */

#include <stdbool.h>
#include <stdint.h>

#include "sl_trace_context.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    double ratio;     /* 0.0 .. 1.0 */
} sl_trace_sampler_t;

void sl_trace_sampler_init(sl_trace_sampler_t *s, double ratio);

bool sl_trace_sampler_should_sample(const sl_trace_sampler_t *s,
                                    const sl_trace_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_TRACE_SAMPLER_H */
