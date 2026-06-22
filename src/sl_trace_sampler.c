#include "sl_trace_sampler.h"

#include <math.h>

void sl_trace_sampler_init(sl_trace_sampler_t *s, double ratio) {
    if (!s) return;
    if (ratio < 0.0 || isnan(ratio)) ratio = 0.0;
    if (ratio > 1.0) ratio = 1.0;
    s->ratio = ratio;
}

bool sl_trace_sampler_should_sample(const sl_trace_sampler_t *s,
                                    const sl_trace_ctx_t *ctx) {
    if (!s || !ctx) return false;
    if (sl_trace_flag_is_set(ctx->flags, SL_TRACE_FLAG_DEBUG)) return true;
    if (s->ratio <= 0.0) return false;
    if (s->ratio >= 1.0) return true;

    /* First 8 bytes → uint64 → fraction. */
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | (uint64_t)ctx->trace_id.bytes[i];
    }
    /* Threshold = ratio * 2^64. Compute in double, compare carefully. */
    const double f = (double)v / 18446744073709551616.0;   /* 2^64 */
    return f < s->ratio;
}
