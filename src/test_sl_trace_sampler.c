/* Tests for sl_trace_sampler.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_trace_sampler.c \
 *       src/sl_trace_sampler.c src/sl_trace_context.c \
 *       src/sl_trace_id.c src/sl_trace_flags.c src/sl_rng.c \
 *       -lcrypto -o test_sl_trace_sampler
 */

#include <stdio.h>
#include <string.h>

#include "sl_trace_sampler.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_zero_ratio_never_samples(void) {
    sl_trace_sampler_t s;
    sl_trace_sampler_init(&s, 0.0);
    for (int i = 0; i < 100; ++i) {
        sl_trace_ctx_t c; sl_trace_ctx_root(&c);
        CHECK(!sl_trace_sampler_should_sample(&s, &c));
    }
    return 0;
}

static int test_one_ratio_always_samples(void) {
    sl_trace_sampler_t s;
    sl_trace_sampler_init(&s, 1.0);
    for (int i = 0; i < 100; ++i) {
        sl_trace_ctx_t c; sl_trace_ctx_root(&c);
        CHECK(sl_trace_sampler_should_sample(&s, &c));
    }
    return 0;
}

static int test_debug_flag_forces_sample(void) {
    sl_trace_sampler_t s;
    sl_trace_sampler_init(&s, 0.0);
    sl_trace_ctx_t c; sl_trace_ctx_root(&c);
    c.flags = sl_trace_flags_with(c.flags, SL_TRACE_FLAG_DEBUG);
    CHECK(sl_trace_sampler_should_sample(&s, &c));
    return 0;
}

static int test_ratio_bounds_are_clamped(void) {
    sl_trace_sampler_t s;
    sl_trace_sampler_init(&s, -3.0);
    CHECK(s.ratio == 0.0);
    sl_trace_sampler_init(&s, 5.0);
    CHECK(s.ratio == 1.0);
    return 0;
}

static int test_partial_ratio_approximates(void) {
    /* 50% sampler should produce ~50% sampled over many random IDs.
     * We accept a wide band to avoid flakiness. */
    sl_trace_sampler_t s;
    sl_trace_sampler_init(&s, 0.5);
    int hits = 0;
    const int N = 4000;
    for (int i = 0; i < N; ++i) {
        sl_trace_ctx_t c; sl_trace_ctx_root(&c);
        if (sl_trace_sampler_should_sample(&s, &c)) ++hits;
    }
    CHECK(hits > N / 4);
    CHECK(hits < N * 3 / 4);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_zero_ratio_never_samples();
    rc |= test_one_ratio_always_samples();
    rc |= test_debug_flag_forces_sample();
    rc |= test_ratio_bounds_are_clamped();
    rc |= test_partial_ratio_approximates();
    if (rc == 0) puts("test_sl_trace_sampler: OK");
    return rc;
}
