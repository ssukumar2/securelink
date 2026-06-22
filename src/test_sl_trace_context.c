/* Tests for sl_trace_context.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_trace_context.c src/sl_trace_context.c \
 *       src/sl_trace_id.c src/sl_trace_flags.c src/sl_rng.c \
 *       -lcrypto -o test_sl_trace_context
 */

#include <stdio.h>
#include <string.h>

#include "sl_trace_context.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_format_parse_roundtrip(void) {
    sl_trace_ctx_t a, b;
    CHECK(sl_trace_ctx_root(&a) == 0);
    a.flags = sl_trace_flags_with(a.flags, SL_TRACE_FLAG_SAMPLED);

    char buf[SL_TRACE_CTX_WIRE_LEN + 1];
    int n = sl_trace_ctx_format(&a, buf, sizeof(buf));
    CHECK(n == (int)SL_TRACE_CTX_WIRE_LEN);
    CHECK(buf[0] == '0' && buf[1] == '0' && buf[2] == '-');

    CHECK(sl_trace_ctx_parse(buf, (size_t)n, &b) == 0);
    CHECK(memcmp(&a.trace_id, &b.trace_id, sizeof(a.trace_id)) == 0);
    CHECK(memcmp(&a.span_id,  &b.span_id,  sizeof(a.span_id))  == 0);
    CHECK(a.flags == b.flags);
    return 0;
}

static int test_parse_rejects_bad_inputs(void) {
    sl_trace_ctx_t c;
    /* wrong length */
    CHECK(sl_trace_ctx_parse("00-aaaa", 7, &c) != 0);
    /* wrong version */
    char buf[SL_TRACE_CTX_WIRE_LEN + 1];
    sl_trace_ctx_t ok; sl_trace_ctx_root(&ok);
    sl_trace_ctx_format(&ok, buf, sizeof(buf));
    buf[1] = '1';
    CHECK(sl_trace_ctx_parse(buf, SL_TRACE_CTX_WIRE_LEN, &c) != 0);
    /* all-zero IDs */
    static const char zero[SL_TRACE_CTX_WIRE_LEN] =
        "00-00000000000000000000000000000000-0000000000000000-01";
    CHECK(sl_trace_ctx_parse(zero, SL_TRACE_CTX_WIRE_LEN, &c) != 0);
    return 0;
}

static int test_child_preserves_trace_id(void) {
    sl_trace_ctx_t parent, child;
    sl_trace_ctx_root(&parent);
    parent.flags = SL_TRACE_FLAG_SAMPLED;

    CHECK(sl_trace_ctx_child(&parent, &child) == 0);
    CHECK(memcmp(&parent.trace_id, &child.trace_id, sizeof(parent.trace_id)) == 0);
    CHECK(memcmp(&parent.span_id,  &child.span_id,  sizeof(parent.span_id))  != 0);
    CHECK(child.flags == parent.flags);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_format_parse_roundtrip();
    rc |= test_parse_rejects_bad_inputs();
    rc |= test_child_preserves_trace_id();
    if (rc == 0) puts("test_sl_trace_context: OK");
    return rc;
}
