#include "sl_trace_context.h"

#include <stdio.h>
#include <string.h>

bool sl_trace_ctx_is_zero(const sl_trace_ctx_t *c) {
    if (!c) return true;
    return sl_trace_id_is_zero(&c->trace_id) ||
           sl_span_id_is_zero (&c->span_id);
}

int sl_trace_ctx_format(const sl_trace_ctx_t *c, char *out, size_t out_cap) {
    if (!c || !out) return -1;
    if (out_cap < SL_TRACE_CTX_WIRE_LEN + 1) return -1;

    char tid[SL_TRACE_ID_HEX_LEN + 1];
    char sid[SL_SPAN_ID_HEX_LEN  + 1];
    char fl [3];
    if (sl_trace_id_to_hex (&c->trace_id, tid, sizeof(tid)) < 0) return -1;
    if (sl_span_id_to_hex  (&c->span_id,  sid, sizeof(sid)) < 0) return -1;
    if (sl_trace_flags_to_hex(c->flags,   fl,  sizeof(fl))  < 0) return -1;

    const int n = snprintf(out, out_cap, "00-%s-%s-%s", tid, sid, fl);
    if (n < 0 || (size_t)n != SL_TRACE_CTX_WIRE_LEN) return -1;
    return n;
}

int sl_trace_ctx_parse(const char *in, size_t in_len, sl_trace_ctx_t *out) {
    if (!in || !out) return -1;
    if (in_len != SL_TRACE_CTX_WIRE_LEN) return -1;

    /* Layout: 00-XXXX..-XXXX..-XX */
    if (in[0] != '0' || in[1] != '0' || in[2] != '-') return -1;
    if (in[3 + SL_TRACE_ID_HEX_LEN] != '-') return -1;
    if (in[3 + SL_TRACE_ID_HEX_LEN + 1 + SL_SPAN_ID_HEX_LEN] != '-') return -1;

    if (sl_trace_id_from_hex(in + 3, SL_TRACE_ID_HEX_LEN,
                             &out->trace_id) != 0) return -1;
    if (sl_span_id_from_hex (in + 3 + SL_TRACE_ID_HEX_LEN + 1,
                             SL_SPAN_ID_HEX_LEN, &out->span_id) != 0) return -1;
    if (sl_trace_flags_from_hex(in + SL_TRACE_CTX_WIRE_LEN - 2, 2,
                                &out->flags) != 0) return -1;

    if (sl_trace_id_is_zero(&out->trace_id) ||
        sl_span_id_is_zero (&out->span_id)) return -1;
    return 0;
}

int sl_trace_ctx_child(const sl_trace_ctx_t *parent, sl_trace_ctx_t *out) {
    if (!parent || !out) return -1;
    if (sl_trace_ctx_is_zero(parent)) return -1;
    out->trace_id = parent->trace_id;
    if (sl_span_id_random(&out->span_id) != 0) return -1;
    out->flags = parent->flags;
    return 0;
}

int sl_trace_ctx_root(sl_trace_ctx_t *out) {
    if (!out) return -1;
    if (sl_trace_id_random(&out->trace_id) != 0) return -1;
    if (sl_span_id_random (&out->span_id)  != 0) return -1;
    out->flags = SL_TRACE_FLAG_NONE;
    return 0;
}
