#ifndef SECURELINK_SL_TRACE_CONTEXT_H
#define SECURELINK_SL_TRACE_CONTEXT_H

/* Trace context propagation, modelled after W3C traceparent:
 *
 *   00-<32 hex>-<16 hex>-<2 hex>
 *
 * Total length: 55 bytes. Version is fixed at 00. We deliberately keep
 * tracestate out of scope; it's a free-form vendor field and the audit
 * cost outweighs the value for an internal protocol. */

#include <stdbool.h>
#include <stddef.h>

#include "sl_trace_flags.h"
#include "sl_trace_id.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SL_TRACE_CTX_WIRE_LEN 55U

typedef struct {
    sl_trace_id_t    trace_id;
    sl_span_id_t     span_id;
    sl_trace_flags_t flags;
} sl_trace_ctx_t;

bool sl_trace_ctx_is_zero(const sl_trace_ctx_t *c);

int  sl_trace_ctx_format(const sl_trace_ctx_t *c, char *out, size_t out_cap);
int  sl_trace_ctx_parse (const char *in, size_t in_len, sl_trace_ctx_t *out);

/* Create a child span by keeping trace_id, generating a fresh span_id,
 * and preserving flags. */
int  sl_trace_ctx_child(const sl_trace_ctx_t *parent, sl_trace_ctx_t *out);

/* Create a fresh root context (new trace_id, new span_id, unsampled). */
int  sl_trace_ctx_root(sl_trace_ctx_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_TRACE_CONTEXT_H */
