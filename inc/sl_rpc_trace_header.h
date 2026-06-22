#ifndef SECURELINK_SL_RPC_TRACE_HEADER_H
#define SECURELINK_SL_RPC_TRACE_HEADER_H

/* RPC trace header: a fixed-size sidecar that travels alongside the
 * normal sl_rpc_request body, propagating the W3C-style trace context
 * to the callee.
 *
 * Wire layout (fixed 56 bytes):
 *
 *   u8   version        (= 1)
 *   ...  traceparent    (55 bytes, see sl_trace_context.h)
 *
 * Carried as the first 56 bytes of the request body. Higher layers
 * SHOULD strip these bytes before handing the body to the user. */

#include <stddef.h>
#include <stdint.h>

#include "sl_trace_context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SL_RPC_TRACE_HEADER_LEN 56U
#define SL_RPC_TRACE_HEADER_V1  1U

int sl_rpc_trace_header_pack(const sl_trace_ctx_t *ctx,
                             uint8_t out[SL_RPC_TRACE_HEADER_LEN]);

int sl_rpc_trace_header_unpack(const uint8_t in[SL_RPC_TRACE_HEADER_LEN],
                               sl_trace_ctx_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_RPC_TRACE_HEADER_H */
