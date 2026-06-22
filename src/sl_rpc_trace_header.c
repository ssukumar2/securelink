#include "sl_rpc_trace_header.h"

#include <string.h>

int sl_rpc_trace_header_pack(const sl_trace_ctx_t *ctx,
                             uint8_t out[SL_RPC_TRACE_HEADER_LEN]) {
    if (!ctx || !out) return -1;

    char wire[SL_TRACE_CTX_WIRE_LEN + 1];
    if (sl_trace_ctx_format(ctx, wire, sizeof(wire)) < 0) return -1;

    out[0] = SL_RPC_TRACE_HEADER_V1;
    memcpy(out + 1, wire, SL_TRACE_CTX_WIRE_LEN);
    return SL_RPC_TRACE_HEADER_LEN;
}

int sl_rpc_trace_header_unpack(const uint8_t in[SL_RPC_TRACE_HEADER_LEN],
                               sl_trace_ctx_t *out) {
    if (!in || !out) return -1;
    if (in[0] != SL_RPC_TRACE_HEADER_V1) return -1;
    return sl_trace_ctx_parse((const char *)(in + 1),
                              SL_TRACE_CTX_WIRE_LEN, out);
}
