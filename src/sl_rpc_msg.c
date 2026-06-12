#include "sl_rpc_msg.h"

#include <string.h>

static void pack_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
static void pack_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)v;
}
static uint16_t unpack_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
static uint32_t unpack_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

int sl_rpc_request_pack(const sl_rpc_request_t *r,
                        uint8_t *out, size_t out_cap) {
    if (!r || !out) return -1;
    if (r->method_len == 0 || r->method_len > SL_RPC_METHOD_MAX) return -1;
    if (r->body_len > SL_RPC_BODY_MAX) return -1;
    if (r->body_len > 0 && !r->body) return -1;

    const size_t need = 1 + 1 + 4 + 2 + r->method_len + 4 + r->body_len;
    if (out_cap < need) return -1;

    size_t off = 0;
    out[off++] = (uint8_t)SL_RPC_REQUEST;
    out[off++] = 0;
    pack_u32(out + off, r->request_id);    off += 4;
    pack_u16(out + off, r->method_len);    off += 2;
    memcpy(out + off, r->method, r->method_len);
    off += r->method_len;
    pack_u32(out + off, r->body_len);      off += 4;
    if (r->body_len > 0) {
        memcpy(out + off, r->body, r->body_len);
        off += r->body_len;
    }
    return (int)off;
}

int sl_rpc_request_unpack(const uint8_t *in, size_t in_len,
                          sl_rpc_request_t *out) {
    if (!in || !out) return -1;
    if (in_len < 12) return -1;

    if (in[0] != (uint8_t)SL_RPC_REQUEST) return -1;
    out->request_id = unpack_u32(in + 2);
    out->method_len = unpack_u16(in + 6);
    if (out->method_len == 0 || out->method_len > SL_RPC_METHOD_MAX) return -1;
    if (in_len < (size_t)8 + out->method_len + 4) return -1;

    memcpy(out->method, in + 8, out->method_len);
    out->method[out->method_len] = '\0';

    const uint32_t body_len = unpack_u32(in + 8 + out->method_len);
    if (body_len > SL_RPC_BODY_MAX) return -1;
    if (in_len < (size_t)8 + out->method_len + 4 + body_len) return -1;
    out->body_len = body_len;
    out->body     = (body_len > 0) ? (in + 8 + out->method_len + 4) : NULL;
    return 0;
}

int sl_rpc_response_pack(const sl_rpc_response_t *r,
                         uint8_t *out, size_t out_cap) {
    if (!r || !out) return -1;
    if (r->body_len > SL_RPC_BODY_MAX) return -1;
    if (r->body_len > 0 && !r->body) return -1;

    const size_t need = 1 + 1 + 4 + 2 + 4 + r->body_len;
    if (out_cap < need) return -1;

    size_t off = 0;
    out[off++] = (uint8_t)SL_RPC_RESPONSE;
    out[off++] = (uint8_t)r->status;
    pack_u32(out + off, r->request_id); off += 4;
    pack_u16(out + off, 0);             off += 2;
    pack_u32(out + off, r->body_len);   off += 4;
    if (r->body_len > 0) {
        memcpy(out + off, r->body, r->body_len);
        off += r->body_len;
    }
    return (int)off;
}

int sl_rpc_response_unpack(const uint8_t *in, size_t in_len,
                           sl_rpc_response_t *out) {
    if (!in || !out) return -1;
    if (in_len < 12) return -1;

    if (in[0] != (uint8_t)SL_RPC_RESPONSE) return -1;
    out->status     = (sl_rpc_status_t)in[1];
    out->request_id = unpack_u32(in + 2);
    if (unpack_u16(in + 6) != 0) return -1;
    out->body_len   = unpack_u32(in + 8);
    if (out->body_len > SL_RPC_BODY_MAX) return -1;
    if (in_len < (size_t)12 + out->body_len) return -1;
    out->body = (out->body_len > 0) ? (in + 12) : NULL;
    return 0;
}

const char *sl_rpc_status_name(sl_rpc_status_t s) {
    switch (s) {
        case SL_RPC_OK:            return "ok";
        case SL_RPC_BAD_REQUEST:   return "bad_request";
        case SL_RPC_NOT_FOUND:     return "not_found";
        case SL_RPC_NOT_PERMITTED: return "not_permitted";
        case SL_RPC_INTERNAL:      return "internal";
        case SL_RPC_RATE_LIMITED:  return "rate_limited";
        case SL_RPC_UNAVAILABLE:   return "unavailable";
    }
    return "?";
}
