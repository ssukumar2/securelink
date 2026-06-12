#include "sl_stream_frame.h"

#include <string.h>

static void pack_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
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

int sl_stream_frame_pack(const sl_stream_frame_t *f,
                         uint8_t *out, size_t out_cap) {
    if (!f || !out) return -1;
    if (f->payload_len > SL_STREAM_FRAME_MAX_PAYLOAD) return -1;
    if (f->payload_len > 0 && !f->payload) return -1;

    const size_t need = SL_STREAM_FRAME_HEADER_LEN + (size_t)f->payload_len;
    if (out_cap < need) return -1;

    out[0] = (uint8_t)f->type;
    out[1] = f->flags;
    pack_u16(out + 2, 0);
    pack_u32(out + 4, f->stream_id);
    pack_u16(out + 8, f->payload_len);
    if (f->payload_len > 0) {
        memcpy(out + SL_STREAM_FRAME_HEADER_LEN, f->payload, f->payload_len);
    }
    return (int)need;
}

int sl_stream_frame_unpack(const uint8_t *in, size_t in_len,
                           sl_stream_frame_t *out) {
    if (!in || !out) return -1;
    if (in_len < SL_STREAM_FRAME_HEADER_LEN) return -1;

    const uint16_t rsv = unpack_u16(in + 2);
    if (rsv != 0) return -1;

    const uint8_t  type  = in[0];
    const uint8_t  flags = in[1];
    const uint32_t sid   = unpack_u32(in + 4);
    const uint16_t plen  = unpack_u16(in + 8);

    if (plen > SL_STREAM_FRAME_MAX_PAYLOAD) return -1;
    if (in_len < SL_STREAM_FRAME_HEADER_LEN + (size_t)plen) return -1;
    if (type == 0 || type > SL_STREAM_FRAME_PONG) return -1;

    out->type        = (sl_stream_frame_type_t)type;
    out->flags       = flags;
    out->stream_id   = sid;
    out->payload     = (plen > 0) ? (in + SL_STREAM_FRAME_HEADER_LEN) : NULL;
    out->payload_len = plen;
    return (int)(SL_STREAM_FRAME_HEADER_LEN + (size_t)plen);
}

const char *sl_stream_frame_type_name(sl_stream_frame_type_t t) {
    switch (t) {
        case SL_STREAM_FRAME_INVALID: return "invalid";
        case SL_STREAM_FRAME_DATA:    return "data";
        case SL_STREAM_FRAME_WINDOW:  return "window";
        case SL_STREAM_FRAME_RESET:   return "reset";
        case SL_STREAM_FRAME_PING:    return "ping";
        case SL_STREAM_FRAME_PONG:    return "pong";
    }
    return "?";
}
