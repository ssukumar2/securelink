#include "sl_pubsub_msg.h"

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

int sl_pubsub_pack(const sl_pubsub_msg_t *m, uint8_t *out, size_t out_cap) {
    if (!m || !out) return -1;
    if (m->topic_len > SL_PUBSUB_MAX_TOPIC) return -1;
    if (m->payload_len > SL_PUBSUB_MAX_PAYLOAD) return -1;
    if (m->topic_len > 0 && !m->topic) return -1;
    if (m->payload_len > 0 && !m->payload) return -1;

    const size_t need = SL_PUBSUB_HEADER_LEN +
                        (size_t)m->topic_len + (size_t)m->payload_len;
    if (out_cap < need) return -1;

    out[0] = (uint8_t)m->type;
    out[1] = m->flags;
    pack_u16(out + 2, m->topic_len);
    pack_u32(out + 4, m->payload_len);
    if (m->topic_len > 0) memcpy(out + SL_PUBSUB_HEADER_LEN, m->topic, m->topic_len);
    if (m->payload_len > 0) {
        memcpy(out + SL_PUBSUB_HEADER_LEN + m->topic_len,
               m->payload, m->payload_len);
    }
    return (int)need;
}

int sl_pubsub_unpack(const uint8_t *in, size_t in_len, sl_pubsub_msg_t *out) {
    if (!in || !out) return -1;
    if (in_len < SL_PUBSUB_HEADER_LEN) return -1;

    const uint8_t  type   = in[0];
    const uint8_t  flags  = in[1];
    const uint16_t tlen   = unpack_u16(in + 2);
    const uint32_t plen   = unpack_u32(in + 4);

    if (type == 0 || type > SL_PUBSUB_SUBACK) return -1;
    if (tlen > SL_PUBSUB_MAX_TOPIC || plen > SL_PUBSUB_MAX_PAYLOAD) return -1;
    if (in_len < SL_PUBSUB_HEADER_LEN + (size_t)tlen + (size_t)plen) return -1;

    out->type        = (sl_pubsub_msg_type_t)type;
    out->flags       = flags;
    out->topic_len   = tlen;
    out->topic       = (tlen > 0) ? (const char *)(in + SL_PUBSUB_HEADER_LEN) : NULL;
    out->payload_len = plen;
    out->payload     = (plen > 0)
                          ? (in + SL_PUBSUB_HEADER_LEN + tlen)
                          : NULL;
    return 0;
}

const char *sl_pubsub_type_name(sl_pubsub_msg_type_t t) {
    switch (t) {
        case SL_PUBSUB_INVALID:     return "invalid";
        case SL_PUBSUB_PUBLISH:     return "publish";
        case SL_PUBSUB_SUBSCRIBE:   return "subscribe";
        case SL_PUBSUB_UNSUBSCRIBE: return "unsubscribe";
        case SL_PUBSUB_PUBACK:      return "puback";
        case SL_PUBSUB_SUBACK:      return "suback";
    }
    return "?";
}
