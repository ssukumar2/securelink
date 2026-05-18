#include "sl_beacon_ack.h"

#include <string.h>

static void pack_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static void pack_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
}

static void pack_u64(uint8_t *p, uint64_t v) {
    pack_u32(p,     (uint32_t)(v >> 32));
    pack_u32(p + 4, (uint32_t)(v));
}

static uint16_t unpack_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t unpack_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static uint64_t unpack_u64(const uint8_t *p) {
    return ((uint64_t)unpack_u32(p) << 32) | (uint64_t)unpack_u32(p + 4);
}

int sl_beacon_ack_pack(const sl_beacon_ack_t *a, uint8_t out[SL_BEACON_ACK_HEADER_LEN]) {
    if (a == NULL || out == NULL) return -1;
    pack_u64(out + 0,  a->client_id);
    pack_u64(out + 8,  a->ack_sequence);
    pack_u64(out + 16, a->server_time_ms);
    pack_u16(out + 24, a->status);
    pack_u16(out + 26, 0);  /* reserved */
    pack_u32(out + 28, a->suggested_interval_ms);
    return 0;
}

int sl_beacon_ack_unpack(const uint8_t in[SL_BEACON_ACK_HEADER_LEN], sl_beacon_ack_t *a) {
    if (in == NULL || a == NULL) return -1;
    a->client_id             = unpack_u64(in + 0);
    a->ack_sequence          = unpack_u64(in + 8);
    a->server_time_ms        = unpack_u64(in + 16);
    a->status                = unpack_u16(in + 24);
    a->reserved              = unpack_u16(in + 26);
    a->suggested_interval_ms = unpack_u32(in + 28);
    return 0;
}

int sl_beacon_ack_validate(const sl_beacon_ack_t *a) {
    if (a == NULL) return -1;
    if (a->reserved != 0) return -1;
    if (a->ack_sequence == 0) return -1;
    if (a->status > SL_ACK_SHUTDOWN) return -1;
    if (a->suggested_interval_ms != 0 &&
        (a->suggested_interval_ms < 100U ||
         a->suggested_interval_ms > 600000U)) {
        return -1;
    }
    return 0;
}
