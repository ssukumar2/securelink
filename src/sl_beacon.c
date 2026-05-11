#include "sl_beacon.h"

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

int sl_beacon_pack_header(const sl_beacon_t *b, uint8_t out[SL_BEACON_HEADER_LEN]) {
    if (b == NULL || out == NULL) return -1;
    pack_u64(out + 0,  b->client_id);
    pack_u64(out + 8,  b->sequence);
    pack_u64(out + 16, b->timestamp_ms);
    pack_u32(out + 24, b->interval_ms);
    pack_u16(out + 28, b->payload_len);
    pack_u16(out + 30, b->flags);
    return 0;
}

int sl_beacon_unpack_header(const uint8_t in[SL_BEACON_HEADER_LEN], sl_beacon_t *b) {
    if (in == NULL || b == NULL) return -1;
    b->client_id    = unpack_u64(in + 0);
    b->sequence     = unpack_u64(in + 8);
    b->timestamp_ms = unpack_u64(in + 16);
    b->interval_ms  = unpack_u32(in + 24);
    b->payload_len  = unpack_u16(in + 28);
    b->flags        = unpack_u16(in + 30);
    /* Payload is not unpacked here — caller copies from the wire buffer. */
    memset(b->payload, 0, sizeof(b->payload));
    return 0;
}

int sl_beacon_validate(const sl_beacon_t *b) {
    if (b == NULL) return -1;
    if (b->sequence == 0) return -1;
    if (b->payload_len > SL_BEACON_MAX_PAYLOAD) return -1;

    /* Reject unknown flag bits — protects against future-flag confusion. */
    const uint16_t known = SL_BEACON_FLAG_REQUEST_ACK | SL_BEACON_FLAG_LAST;
    if ((b->flags & ~known) != 0) return -1;

    /* interval_ms of 0 means "no hint"; otherwise enforce sane bounds. */
    if (b->interval_ms != 0 &&
        (b->interval_ms < 100U || b->interval_ms > 600000U)) {
        return -1;
    }
    return 0;
}
