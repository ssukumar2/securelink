#include "sl_file_chunk.h"

#include <string.h>

#include "sl_crc32.h"

static void pack_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)v;
}
static uint32_t unpack_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

int sl_file_chunk_pack(const sl_file_chunk_t *c,
                       uint8_t *out, size_t out_cap) {
    if (!c || !out) return -1;
    if (c->data_len > 0 && !c->data) return -1;
    const size_t need = SL_FILE_CHUNK_HEADER_LEN + (size_t)c->data_len;
    if (out_cap < need) return -1;

    const uint32_t crc = (c->data_len > 0)
                            ? sl_crc32c(c->data, c->data_len) : 0;

    pack_u32(out + 0, c->chunk_index);
    pack_u32(out + 4, c->data_len);
    pack_u32(out + 8, crc);
    out[12] = c->flags;
    out[13] = 0; out[14] = 0; out[15] = 0;
    if (c->data_len > 0) {
        memcpy(out + SL_FILE_CHUNK_HEADER_LEN, c->data, c->data_len);
    }
    return (int)need;
}

int sl_file_chunk_unpack(const uint8_t *in, size_t in_len,
                         sl_file_chunk_t *out) {
    if (!in || !out) return -1;
    if (in_len < SL_FILE_CHUNK_HEADER_LEN) return -1;

    out->chunk_index = unpack_u32(in + 0);
    out->data_len    = unpack_u32(in + 4);
    out->crc32c      = unpack_u32(in + 8);
    out->flags       = in[12];
    if (in[13] != 0 || in[14] != 0 || in[15] != 0) return -1;
    if (out->data_len > SL_FILE_CHUNK_MAX) return -1;
    if (in_len < SL_FILE_CHUNK_HEADER_LEN + (size_t)out->data_len) return -1;

    out->data = (out->data_len > 0)
                   ? (in + SL_FILE_CHUNK_HEADER_LEN) : NULL;
    return 0;
}

bool sl_file_chunk_crc_ok(const sl_file_chunk_t *c) {
    if (!c) return false;
    if (c->data_len == 0) return c->crc32c == 0;
    return sl_crc32c(c->data, c->data_len) == c->crc32c;
}
