#include "sl_file_meta.h"

#include <ctype.h>
#include <string.h>

static void pack_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
static void pack_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)v;
}
static void pack_u64(uint8_t *p, uint64_t v) {
    pack_u32(p,     (uint32_t)(v >> 32));
    pack_u32(p + 4, (uint32_t)v);
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

int sl_file_meta_pack(const sl_file_meta_t *m, uint8_t *out, size_t out_cap) {
    if (!m || !out) return -1;
    if (sl_file_meta_validate(m) != 0) return -1;
    const size_t need = SL_FILE_META_FIXED_LEN + m->name_len;
    if (out_cap < need) return -1;

    pack_u64(out + 0,  m->total_size);
    pack_u32(out + 8,  m->chunk_size);
    pack_u32(out + 12, m->total_chunks);
    pack_u32(out + 16, m->mode);
    pack_u32(out + 20, m->mtime_s);
    memcpy(out + 24, m->sha256, 32);
    pack_u16(out + 56, m->name_len);
    /* 56 + 2 = 58 used so far; pad to 82 with reserved zeros. */
    memset(out + 58, 0, SL_FILE_META_FIXED_LEN - 58);
    memcpy(out + SL_FILE_META_FIXED_LEN, m->name, m->name_len);
    return (int)need;
}

int sl_file_meta_unpack(const uint8_t *in, size_t in_len, sl_file_meta_t *out) {
    if (!in || !out) return -1;
    if (in_len < SL_FILE_META_FIXED_LEN) return -1;

    memset(out, 0, sizeof(*out));
    out->total_size   = unpack_u64(in + 0);
    out->chunk_size   = unpack_u32(in + 8);
    out->total_chunks = unpack_u32(in + 12);
    out->mode         = unpack_u32(in + 16);
    out->mtime_s      = unpack_u32(in + 20);
    memcpy(out->sha256, in + 24, 32);
    out->name_len     = unpack_u16(in + 56);

    if (out->name_len > SL_FILE_NAME_MAX) return -1;
    if (in_len < (size_t)SL_FILE_META_FIXED_LEN + out->name_len) return -1;

    memcpy(out->name, in + SL_FILE_META_FIXED_LEN, out->name_len);
    out->name[out->name_len] = '\0';

    return sl_file_meta_validate(out);
}

int sl_file_meta_validate(const sl_file_meta_t *m) {
    if (!m) return -1;
    if (m->chunk_size < SL_FILE_CHUNK_MIN ||
        m->chunk_size > SL_FILE_CHUNK_MAX) return -1;
    if (m->name_len == 0 || m->name_len > SL_FILE_NAME_MAX) return -1;

    /* Reject any path-traversal characters. Receiver is expected to apply
     * its own sandboxing too, but stopping it here is cheap. */
    for (uint16_t i = 0; i < m->name_len; ++i) {
        const unsigned char c = (unsigned char)m->name[i];
        if (c == '/' || c == '\\' || c == 0) return -1;
        if (i == 0 && c == '.' && m->name_len >= 2 && m->name[1] == '.') {
            return -1;   /* ".." */
        }
        if (c < 0x20) return -1;
    }

    /* total_chunks must equal ceil(total_size / chunk_size). */
    const uint64_t expected =
        (m->total_size + (uint64_t)m->chunk_size - 1) / (uint64_t)m->chunk_size;
    if (m->total_size == 0) {
        if (m->total_chunks != 0) return -1;
    } else if ((uint64_t)m->total_chunks != expected) {
        return -1;
    }
    return 0;
}
