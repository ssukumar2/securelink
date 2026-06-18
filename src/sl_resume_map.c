#include "sl_resume_map.h"

#include <stdlib.h>
#include <string.h>

int sl_resume_map_init(sl_resume_map_t *r, uint32_t total_chunks) {
    if (!r) return -1;
    const size_t bytes = (size_t)((total_chunks + 7U) / 8U);
    r->bits = (uint8_t *)calloc(1, bytes ? bytes : 1);
    if (!r->bits) return -1;
    r->total_chunks    = total_chunks;
    r->received_chunks = 0;
    return 0;
}

void sl_resume_map_free(sl_resume_map_t *r) {
    if (!r) return;
    free(r->bits);
    r->bits = NULL;
    r->total_chunks = r->received_chunks = 0;
}

int sl_resume_map_set(sl_resume_map_t *r, uint32_t chunk_index) {
    if (!r || chunk_index >= r->total_chunks) return -1;
    uint8_t *byte = &r->bits[chunk_index / 8U];
    const uint8_t mask = (uint8_t)(1U << (chunk_index % 8U));
    if ((*byte & mask) == 0) {
        *byte |= mask;
        ++r->received_chunks;
    }
    return 0;
}

bool sl_resume_map_has(const sl_resume_map_t *r, uint32_t chunk_index) {
    if (!r || chunk_index >= r->total_chunks) return false;
    return (r->bits[chunk_index / 8U] >> (chunk_index % 8U)) & 1U;
}

bool sl_resume_map_complete(const sl_resume_map_t *r) {
    return r && r->received_chunks == r->total_chunks;
}

size_t sl_resume_map_missing(const sl_resume_map_t *r,
                             uint32_t *out, size_t out_cap, bool *more) {
    if (more) *more = false;
    if (!r || !out) return 0;
    size_t found = 0;
    for (uint32_t i = 0; i < r->total_chunks; ++i) {
        if (sl_resume_map_has(r, i)) continue;
        if (found < out_cap) {
            out[found++] = i;
        } else {
            if (more) *more = true;
            break;
        }
    }
    return found;
}

int sl_resume_map_serialize(const sl_resume_map_t *r,
                            uint8_t *out, size_t out_cap) {
    if (!r || !out) return -1;
    const size_t bytes = (size_t)((r->total_chunks + 7U) / 8U);
    if (out_cap < bytes) return -1;
    memcpy(out, r->bits, bytes);
    return (int)bytes;
}

int sl_resume_map_deserialize(sl_resume_map_t *r,
                              const uint8_t *in, size_t in_len,
                              uint32_t total_chunks) {
    if (!r || !in) return -1;
    const size_t bytes = (size_t)((total_chunks + 7U) / 8U);
    if (in_len < bytes) return -1;
    if (sl_resume_map_init(r, total_chunks) != 0) return -1;
    memcpy(r->bits, in, bytes);
    r->received_chunks = 0;
    for (uint32_t i = 0; i < total_chunks; ++i) {
        if (sl_resume_map_has(r, i)) ++r->received_chunks;
    }
    return 0;
}
