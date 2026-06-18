#ifndef SECURELINK_SL_RESUME_MAP_H
#define SECURELINK_SL_RESUME_MAP_H

/* Resume bitmap for file transfers.
 *
 * One bit per chunk; bit set means the chunk has been received and
 * verified. Persisting this bitmap alongside the partial file lets a
 * receiver tell the sender exactly which chunks are missing after a
 * disconnect, so retries cost only the gaps. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t  *bits;
    uint32_t  total_chunks;
    uint32_t  received_chunks;
} sl_resume_map_t;

int  sl_resume_map_init(sl_resume_map_t *r, uint32_t total_chunks);
void sl_resume_map_free(sl_resume_map_t *r);

int  sl_resume_map_set(sl_resume_map_t *r, uint32_t chunk_index);
bool sl_resume_map_has(const sl_resume_map_t *r, uint32_t chunk_index);
bool sl_resume_map_complete(const sl_resume_map_t *r);

/* Fill `out` with the indices of the first `out_cap` missing chunks.
 * Returns the number written; sets *more if there are additional gaps. */
size_t sl_resume_map_missing(const sl_resume_map_t *r,
                             uint32_t *out, size_t out_cap, bool *more);

/* Serialize the bitmap into a buffer for persistence. */
int  sl_resume_map_serialize(const sl_resume_map_t *r,
                             uint8_t *out, size_t out_cap);

int  sl_resume_map_deserialize(sl_resume_map_t *r,
                               const uint8_t *in, size_t in_len,
                               uint32_t total_chunks);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_RESUME_MAP_H */
