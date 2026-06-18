#ifndef SECURELINK_SL_FILE_CHUNK_H
#define SECURELINK_SL_FILE_CHUNK_H

/* File chunk wire format.
 *
 *   u32  chunk_index    (0-based)
 *   u32  data_len       (must be <= sl_file_meta.chunk_size)
 *   u32  crc32c         (over data_len bytes of `data`)
 *   u8   flags          (bit 0 = LAST)
 *   u8   reserved[3]    (must be 0)
 *   ...  data (data_len bytes)
 *
 * Header is 16 bytes. CRC is for transport-corruption detection;
 * end-to-end authenticity comes from the outer AEAD and the SHA-256
 * carried in sl_file_meta. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_FILE_CHUNK_HEADER_LEN 16U

#define SL_FILE_CHUNK_FLAG_NONE   0x00
#define SL_FILE_CHUNK_FLAG_LAST   0x01

typedef struct {
    uint32_t       chunk_index;
    uint32_t       data_len;
    uint32_t       crc32c;
    uint8_t        flags;
    const uint8_t *data;
} sl_file_chunk_t;

int sl_file_chunk_pack  (const sl_file_chunk_t *c,
                         uint8_t *out, size_t out_cap);

/* Parse a chunk frame. `c->data` will point into `in`. */
int sl_file_chunk_unpack(const uint8_t *in, size_t in_len,
                         sl_file_chunk_t *out);

/* Verify the CRC field matches the data. Returns true on success. */
bool sl_file_chunk_crc_ok(const sl_file_chunk_t *c);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_FILE_CHUNK_H */
