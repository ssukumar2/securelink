#ifndef SECURELINK_SL_FILE_META_H
#define SECURELINK_SL_FILE_META_H

/* File transfer metadata.
 *
 * Sent as the first message of a transfer so the receiver knows total
 * size, chunk size, and expected end-to-end hash for verification.
 *
 * Wire layout (big-endian):
 *
 *   u64  total_size
 *   u32  chunk_size
 *   u32  total_chunks
 *   u32  mode            (POSIX permission bits, advisory)
 *   u32  mtime_seconds
 *   u8   sha256[32]      (digest of the whole file, computed by sender)
 *   u16  name_len
 *   ...  name (UTF-8, no NUL)
 *
 * Header without the name is 80 bytes. Receivers MUST verify the digest
 * before accepting the transfer as complete. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_FILE_META_FIXED_LEN  82U   /* without name */
#define SL_FILE_NAME_MAX        256U
#define SL_FILE_CHUNK_MIN       1024U
#define SL_FILE_CHUNK_MAX       65536U

typedef struct {
    uint64_t total_size;
    uint32_t chunk_size;
    uint32_t total_chunks;
    uint32_t mode;
    uint32_t mtime_s;
    uint8_t  sha256[32];
    char     name[SL_FILE_NAME_MAX + 1];
    uint16_t name_len;
} sl_file_meta_t;

int sl_file_meta_pack  (const sl_file_meta_t *m, uint8_t *out, size_t out_cap);
int sl_file_meta_unpack(const uint8_t *in, size_t in_len, sl_file_meta_t *out);

/* Validate semantic constraints (chunk size, name, total chunks math). */
int sl_file_meta_validate(const sl_file_meta_t *m);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_FILE_META_H */
