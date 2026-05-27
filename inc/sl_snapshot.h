#ifndef SECURELINK_SL_SNAPSHOT_H
#define SECURELINK_SL_SNAPSHOT_H

/* Atomic snapshot writer.
 *
 * Writes a payload to `path.tmp`, fsyncs, then renames over `path`. On
 * a POSIX filesystem this gives an all-or-nothing replacement — readers
 * either see the old file or the new file, never a half-written one.
 *
 * On top of that we wrap the payload in a tiny header:
 *
 *   magic[4]   = "SLSS"
 *   version    = 1 (u32 BE)
 *   payload_len (u64 BE)
 *   payload    (payload_len bytes)
 *   crc32c     (u32 BE, over header+payload)
 *
 * sl_snapshot_load() verifies the magic, version, length, and CRC. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_SNAPSHOT_MAGIC   "SLSS"
#define SL_SNAPSHOT_VERSION 1U

int sl_snapshot_save(const char *path,
                     const void *payload, size_t payload_len);

/* Load into a caller-supplied buffer. Returns 0 on success and writes the
 * actual length to *out_len. Returns -1 on I/O or CRC errors, -2 if the
 * buffer is too small (out_len is still set so caller can retry). */
int sl_snapshot_load(const char *path,
                     void *buf, size_t buf_cap, size_t *out_len);

/* Verify integrity without loading the payload. */
int sl_snapshot_verify(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_SNAPSHOT_H */
