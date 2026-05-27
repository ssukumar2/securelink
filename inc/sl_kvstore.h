#ifndef SECURELINK_SL_KVSTORE_H
#define SECURELINK_SL_KVSTORE_H

/* Append-only key-value store with in-memory index.
 *
 * Each on-disk record:
 *
 *   varint klen
 *   varint vlen
 *   bytes  key
 *   bytes  value
 *   u32    crc32c(over the above)
 *
 * Newer records shadow older ones with the same key. Deletes write a
 * tombstone record (vlen == 0 and a flag byte). Periodic compaction is
 * an exercise for later. The in-memory index keeps offsets so lookups
 * are O(1) average.
 *
 * Use case: persist client registry, replay-window high-water marks,
 * threat scores, configuration overrides, etc. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sl_kvstore sl_kvstore_t;

sl_kvstore_t *sl_kvstore_open(const char *path);
void          sl_kvstore_close(sl_kvstore_t *kv);

int  sl_kvstore_put(sl_kvstore_t *kv,
                    const void *key, size_t klen,
                    const void *value, size_t vlen);

/* Read into caller-supplied buffer. On success writes the value and sets
 * *vlen_out to its actual length. Returns:
 *    0  on success
 *   -1  on error
 *   -2  if key not found
 *   -3  if `buf_cap` is too small (vlen_out still updated). */
int  sl_kvstore_get(sl_kvstore_t *kv,
                    const void *key, size_t klen,
                    void *buf, size_t buf_cap,
                    size_t *vlen_out);

int  sl_kvstore_delete(sl_kvstore_t *kv,
                       const void *key, size_t klen);

bool   sl_kvstore_has(sl_kvstore_t *kv, const void *key, size_t klen);
size_t sl_kvstore_size(const sl_kvstore_t *kv);

/* Force the underlying file to be flushed and fsynced. */
int  sl_kvstore_sync(sl_kvstore_t *kv);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_KVSTORE_H */
