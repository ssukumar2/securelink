#ifndef SECURELINK_SL_ID_H
#define SECURELINK_SL_ID_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Generate a non-zero random 64-bit client identifier.
 * Returns 0 on success. The output is suitable for use as `client_id`
 * in beacons; it avoids the zero value which is reserved/uninitialized. */
int sl_id_random_u64(uint64_t *out);

/* Format a 64-bit ID as a 16-char lowercase hex string into `buf`.
 * `buf` must be at least 17 bytes (16 hex + NUL). */
int sl_id_to_hex(uint64_t id, char buf[17]);

/* Parse 16-char lowercase/uppercase hex string into a uint64_t.
 * Returns 0 on success, -1 on malformed input. */
int sl_id_from_hex(const char *hex, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_ID_H */
