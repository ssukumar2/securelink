#ifndef SECURELINK_SL_ATOMIC_FILE_H
#define SECURELINK_SL_ATOMIC_FILE_H

/* Atomic file write helpers. Independent of sl_snapshot — those add
 * a framed header; these are raw write-and-rename.
 *
 * sl_atomic_write_bytes: writes the buffer to `path.tmp` then renames.
 * sl_atomic_append_line: open-O_APPEND write of a single line, with
 *                       implicit newline and a single write(2) call to
 *                       avoid interleaving between processes/threads.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int sl_atomic_write_bytes(const char *path,
                          const void *data, size_t len,
                          int do_fsync);

int sl_atomic_append_line(const char *path, const char *line);

/* Read the entire file into a newly-allocated buffer. Caller frees with
 * free(). Returns 0 on success, sets *out_data and *out_len. */
int sl_read_all(const char *path, uint8_t **out_data, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_ATOMIC_FILE_H */
