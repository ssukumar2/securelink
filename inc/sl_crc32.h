#ifndef SECURELINK_SL_CRC32_H
#define SECURELINK_SL_CRC32_H

/* CRC-32C (Castagnoli, polynomial 0x1EDC6F41). Used for integrity checking
 * of persistent records and snapshots. Not a substitute for the AEAD tag
 * on wire data — purely a corruption check for on-disk artefacts.
 *
 * Implementation is a 256-entry lookup table, byte-at-a-time. Fast enough
 * for log-write paths; the hardware-accelerated CRC32C instructions can
 * be wired in later behind the same API. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compute CRC-32C over a single buffer. */
uint32_t sl_crc32c(const void *data, size_t len);

/* Streaming API for chained buffers. Pass 0 as initial `crc`. */
uint32_t sl_crc32c_init(void);
uint32_t sl_crc32c_update(uint32_t crc, const void *data, size_t len);
uint32_t sl_crc32c_finalize(uint32_t crc);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_CRC32_H */
