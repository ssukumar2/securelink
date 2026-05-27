#ifndef SECURELINK_SL_VARINT_H
#define SECURELINK_SL_VARINT_H

/* Unsigned LEB128 / protobuf-style varint encoding for compact persistence.
 *
 * Each byte stores 7 bits of payload; the top bit is the continuation flag.
 * Small integers cost 1 byte, 14-bit values cost 2, etc. Maximum encoded
 * size for uint64_t is 10 bytes. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_VARINT_MAX_LEN 10

/* Encode `v` into `out`. Returns bytes written, or -1 if `out_cap < needed`. */
int sl_varint_encode_u64(uint64_t v, uint8_t *out, size_t out_cap);

/* Decode a varint from `in`. On success writes the value to `*out` and
 * returns the number of bytes consumed. Returns -1 on malformed/truncated. */
int sl_varint_decode_u64(const uint8_t *in, size_t in_len, uint64_t *out);

/* Cheap size predictor without writing. */
int sl_varint_size_u64(uint64_t v);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_VARINT_H */
