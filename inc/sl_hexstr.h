#ifndef SECURELINK_SL_HEXSTR_H
#define SECURELINK_SL_HEXSTR_H

/* Hex string conversion helpers. Independent of the C++ hexdump utility.
 *
 * Encoding writes 2 hex chars per byte, no separators. Decoding accepts
 * upper or lowercase but rejects mixed nibbles with non-hex characters. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Encode `in` (len bytes) into `out` as lowercase hex.
 * `out_cap` must be >= 2*len + 1. Returns bytes written excluding NUL. */
int sl_hexstr_encode(const uint8_t *in, size_t len,
                     char *out, size_t out_cap);

/* Decode `in` (must be 2*expected_len hex chars, no separators) into
 * `out`. Returns 0 on success, -1 on malformed input. */
int sl_hexstr_decode(const char *in, uint8_t *out, size_t expected_len);

/* Constant-time hex compare of two equal-length hex strings.
 * Both must be 2*n hex chars. Returns 1 if equal, 0 otherwise. */
int sl_hexstr_ct_equal(const char *a, const char *b, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_HEXSTR_H */
