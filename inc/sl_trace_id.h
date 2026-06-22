#ifndef SECURELINK_SL_TRACE_ID_H
#define SECURELINK_SL_TRACE_ID_H

/* 128-bit trace IDs and 64-bit span IDs, mirroring the W3C Trace Context
 * convention so traces are interoperable with external collectors.
 *
 * Wire format on disk and over the network is lower-case hex with no
 * separators (32 chars for trace, 16 chars for span). The all-zero ID
 * is reserved as "no trace" / "no parent". */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_TRACE_ID_LEN     16U
#define SL_TRACE_ID_HEX_LEN 32U
#define SL_SPAN_ID_LEN       8U
#define SL_SPAN_ID_HEX_LEN  16U

typedef struct { uint8_t bytes[SL_TRACE_ID_LEN]; } sl_trace_id_t;
typedef struct { uint8_t bytes[SL_SPAN_ID_LEN];  } sl_span_id_t;

int  sl_trace_id_random(sl_trace_id_t *out);
int  sl_span_id_random (sl_span_id_t *out);

bool sl_trace_id_is_zero(const sl_trace_id_t *id);
bool sl_span_id_is_zero (const sl_span_id_t *id);

/* Hex encoding. `out` must be at least HEX_LEN + 1 bytes; result is NUL-
 * terminated. */
int  sl_trace_id_to_hex(const sl_trace_id_t *id, char *out, size_t out_cap);
int  sl_span_id_to_hex (const sl_span_id_t *id,  char *out, size_t out_cap);

/* Parse exactly HEX_LEN lowercase hex chars. Returns 0 on success. */
int  sl_trace_id_from_hex(const char *hex, size_t len, sl_trace_id_t *out);
int  sl_span_id_from_hex (const char *hex, size_t len, sl_span_id_t  *out);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_TRACE_ID_H */
