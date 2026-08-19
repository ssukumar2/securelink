#ifndef SECURELINK_SL_TRACE_FLAGS_H
#define SECURELINK_SL_TRACE_FLAGS_H
#include <stddef.h>

/* Per-span flags propagated along with trace and span IDs.
 *
 * Bit 0: SAMPLED   — span will be exported to the trace backend
 * Bit 1: DEBUG     — verbose collection requested; collectors keep extras
 * Bit 2: SYNTHETIC — synthetic check (probes, health pings); usually
 *                    excluded from latency aggregates */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_TRACE_FLAG_NONE       0x00U
#define SL_TRACE_FLAG_SAMPLED    0x01U
#define SL_TRACE_FLAG_DEBUG      0x02U
#define SL_TRACE_FLAG_SYNTHETIC  0x04U

#define SL_TRACE_FLAGS_MASK      0x07U

typedef uint8_t sl_trace_flags_t;

bool sl_trace_flag_is_set(sl_trace_flags_t f, sl_trace_flags_t bit);
sl_trace_flags_t sl_trace_flags_with (sl_trace_flags_t f, sl_trace_flags_t bit);
sl_trace_flags_t sl_trace_flags_without(sl_trace_flags_t f, sl_trace_flags_t bit);

/* Hex encode flags as exactly 2 lowercase chars; out must have >= 3 bytes. */
int sl_trace_flags_to_hex(sl_trace_flags_t f, char *out, size_t out_cap);
int sl_trace_flags_from_hex(const char *hex, size_t len, sl_trace_flags_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_TRACE_FLAGS_H */
