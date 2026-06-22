#ifndef SECURELINK_SL_SPAN_KIND_H
#define SECURELINK_SL_SPAN_KIND_H

/* Span kinds describe a span's relationship to its peers, mirroring the
 * OpenTelemetry vocabulary so traces can be exported into existing
 * collectors. Status codes describe the outcome of the operation. */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SL_SPAN_INTERNAL = 0,   /* operation entirely within the process */
    SL_SPAN_SERVER   = 1,   /* handling an inbound RPC */
    SL_SPAN_CLIENT   = 2,   /* making an outbound RPC */
    SL_SPAN_PRODUCER = 3,   /* publishing to a stream/queue */
    SL_SPAN_CONSUMER = 4,   /* receiving from a stream/queue */
} sl_span_kind_t;

typedef enum {
    SL_SPAN_STATUS_UNSET = 0,
    SL_SPAN_STATUS_OK    = 1,
    SL_SPAN_STATUS_ERROR = 2,
} sl_span_status_t;

const char *sl_span_kind_name  (sl_span_kind_t k);
const char *sl_span_status_name(sl_span_status_t s);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_SPAN_KIND_H */
