#ifndef SECURELINK_SL_PRIORITY_H
#define SECURELINK_SL_PRIORITY_H

/* Stream priority bands.
 *
 * When many streams have data to send and only finite bandwidth, the
 * scheduler picks which stream gets the next slot. Five priority bands
 * are exposed; within a band streams are served round-robin.
 *
 *   URGENT      — control plane, alerts, key updates
 *   HIGH        — interactive request/response, RPC
 *   NORMAL      — default
 *   LOW         — bulk upload, prefetch
 *   BACKGROUND  — telemetry, log shipping
 *
 * The priority is advisory: peers send a hint; the local scheduler
 * decides locally. No cryptographic significance. */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SL_PRIO_URGENT     = 0,
    SL_PRIO_HIGH       = 1,
    SL_PRIO_NORMAL     = 2,
    SL_PRIO_LOW        = 3,
    SL_PRIO_BACKGROUND = 4,
} sl_priority_t;

#define SL_PRIORITY_COUNT 5

const char *sl_priority_name(sl_priority_t p);

/* Map a stream-id parity / type hint to a sensible default priority.
 * Control streams always go to URGENT; everything else to NORMAL. */
sl_priority_t sl_priority_default_for(uint32_t stream_id);

/* Pack/unpack 1-byte priority on the wire. Clamps out-of-range values
 * to NORMAL rather than rejecting (graceful evolution). */
uint8_t       sl_priority_to_byte(sl_priority_t p);
sl_priority_t sl_priority_from_byte(uint8_t b);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_PRIORITY_H */
