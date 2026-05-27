#ifndef SECURELINK_SL_EVENT_LOG_H
#define SECURELINK_SL_EVENT_LOG_H

/* Deterministic ordered event log for replay/debugging.
 *
 * Distinct from sl_audit_log (which is hash-chained for tamper-evidence)
 * and the leveled sl_log (which is human-readable). This log is binary,
 * compact, and structured for machine consumption:
 *
 *   varint  monotonic_seq
 *   varint  timestamp_ns
 *   varint  event_type
 *   varint  payload_len
 *   bytes   payload
 *   u32     crc32c(record)
 *
 * Use to feed the replay harness, drive deterministic tests against
 * captured traffic, or debug a server's decision sequence post-hoc. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SL_EV_CONN_ACCEPTED  = 1,
    SL_EV_CONN_CLOSED    = 2,
    SL_EV_HANDSHAKE_OK   = 3,
    SL_EV_HANDSHAKE_FAIL = 4,
    SL_EV_BEACON_OK      = 5,
    SL_EV_BEACON_REJECT  = 6,
    SL_EV_KEY_ROTATE     = 7,
    SL_EV_QUARANTINE     = 8,
    SL_EV_RATE_LIMIT     = 9,
    SL_EV_INTERNAL       = 99,
} sl_event_type_t;

typedef struct sl_event_log sl_event_log_t;

sl_event_log_t *sl_event_log_open(const char *path);
void            sl_event_log_close(sl_event_log_t *L);

int sl_event_log_append(sl_event_log_t *L,
                        sl_event_type_t type,
                        const void *payload, size_t payload_len);

uint64_t sl_event_log_seq(const sl_event_log_t *L);

/* Iteration */
typedef struct {
    uint64_t        seq;
    uint64_t        timestamp_ns;
    sl_event_type_t type;
    const uint8_t  *payload;
    size_t          payload_len;
} sl_event_record_t;

typedef int (*sl_event_visitor_fn)(const sl_event_record_t *rec, void *user);

/* Visit each record in order. The visitor must not retain `payload`
 * past return. Stops early if visitor returns non-zero. */
int sl_event_log_iterate(const char *path,
                         sl_event_visitor_fn visitor,
                         void *user);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_EVENT_LOG_H */
