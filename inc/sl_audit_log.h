#ifndef SECURELINK_SL_AUDIT_LOG_H
#define SECURELINK_SL_AUDIT_LOG_H

/* Append-only hash-chained audit log.
 *
 * Each entry stores:
 *
 *   prev_hash || timestamp_ms || event_code || payload
 *
 * and the file records SHA-256(prev_hash || entry_body) immediately after
 * the entry. An attacker who modifies any past entry breaks the chain
 * and verification of subsequent entries fails.
 *
 * This is the standard pattern from forensic logging: it does not stop
 * an attacker from deleting log lines, but they cannot rewrite history
 * silently. Combine with offsite log shipping for stronger guarantees.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SL_AUDIT_HANDSHAKE_OK    = 1,
    SL_AUDIT_HANDSHAKE_FAIL  = 2,
    SL_AUDIT_AUTH_FAIL       = 3,
    SL_AUDIT_REPLAY          = 4,
    SL_AUDIT_RATE_LIMIT      = 5,
    SL_AUDIT_LOCKOUT         = 6,
    SL_AUDIT_KEY_ROTATE      = 7,
    SL_AUDIT_QUARANTINE      = 8,
    SL_AUDIT_ANOMALY         = 9,
    SL_AUDIT_SHUTDOWN        = 10,
} sl_audit_event_t;

typedef struct sl_audit_log sl_audit_log_t;

sl_audit_log_t *sl_audit_log_open(const char *path);
void            sl_audit_log_close(sl_audit_log_t *L);

/* Append an event with a short text payload. Returns 0 on success. */
int sl_audit_log_append(sl_audit_log_t *L,
                        sl_audit_event_t event,
                        const char *payload);

/* Verify the hash chain of an existing log file at `path`.
 * Returns 0 if intact, -1 if the file is tampered or truncated. */
int sl_audit_log_verify(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_AUDIT_LOG_H */
