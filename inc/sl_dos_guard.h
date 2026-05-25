#ifndef SECURELINK_SL_DOS_GUARD_H
#define SECURELINK_SL_DOS_GUARD_H

/* Denial-of-service guards at the connection layer.
 *
 *  - Caps simultaneous half-open connections per source IP.
 *  - Tracks total in-flight connections and rejects new ones above a
 *    global cap to prevent file-descriptor exhaustion.
 *  - Provides a cheap "is this IP currently abusive" predicate that the
 *    accept loop can call before allocating per-connection state.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sl_dos_guard sl_dos_guard_t;

sl_dos_guard_t *sl_dos_guard_new(uint32_t max_per_ip,
                                 uint32_t max_global,
                                 uint32_t half_open_timeout_ms);
void            sl_dos_guard_free(sl_dos_guard_t *g);

/* Call when accepting a new connection. Returns true if allowed; on true
 * the connection is registered as half-open. On false the caller must
 * close the socket immediately without further work. */
bool sl_dos_guard_admit(sl_dos_guard_t *g, const char *peer_ip);

/* Call once the handshake completes successfully — promotes the entry
 * out of the half-open pool. */
void sl_dos_guard_promote(sl_dos_guard_t *g, const char *peer_ip);

/* Call when the connection is closed for any reason. */
void sl_dos_guard_release(sl_dos_guard_t *g, const char *peer_ip);

/* Sweep half-open entries older than half_open_timeout_ms and free them. */
size_t sl_dos_guard_sweep(sl_dos_guard_t *g);

uint32_t sl_dos_guard_global_inflight(const sl_dos_guard_t *g);
uint32_t sl_dos_guard_per_ip(const sl_dos_guard_t *g, const char *peer_ip);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_DOS_GUARD_H */
