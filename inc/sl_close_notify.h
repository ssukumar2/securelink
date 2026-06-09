#ifndef SECURELINK_SL_CLOSE_NOTIFY_H
#define SECURELINK_SL_CLOSE_NOTIFY_H

/* Graceful close — also called "close_notify" in TLS terminology.
 *
 * Sending a sealed close_notify alert before tearing down the TCP socket
 * lets the peer distinguish a clean shutdown from a truncation attack
 * (where an attacker fakes RST/FIN to drop in-flight ciphertext).
 *
 * Format: a single SL_REC_ALERT record carrying:
 *   level=fatal, code=SL_ALERT_CLOSE_NOTIFY
 *
 * The caller uses sl_record_seal() with the session keys; this module
 * builds and parses the inner 2-byte payload only. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_CLOSE_NOTIFY_LEN 2U

void sl_close_notify_pack(uint8_t out[SL_CLOSE_NOTIFY_LEN]);

/* Returns 1 if `buf` looks like a close_notify, 0 otherwise. */
int  sl_close_notify_is(const uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_CLOSE_NOTIFY_H */
