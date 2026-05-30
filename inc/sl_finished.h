#ifndef SECURELINK_SL_FINISHED_H
#define SECURELINK_SL_FINISHED_H

/* Finished MAC: HMAC-SHA256 over the transcript hash, keyed by a value
 * derived via HKDF from the handshake shared secret. Each side proves
 * to the other that it sees the same handshake transcript AND knows the
 * same secret. Failure of this check terminates the handshake.
 *
 * The "finished key" for each direction is derived using a label:
 *   client_finished_key = HKDF-Expand(secret, "securelink v1 c2s finished")
 *   server_finished_key = HKDF-Expand(secret, "securelink v1 s2c finished") */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_FINISHED_LEN 32

int sl_finished_derive_key(const uint8_t *handshake_secret, size_t hs_len,
                           int is_server,
                           uint8_t out_key[SL_FINISHED_LEN]);

int sl_finished_compute(const uint8_t finished_key[SL_FINISHED_LEN],
                        const uint8_t transcript_hash[32],
                        uint8_t out_mac[SL_FINISHED_LEN]);

/* Constant-time verify of a received MAC. Returns 0 if match. */
int sl_finished_verify(const uint8_t finished_key[SL_FINISHED_LEN],
                       const uint8_t transcript_hash[32],
                       const uint8_t received_mac[SL_FINISHED_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_FINISHED_H */
