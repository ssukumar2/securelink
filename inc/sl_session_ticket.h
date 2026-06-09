#ifndef SECURELINK_SL_SESSION_TICKET_H
#define SECURELINK_SL_SESSION_TICKET_H

/* Session resumption tickets.
 *
 * After a successful handshake, the server may issue a ticket the client
 * can present on a future connection to resume without re-running the
 * full ECDHE+identity flow. The ticket is encrypted by a server-only
 * master ticket key (STK) that the client never sees.
 *
 * On wire the ticket is opaque to the client. Internally:
 *
 *   u32 issued_at_seconds
 *   u32 lifetime_seconds
 *   u8  resumption_secret[32]
 *   u8  peer_identity_pub[32]
 *
 * sealed by AES-256-GCM with a per-ticket random IV; the IV is prepended
 * to the ciphertext so the server can decrypt without state. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_TICKET_PT_LEN    72U
#define SL_TICKET_IV_LEN    12U
#define SL_TICKET_TAG_LEN   16U
#define SL_TICKET_TOTAL_LEN (SL_TICKET_IV_LEN + SL_TICKET_PT_LEN + SL_TICKET_TAG_LEN)

typedef struct {
    uint32_t issued_at_s;
    uint32_t lifetime_s;
    uint8_t  resumption_secret[32];
    uint8_t  peer_identity_pub[32];
} sl_ticket_body_t;

int sl_ticket_seal(const uint8_t          stk[32],
                   const sl_ticket_body_t *body,
                   uint8_t                out[SL_TICKET_TOTAL_LEN]);

int sl_ticket_open(const uint8_t          stk[32],
                   const uint8_t          wire[SL_TICKET_TOTAL_LEN],
                   sl_ticket_body_t      *out);

/* Returns 1 if the ticket is still inside its lifetime window relative
 * to `now_s`; 0 otherwise. */
int sl_ticket_is_fresh(const sl_ticket_body_t *body, uint32_t now_s);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_SESSION_TICKET_H */
