#include "sl_session_ticket.h"

#include <string.h>

#include "sl_aead.h"
#include "sl_mem.h"
#include "sl_rng.h"

static void pack_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)v;
}

static uint32_t unpack_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static void pack_body(const sl_ticket_body_t *b, uint8_t pt[SL_TICKET_PT_LEN]) {
    pack_u32_be(pt + 0, b->issued_at_s);
    pack_u32_be(pt + 4, b->lifetime_s);
    memcpy(pt + 8,                  b->resumption_secret, 32);
    memcpy(pt + 8 + 32,             b->peer_identity_pub, 32);
}

static void unpack_body(const uint8_t pt[SL_TICKET_PT_LEN], sl_ticket_body_t *b) {
    b->issued_at_s = unpack_u32_be(pt + 0);
    b->lifetime_s  = unpack_u32_be(pt + 4);
    memcpy(b->resumption_secret, pt + 8,        32);
    memcpy(b->peer_identity_pub, pt + 8 + 32,   32);
}

int sl_ticket_seal(const uint8_t          stk[32],
                   const sl_ticket_body_t *body,
                   uint8_t                out[SL_TICKET_TOTAL_LEN]) {
    if (!stk || !body || !out) return -1;

    uint8_t pt[SL_TICKET_PT_LEN];
    pack_body(body, pt);

    /* Random IV in front of ciphertext. */
    if (sl_rng_bytes(out, SL_TICKET_IV_LEN) != 0) {
        sl_secure_zero(pt, sizeof(pt));
        return -1;
    }
    uint8_t *ct  = out + SL_TICKET_IV_LEN;
    uint8_t *tag = ct + SL_TICKET_PT_LEN;

    /* AAD = the IV itself, which binds the ticket to its nonce. */
    int rc = sl_aead_seal(stk, out,
                          out, SL_TICKET_IV_LEN,
                          pt, SL_TICKET_PT_LEN,
                          ct, tag);
    sl_secure_zero(pt, sizeof(pt));
    return rc;
}

int sl_ticket_open(const uint8_t          stk[32],
                   const uint8_t          wire[SL_TICKET_TOTAL_LEN],
                   sl_ticket_body_t      *out) {
    if (!stk || !wire || !out) return -1;

    const uint8_t *iv  = wire;
    const uint8_t *ct  = wire + SL_TICKET_IV_LEN;
    const uint8_t *tag = ct + SL_TICKET_PT_LEN;

    uint8_t pt[SL_TICKET_PT_LEN];
    int rc = sl_aead_open(stk, iv,
                          iv, SL_TICKET_IV_LEN,
                          ct, SL_TICKET_PT_LEN,
                          tag, pt);
    if (rc != 0) {
        sl_secure_zero(pt, sizeof(pt));
        memset(out, 0, sizeof(*out));
        return -1;
    }
    unpack_body(pt, out);
    sl_secure_zero(pt, sizeof(pt));
    return 0;
}

int sl_ticket_is_fresh(const sl_ticket_body_t *body, uint32_t now_s) {
    if (!body || body->lifetime_s == 0) return 0;
    if (now_s < body->issued_at_s) return 0;     /* clock skew / forgery */
    return (now_s - body->issued_at_s) < body->lifetime_s;
}
