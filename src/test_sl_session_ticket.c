/* Tests for sl_session_ticket.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_session_ticket.c src/sl_session_ticket.c \
 *       src/sl_aead.c src/sl_mem.c src/sl_rng.c \
 *       -lcrypto -o test_sl_session_ticket
 */

#include <stdio.h>
#include <string.h>

#include "sl_session_ticket.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static void fill_body(sl_ticket_body_t *b, uint32_t now) {
    b->issued_at_s = now;
    b->lifetime_s  = 3600;
    for (int i = 0; i < 32; ++i) b->resumption_secret[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 32; ++i) b->peer_identity_pub[i] = (uint8_t)(0x80 | i);
}

static int test_seal_open_roundtrip(void) {
    uint8_t stk[32];
    for (int i = 0; i < 32; ++i) stk[i] = (uint8_t)i;

    sl_ticket_body_t src;
    fill_body(&src, 1000);

    uint8_t wire[SL_TICKET_TOTAL_LEN];
    CHECK(sl_ticket_seal(stk, &src, wire) == 0);

    sl_ticket_body_t dst;
    CHECK(sl_ticket_open(stk, wire, &dst) == 0);
    CHECK(dst.issued_at_s == src.issued_at_s);
    CHECK(dst.lifetime_s  == src.lifetime_s);
    CHECK(memcmp(dst.resumption_secret, src.resumption_secret, 32) == 0);
    CHECK(memcmp(dst.peer_identity_pub, src.peer_identity_pub, 32) == 0);
    return 0;
}

static int test_wrong_stk_fails(void) {
    uint8_t stk1[32] = {0}; stk1[0] = 1;
    uint8_t stk2[32] = {0}; stk2[0] = 2;

    sl_ticket_body_t src; fill_body(&src, 1000);
    uint8_t wire[SL_TICKET_TOTAL_LEN];
    CHECK(sl_ticket_seal(stk1, &src, wire) == 0);

    sl_ticket_body_t dst;
    CHECK(sl_ticket_open(stk2, wire, &dst) != 0);
    return 0;
}

static int test_tamper_detected(void) {
    uint8_t stk[32] = {0};
    sl_ticket_body_t src; fill_body(&src, 1000);
    uint8_t wire[SL_TICKET_TOTAL_LEN];
    sl_ticket_seal(stk, &src, wire);

    /* Flip a byte inside the ciphertext. */
    wire[SL_TICKET_IV_LEN + 10] ^= 0x01;
    sl_ticket_body_t dst;
    CHECK(sl_ticket_open(stk, wire, &dst) != 0);
    return 0;
}

static int test_freshness_check(void) {
    sl_ticket_body_t b; fill_body(&b, 1000);
    CHECK(sl_ticket_is_fresh(&b, 1000) == 1);
    CHECK(sl_ticket_is_fresh(&b, 1000 + 3599) == 1);
    CHECK(sl_ticket_is_fresh(&b, 1000 + 3600) == 0);
    CHECK(sl_ticket_is_fresh(&b, 999) == 0);          /* clock skew */
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_seal_open_roundtrip();
    rc |= test_wrong_stk_fails();
    rc |= test_tamper_detected();
    rc |= test_freshness_check();
    if (rc == 0) puts("test_sl_session_ticket: OK");
    return rc;
}
