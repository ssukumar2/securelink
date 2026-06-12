/* Tests for sl_flow_control.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_flow_control.c src/sl_flow_control.c \
 *       -o test_sl_flow_control
 */

#include <stdio.h>

#include "sl_flow_control.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_initial_window_default(void) {
    sl_flow_ctrl_t fc;
    sl_flow_init(&fc);
    CHECK(fc.send_credit == (int64_t)SL_FC_INITIAL_WINDOW);
    CHECK(fc.recv_window == (int64_t)SL_FC_INITIAL_WINDOW);
    return 0;
}

static int test_charge_send_decrements(void) {
    sl_flow_ctrl_t fc;
    sl_flow_init_with(&fc, 1000);
    CHECK(sl_flow_charge_send(&fc, 300) == 0);
    CHECK(fc.send_credit == 700);
    CHECK(sl_flow_charge_send(&fc, 700) == 0);
    CHECK(fc.send_credit == 0);
    CHECK(sl_flow_charge_send(&fc, 1) != 0);
    return 0;
}

static int test_grant_send_restores(void) {
    sl_flow_ctrl_t fc;
    sl_flow_init_with(&fc, 100);
    sl_flow_charge_send(&fc, 80);
    CHECK(sl_flow_grant_send(&fc, 50) == 0);
    CHECK(fc.send_credit == 70);
    return 0;
}

static int test_grant_cap(void) {
    sl_flow_ctrl_t fc;
    sl_flow_init_with(&fc, 100);
    CHECK(sl_flow_grant_send(&fc, SL_FC_MAX_WINDOW) != 0);
    return 0;
}

static int test_charge_recv_overflow_rejects(void) {
    sl_flow_ctrl_t fc;
    sl_flow_init_with(&fc, 100);
    /* Peer tries to send 200 when we advertised 100 — protocol violation. */
    CHECK(sl_flow_charge_recv(&fc, 200) != 0);
    /* Original window untouched on failure. */
    CHECK(fc.recv_window == 100);
    return 0;
}

static int test_can_send_predicate(void) {
    sl_flow_ctrl_t fc;
    sl_flow_init_with(&fc, 50);
    CHECK(sl_flow_can_send(&fc, 50));
    CHECK(!sl_flow_can_send(&fc, 51));
    sl_flow_charge_send(&fc, 30);
    CHECK(sl_flow_can_send(&fc, 20));
    CHECK(!sl_flow_can_send(&fc, 21));
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_initial_window_default();
    rc |= test_charge_send_decrements();
    rc |= test_grant_send_restores();
    rc |= test_grant_cap();
    rc |= test_charge_recv_overflow_rejects();
    rc |= test_can_send_predicate();
    if (rc == 0) puts("test_sl_flow_control: OK");
    return rc;
}
