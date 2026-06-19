/* Attack: credential brute-force.
 *
 * Attacker pounds the same IP against the lockout subsystem with bad
 * attempts, hoping to find a successful one before being throttled.
 *
 * Defense: sl_lockout with threshold + exponential backoff.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/attack_brute_force.c \
 *       src/sl_lockout.c \
 *       -o attack_brute_force
 */

#include <stdio.h>

#include "sl_lockout.h"

#define CHECK(cond, name) do {                                    \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL [%s] %s:%d  %s\n",                  \
                name, __FILE__, __LINE__, #cond);                 \
        return 1;                                                 \
    }                                                             \
} while (0)

static int attack_rapid_fire(void) {
    /* threshold=3 means the 3rd consecutive fail locks out. */
    sl_lockout_t *L = sl_lockout_new(60000, 3600000, 3);
    CHECK(L, "rapid_fire");

    const char *ip = "203.0.113.7";
    int blocked_at = -1;
    for (int i = 0; i < 50; ++i) {
        sl_lockout_status_t s = sl_lockout_fail(L, ip);
        if (s == SL_LOCKOUT_BLOCKED) { blocked_at = i + 1; break; }
    }
    CHECK(blocked_at == 3, "rapid_fire");

    /* Further attempts should all be blocked without contributing more. */
    int blocked_count = 0;
    for (int i = 0; i < 100; ++i) {
        if (sl_lockout_check(L, ip) == SL_LOCKOUT_BLOCKED) ++blocked_count;
    }
    CHECK(blocked_count == 100, "rapid_fire");
    sl_lockout_free(L);
    printf("attack_brute_force[rapid_fire]: BLOCKED at attempt %d\n", blocked_at);
    return 0;
}

static int attack_distributed_does_not_lock_others(void) {
    /* One bad actor must not lock out unrelated peers. */
    sl_lockout_t *L = sl_lockout_new(60000, 3600000, 3);
    sl_lockout_fail(L, "10.0.0.1");
    sl_lockout_fail(L, "10.0.0.1");
    sl_lockout_fail(L, "10.0.0.1");
    CHECK(sl_lockout_check(L, "10.0.0.1") == SL_LOCKOUT_BLOCKED, "isolation");
    CHECK(sl_lockout_check(L, "10.0.0.2") == SL_LOCKOUT_ALLOW,   "isolation");
    sl_lockout_free(L);
    printf("attack_brute_force[isolation]: HELD (collateral safe)\n");
    return 0;
}

static int success_clears_state(void) {
    sl_lockout_t *L = sl_lockout_new(60000, 3600000, 3);
    sl_lockout_fail(L, "ip");
    sl_lockout_fail(L, "ip");
    sl_lockout_succeed(L, "ip");
    /* After success, we should be back to a clean slate. */
    for (int i = 0; i < 2; ++i) {
        CHECK(sl_lockout_fail(L, "ip") == SL_LOCKOUT_ALLOW, "reset");
    }
    sl_lockout_free(L);
    printf("attack_brute_force[reset_on_success]: HELD\n");
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= attack_rapid_fire();
    rc |= attack_distributed_does_not_lock_others();
    rc |= success_clears_state();
    if (rc == 0) puts("attack_brute_force: ALL DEFENSES HELD");
    return rc;
}
