/* Attack: connection flood.
 *
 * Attacker opens many connections from one IP (or several), never
 * completes the handshake, and tries to exhaust server file descriptors.
 *
 * Defense: sl_dos_guard with per-IP cap, global cap, and stale-sweep.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/attack_dos_flood.c \
 *       src/sl_dos_guard.c \
 *       -o attack_dos_flood
 */

#include <stdio.h>

#include "sl_dos_guard.h"

#define CHECK(cond, name) do {                                    \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL [%s] %s:%d  %s\n",                  \
                name, __FILE__, __LINE__, #cond);                 \
        return 1;                                                 \
    }                                                             \
} while (0)

static int attack_single_ip_caps_out(void) {
    sl_dos_guard_t *g = sl_dos_guard_new(/*per_ip=*/5,
                                         /*global=*/100,
                                         /*half_open_ms=*/5000);
    CHECK(g, "single_ip");

    int admitted = 0;
    for (int i = 0; i < 50; ++i) {
        if (sl_dos_guard_admit(g, "198.51.100.9")) ++admitted;
    }
    CHECK(admitted == 5, "single_ip");
    /* Other IPs unaffected. */
    CHECK(sl_dos_guard_admit(g, "198.51.100.10"), "single_ip");
    sl_dos_guard_free(g);
    printf("attack_dos_flood[single_ip]: BLOCKED (admitted=%d/50)\n", admitted);
    return 0;
}

static int attack_distributed_hits_global_cap(void) {
    sl_dos_guard_t *g = sl_dos_guard_new(/*per_ip=*/2,
                                         /*global=*/10,
                                         /*half_open_ms=*/5000);
    int admitted = 0;
    char ip[32];
    for (int i = 0; i < 100; ++i) {
        snprintf(ip, sizeof(ip), "203.0.113.%d", i);
        if (sl_dos_guard_admit(g, ip)) ++admitted;
    }
    CHECK(admitted == 10, "distributed");
    sl_dos_guard_free(g);
    printf("attack_dos_flood[distributed_global_cap]: BLOCKED at %d\n", admitted);
    return 0;
}

static int sweep_reclaims_stale(void) {
    sl_dos_guard_t *g = sl_dos_guard_new(/*per_ip=*/2,
                                         /*global=*/4,
                                         /*half_open_ms=*/1);  /* 1ms */
    sl_dos_guard_admit(g, "1.1.1.1");
    sl_dos_guard_admit(g, "1.1.1.1");
    sl_dos_guard_admit(g, "2.2.2.2");
    sl_dos_guard_admit(g, "3.3.3.3");

    /* Saturated: 5th admit must fail before sweep. */
    CHECK(!sl_dos_guard_admit(g, "4.4.4.4"), "sweep");

    struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000000L };
    nanosleep(&ts, NULL);
    const size_t reaped = sl_dos_guard_sweep(g);
    CHECK(reaped >= 4, "sweep");
    CHECK(sl_dos_guard_admit(g, "4.4.4.4"), "sweep");
    sl_dos_guard_free(g);
    printf("attack_dos_flood[stale_sweep]: HELD (reaped=%zu)\n", reaped);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= attack_single_ip_caps_out();
    rc |= attack_distributed_hits_global_cap();
    rc |= sweep_reclaims_stale();
    if (rc == 0) puts("attack_dos_flood: ALL DEFENSES HELD");
    return rc;
}
