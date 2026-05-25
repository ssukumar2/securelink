/* Tests for lockout, dos_guard, pow, input_sanitize.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_security_modules.c \
 *       src/sl_lockout.c src/sl_dos_guard.c src/sl_pow.c \
 *       src/sl_input_sanitize.c src/sl_rng.c \
 *       -lcrypto -o test_security_modules
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sl_dos_guard.h"
#include "sl_input_sanitize.h"
#include "sl_lockout.h"
#include "sl_pow.h"
#include "sl_rng.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_lockout_threshold(void) {
    sl_lockout_t *L = sl_lockout_new(50, 1000, 3);
    CHECK(L != NULL);
    CHECK(sl_lockout_check(L, "1.2.3.4") == SL_LOCKOUT_ALLOW);
    CHECK(sl_lockout_fail (L, "1.2.3.4") == SL_LOCKOUT_ALLOW);  /* 1 */
    CHECK(sl_lockout_fail (L, "1.2.3.4") == SL_LOCKOUT_ALLOW);  /* 2 */
    CHECK(sl_lockout_fail (L, "1.2.3.4") == SL_LOCKOUT_BLOCKED);/* 3 = threshold */
    CHECK(sl_lockout_check(L, "1.2.3.4") == SL_LOCKOUT_BLOCKED);
    /* Different IP unaffected. */
    CHECK(sl_lockout_check(L, "5.6.7.8") == SL_LOCKOUT_ALLOW);
    sl_lockout_succeed(L, "1.2.3.4");
    CHECK(sl_lockout_check(L, "1.2.3.4") == SL_LOCKOUT_ALLOW);
    sl_lockout_free(L);
    return 0;
}

static int test_dos_guard_caps(void) {
    sl_dos_guard_t *g = sl_dos_guard_new(2, 5, 1000);
    CHECK(g != NULL);
    CHECK(sl_dos_guard_admit(g, "1.1.1.1"));
    CHECK(sl_dos_guard_admit(g, "1.1.1.1"));
    CHECK(!sl_dos_guard_admit(g, "1.1.1.1"));   /* per-IP cap */
    CHECK(sl_dos_guard_admit(g, "2.2.2.2"));
    CHECK(sl_dos_guard_admit(g, "3.3.3.3"));
    CHECK(sl_dos_guard_admit(g, "4.4.4.4"));
    CHECK(!sl_dos_guard_admit(g, "5.5.5.5"));   /* global cap */
    sl_dos_guard_release(g, "1.1.1.1");
    CHECK(sl_dos_guard_admit(g, "5.5.5.5"));
    sl_dos_guard_free(g);
    return 0;
}

static int test_pow_round_trip(void) {
    sl_rng_init();
    uint8_t challenge[SL_POW_CHALLENGE_LEN];
    CHECK(sl_pow_make_challenge(challenge) == 0);

    uint8_t nonce[SL_POW_NONCE_LEN];
    /* Difficulty 10 bits ~ 1024 hashes on average; cap generously. */
    CHECK(sl_pow_solve(challenge, 10, 1000000, nonce) == 0);
    CHECK(sl_pow_verify(challenge, nonce, 10));
    /* Different challenge => same nonce should not verify. */
    challenge[0] ^= 0xFF;
    CHECK(!sl_pow_verify(challenge, nonce, 10));
    return 0;
}

static int test_input_sanitize(void) {
    CHECK(sl_in_range_size(5, 1, 10));
    CHECK(!sl_in_range_size(0, 1, 10));
    CHECK(!sl_in_range_size(11, 1, 10));

    CHECK(sl_is_printable_ascii((const uint8_t *)"hello", 5));
    CHECK(!sl_is_printable_ascii((const uint8_t *)"a\x01b", 3));

    CHECK(sl_is_valid_utf8((const uint8_t *)"abc", 3));
    const uint8_t bad_overlong[] = {0xC0, 0xAF};            /* overlong '/' */
    CHECK(!sl_is_valid_utf8(bad_overlong, 2));
    const uint8_t surrogate[] = {0xED, 0xA0, 0x80};          /* U+D800 */
    CHECK(!sl_is_valid_utf8(surrogate, 3));

    CHECK(sl_has_metachars((const uint8_t *)"rm -rf /", 8));
    CHECK(!sl_has_metachars((const uint8_t *)"alphaNum123", 11));

    size_t r = 0;
    CHECK(sl_size_add_safe(10, 20, &r) && r == 30);
    CHECK(!sl_size_add_safe(SIZE_MAX, 1, &r));
    CHECK(sl_size_mul_safe(7, 6, &r) && r == 42);
    CHECK(!sl_size_mul_safe(SIZE_MAX / 2 + 1, 3, &r));
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_lockout_threshold();
    rc |= test_dos_guard_caps();
    rc |= test_pow_round_trip();
    rc |= test_input_sanitize();
    if (rc == 0) puts("test_security_modules: OK");
    return rc;
}
