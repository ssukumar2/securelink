/* Tests for sl_packet_mutator.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_packet_mutator.c src/sl_packet_mutator.c \
 *       -o test_sl_packet_mutator
 */

#include <stdio.h>
#include <string.h>

#include "sl_packet_mutator.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_same_seed_deterministic(void) {
    sl_mut_rng_t a, b;
    sl_mut_rng_seed(&a, 12345);
    sl_mut_rng_seed(&b, 12345);
    for (int i = 0; i < 100; ++i) {
        CHECK(sl_mut_rng_next(&a) == sl_mut_rng_next(&b));
    }
    return 0;
}

static int test_flip_bit_changes_buffer(void) {
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    sl_mut_rng_t r; sl_mut_rng_seed(&r, 1);
    sl_mut_flip_bit(&r, buf, sizeof(buf));
    int nonzero = 0;
    for (int i = 0; i < 16; ++i) if (buf[i]) ++nonzero;
    CHECK(nonzero == 1);
    return 0;
}

static int test_flip_n_bits(void) {
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    sl_mut_rng_t r; sl_mut_rng_seed(&r, 2);
    sl_mut_flip_bits(&r, buf, sizeof(buf), 10);
    /* Up to 10 unique bits flipped — some may collide but it's <=10. */
    int popcount = 0;
    for (int i = 0; i < 64; ++i) {
        uint8_t b = buf[i];
        while (b) { popcount += (b & 1); b >>= 1; }
    }
    CHECK(popcount >= 1 && popcount <= 10);
    return 0;
}

static int test_overwrite_range_check(void) {
    uint8_t buf[8] = {0};
    sl_mut_rng_t r; sl_mut_rng_seed(&r, 3);
    CHECK(sl_mut_overwrite(&r, buf, sizeof(buf), 0, 8) == 0);
    CHECK(sl_mut_overwrite(&r, buf, sizeof(buf), 4, 8) != 0);
    CHECK(sl_mut_overwrite(&r, buf, sizeof(buf), 9, 1) != 0);
    return 0;
}

static int test_truncate(void) {
    CHECK(sl_mut_truncate(10, 0)  == 10);
    CHECK(sl_mut_truncate(10, 3)  == 7);
    CHECK(sl_mut_truncate(10, 10) == 0);
    CHECK(sl_mut_truncate(10, 99) == 0);
    return 0;
}

static int test_swap_bytes(void) {
    uint8_t buf[4] = {1, 2, 3, 4};
    sl_mut_rng_t r; sl_mut_rng_seed(&r, 4);
    sl_mut_swap_bytes(&r, buf, sizeof(buf));
    int sum = 0;
    for (int i = 0; i < 4; ++i) sum += buf[i];
    CHECK(sum == 1 + 2 + 3 + 4);   /* swap preserves multiset */
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_same_seed_deterministic();
    rc |= test_flip_bit_changes_buffer();
    rc |= test_flip_n_bits();
    rc |= test_overwrite_range_check();
    rc |= test_truncate();
    rc |= test_swap_bytes();
    if (rc == 0) puts("test_sl_packet_mutator: OK");
    return rc;
}
