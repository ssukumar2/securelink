/* Tests for sl_version.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_version.c src/sl_version.c -o test_sl_version
 */

#include <stdio.h>
#include <string.h>

#include "sl_version.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_add_and_has(void) {
    sl_version_list_t l;
    sl_version_list_init(&l);
    CHECK(l.count == 0);
    CHECK(sl_version_list_add(&l, 0x0100) == 0);
    CHECK(sl_version_list_add(&l, 0x0101) == 0);
    CHECK(sl_version_list_add(&l, 0x0100) == 0);  /* dedup */
    CHECK(l.count == 2);
    CHECK(sl_version_list_has(&l, 0x0100));
    CHECK(!sl_version_list_has(&l, 0x0200));
    return 0;
}

static int test_encode_decode_roundtrip(void) {
    sl_version_list_t a, b;
    sl_version_list_init(&a);
    sl_version_list_add(&a, 0x0100);
    sl_version_list_add(&a, 0x0102);
    sl_version_list_add(&a, 0x0203);

    uint8_t wire[64];
    int n = sl_version_list_encode(&a, wire, sizeof(wire));
    CHECK(n > 0);

    CHECK(sl_version_list_decode(wire, (size_t)n, &b) == 0);
    CHECK(b.count == a.count);
    for (uint8_t i = 0; i < a.count; ++i) {
        CHECK(a.versions[i] == b.versions[i]);
    }
    return 0;
}

static int test_choose_picks_highest_overlap(void) {
    sl_version_list_t a, b;
    sl_version_list_init(&a);
    sl_version_list_init(&b);
    sl_version_list_add(&a, 0x0100);
    sl_version_list_add(&a, 0x0102);
    sl_version_list_add(&a, 0x0200);
    sl_version_list_add(&b, 0x0102);
    sl_version_list_add(&b, 0x0103);
    sl_version_list_add(&b, 0x0200);

    CHECK(sl_version_choose(&a, &b) == 0x0200);
    return 0;
}

static int test_choose_returns_zero_when_no_overlap(void) {
    sl_version_list_t a, b;
    sl_version_list_init(&a);
    sl_version_list_init(&b);
    sl_version_list_add(&a, 0x0100);
    sl_version_list_add(&b, 0x0200);
    CHECK(sl_version_choose(&a, &b) == 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_add_and_has();
    rc |= test_encode_decode_roundtrip();
    rc |= test_choose_picks_highest_overlap();
    rc |= test_choose_returns_zero_when_no_overlap();
    if (rc == 0) puts("test_sl_version: OK");
    return rc;
}
