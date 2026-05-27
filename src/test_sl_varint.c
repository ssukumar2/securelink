/* Tests for sl_varint.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_varint.c src/sl_varint.c -o test_sl_varint
 */

#include <stdio.h>
#include <string.h>

#include "sl_varint.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int roundtrip(uint64_t v, int expected_size) {
    uint8_t buf[SL_VARINT_MAX_LEN];
    int n = sl_varint_encode_u64(v, buf, sizeof(buf));
    CHECK(n == expected_size);
    CHECK(sl_varint_size_u64(v) == expected_size);
    uint64_t back = 0;
    int m = sl_varint_decode_u64(buf, sizeof(buf), &back);
    CHECK(m == n);
    CHECK(back == v);
    return 0;
}

static int test_size_boundaries(void) {
    if (roundtrip(0,                       1) != 0) return 1;
    if (roundtrip(1,                       1) != 0) return 1;
    if (roundtrip(127,                     1) != 0) return 1;
    if (roundtrip(128,                     2) != 0) return 1;
    if (roundtrip(16383,                   2) != 0) return 1;
    if (roundtrip(16384,                   3) != 0) return 1;
    if (roundtrip(UINT32_MAX,              5) != 0) return 1;
    if (roundtrip((uint64_t)1 << 56,       9) != 0) return 1;
    if (roundtrip(UINT64_MAX,              10) != 0) return 1;
    return 0;
}

static int test_truncated_decode(void) {
    uint8_t buf[SL_VARINT_MAX_LEN];
    int n = sl_varint_encode_u64((uint64_t)1 << 40, buf, sizeof(buf));
    CHECK(n > 1);
    uint64_t v = 0;
    /* Truncate to half — decode should fail. */
    CHECK(sl_varint_decode_u64(buf, (size_t)(n / 2), &v) < 0);
    return 0;
}

static int test_out_buffer_too_small(void) {
    uint8_t buf[1];
    CHECK(sl_varint_encode_u64(128, buf, sizeof(buf)) < 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_size_boundaries();
    rc |= test_truncated_decode();
    rc |= test_out_buffer_too_small();
    if (rc == 0) puts("test_sl_varint: OK");
    return rc;
}
