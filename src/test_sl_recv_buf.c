/* Tests for sl_recv_buf incremental record assembly.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_recv_buf.c src/sl_recv_buf.c src/sl_record.c \
 *       src/sl_aead.c src/sl_mem.c src/sl_nonce.c src/sl_rng.c \
 *       -lcrypto -o test_sl_recv_buf
 */

#include <stdio.h>
#include <string.h>

#include "sl_recv_buf.h"
#include "sl_record.h"
#include "sl_rng.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int make_record(uint8_t *out, size_t cap, uint64_t seq,
                       const char *msg) {
    static uint8_t key[SL_AEAD_KEY_LEN], iv[SL_AEAD_IV_LEN];
    static int     keyed = 0;
    if (!keyed) { sl_rng_init(); sl_rng_bytes(key, 32); sl_rng_bytes(iv, 12); keyed = 1; }
    return sl_record_seal(SL_REC_APP_DATA, key, iv, seq,
                          (const uint8_t *)msg, strlen(msg), out, cap);
}

static int test_single_record(void) {
    uint8_t rec[256];
    int n = make_record(rec, sizeof(rec), 1, "hello");
    CHECK(n > 0);

    sl_recv_buf_t rb;
    CHECK(sl_recv_buf_init(&rb, 4096) == 0);
    CHECK(sl_recv_buf_push(&rb, rec, (size_t)n) == 0);

    uint8_t taken[256];
    int got = sl_recv_buf_take(&rb, taken, sizeof(taken));
    CHECK(got == n);
    CHECK(memcmp(taken, rec, (size_t)n) == 0);
    CHECK(sl_recv_buf_buffered(&rb) == 0);
    sl_recv_buf_free(&rb);
    return 0;
}

static int test_byte_at_a_time(void) {
    uint8_t rec[256];
    int n = make_record(rec, sizeof(rec), 2, "drip-fed bytes");
    CHECK(n > 0);

    sl_recv_buf_t rb;
    sl_recv_buf_init(&rb, 4096);

    uint8_t taken[256];
    for (int i = 0; i < n - 1; ++i) {
        CHECK(sl_recv_buf_push(&rb, &rec[i], 1) == 0);
        CHECK(sl_recv_buf_take(&rb, taken, sizeof(taken)) == 0);
    }
    CHECK(sl_recv_buf_push(&rb, &rec[n - 1], 1) == 0);
    CHECK(sl_recv_buf_take(&rb, taken, sizeof(taken)) == n);
    sl_recv_buf_free(&rb);
    return 0;
}

static int test_two_back_to_back(void) {
    uint8_t a[256], b[256];
    int na = make_record(a, sizeof(a), 3, "first");
    int nb = make_record(b, sizeof(b), 4, "second");

    sl_recv_buf_t rb;
    sl_recv_buf_init(&rb, 4096);
    sl_recv_buf_push(&rb, a, (size_t)na);
    sl_recv_buf_push(&rb, b, (size_t)nb);

    uint8_t taken[256];
    CHECK(sl_recv_buf_take(&rb, taken, sizeof(taken)) == na);
    CHECK(memcmp(taken, a, (size_t)na) == 0);
    CHECK(sl_recv_buf_take(&rb, taken, sizeof(taken)) == nb);
    CHECK(memcmp(taken, b, (size_t)nb) == 0);
    CHECK(sl_recv_buf_take(&rb, taken, sizeof(taken)) == 0);
    sl_recv_buf_free(&rb);
    return 0;
}

static int test_overflow_rejected(void) {
    sl_recv_buf_t rb;
    sl_recv_buf_init(&rb, 16);
    uint8_t big[32] = {0};
    CHECK(sl_recv_buf_push(&rb, big, sizeof(big)) == -1);
    sl_recv_buf_free(&rb);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_single_record();
    rc |= test_byte_at_a_time();
    rc |= test_two_back_to_back();
    rc |= test_overflow_rejected();
    if (rc == 0) puts("test_sl_recv_buf: OK");
    return rc;
}
