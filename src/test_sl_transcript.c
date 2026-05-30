/* Tests for sl_transcript.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_transcript.c src/sl_transcript.c \
 *       -lcrypto -o test_sl_transcript
 */

#include <stdio.h>
#include <string.h>

#include "sl_transcript.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_snapshot_is_idempotent(void) {
    sl_transcript_t t;
    sl_transcript_init(&t);
    sl_transcript_update(&t, "abc", 3);

    uint8_t a[SL_TRANSCRIPT_LEN], b[SL_TRANSCRIPT_LEN];
    CHECK(sl_transcript_get(&t, a) == 0);
    CHECK(sl_transcript_get(&t, b) == 0);
    CHECK(memcmp(a, b, SL_TRANSCRIPT_LEN) == 0);
    return 0;
}

static int test_running_hash_differs_per_update(void) {
    sl_transcript_t t;
    sl_transcript_init(&t);
    sl_transcript_update(&t, "abc", 3);
    uint8_t h1[SL_TRANSCRIPT_LEN]; sl_transcript_get(&t, h1);

    sl_transcript_update(&t, "def", 3);
    uint8_t h2[SL_TRANSCRIPT_LEN]; sl_transcript_get(&t, h2);

    CHECK(memcmp(h1, h2, SL_TRANSCRIPT_LEN) != 0);
    return 0;
}

static int test_order_matters(void) {
    sl_transcript_t a, b;
    sl_transcript_init(&a);
    sl_transcript_init(&b);
    sl_transcript_update(&a, "12", 2);
    sl_transcript_update(&a, "34", 2);
    sl_transcript_update(&b, "1234", 4);

    /* "12" then "34" and "1234" produce the same SHA-256 of "1234". */
    uint8_t ha[SL_TRANSCRIPT_LEN], hb[SL_TRANSCRIPT_LEN];
    sl_transcript_get(&a, ha);
    sl_transcript_get(&b, hb);
    CHECK(memcmp(ha, hb, SL_TRANSCRIPT_LEN) == 0);

    /* But reordered chunks produce different transcripts. */
    sl_transcript_t c;
    sl_transcript_init(&c);
    sl_transcript_update(&c, "34", 2);
    sl_transcript_update(&c, "12", 2);
    uint8_t hc[SL_TRANSCRIPT_LEN];
    sl_transcript_get(&c, hc);
    CHECK(memcmp(ha, hc, SL_TRANSCRIPT_LEN) != 0);
    return 0;
}

static int test_labelled_snapshot_distinct(void) {
    sl_transcript_t t;
    sl_transcript_init(&t);
    sl_transcript_update(&t, "data", 4);

    uint8_t plain[SL_TRANSCRIPT_LEN], la[SL_TRANSCRIPT_LEN], lb[SL_TRANSCRIPT_LEN];
    sl_transcript_get(&t, plain);
    CHECK(sl_transcript_labelled(&t, "labelA", la) == 0);
    CHECK(sl_transcript_labelled(&t, "labelB", lb) == 0);

    CHECK(memcmp(plain, la, SL_TRANSCRIPT_LEN) != 0);
    CHECK(memcmp(la,    lb, SL_TRANSCRIPT_LEN) != 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_snapshot_is_idempotent();
    rc |= test_running_hash_differs_per_update();
    rc |= test_order_matters();
    rc |= test_labelled_snapshot_distinct();
    if (rc == 0) puts("test_sl_transcript: OK");
    return rc;
}
