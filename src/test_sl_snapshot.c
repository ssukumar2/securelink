/* Tests for sl_snapshot atomic save/load and corruption detection.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_snapshot.c src/sl_snapshot.c src/sl_crc32.c \
 *       -o test_sl_snapshot
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sl_snapshot.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

#define TMP_PATH "/tmp/securelink_test_snapshot.bin"

static int test_save_load_roundtrip(void) {
    unlink(TMP_PATH);
    const uint8_t payload[] = "hello securelink snapshot";
    CHECK(sl_snapshot_save(TMP_PATH, payload, sizeof(payload)) == 0);

    uint8_t buf[256];
    size_t got = 0;
    CHECK(sl_snapshot_load(TMP_PATH, buf, sizeof(buf), &got) == 0);
    CHECK(got == sizeof(payload));
    CHECK(memcmp(buf, payload, sizeof(payload)) == 0);
    unlink(TMP_PATH);
    return 0;
}

static int test_empty_payload(void) {
    unlink(TMP_PATH);
    CHECK(sl_snapshot_save(TMP_PATH, NULL, 0) == 0);
    uint8_t buf[16];
    size_t got = 99;
    CHECK(sl_snapshot_load(TMP_PATH, buf, sizeof(buf), &got) == 0);
    CHECK(got == 0);
    unlink(TMP_PATH);
    return 0;
}

static int test_corruption_detected(void) {
    unlink(TMP_PATH);
    const uint8_t payload[] = "important state";
    CHECK(sl_snapshot_save(TMP_PATH, payload, sizeof(payload)) == 0);

    /* Flip a byte inside the payload region (after 16-byte header). */
    FILE *fp = fopen(TMP_PATH, "r+b");
    CHECK(fp != NULL);
    fseek(fp, 17, SEEK_SET);
    uint8_t b;
    fread(&b, 1, 1, fp);
    b ^= 0x01;
    fseek(fp, 17, SEEK_SET);
    fwrite(&b, 1, 1, fp);
    fclose(fp);

    uint8_t buf[256];
    size_t got = 0;
    /* Load should detect CRC mismatch. */
    CHECK(sl_snapshot_load(TMP_PATH, buf, sizeof(buf), &got) != 0);
    CHECK(sl_snapshot_verify(TMP_PATH) != 0);
    unlink(TMP_PATH);
    return 0;
}

static int test_buffer_too_small(void) {
    unlink(TMP_PATH);
    const uint8_t payload[] = "01234567890123456789";
    CHECK(sl_snapshot_save(TMP_PATH, payload, sizeof(payload)) == 0);

    uint8_t small[4];
    size_t got = 0;
    CHECK(sl_snapshot_load(TMP_PATH, small, sizeof(small), &got) == -2);
    CHECK(got == sizeof(payload));
    unlink(TMP_PATH);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_save_load_roundtrip();
    rc |= test_empty_payload();
    rc |= test_corruption_detected();
    rc |= test_buffer_too_small();
    if (rc == 0) puts("test_sl_snapshot: OK");
    return rc;
}
