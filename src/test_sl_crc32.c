/* Tests for sl_crc32c against published Castagnoli reference vectors.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_crc32.c src/sl_crc32.c -o test_sl_crc32
 */

#include <stdio.h>
#include <string.h>

#include "sl_crc32.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_empty(void) {
    CHECK(sl_crc32c(NULL, 0) == 0x00000000u);
    return 0;
}

static int test_known_vectors(void) {
    /* CRC-32C of "123456789" should be 0xE3069283 (RFC 3720, iSCSI). */
    const char *s = "123456789";
    CHECK(sl_crc32c(s, 9) == 0xE3069283u);

    /* CRC-32C of 32 bytes of zero. */
    uint8_t zeros[32] = {0};
    /* Reference (published): 0x8a9136aa */
    CHECK(sl_crc32c(zeros, 32) == 0x8A9136AAu);

    /* CRC-32C of "The quick brown fox jumps over the lazy dog" */
    const char *fox = "The quick brown fox jumps over the lazy dog";
    /* Reference: 0x22620404 */
    CHECK(sl_crc32c(fox, strlen(fox)) == 0x22620404u);
    return 0;
}

static int test_streaming_matches_one_shot(void) {
    const char *s = "abcdefghijklmnopqrstuvwxyz0123456789";
    const size_t n = strlen(s);

    uint32_t one_shot = sl_crc32c(s, n);

    uint32_t stream = sl_crc32c_init();
    stream = sl_crc32c_update(stream, s,         10);
    stream = sl_crc32c_update(stream, s + 10,    15);
    stream = sl_crc32c_update(stream, s + 25, n - 25);
    stream = sl_crc32c_finalize(stream);

    CHECK(one_shot == stream);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_empty();
    rc |= test_known_vectors();
    rc |= test_streaming_matches_one_shot();
    if (rc == 0) puts("test_sl_crc32: OK");
    return rc;
}
