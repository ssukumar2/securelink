/* Tests for sl_file_meta.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_file_meta.c src/sl_file_meta.c \
 *       -o test_sl_file_meta
 */

#include <stdio.h>
#include <string.h>

#include "sl_file_meta.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static void fill_meta(sl_file_meta_t *m, const char *name) {
    memset(m, 0, sizeof(*m));
    m->chunk_size   = 4096;
    m->total_size   = 4096 * 5 + 100;
    m->total_chunks = 6;
    m->mode         = 0644;
    m->mtime_s      = 1700000000;
    for (int i = 0; i < 32; ++i) m->sha256[i] = (uint8_t)(i + 1);
    m->name_len = (uint16_t)strlen(name);
    memcpy(m->name, name, m->name_len);
}

static int test_pack_unpack_roundtrip(void) {
    sl_file_meta_t src, dst;
    fill_meta(&src, "report.txt");

    uint8_t wire[300];
    int n = sl_file_meta_pack(&src, wire, sizeof(wire));
    CHECK(n > 0);
    CHECK((size_t)n == SL_FILE_META_FIXED_LEN + src.name_len);

    CHECK(sl_file_meta_unpack(wire, (size_t)n, &dst) == 0);
    CHECK(dst.total_size == src.total_size);
    CHECK(dst.chunk_size == src.chunk_size);
    CHECK(dst.total_chunks == src.total_chunks);
    CHECK(dst.mode == src.mode);
    CHECK(dst.mtime_s == src.mtime_s);
    CHECK(memcmp(dst.sha256, src.sha256, 32) == 0);
    CHECK(dst.name_len == src.name_len);
    CHECK(strcmp(dst.name, "report.txt") == 0);
    return 0;
}

static int test_chunk_size_bounds(void) {
    sl_file_meta_t m;
    fill_meta(&m, "x.bin");

    m.chunk_size = SL_FILE_CHUNK_MIN - 1;
    CHECK(sl_file_meta_validate(&m) != 0);

    m.chunk_size = SL_FILE_CHUNK_MAX + 1;
    CHECK(sl_file_meta_validate(&m) != 0);

    m.chunk_size = SL_FILE_CHUNK_MIN;
    m.total_size = m.chunk_size;
    m.total_chunks = 1;
    CHECK(sl_file_meta_validate(&m) == 0);
    return 0;
}

static int test_chunk_count_consistency(void) {
    sl_file_meta_t m;
    fill_meta(&m, "x.bin");
    m.chunk_size = 1000;
    m.total_size = 5500;
    m.total_chunks = 5;        /* wrong: ceil(5500/1000) = 6 */
    CHECK(sl_file_meta_validate(&m) != 0);
    m.total_chunks = 6;
    CHECK(sl_file_meta_validate(&m) == 0);
    return 0;
}

static int test_path_traversal_rejected(void) {
    sl_file_meta_t m;
    fill_meta(&m, "../etc/passwd");
    CHECK(sl_file_meta_validate(&m) != 0);

    fill_meta(&m, "a/b/c");
    CHECK(sl_file_meta_validate(&m) != 0);

    fill_meta(&m, "ok.bin");
    CHECK(sl_file_meta_validate(&m) == 0);
    return 0;
}

static int test_empty_file_valid(void) {
    sl_file_meta_t m;
    fill_meta(&m, "empty.bin");
    m.total_size   = 0;
    m.total_chunks = 0;
    CHECK(sl_file_meta_validate(&m) == 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_pack_unpack_roundtrip();
    rc |= test_chunk_size_bounds();
    rc |= test_chunk_count_consistency();
    rc |= test_path_traversal_rejected();
    rc |= test_empty_file_valid();
    if (rc == 0) puts("test_sl_file_meta: OK");
    return rc;
}
