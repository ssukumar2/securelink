#include "sl_snapshot.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sl_crc32.h"

static void pack_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)(v);
}

static void pack_u64_be(uint8_t *p, uint64_t v) {
    pack_u32_be(p,     (uint32_t)(v >> 32));
    pack_u32_be(p + 4, (uint32_t)(v));
}

static uint32_t unpack_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static uint64_t unpack_u64_be(const uint8_t *p) {
    return ((uint64_t)unpack_u32_be(p) << 32) | (uint64_t)unpack_u32_be(p + 4);
}

int sl_snapshot_save(const char *path,
                     const void *payload, size_t payload_len) {
    if (!path || (!payload && payload_len > 0)) return -1;

    char tmp[1024];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return -1;

    FILE *fp = fopen(tmp, "wb");
    if (!fp) return -1;

    uint8_t header[16];
    memcpy(header, SL_SNAPSHOT_MAGIC, 4);
    pack_u32_be(header + 4,  SL_SNAPSHOT_VERSION);
    pack_u64_be(header + 8,  payload_len);
    /* Note: header is 4+4+8=16; the 4-byte version uses positions [4..7] */

    if (fwrite(header, 1, sizeof(header), fp) != sizeof(header)) {
        fclose(fp); unlink(tmp); return -1;
    }
    if (payload_len > 0 &&
        fwrite(payload, 1, payload_len, fp) != payload_len) {
        fclose(fp); unlink(tmp); return -1;
    }

    uint32_t crc = sl_crc32c_init();
    crc = sl_crc32c_update(crc, header, sizeof(header));
    if (payload_len > 0) crc = sl_crc32c_update(crc, payload, payload_len);
    const uint32_t crc_final = sl_crc32c_finalize(crc);
    uint8_t crc_buf[4];
    pack_u32_be(crc_buf, crc_final);
    if (fwrite(crc_buf, 1, sizeof(crc_buf), fp) != sizeof(crc_buf)) {
        fclose(fp); unlink(tmp); return -1;
    }

    if (fflush(fp) != 0) { fclose(fp); unlink(tmp); return -1; }
    int fd = fileno(fp);
    if (fd >= 0) (void)fsync(fd);
    fclose(fp);

    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static int read_header(FILE *fp, uint64_t *payload_len_out) {
    uint8_t header[16];
    if (fread(header, 1, sizeof(header), fp) != sizeof(header)) return -1;
    if (memcmp(header, SL_SNAPSHOT_MAGIC, 4) != 0) return -1;
    if (unpack_u32_be(header + 4) != SL_SNAPSHOT_VERSION) return -1;
    *payload_len_out = unpack_u64_be(header + 8);
    return 0;
}

int sl_snapshot_load(const char *path,
                     void *buf, size_t buf_cap, size_t *out_len) {
    if (!path || !out_len) return -1;
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    uint64_t plen = 0;
    if (read_header(fp, &plen) != 0) { fclose(fp); return -1; }
    *out_len = (size_t)plen;
    if (buf_cap < plen) { fclose(fp); return -2; }

    if (plen > 0 && fread(buf, 1, plen, fp) != plen) { fclose(fp); return -1; }

    uint8_t crc_buf[4];
    if (fread(crc_buf, 1, sizeof(crc_buf), fp) != sizeof(crc_buf)) {
        fclose(fp); return -1;
    }
    const uint32_t stored = unpack_u32_be(crc_buf);

    /* Re-read header for CRC. */
    rewind(fp);
    uint8_t hdr[16];
    fread(hdr, 1, sizeof(hdr), fp);
    fclose(fp);

    uint32_t crc = sl_crc32c_init();
    crc = sl_crc32c_update(crc, hdr, sizeof(hdr));
    if (plen > 0) crc = sl_crc32c_update(crc, buf, (size_t)plen);
    const uint32_t computed = sl_crc32c_finalize(crc);
    if (stored != computed) return -1;
    return 0;
}

int sl_snapshot_verify(const char *path) {
    if (!path) return -1;
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if ((uint64_t)st.st_size < 20) return -1;
    const size_t plen = (size_t)st.st_size - 20;
    uint8_t *buf = (uint8_t *)malloc(plen);
    if (!buf && plen > 0) return -1;
    size_t got = 0;
    int rc = sl_snapshot_load(path, buf, plen, &got);
    free(buf);
    return rc;
}
