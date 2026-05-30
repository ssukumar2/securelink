#include "sl_identity_file.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sl_crc32.h"
#include "sl_mem.h"

#define SL_ID_MAGIC  "SLID"
#define SL_ID_VER    1U
#define SL_ID_TOTAL  (4 + 4 + SL_ED25519_PRIVKEY_LEN + SL_ED25519_PUBKEY_LEN + 4)

static void pack_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)v;
}

static uint32_t unpack_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

int sl_identity_file_save(const char *path,
                          const uint8_t priv[SL_ED25519_PRIVKEY_LEN],
                          const uint8_t pub [SL_ED25519_PUBKEY_LEN]) {
    if (!path || !priv || !pub) return -1;

    uint8_t buf[SL_ID_TOTAL];
    memcpy(buf, SL_ID_MAGIC, 4);
    pack_u32_be(buf + 4, SL_ID_VER);
    memcpy(buf + 8, priv, SL_ED25519_PRIVKEY_LEN);
    memcpy(buf + 8 + SL_ED25519_PRIVKEY_LEN, pub, SL_ED25519_PUBKEY_LEN);
    const uint32_t crc = sl_crc32c(buf, SL_ID_TOTAL - 4);
    pack_u32_be(buf + SL_ID_TOTAL - 4, crc);

    char tmp[1024];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return -1;

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { sl_secure_zero(buf, sizeof(buf)); return -1; }

    size_t off = 0;
    while (off < sizeof(buf)) {
        ssize_t w = write(fd, buf + off, sizeof(buf) - off);
        if (w < 0) { close(fd); unlink(tmp); sl_secure_zero(buf, sizeof(buf)); return -1; }
        off += (size_t)w;
    }
    fsync(fd);
    close(fd);
    sl_secure_zero(buf, sizeof(buf));

    return rename(tmp, path);
}

int sl_identity_file_load(const char *path,
                          uint8_t priv[SL_ED25519_PRIVKEY_LEN],
                          uint8_t pub [SL_ED25519_PUBKEY_LEN]) {
    if (!path || !priv || !pub) return -1;

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    uint8_t buf[SL_ID_TOTAL];
    size_t got = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    if (got != sizeof(buf)) { sl_secure_zero(buf, sizeof(buf)); return -1; }

    if (memcmp(buf, SL_ID_MAGIC, 4) != 0) { sl_secure_zero(buf, sizeof(buf)); return -1; }
    if (unpack_u32_be(buf + 4) != SL_ID_VER) { sl_secure_zero(buf, sizeof(buf)); return -1; }

    const uint32_t crc_stored = unpack_u32_be(buf + SL_ID_TOTAL - 4);
    const uint32_t crc_calc   = sl_crc32c(buf, SL_ID_TOTAL - 4);
    if (crc_stored != crc_calc) { sl_secure_zero(buf, sizeof(buf)); return -1; }

    memcpy(priv, buf + 8, SL_ED25519_PRIVKEY_LEN);
    memcpy(pub,  buf + 8 + SL_ED25519_PRIVKEY_LEN, SL_ED25519_PUBKEY_LEN);
    sl_secure_zero(buf, sizeof(buf));
    return 0;
}

int sl_identity_file_load_or_create(const char *path,
                                    uint8_t priv[SL_ED25519_PRIVKEY_LEN],
                                    uint8_t pub [SL_ED25519_PUBKEY_LEN],
                                    int *was_created) {
    if (!path || !priv || !pub) return -1;
    if (was_created) *was_created = 0;

    if (sl_identity_file_load(path, priv, pub) == 0) return 0;

    if (sl_ed25519_keypair_new(priv, pub) != 0) return -1;
    if (sl_identity_file_save(path, priv, pub) != 0) {
        sl_secure_zero(priv, SL_ED25519_PRIVKEY_LEN);
        return -1;
    }
    if (was_created) *was_created = 1;
    return 0;
}
