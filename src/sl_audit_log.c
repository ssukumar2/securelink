#include "sl_audit_log.h"

#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct sl_audit_log {
    FILE   *fp;
    uint8_t prev_hash[SHA256_DIGEST_LENGTH];
};

static uint64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void pack_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)(v);
}

static void pack_u64_be(uint8_t *p, uint64_t v) {
    pack_u32_be(p,     (uint32_t)(v >> 32));
    pack_u32_be(p + 4, (uint32_t)(v));
}

sl_audit_log_t *sl_audit_log_open(const char *path) {
    if (!path) return NULL;
    sl_audit_log_t *L = (sl_audit_log_t *)calloc(1, sizeof(*L));
    if (!L) return NULL;
    L->fp = fopen(path, "ab");
    if (!L->fp) { free(L); return NULL; }

    /* Try to recover the last hash from the existing file. */
    FILE *r = fopen(path, "rb");
    if (r) {
        fseek(r, 0, SEEK_END);
        long size = ftell(r);
        if (size >= (long)SHA256_DIGEST_LENGTH) {
            fseek(r, size - SHA256_DIGEST_LENGTH, SEEK_SET);
            (void)fread(L->prev_hash, 1, SHA256_DIGEST_LENGTH, r);
        }
        fclose(r);
    }
    return L;
}

void sl_audit_log_close(sl_audit_log_t *L) {
    if (!L) return;
    if (L->fp) fclose(L->fp);
    free(L);
}

int sl_audit_log_append(sl_audit_log_t *L,
                        sl_audit_event_t event,
                        const char *payload) {
    if (!L || !L->fp) return -1;
    const size_t plen = payload ? strlen(payload) : 0;
    if (plen > 1024) return -1;

    uint8_t header[8 + 4 + 4];
    pack_u64_be(header + 0, now_ms());
    pack_u32_be(header + 8, (uint32_t)event);
    pack_u32_be(header + 12, (uint32_t)plen);

    /* hash = SHA256(prev_hash || header || payload) */
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, L->prev_hash, sizeof(L->prev_hash));
    SHA256_Update(&ctx, header, sizeof(header));
    if (plen > 0) SHA256_Update(&ctx, payload, plen);
    uint8_t new_hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(new_hash, &ctx);

    if (fwrite(header, 1, sizeof(header), L->fp) != sizeof(header)) return -1;
    if (plen > 0 && fwrite(payload, 1, plen, L->fp) != plen)        return -1;
    if (fwrite(new_hash, 1, sizeof(new_hash), L->fp) != sizeof(new_hash)) return -1;
    fflush(L->fp);

    memcpy(L->prev_hash, new_hash, sizeof(new_hash));
    return 0;
}

int sl_audit_log_verify(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    uint8_t prev[SHA256_DIGEST_LENGTH] = {0};
    uint8_t header[16];
    int rc = 0;

    while (fread(header, 1, sizeof(header), fp) == sizeof(header)) {
        uint32_t plen =
            ((uint32_t)header[12] << 24) | ((uint32_t)header[13] << 16) |
            ((uint32_t)header[14] <<  8) |  (uint32_t)header[15];
        if (plen > 1024) { rc = -1; break; }

        uint8_t payload[1024];
        if (plen > 0 && fread(payload, 1, plen, fp) != plen) {
            rc = -1; break;
        }

        uint8_t stored[SHA256_DIGEST_LENGTH];
        if (fread(stored, 1, sizeof(stored), fp) != sizeof(stored)) {
            rc = -1; break;
        }

        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, prev, sizeof(prev));
        SHA256_Update(&ctx, header, sizeof(header));
        if (plen > 0) SHA256_Update(&ctx, payload, plen);
        uint8_t computed[SHA256_DIGEST_LENGTH];
        SHA256_Final(computed, &ctx);

        if (memcmp(stored, computed, sizeof(computed)) != 0) {
            rc = -1; break;
        }
        memcpy(prev, computed, sizeof(prev));
    }
    fclose(fp);
    return rc;
}
