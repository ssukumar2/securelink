/* clock_gettime and CLOCK_REALTIME are POSIX, not standard C11 -- same
 * pattern as sl_lockout.c, sl_dos_guard.c, sl_token_bucket.c, sl_clock.c. */
#define _POSIX_C_SOURCE 200809L

#include "sl_event_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sl_crc32.h"
#include "sl_varint.h"

struct sl_event_log {
    FILE    *fp;
    uint64_t next_seq;
};

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int read_u32_be(FILE *fp, uint32_t *out) {
    uint8_t b[4];
    if (fread(b, 1, 4, fp) != 4) return -1;
    *out = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
    return 0;
}

static void write_u32_be(FILE *fp, uint32_t v) {
    uint8_t b[4] = {
        (uint8_t)(v >> 24), (uint8_t)(v >> 16),
        (uint8_t)(v >>  8), (uint8_t)v
    };
    fwrite(b, 1, 4, fp);
}

sl_event_log_t *sl_event_log_open(const char *path) {
    if (!path) return NULL;
    sl_event_log_t *L = (sl_event_log_t *)calloc(1, sizeof(*L));
    if (!L) return NULL;
    L->fp = fopen(path, "a+b");
    if (!L->fp) { free(L); return NULL; }
    L->next_seq = 1;
    /* Walk existing records to find next sequence. */
    rewind(L->fp);
    uint8_t hdr[64];
    while (1) {
        long pos = ftell(L->fp);
        if (pos < 0) break;
        size_t got = fread(hdr, 1, sizeof(hdr), L->fp);
        if (got == 0) break;
        uint64_t seq = 0, ts = 0, type = 0, plen = 0;
        int o = 0, n;
        n = sl_varint_decode_u64(hdr + o, got - o, &seq);  if (n < 0) break; o += n;
        n = sl_varint_decode_u64(hdr + o, got - o, &ts);   if (n < 0) break; o += n;
        n = sl_varint_decode_u64(hdr + o, got - o, &type); if (n < 0) break; o += n;
        n = sl_varint_decode_u64(hdr + o, got - o, &plen); if (n < 0) break; o += n;
        fseek(L->fp, pos + o + (long)plen + 4, SEEK_SET);
        if (seq >= L->next_seq) L->next_seq = seq + 1;
    }
    fseek(L->fp, 0, SEEK_END);
    return L;
}

void sl_event_log_close(sl_event_log_t *L) {
    if (!L) return;
    if (L->fp) fclose(L->fp);
    free(L);
}

int sl_event_log_append(sl_event_log_t *L,
                        sl_event_type_t type,
                        const void *payload, size_t payload_len) {
    if (!L || !L->fp) return -1;
    if (payload_len > 1U << 20) return -1;

    uint8_t hdr[SL_VARINT_MAX_LEN * 4];
    int off = 0;
    int n;
    n = sl_varint_encode_u64(L->next_seq, hdr + off, sizeof(hdr) - off);
    if (n < 0) return -1; off += n;
    n = sl_varint_encode_u64(now_ns(),    hdr + off, sizeof(hdr) - off);
    if (n < 0) return -1; off += n;
    n = sl_varint_encode_u64((uint64_t)type, hdr + off, sizeof(hdr) - off);
    if (n < 0) return -1; off += n;
    n = sl_varint_encode_u64(payload_len, hdr + off, sizeof(hdr) - off);
    if (n < 0) return -1; off += n;

    uint32_t crc = sl_crc32c_init();
    crc = sl_crc32c_update(crc, hdr, (size_t)off);
    if (payload_len > 0) crc = sl_crc32c_update(crc, payload, payload_len);
    const uint32_t crc_final = sl_crc32c_finalize(crc);

    if (fwrite(hdr, 1, (size_t)off, L->fp) != (size_t)off) return -1;
    if (payload_len > 0 &&
        fwrite(payload, 1, payload_len, L->fp) != payload_len) return -1;
    write_u32_be(L->fp, crc_final);
    fflush(L->fp);
    ++L->next_seq;
    return 0;
}

uint64_t sl_event_log_seq(const sl_event_log_t *L) {
    return L ? L->next_seq : 0;
}

int sl_event_log_iterate(const char *path,
                         sl_event_visitor_fn visitor,
                         void *user) {
    if (!path || !visitor) return -1;
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    uint8_t hdr_buf[SL_VARINT_MAX_LEN * 4];
    uint8_t payload[1U << 20];

    while (1) {
        long pos = ftell(fp);
        if (pos < 0) break;
        size_t got = fread(hdr_buf, 1, sizeof(hdr_buf), fp);
        if (got == 0) break;

        uint64_t seq = 0, ts = 0, type = 0, plen = 0;
        int o = 0, n;
        n = sl_varint_decode_u64(hdr_buf + o, got - o, &seq);  if (n < 0) break; o += n;
        n = sl_varint_decode_u64(hdr_buf + o, got - o, &ts);   if (n < 0) break; o += n;
        n = sl_varint_decode_u64(hdr_buf + o, got - o, &type); if (n < 0) break; o += n;
        n = sl_varint_decode_u64(hdr_buf + o, got - o, &plen); if (n < 0) break; o += n;

        fseek(fp, pos + o, SEEK_SET);
        if (plen > sizeof(payload)) break;
        if (plen > 0 && fread(payload, 1, (size_t)plen, fp) != plen) break;
        uint32_t crc_stored = 0;
        if (read_u32_be(fp, &crc_stored) != 0) break;

        sl_event_record_t rec;
        rec.seq          = seq;
        rec.timestamp_ns = ts;
        rec.type         = (sl_event_type_t)type;
        rec.payload      = (plen > 0) ? payload : NULL;
        rec.payload_len  = (size_t)plen;
        if (visitor(&rec, user) != 0) break;
    }
    fclose(fp);
    return 0;
}
