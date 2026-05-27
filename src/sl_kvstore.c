#include "sl_kvstore.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sl_crc32.h"
#include "sl_varint.h"

#define SL_KV_BUCKETS  4096U
#define SL_KV_FLAG_TOMB 0x01

typedef struct kv_entry {
    uint8_t          *key;
    size_t            klen;
    long              file_offset;
    size_t            vlen;
    uint8_t           flags;
    struct kv_entry  *next;
} kv_entry_t;

struct sl_kvstore {
    FILE        *fp;
    kv_entry_t  *buckets[SL_KV_BUCKETS];
    size_t       count;
};

static uint32_t hash_bytes(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; ++i) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static kv_entry_t *find_entry(sl_kvstore_t *kv,
                              const void *key, size_t klen) {
    const uint32_t b = hash_bytes(key, klen) % SL_KV_BUCKETS;
    for (kv_entry_t *e = kv->buckets[b]; e; e = e->next) {
        if (e->klen == klen && memcmp(e->key, key, klen) == 0) return e;
    }
    return NULL;
}

static kv_entry_t *upsert_entry(sl_kvstore_t *kv,
                                const void *key, size_t klen) {
    kv_entry_t *e = find_entry(kv, key, klen);
    if (e) return e;
    const uint32_t b = hash_bytes(key, klen) % SL_KV_BUCKETS;
    kv_entry_t *ne = (kv_entry_t *)calloc(1, sizeof(*ne));
    if (!ne) return NULL;
    ne->key = (uint8_t *)malloc(klen);
    if (!ne->key) { free(ne); return NULL; }
    memcpy(ne->key, key, klen);
    ne->klen = klen;
    ne->next = kv->buckets[b];
    kv->buckets[b] = ne;
    ++kv->count;
    return ne;
}

static int write_record(FILE *fp,
                        const void *key, size_t klen,
                        const void *value, size_t vlen,
                        uint8_t flags,
                        long *out_offset) {
    uint8_t hdr[SL_VARINT_MAX_LEN * 2 + 1];
    int hp = 0;
    int n;
    n = sl_varint_encode_u64(klen, hdr + hp, sizeof(hdr) - hp);
    if (n < 0) return -1; hp += n;
    n = sl_varint_encode_u64(vlen, hdr + hp, sizeof(hdr) - hp);
    if (n < 0) return -1; hp += n;
    hdr[hp++] = flags;

    if (fseek(fp, 0, SEEK_END) != 0) return -1;
    const long off = ftell(fp);
    if (off < 0) return -1;

    uint32_t crc = sl_crc32c_init();
    crc = sl_crc32c_update(crc, hdr, (size_t)hp);
    crc = sl_crc32c_update(crc, key, klen);
    if (vlen > 0) crc = sl_crc32c_update(crc, value, vlen);
    const uint32_t crc_final = sl_crc32c_finalize(crc);

    if (fwrite(hdr, 1, (size_t)hp, fp) != (size_t)hp) return -1;
    if (fwrite(key, 1, klen, fp) != klen)              return -1;
    if (vlen > 0 && fwrite(value, 1, vlen, fp) != vlen) return -1;
    uint8_t crc_buf[4] = {
        (uint8_t)(crc_final >> 24), (uint8_t)(crc_final >> 16),
        (uint8_t)(crc_final >> 8),  (uint8_t)(crc_final),
    };
    if (fwrite(crc_buf, 1, 4, fp) != 4) return -1;
    if (out_offset) *out_offset = off;
    return 0;
}

sl_kvstore_t *sl_kvstore_open(const char *path) {
    if (!path) return NULL;
    sl_kvstore_t *kv = (sl_kvstore_t *)calloc(1, sizeof(*kv));
    if (!kv) return NULL;
    kv->fp = fopen(path, "a+b");
    if (!kv->fp) { free(kv); return NULL; }

    /* Replay file to rebuild index. */
    rewind(kv->fp);
    uint8_t buf[4096];
    long pos = 0;
    while (1) {
        long rec_off = pos;
        uint8_t hdr_buf[SL_VARINT_MAX_LEN * 2 + 1];
        size_t got = fread(hdr_buf, 1, sizeof(hdr_buf), kv->fp);
        if (got == 0) break;
        uint64_t klen = 0, vlen = 0;
        int kn = sl_varint_decode_u64(hdr_buf, got, &klen);
        if (kn < 0) break;
        int vn = sl_varint_decode_u64(hdr_buf + kn, got - kn, &vlen);
        if (vn < 0) break;
        if ((size_t)(kn + vn + 1) > got) break;
        uint8_t flags = hdr_buf[kn + vn];

        /* Re-seek to start of key data. */
        const long key_off = rec_off + kn + vn + 1;
        if (fseek(kv->fp, key_off, SEEK_SET) != 0) break;
        if (klen > sizeof(buf)) break;
        if (fread(buf, 1, klen, kv->fp) != klen) break;

        if (flags & SL_KV_FLAG_TOMB) {
            kv_entry_t *e = find_entry(kv, buf, (size_t)klen);
            if (e) e->flags |= SL_KV_FLAG_TOMB;
        } else {
            kv_entry_t *e = upsert_entry(kv, buf, (size_t)klen);
            if (e) {
                e->file_offset = key_off + (long)klen;
                e->vlen        = (size_t)vlen;
                e->flags       = 0;
            }
            if (fseek(kv->fp, (long)vlen, SEEK_CUR) != 0) break;
        }
        /* Skip CRC. */
        if (fseek(kv->fp, 4, SEEK_CUR) != 0) break;
        pos = ftell(kv->fp);
        if (pos < 0) break;
    }
    return kv;
}

void sl_kvstore_close(sl_kvstore_t *kv) {
    if (!kv) return;
    for (size_t i = 0; i < SL_KV_BUCKETS; ++i) {
        kv_entry_t *e = kv->buckets[i];
        while (e) {
            kv_entry_t *n = e->next;
            free(e->key);
            free(e);
            e = n;
        }
    }
    if (kv->fp) fclose(kv->fp);
    free(kv);
}

int sl_kvstore_put(sl_kvstore_t *kv,
                   const void *key, size_t klen,
                   const void *value, size_t vlen) {
    if (!kv || !key) return -1;
    long off = 0;
    if (write_record(kv->fp, key, klen, value, vlen, 0, &off) != 0) return -1;
    fflush(kv->fp);
    kv_entry_t *e = upsert_entry(kv, key, klen);
    if (!e) return -1;
    e->file_offset = off + (long)klen + 0; /* offset of value bytes */
    /* Recompute offset properly: write_record stored rec start; we need
     * to seek past varints+flag+key to land on value. */
    long here = ftell(kv->fp);
    e->vlen   = vlen;
    e->flags  = 0;
    /* We'll re-read on get() by seeking from rec start; store rec start. */
    e->file_offset = off;
    (void)here;
    return 0;
}

int sl_kvstore_delete(sl_kvstore_t *kv, const void *key, size_t klen) {
    if (!kv || !key) return -1;
    if (write_record(kv->fp, key, klen, NULL, 0, SL_KV_FLAG_TOMB, NULL) != 0) {
        return -1;
    }
    fflush(kv->fp);
    kv_entry_t *e = find_entry(kv, key, klen);
    if (e) { e->flags |= SL_KV_FLAG_TOMB; e->vlen = 0; }
    return 0;
}

int sl_kvstore_get(sl_kvstore_t *kv,
                   const void *key, size_t klen,
                   void *buf, size_t buf_cap,
                   size_t *vlen_out) {
    if (!kv || !key || !vlen_out) return -1;
    kv_entry_t *e = find_entry(kv, key, klen);
    if (!e || (e->flags & SL_KV_FLAG_TOMB)) return -2;
    *vlen_out = e->vlen;
    if (buf_cap < e->vlen) return -3;

    /* Seek from record start, skip varints + flag + key. */
    if (fseek(kv->fp, e->file_offset, SEEK_SET) != 0) return -1;
    uint8_t hdr[SL_VARINT_MAX_LEN * 2 + 1];
    size_t got = fread(hdr, 1, sizeof(hdr), kv->fp);
    if (got == 0) return -1;
    uint64_t klen_disk = 0, vlen_disk = 0;
    int kn = sl_varint_decode_u64(hdr, got, &klen_disk);
    if (kn < 0) return -1;
    int vn = sl_varint_decode_u64(hdr + kn, got - kn, &vlen_disk);
    if (vn < 0) return -1;
    if (fseek(kv->fp, e->file_offset + kn + vn + 1 + (long)klen_disk,
              SEEK_SET) != 0) return -1;
    if (fread(buf, 1, (size_t)vlen_disk, kv->fp) != vlen_disk) return -1;
    return 0;
}

bool sl_kvstore_has(sl_kvstore_t *kv, const void *key, size_t klen) {
    if (!kv) return false;
    kv_entry_t *e = find_entry(kv, key, klen);
    return e && !(e->flags & SL_KV_FLAG_TOMB);
}

size_t sl_kvstore_size(const sl_kvstore_t *kv) {
    if (!kv) return 0;
    size_t live = 0;
    for (size_t i = 0; i < SL_KV_BUCKETS; ++i) {
        for (kv_entry_t *e = kv->buckets[i]; e; e = e->next) {
            if (!(e->flags & SL_KV_FLAG_TOMB)) ++live;
        }
    }
    return live;
}

int sl_kvstore_sync(sl_kvstore_t *kv) {
    if (!kv || !kv->fp) return -1;
    if (fflush(kv->fp) != 0) return -1;
    int fd = fileno(kv->fp);
    return fd >= 0 ? fsync(fd) : -1;
}
