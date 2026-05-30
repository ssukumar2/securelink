#include "sl_transcript.h"

#include <string.h>

int sl_transcript_init(sl_transcript_t *t) {
    if (!t) return -1;
    if (SHA256_Init(&t->ctx) != 1) return -1;
    t->bytes_absorbed = 0;
    return 0;
}

int sl_transcript_update(sl_transcript_t *t, const void *data, size_t len) {
    if (!t || (!data && len > 0)) return -1;
    if (SHA256_Update(&t->ctx, data, len) != 1) return -1;
    t->bytes_absorbed += (uint64_t)len;
    return 0;
}

int sl_transcript_get(const sl_transcript_t *t, uint8_t out[SL_TRANSCRIPT_LEN]) {
    if (!t || !out) return -1;
    /* Copy the context so we can finalize without disturbing the original. */
    SHA256_CTX copy;
    memcpy(&copy, &t->ctx, sizeof(copy));
    if (SHA256_Final(out, &copy) != 1) return -1;
    return 0;
}

int sl_transcript_labelled(const sl_transcript_t *t,
                           const char *label,
                           uint8_t out[SL_TRANSCRIPT_LEN]) {
    if (!t || !label || !out) return -1;
    uint8_t base[SL_TRANSCRIPT_LEN];
    if (sl_transcript_get(t, base) != 0) return -1;

    SHA256_CTX h;
    if (SHA256_Init(&h) != 1) return -1;
    SHA256_Update(&h, label, strlen(label));
    SHA256_Update(&h, base, sizeof(base));
    if (SHA256_Final(out, &h) != 1) return -1;
    return 0;
}

uint64_t sl_transcript_bytes(const sl_transcript_t *t) {
    return t ? t->bytes_absorbed : 0;
}
