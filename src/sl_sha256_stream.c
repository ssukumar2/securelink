#include "sl_sha256_stream.h"

#include <openssl/evp.h>
#include <stdlib.h>

struct sl_sha256_stream {
    EVP_MD_CTX *ctx;
    uint64_t    bytes;
    int         finalized;
};

sl_sha256_stream_t *sl_sha256_stream_new(void) {
    sl_sha256_stream_t *h = (sl_sha256_stream_t *)calloc(1, sizeof(*h));
    if (!h) return NULL;
    h->ctx = EVP_MD_CTX_new();
    if (!h->ctx) { free(h); return NULL; }
    if (EVP_DigestInit_ex(h->ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(h->ctx);
        free(h);
        return NULL;
    }
    return h;
}

void sl_sha256_stream_free(sl_sha256_stream_t *h) {
    if (!h) return;
    if (h->ctx) EVP_MD_CTX_free(h->ctx);
    free(h);
}

int sl_sha256_stream_update(sl_sha256_stream_t *h,
                            const void *data, size_t len) {
    if (!h || h->finalized) return -1;
    if (len == 0) return 0;
    if (!data) return -1;
    if (EVP_DigestUpdate(h->ctx, data, len) != 1) return -1;
    h->bytes += (uint64_t)len;
    return 0;
}

int sl_sha256_stream_finalize(sl_sha256_stream_t *h,
                              uint8_t out[SL_SHA256_DIGEST_LEN]) {
    if (!h || !out || h->finalized) return -1;
    unsigned int n = 0;
    if (EVP_DigestFinal_ex(h->ctx, out, &n) != 1) return -1;
    if (n != SL_SHA256_DIGEST_LEN) return -1;
    h->finalized = 1;
    return 0;
}

uint64_t sl_sha256_stream_bytes(const sl_sha256_stream_t *h) {
    return h ? h->bytes : 0;
}
