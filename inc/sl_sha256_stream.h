#ifndef SECURELINK_SL_SHA256_STREAM_H
#define SECURELINK_SL_SHA256_STREAM_H

/* Streaming SHA-256 wrapper.
 *
 * The file transfer machinery hashes data as it flows through, so the
 * receiver can compare against the digest in sl_file_meta without ever
 * holding the whole file in memory. This is a thin layer over OpenSSL's
 * EVP API exposed as a stable C handle. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_SHA256_DIGEST_LEN 32

typedef struct sl_sha256_stream sl_sha256_stream_t;

sl_sha256_stream_t *sl_sha256_stream_new(void);
void                sl_sha256_stream_free(sl_sha256_stream_t *h);

int sl_sha256_stream_update(sl_sha256_stream_t *h,
                            const void *data, size_t len);

/* Finalize and return the digest. After this call the handle is unusable;
 * caller must still free it. Returns 0 on success. */
int sl_sha256_stream_finalize(sl_sha256_stream_t *h,
                              uint8_t out[SL_SHA256_DIGEST_LEN]);

uint64_t sl_sha256_stream_bytes(const sl_sha256_stream_t *h);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_SHA256_STREAM_H */
