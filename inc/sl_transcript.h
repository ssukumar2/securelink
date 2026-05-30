#ifndef SECURELINK_SL_TRANSCRIPT_H
#define SECURELINK_SL_TRANSCRIPT_H

/* Handshake transcript hash.
 *
 * Both peers maintain a running SHA-256 of every handshake message
 * exchanged. Signatures and Finished MACs are computed over this hash,
 * which binds them to the exact handshake history. Any tampering with
 * a prior message produces a different transcript and the verification
 * fails.
 *
 * Usage:
 *   sl_transcript_t t; sl_transcript_init(&t);
 *   sl_transcript_update(&t, client_hello, n);
 *   sl_transcript_update(&t, server_hello, m);
 *   uint8_t hash[32];
 *   sl_transcript_get(&t, hash);   // snapshot, does not finalize */

#include <stddef.h>
#include <stdint.h>

#include <openssl/sha.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_TRANSCRIPT_LEN 32U

typedef struct {
    SHA256_CTX ctx;
    uint64_t   bytes_absorbed;
} sl_transcript_t;

int sl_transcript_init  (sl_transcript_t *t);
int sl_transcript_update(sl_transcript_t *t, const void *data, size_t len);

/* Snapshot the current hash without disturbing the running state. */
int sl_transcript_get   (const sl_transcript_t *t, uint8_t out[SL_TRANSCRIPT_LEN]);

/* Convenience: hash a labelled snapshot, equivalent to SHA256(label || hash). */
int sl_transcript_labelled(const sl_transcript_t *t,
                           const char *label,
                           uint8_t out[SL_TRANSCRIPT_LEN]);

uint64_t sl_transcript_bytes(const sl_transcript_t *t);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_TRANSCRIPT_H */
