#ifndef SECURELINK_SL_HKDF_H
#define SECURELINK_SL_HKDF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HKDF-Extract-then-Expand using SHA-256 (RFC 5869).
 *
 *   ikm   : input keying material (e.g. ECDH shared secret)
 *   salt  : optional salt; pass NULL/0 for the all-zero default
 *   info  : optional context/label binding the output to a purpose
 *   out   : buffer of `out_len` bytes for the derived key
 *
 * out_len must be <= 255 * 32 = 8160 bytes. Returns 0 on success.
 */
int sl_hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                   const uint8_t *salt, size_t salt_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t       *out,  size_t out_len);

/* Two-stage variants for callers that want to cache the PRK. */
int sl_hkdf_extract_sha256(const uint8_t *ikm,  size_t ikm_len,
                           const uint8_t *salt, size_t salt_len,
                           uint8_t       prk_out[32]);

int sl_hkdf_expand_sha256(const uint8_t prk[32],
                          const uint8_t *info, size_t info_len,
                          uint8_t       *out,  size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_HKDF_H */
