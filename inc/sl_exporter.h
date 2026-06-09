#ifndef SECURELINK_SL_EXPORTER_H
#define SECURELINK_SL_EXPORTER_H

/* Exported keying material (EKM), modelled after RFC 5705 / TLS 1.3
 * exporter_master_secret.
 *
 * Once the handshake is complete, applications layered above securelink
 * sometimes need their own keys bound to this exact session — e.g. to
 * derive per-stream keys, channel-binding tokens, or to derive a token
 * a client can present elsewhere. The exporter gives them a clean way
 * to do that without re-using the AEAD traffic keys.
 *
 * Output = HKDF-Expand(exporter_secret,
 *                       SHA-256(label) || optional context).
 *
 * Two different labels always produce independent material. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_EXPORTER_SECRET_LEN 32

int sl_exporter_init(const uint8_t  master_secret[SL_EXPORTER_SECRET_LEN],
                     uint8_t        out[SL_EXPORTER_SECRET_LEN]);

int sl_exporter_derive(const uint8_t  exporter_secret[SL_EXPORTER_SECRET_LEN],
                       const char    *label,
                       const uint8_t *context, size_t context_len,
                       uint8_t       *out,     size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_EXPORTER_H */
