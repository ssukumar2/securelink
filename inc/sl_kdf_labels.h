#ifndef SECURELINK_SL_KDF_LABELS_H
#define SECURELINK_SL_KDF_LABELS_H

/* Fixed HKDF info strings ("labels") used throughout securelink.
 *
 * Centralizing them prevents accidental reuse of the same label for
 * different purposes — which would derive identical key material in
 * two contexts and break domain separation.
 *
 * Format convention: "securelink v1 <purpose>".
 * Bumping the version prefix forces a fresh derivation across every
 * label simultaneously, which is what we want for protocol upgrades.
 */

#define SL_KDF_LABEL_CLIENT_KEY     "securelink v1 c2s key"
#define SL_KDF_LABEL_SERVER_KEY     "securelink v1 s2c key"
#define SL_KDF_LABEL_CLIENT_IV      "securelink v1 c2s iv"
#define SL_KDF_LABEL_SERVER_IV      "securelink v1 s2c iv"
#define SL_KDF_LABEL_HANDSHAKE_MAC  "securelink v1 handshake mac"
#define SL_KDF_LABEL_REKEY          "securelink v1 rekey"
#define SL_KDF_LABEL_RESUMPTION     "securelink v1 resumption"
#define SL_KDF_LABEL_EXPORTER       "securelink v1 exporter"

/* Compile-time string length helpers (excluding NUL). */
#define SL_KDF_LABEL_LEN(s) (sizeof(s) - 1)

#endif /* SECURELINK_SL_KDF_LABELS_H */
