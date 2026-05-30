#ifndef SECURELINK_SL_HANDSHAKE_MSG_H
#define SECURELINK_SL_HANDSHAKE_MSG_H

/* Handshake message types. Each message is carried inside one or more
 * SL_REC_HANDSHAKE records. The handshake layer is structured similar
 * to TLS 1.3 but stripped to what securelink actually needs:
 *
 *   ClientHello    1 — client_random || client_ecdh_pub || cipher list
 *   ServerHello    2 — server_random || server_ecdh_pub || chosen_cipher
 *   Certificate    3 — server_identity_pubkey (Ed25519, raw 32 bytes)
 *   CertVerify     4 — Ed25519(server_priv, transcript_hash_so_far)
 *   Finished       5 — HMAC(finished_key, transcript_hash_at_finished)
 *
 * Wire framing of a single handshake message:
 *
 *   u8  msg_type
 *   u24 length         (payload bytes, NOT including this 4-byte header)
 *   .. payload ..
 */

#include <stddef.h>
#include <stdint.h>

#include "sl_ecdh.h"
#include "sl_ed25519.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SL_HS_HEADER_LEN          4U
#define SL_HS_RANDOM_LEN         32U
#define SL_HS_MAX_PAYLOAD       2048U

#define SL_HS_CIPHER_AES256_GCM   0x0001U   /* the only one we support */

typedef enum {
    SL_HS_INVALID      = 0,
    SL_HS_CLIENT_HELLO = 1,
    SL_HS_SERVER_HELLO = 2,
    SL_HS_CERTIFICATE  = 3,
    SL_HS_CERT_VERIFY  = 4,
    SL_HS_FINISHED     = 5,
} sl_hs_type_t;

typedef struct {
    uint8_t  random[SL_HS_RANDOM_LEN];
    uint8_t  ecdh_pub[SL_ECDH_PUBKEY_LEN];
    uint16_t cipher;
} sl_hs_hello_t;

typedef struct {
    uint8_t pub[SL_ED25519_PUBKEY_LEN];
} sl_hs_certificate_t;

typedef struct {
    uint8_t sig[SL_ED25519_SIG_LEN];
} sl_hs_cert_verify_t;

typedef struct {
    uint8_t mac[32];
} sl_hs_finished_t;

/* Pack the 4-byte handshake header. */
int sl_hs_pack_header(uint8_t out[SL_HS_HEADER_LEN],
                      sl_hs_type_t type, uint32_t payload_len);

/* Inverse of pack_header. */
int sl_hs_unpack_header(const uint8_t in[SL_HS_HEADER_LEN],
                        sl_hs_type_t *type_out, uint32_t *payload_len_out);

/* Hello messages: pack/unpack the fixed-size body. */
int sl_hs_pack_hello  (const sl_hs_hello_t *h, uint8_t *out, size_t cap);
int sl_hs_unpack_hello(const uint8_t *in, size_t len, sl_hs_hello_t *out);

#define SL_HS_HELLO_BODY_LEN (SL_HS_RANDOM_LEN + SL_ECDH_PUBKEY_LEN + 2)

const char *sl_hs_type_name(sl_hs_type_t t);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_HANDSHAKE_MSG_H */
