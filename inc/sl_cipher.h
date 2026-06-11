#ifndef SECURELINK_SL_CIPHER_H
#define SECURELINK_SL_CIPHER_H

/* Cipher suite registry.
 *
 * A cipher suite is the bundle of (AEAD, KDF hash, key length). Today we
 * only support AES-256-GCM with HKDF-SHA256, but the registry exists so
 * future additions (e.g. ChaCha20-Poly1305) can be negotiated cleanly.
 *
 * Each suite has a stable u16 ID used on the wire. The list-encoding
 * format mirrors sl_version: u8 count || u16[count].
 *
 * Selection follows the standard rule: the SERVER picks from its own
 * preference order, considering only suites also offered by the client. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_CIPHER_AES256_GCM_SHA256   0x0001U
#define SL_CIPHER_CHACHA20_POLY1305   0x0002U   /* reserved, not yet supported */

#define SL_CIPHER_LIST_MAX 8

typedef struct {
    uint16_t suites[SL_CIPHER_LIST_MAX];
    uint8_t  count;
} sl_cipher_list_t;

void sl_cipher_list_init(sl_cipher_list_t *l);
int  sl_cipher_list_add (sl_cipher_list_t *l, uint16_t suite);
bool sl_cipher_list_has (const sl_cipher_list_t *l, uint16_t suite);

int sl_cipher_list_encode(const sl_cipher_list_t *l,
                          uint8_t *out, size_t out_cap);
int sl_cipher_list_decode(const uint8_t *in, size_t in_len,
                          sl_cipher_list_t *out);

/* Pick from `server_pref` the first suite the client also offers. */
uint16_t sl_cipher_choose(const sl_cipher_list_t *server_pref,
                          const sl_cipher_list_t *client_offered);

const char *sl_cipher_name(uint16_t suite);
bool        sl_cipher_is_supported(uint16_t suite);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_CIPHER_H */
