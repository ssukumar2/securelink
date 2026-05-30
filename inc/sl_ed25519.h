#ifndef SECURELINK_SL_ED25519_H
#define SECURELINK_SL_ED25519_H

/* Ed25519 long-term identity signatures.
 *
 * Each securelink endpoint owns a long-term Ed25519 keypair that signs
 * the handshake transcript. This is what gives the protocol authenticity
 * (the ECDH alone only gives confidentiality + integrity-against-MITM-
 * after-key-agreement, not authentication of who you're talking to).
 *
 * Keys are stored on disk as raw 32-byte secret / public material. In
 * a real deployment you'd protect the private key file via filesystem
 * permissions and/or hardware key storage. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_ED25519_PUBKEY_LEN    32
#define SL_ED25519_PRIVKEY_LEN   32
#define SL_ED25519_SIG_LEN       64

int sl_ed25519_keypair_new(uint8_t priv[SL_ED25519_PRIVKEY_LEN],
                           uint8_t pub [SL_ED25519_PUBKEY_LEN]);

int sl_ed25519_derive_pub(const uint8_t priv[SL_ED25519_PRIVKEY_LEN],
                          uint8_t pub[SL_ED25519_PUBKEY_LEN]);

int sl_ed25519_sign(const uint8_t priv[SL_ED25519_PRIVKEY_LEN],
                    const uint8_t *msg, size_t msg_len,
                    uint8_t sig[SL_ED25519_SIG_LEN]);

int sl_ed25519_verify(const uint8_t pub[SL_ED25519_PUBKEY_LEN],
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t sig[SL_ED25519_SIG_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_ED25519_H */
