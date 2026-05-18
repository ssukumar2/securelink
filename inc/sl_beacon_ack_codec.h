#ifndef SECURELINK_SL_BEACON_ACK_CODEC_H
#define SECURELINK_SL_BEACON_ACK_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "sl_aead.h"
#include "sl_beacon_ack.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Wire format: [32 header (AAD)] [16 tag]. No payload — ACKs are header-only.
 * Total size: SL_BEACON_ACK_HEADER_LEN + SL_AEAD_TAG_LEN = 48 bytes. */
#define SL_BEACON_ACK_WIRE_LEN  (SL_BEACON_ACK_HEADER_LEN + SL_AEAD_TAG_LEN)

int sl_beacon_ack_seal(const sl_beacon_ack_t *a,
                       const uint8_t key[SL_AEAD_KEY_LEN],
                       const uint8_t static_iv[SL_AEAD_IV_LEN],
                       uint64_t seq,
                       uint8_t out[SL_BEACON_ACK_WIRE_LEN]);

int sl_beacon_ack_open(const uint8_t wire[SL_BEACON_ACK_WIRE_LEN],
                       const uint8_t key[SL_AEAD_KEY_LEN],
                       const uint8_t static_iv[SL_AEAD_IV_LEN],
                       uint64_t seq,
                       sl_beacon_ack_t *a);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_BEACON_ACK_CODEC_H */
