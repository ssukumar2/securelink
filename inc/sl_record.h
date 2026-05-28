#ifndef SECURELINK_SL_RECORD_H
#define SECURELINK_SL_RECORD_H

/* Encrypted record layer modelled loosely on TLS 1.3 records.
 *
 * On-wire layout:
 *
 *   u8  content_type        (sl_record_type_t)
 *   u16 version             (always 0x0301 — fixed, for legibility on tcpdump)
 *   u16 ciphertext_length   (includes 16-byte AEAD tag)
 *   ...ciphertext + tag...
 *
 * The 5-byte header is the AEAD AAD. Plaintext is the inner payload.
 * Sequence numbers are NOT on the wire; both peers count locally and
 * XOR them into the static IV (see sl_nonce). This keeps records minimal
 * but means out-of-order or skipped records are fatal — TCP delivers
 * in order, so that's fine. */

#include <stddef.h>
#include <stdint.h>

#include "sl_aead.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SL_RECORD_HEADER_LEN  5U
#define SL_RECORD_VERSION     0x0301U
#define SL_RECORD_MAX_PLAINTEXT  16384U
#define SL_RECORD_MAX_CIPHERTEXT (SL_RECORD_MAX_PLAINTEXT + SL_AEAD_TAG_LEN)

typedef enum {
    SL_REC_INVALID    = 0,
    SL_REC_HANDSHAKE  = 22,
    SL_REC_APP_DATA   = 23,
    SL_REC_ALERT      = 21,
    SL_REC_KEY_UPDATE = 24,
} sl_record_type_t;

/* Encode and seal a record into `out`. Caller must provide a buffer of
 * at least SL_RECORD_HEADER_LEN + pt_len + SL_AEAD_TAG_LEN bytes.
 * Returns total bytes written, or -1 on failure. */
int sl_record_seal(sl_record_type_t type,
                   const uint8_t key[SL_AEAD_KEY_LEN],
                   const uint8_t static_iv[SL_AEAD_IV_LEN],
                   uint64_t seq,
                   const uint8_t *pt, size_t pt_len,
                   uint8_t *out, size_t out_cap);

/* Parse and authenticate a record. `wire` must point at a complete record;
 * use sl_record_peek_len to find the expected size from the first 5 bytes.
 * On success writes plaintext into `pt_out` and sets *pt_len_out. */
int sl_record_open(const uint8_t *wire, size_t wire_len,
                   const uint8_t key[SL_AEAD_KEY_LEN],
                   const uint8_t static_iv[SL_AEAD_IV_LEN],
                   uint64_t seq,
                   sl_record_type_t *type_out,
                   uint8_t *pt_out, size_t pt_cap, size_t *pt_len_out);

/* Given the first 5 header bytes, return the total expected record size
 * (header + ciphertext). Returns -1 on malformed header. */
int sl_record_peek_len(const uint8_t header[SL_RECORD_HEADER_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_RECORD_H */
