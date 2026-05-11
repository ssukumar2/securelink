#ifndef SECURELINK_SL_BEACON_H
#define SECURELINK_SL_BEACON_H

/* Beacon protocol — periodic authenticated heartbeats from client to server.
 *
 * Wire layout (all integers big-endian):
 *
 *   offset  size  field
 *   0       8     client_id        (opaque 64-bit identifier)
 *   8       8     sequence         (monotonic per client, starts at 1)
 *   16      8     timestamp_ms     (client wall-clock, milliseconds since epoch)
 *   24      4     interval_ms      (expected next-beacon interval, hint to server)
 *   28      2     payload_len      (bytes of optional metadata)
 *   30      2     flags            (BEACON_FLAG_*)
 *   32      N     payload          (payload_len bytes; opaque to transport)
 *
 * The whole structure above is the AAD passed to AES-256-GCM. The
 * ciphertext output and the 16-byte tag are appended after `payload`.
 * The final wire frame is wrapped in the standard FrameType::kData record.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_BEACON_HEADER_LEN   32U
#define SL_BEACON_MAX_PAYLOAD  1024U

#define SL_BEACON_FLAG_NONE        0x0000
#define SL_BEACON_FLAG_REQUEST_ACK 0x0001  /* server should send beacon_ack */
#define SL_BEACON_FLAG_LAST        0x0002  /* final beacon before shutdown */

typedef struct {
    uint64_t client_id;
    uint64_t sequence;
    uint64_t timestamp_ms;
    uint32_t interval_ms;
    uint16_t payload_len;
    uint16_t flags;
    uint8_t  payload[SL_BEACON_MAX_PAYLOAD];
} sl_beacon_t;

/* Serialize the header fields of `b` (not the payload) into a 32-byte buffer
 * in network byte order. Returns 0 on success, -1 if `out` is NULL. */
int sl_beacon_pack_header(const sl_beacon_t *b, uint8_t out[SL_BEACON_HEADER_LEN]);

/* Inverse of sl_beacon_pack_header. Returns 0 on success. */
int sl_beacon_unpack_header(const uint8_t in[SL_BEACON_HEADER_LEN], sl_beacon_t *b);

/* Validate semantic constraints (payload_len bounds, known flags).
 * Returns 0 if valid. Use after unpack_header before trusting fields. */
int sl_beacon_validate(const sl_beacon_t *b);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_BEACON_H */
