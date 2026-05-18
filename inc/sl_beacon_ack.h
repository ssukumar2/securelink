#ifndef SECURELINK_SL_BEACON_ACK_H
#define SECURELINK_SL_BEACON_ACK_H

/* Beacon ACK — server's authenticated response to a beacon that requested
 * acknowledgement (SL_BEACON_FLAG_REQUEST_ACK).
 *
 * Wire layout (all big-endian, then AEAD-sealed with header as AAD):
 *
 *   offset  size  field
 *   0       8     client_id
 *   8       8     ack_sequence    (echoes the beacon's sequence)
 *   16      8     server_time_ms  (server wall clock at ack time)
 *   24      2     status          (sl_ack_status_t)
 *   26      2     reserved        (must be 0)
 *   28      4     suggested_interval_ms (0 = no change)
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_BEACON_ACK_HEADER_LEN  32U

typedef enum {
    SL_ACK_OK              = 0,
    SL_ACK_RATE_LIMITED    = 1,
    SL_ACK_BACKOFF         = 2,   /* please slow down */
    SL_ACK_REKEY_REQUIRED  = 3,
    SL_ACK_SHUTDOWN        = 4,
} sl_ack_status_t;

typedef struct {
    uint64_t client_id;
    uint64_t ack_sequence;
    uint64_t server_time_ms;
    uint16_t status;
    uint16_t reserved;
    uint32_t suggested_interval_ms;
} sl_beacon_ack_t;

int sl_beacon_ack_pack(const sl_beacon_ack_t *a, uint8_t out[SL_BEACON_ACK_HEADER_LEN]);
int sl_beacon_ack_unpack(const uint8_t in[SL_BEACON_ACK_HEADER_LEN], sl_beacon_ack_t *a);
int sl_beacon_ack_validate(const sl_beacon_ack_t *a);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_BEACON_ACK_H */
