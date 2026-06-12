#ifndef SECURELINK_SL_STREAM_FRAME_H
#define SECURELINK_SL_STREAM_FRAME_H

/* Stream frame: the inner unit carried inside SL_REC_APP_DATA records
 * once multiplexing is enabled.
 *
 * Wire layout:
 *
 *   u8   frame_type
 *   u8   flags
 *   u16  reserved (must be 0)
 *   u32  stream_id
 *   u16  payload_len
 *   ...  payload (payload_len bytes)
 *
 * Total header: 10 bytes. A single AEAD record can hold one or more
 * stream frames; the receiver iterates until the record is exhausted. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_STREAM_FRAME_HEADER_LEN 10U
#define SL_STREAM_FRAME_MAX_PAYLOAD 16000U

#define SL_STREAM_FLAG_NONE   0x00
#define SL_STREAM_FLAG_FIN    0x01   /* sender closes its half */
#define SL_STREAM_FLAG_OPEN   0x02   /* first frame of a new stream */
#define SL_STREAM_FLAG_RESET  0x04   /* abnormal termination */

typedef enum {
    SL_STREAM_FRAME_INVALID = 0,
    SL_STREAM_FRAME_DATA    = 1,
    SL_STREAM_FRAME_WINDOW  = 2,   /* flow-control update */
    SL_STREAM_FRAME_RESET   = 3,
    SL_STREAM_FRAME_PING    = 4,
    SL_STREAM_FRAME_PONG    = 5,
} sl_stream_frame_type_t;

typedef struct {
    sl_stream_frame_type_t type;
    uint8_t                flags;
    uint32_t               stream_id;
    const uint8_t         *payload;
    uint16_t               payload_len;
} sl_stream_frame_t;

int sl_stream_frame_pack(const sl_stream_frame_t *f,
                         uint8_t *out, size_t out_cap);

/* Parse one frame from the front of `in`. On success returns total bytes
 * consumed (header + payload); sets `out->payload` to point INTO `in`. */
int sl_stream_frame_unpack(const uint8_t *in, size_t in_len,
                           sl_stream_frame_t *out);

const char *sl_stream_frame_type_name(sl_stream_frame_type_t t);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_STREAM_FRAME_H */
