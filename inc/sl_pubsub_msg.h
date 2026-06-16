#ifndef SECURELINK_SL_PUBSUB_MSG_H
#define SECURELINK_SL_PUBSUB_MSG_H

/* Pub/sub wire format. Carried inside SL_REC_APP_DATA records, typically
 * over a single dedicated stream per session.
 *
 *   u8   msg_type      (sl_pubsub_msg_type_t)
 *   u8   flags
 *   u16  topic_len
 *   u32  payload_len
 *   ...  topic (topic_len bytes, no NUL)
 *   ...  payload (payload_len bytes)
 *
 * Header is 8 bytes. Subscribe/unsubscribe messages carry a filter
 * pattern in the topic field and a 0-length payload. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_PUBSUB_HEADER_LEN  8U
#define SL_PUBSUB_MAX_TOPIC   256U
#define SL_PUBSUB_MAX_PAYLOAD (16U * 1024U)

#define SL_PUBSUB_FLAG_NONE     0x00
#define SL_PUBSUB_FLAG_RETAIN   0x01   /* broker stores latest for new subs */
#define SL_PUBSUB_FLAG_QOS_ACK  0x02   /* publisher wants a PUBACK */

typedef enum {
    SL_PUBSUB_INVALID     = 0,
    SL_PUBSUB_PUBLISH     = 1,
    SL_PUBSUB_SUBSCRIBE   = 2,
    SL_PUBSUB_UNSUBSCRIBE = 3,
    SL_PUBSUB_PUBACK      = 4,
    SL_PUBSUB_SUBACK      = 5,
} sl_pubsub_msg_type_t;

typedef struct {
    sl_pubsub_msg_type_t  type;
    uint8_t               flags;
    const char           *topic;
    uint16_t              topic_len;
    const uint8_t        *payload;
    uint32_t              payload_len;
} sl_pubsub_msg_t;

int sl_pubsub_pack  (const sl_pubsub_msg_t *m, uint8_t *out, size_t out_cap);
int sl_pubsub_unpack(const uint8_t *in, size_t in_len, sl_pubsub_msg_t *out);

const char *sl_pubsub_type_name(sl_pubsub_msg_type_t t);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_PUBSUB_MSG_H */
