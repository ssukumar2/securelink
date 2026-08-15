#ifndef SECURELINK_SL_RPC_MSG_H
#define SECURELINK_SL_RPC_MSG_H

/* RPC layer message format. Each RPC is one request frame and one
 * response frame, carried over a dedicated bidirectional stream.
 *
 * Request:
 *   u8   msg_type   (= 1)
 *   u8   reserved
 *   u32  request_id (caller-allocated, matched in response)
 *   u16  method_len
 *   ...  method (UTF-8, no NUL)
 *   u32  body_len
 *   ...  body
 *
 * Response:
 *   u8   msg_type   (= 2)
 *   u8   status     (sl_rpc_status_t)
 *   u32  request_id
 *   u16  reserved   (must be 0)
 *   u32  body_len
 *   ...  body
 *
 * Method names and body bytes are opaque to the framing layer;
 * applications choose their own encoding (JSON, CBOR, raw bytes). */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_RPC_METHOD_MAX 128U
#define SL_RPC_BODY_MAX   (16UL * 1024UL)

typedef enum {
    SL_RPC_REQUEST  = 1,
    SL_RPC_RESPONSE = 2,
} sl_rpc_msg_type_t;

typedef enum {
    SL_RPC_OK              = 0,
    SL_RPC_BAD_REQUEST     = 1,
    SL_RPC_NOT_FOUND       = 2,
    SL_RPC_NOT_PERMITTED   = 3,
    SL_RPC_INTERNAL        = 4,
    SL_RPC_RATE_LIMITED    = 5,
    SL_RPC_UNAVAILABLE     = 6,
} sl_rpc_status_t;

typedef struct {
    uint32_t       request_id;
    char           method[SL_RPC_METHOD_MAX + 1];
    uint16_t       method_len;
    const uint8_t *body;
    uint32_t       body_len;
} sl_rpc_request_t;

typedef struct {
    uint32_t        request_id;
    sl_rpc_status_t status;
    const uint8_t  *body;
    uint32_t        body_len;
} sl_rpc_response_t;

int sl_rpc_request_pack (const sl_rpc_request_t *r,
                         uint8_t *out, size_t out_cap);

int sl_rpc_request_unpack(const uint8_t *in, size_t in_len,
                          sl_rpc_request_t *out);

int sl_rpc_response_pack(const sl_rpc_response_t *r,
                         uint8_t *out, size_t out_cap);

int sl_rpc_response_unpack(const uint8_t *in, size_t in_len,
                           sl_rpc_response_t *out);

const char *sl_rpc_status_name(sl_rpc_status_t s);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_RPC_MSG_H */
