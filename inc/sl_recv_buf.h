#ifndef SECURELINK_SL_RECV_BUF_H
#define SECURELINK_SL_RECV_BUF_H

/* Streaming receive buffer that knows about sl_record framing.
 *
 * Feed it raw bytes from recv(); pull whole records via sl_recv_buf_take().
 * Bytes that don't yet form a full record stay buffered for next call.
 *
 * Used by the connection state machine to convert "stream of bytes from
 * the kernel" into "stream of fully-formed records". */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sl_record.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   used;
} sl_recv_buf_t;

int  sl_recv_buf_init(sl_recv_buf_t *rb, size_t cap);
void sl_recv_buf_free(sl_recv_buf_t *rb);

/* Push freshly-recv'd bytes. Returns 0 on success, -1 if it would overflow. */
int  sl_recv_buf_push(sl_recv_buf_t *rb, const uint8_t *data, size_t len);

/* If a complete record is buffered, copy its bytes (including header) to
 * `out` and advance the internal cursor past it. Returns:
 *    >0   bytes written (full record consumed)
 *    0    no full record yet — call recv() again
 *   -1    malformed record (caller should close the connection) */
int  sl_recv_buf_take(sl_recv_buf_t *rb,
                      uint8_t *out, size_t out_cap);

size_t sl_recv_buf_buffered(const sl_recv_buf_t *rb);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_RECV_BUF_H */
