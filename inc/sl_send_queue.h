#ifndef SECURELINK_SL_SEND_QUEUE_H
#define SECURELINK_SL_SEND_QUEUE_H

/* Outbound queue for partially-sent records. The connection enqueues
 * whole records; the I/O loop calls sl_send_queue_flush() whenever the
 * socket is writeable, which sends as much as the kernel will take and
 * leaves the rest in the queue.
 *
 * Bounded capacity; over-the-limit enqueues are rejected so a slow peer
 * can't unboundedly consume server memory. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sl_send_queue sl_send_queue_t;

sl_send_queue_t *sl_send_queue_new(size_t max_bytes);
void             sl_send_queue_free(sl_send_queue_t *q);

/* Enqueue `len` bytes for later flushing. Returns 0 on success, -1 if
 * the queue is full (caller should apply back-pressure or drop). */
int  sl_send_queue_enqueue(sl_send_queue_t *q,
                           const uint8_t *data, size_t len);

/* Try to write up to `q`'s buffered bytes to `fd`. Stops on EAGAIN.
 * Returns bytes actually sent (>= 0), or -1 on hard error. */
int  sl_send_queue_flush(sl_send_queue_t *q, int fd);

size_t sl_send_queue_pending(const sl_send_queue_t *q);
bool   sl_send_queue_empty  (const sl_send_queue_t *q);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_SEND_QUEUE_H */
