#ifndef SECURELINK_SL_STREAM_ID_H
#define SECURELINK_SL_STREAM_ID_H

/* Stream identifiers for multiplexed channels over one session.
 *
 * 32-bit IDs partitioned by initiator parity (similar to HTTP/2):
 *   - Client-initiated stream IDs are ODD   (1, 3, 5, ...)
 *   - Server-initiated stream IDs are EVEN  (2, 4, 6, ...)
 *   - 0 is reserved (control/session-wide messages)
 *
 * This prevents collisions when both sides allocate concurrently
 * without coordination. Each side keeps its own monotonic counter
 * and never reuses an ID within a session. */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_STREAM_ID_CONTROL  0U
#define SL_STREAM_ID_MAX      0x7FFFFFFFU   /* leave high bit reserved */

typedef enum {
    SL_STREAM_ROLE_CLIENT = 0,
    SL_STREAM_ROLE_SERVER = 1,
} sl_stream_role_t;

typedef struct {
    sl_stream_role_t role;
    uint32_t         next_id;
} sl_stream_id_alloc_t;

void     sl_stream_id_init(sl_stream_id_alloc_t *a, sl_stream_role_t role);
uint32_t sl_stream_id_next(sl_stream_id_alloc_t *a);

bool sl_stream_id_is_client_initiated(uint32_t id);
bool sl_stream_id_is_server_initiated(uint32_t id);
bool sl_stream_id_is_control(uint32_t id);
bool sl_stream_id_belongs_to_peer(uint32_t id, sl_stream_role_t my_role);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_STREAM_ID_H */
