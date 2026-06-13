#ifndef SECURELINK_SL_RPC_ID_H
#define SECURELINK_SL_RPC_ID_H

/* Monotonic request-id allocator for the RPC client.
 *
 * 32-bit IDs, never reused within a session. Starts at 1 because 0 is
 * reserved as "no request" / "unsolicited message". The allocator wraps
 * defensively: if 2^32 IDs are exhausted, allocation returns 0 and the
 * client is expected to tear down the session and renegotiate. */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_RPC_ID_RESERVED  0U

typedef struct {
    uint32_t next;
    uint32_t allocated;   /* total IDs ever handed out */
    bool     exhausted;
} sl_rpc_id_alloc_t;

void     sl_rpc_id_init  (sl_rpc_id_alloc_t *a);
uint32_t sl_rpc_id_next  (sl_rpc_id_alloc_t *a);
bool     sl_rpc_id_is_exhausted(const sl_rpc_id_alloc_t *a);
uint32_t sl_rpc_id_allocated_count(const sl_rpc_id_alloc_t *a);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_RPC_ID_H */
