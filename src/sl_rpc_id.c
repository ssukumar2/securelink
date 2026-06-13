#include "sl_rpc_id.h"

void sl_rpc_id_init(sl_rpc_id_alloc_t *a) {
    if (!a) return;
    a->next      = 1;
    a->allocated = 0;
    a->exhausted = false;
}

uint32_t sl_rpc_id_next(sl_rpc_id_alloc_t *a) {
    if (!a || a->exhausted) return SL_RPC_ID_RESERVED;
    const uint32_t id = a->next;
    if (id == UINT32_MAX) {
        a->exhausted = true;
        ++a->allocated;
        return id;          /* this last one is still usable */
    }
    ++a->next;
    ++a->allocated;
    return id;
}

bool sl_rpc_id_is_exhausted(const sl_rpc_id_alloc_t *a) {
    return a ? a->exhausted : true;
}

uint32_t sl_rpc_id_allocated_count(const sl_rpc_id_alloc_t *a) {
    return a ? a->allocated : 0;
}
