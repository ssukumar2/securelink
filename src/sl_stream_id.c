#include "sl_stream_id.h"

void sl_stream_id_init(sl_stream_id_alloc_t *a, sl_stream_role_t role) {
    if (!a) return;
    a->role    = role;
    a->next_id = (role == SL_STREAM_ROLE_CLIENT) ? 1U : 2U;
}

uint32_t sl_stream_id_next(sl_stream_id_alloc_t *a) {
    if (!a) return 0;
    if (a->next_id > SL_STREAM_ID_MAX) return 0;
    const uint32_t id = a->next_id;
    a->next_id += 2U;  /* skip the peer's parity */
    return id;
}

bool sl_stream_id_is_control(uint32_t id) {
    return id == SL_STREAM_ID_CONTROL;
}

bool sl_stream_id_is_client_initiated(uint32_t id) {
    return id != 0 && (id & 1U) == 1U;
}

bool sl_stream_id_is_server_initiated(uint32_t id) {
    return id != 0 && (id & 1U) == 0U;
}

bool sl_stream_id_belongs_to_peer(uint32_t id, sl_stream_role_t my_role) {
    if (sl_stream_id_is_control(id)) return false;
    if (my_role == SL_STREAM_ROLE_CLIENT) {
        return sl_stream_id_is_server_initiated(id);
    }
    return sl_stream_id_is_client_initiated(id);
}
