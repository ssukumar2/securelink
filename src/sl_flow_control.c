#include "sl_flow_control.h"

void sl_flow_init(sl_flow_ctrl_t *fc) {
    sl_flow_init_with(fc, SL_FC_INITIAL_WINDOW);
}

void sl_flow_init_with(sl_flow_ctrl_t *fc, uint32_t initial) {
    if (!fc) return;
    fc->send_credit = (int64_t)initial;
    fc->recv_window = (int64_t)initial;
}

int sl_flow_charge_send(sl_flow_ctrl_t *fc, uint32_t bytes) {
    if (!fc) return -1;
    if (fc->send_credit < (int64_t)bytes) return -1;
    fc->send_credit -= (int64_t)bytes;
    return 0;
}

int sl_flow_charge_recv(sl_flow_ctrl_t *fc, uint32_t bytes) {
    if (!fc) return -1;
    if (fc->recv_window < (int64_t)bytes) return -1;
    fc->recv_window -= (int64_t)bytes;
    return 0;
}

int sl_flow_grant_recv(sl_flow_ctrl_t *fc, uint32_t bytes) {
    if (!fc) return -1;
    if ((uint64_t)fc->recv_window + bytes > SL_FC_MAX_WINDOW) return -1;
    fc->recv_window += (int64_t)bytes;
    return 0;
}

int sl_flow_grant_send(sl_flow_ctrl_t *fc, uint32_t bytes) {
    if (!fc) return -1;
    if ((uint64_t)fc->send_credit + bytes > SL_FC_MAX_WINDOW) return -1;
    fc->send_credit += (int64_t)bytes;
    return 0;
}

bool sl_flow_can_send(const sl_flow_ctrl_t *fc, uint32_t bytes) {
    return fc && fc->send_credit >= (int64_t)bytes;
}
