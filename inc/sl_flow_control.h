#ifndef SECURELINK_SL_FLOW_CONTROL_H
#define SECURELINK_SL_FLOW_CONTROL_H

/* Per-stream and session-level flow control via credit windows.
 *
 * Each side advertises how many more bytes it is willing to receive on a
 * given stream. The sender decrements its credit on every data byte; it
 * MUST stop sending once credit hits zero. The receiver replenishes the
 * credit by sending WINDOW frames as it consumes data from buffers.
 *
 * Two layers run in parallel:
 *   - Per-stream window — prevents one stream from monopolizing memory.
 *   - Session window    — caps total inflight bytes across all streams.
 *
 * Both layers reject sends if either window would go negative. */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_FC_INITIAL_WINDOW   (64U * 1024U)
#define SL_FC_MAX_WINDOW       (1U << 30)       /* 1 GiB hard cap */

typedef struct {
    int64_t send_credit;   /* bytes WE may still send */
    int64_t recv_window;   /* bytes peer may still send */
} sl_flow_ctrl_t;

void sl_flow_init(sl_flow_ctrl_t *fc);
void sl_flow_init_with(sl_flow_ctrl_t *fc, uint32_t initial);

/* Sender side: deduct from send_credit. Returns 0 if allowed, -1 if not. */
int  sl_flow_charge_send(sl_flow_ctrl_t *fc, uint32_t bytes);

/* Receiver side: deduct from recv_window. Returns 0 if peer was allowed
 * to send this much; -1 if they exceeded their window (protocol violation). */
int  sl_flow_charge_recv(sl_flow_ctrl_t *fc, uint32_t bytes);

/* Receiver replenishes its own window after consuming buffered bytes. */
int  sl_flow_grant_recv(sl_flow_ctrl_t *fc, uint32_t bytes);

/* Sender learns the peer extended its window. */
int  sl_flow_grant_send(sl_flow_ctrl_t *fc, uint32_t bytes);

bool sl_flow_can_send(const sl_flow_ctrl_t *fc, uint32_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_FLOW_CONTROL_H */
