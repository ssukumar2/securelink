#include "sl_close_notify.h"

#include "sl_alert.h"

void sl_close_notify_pack(uint8_t out[SL_CLOSE_NOTIFY_LEN]) {
    if (!out) return;
    out[0] = SL_ALERT_LEVEL_FATAL;
    out[1] = (uint8_t)SL_ALERT_CLOSE_NOTIFY;
}

int sl_close_notify_is(const uint8_t *buf, size_t len) {
    if (!buf || len != SL_CLOSE_NOTIFY_LEN) return 0;
    return (buf[0] == SL_ALERT_LEVEL_FATAL &&
            buf[1] == (uint8_t)SL_ALERT_CLOSE_NOTIFY) ? 1 : 0;
}
