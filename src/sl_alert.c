#include "sl_alert.h"

#include <stddef.h>

int sl_alert_pack(uint8_t level, sl_alert_code_t code,
                  uint8_t out[SL_ALERT_PAYLOAD_LEN]) {
    if (!out) return -1;
    if (level != SL_ALERT_LEVEL_WARNING && level != SL_ALERT_LEVEL_FATAL) return -1;
    out[0] = level;
    out[1] = (uint8_t)code;
    return 0;
}

int sl_alert_unpack(const uint8_t in[SL_ALERT_PAYLOAD_LEN],
                    uint8_t *level_out, sl_alert_code_t *code_out) {
    if (!in || !level_out || !code_out) return -1;
    if (in[0] != SL_ALERT_LEVEL_WARNING && in[0] != SL_ALERT_LEVEL_FATAL) return -1;
    *level_out = in[0];
    *code_out  = (sl_alert_code_t)in[1];
    return 0;
}

const char *sl_alert_code_name(sl_alert_code_t c) {
    switch (c) {
        case SL_ALERT_CLOSE_NOTIFY:       return "close_notify";
        case SL_ALERT_UNEXPECTED_RECORD:  return "unexpected_record";
        case SL_ALERT_BAD_RECORD_MAC:     return "bad_record_mac";
        case SL_ALERT_RECORD_OVERFLOW:    return "record_overflow";
        case SL_ALERT_HANDSHAKE_FAILURE:  return "handshake_failure";
        case SL_ALERT_BAD_CERTIFICATE:    return "bad_certificate";
        case SL_ALERT_DECRYPT_ERROR:      return "decrypt_error";
        case SL_ALERT_PROTOCOL_VERSION:   return "protocol_version";
        case SL_ALERT_INTERNAL_ERROR:     return "internal_error";
        case SL_ALERT_USER_CANCELED:      return "user_canceled";
        case SL_ALERT_RATE_LIMITED:       return "rate_limited";
        case SL_ALERT_REPLAY:             return "replay";
        case SL_ALERT_QUARANTINED:        return "quarantined";
    }
    return "unknown";
}
