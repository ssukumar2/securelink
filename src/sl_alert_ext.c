#include "sl_alert_ext.h"

int sl_alert_ext_pack(uint8_t level, sl_alert_code_t legacy,
                      sl_diag_code_t diag,
                      uint8_t out[SL_ALERT_EXT_LEN]) {
    if (!out) return -1;
    if (level != SL_ALERT_LEVEL_WARNING && level != SL_ALERT_LEVEL_FATAL) return -1;
    out[0] = level;
    out[1] = (uint8_t)legacy;
    out[2] = (uint8_t)((uint16_t)diag >> 8);
    out[3] = (uint8_t)((uint16_t)diag & 0xFF);
    return 0;
}

int sl_alert_ext_unpack(const uint8_t in[SL_ALERT_EXT_LEN],
                        uint8_t *level_out,
                        sl_alert_code_t *legacy_out,
                        sl_diag_code_t *diag_out) {
    if (!in || !level_out || !legacy_out || !diag_out) return -1;
    if (in[0] != SL_ALERT_LEVEL_WARNING && in[0] != SL_ALERT_LEVEL_FATAL) return -1;
    *level_out  = in[0];
    *legacy_out = (sl_alert_code_t)in[1];
    *diag_out   = (sl_diag_code_t)(((uint16_t)in[2] << 8) | (uint16_t)in[3]);
    return 0;
}

sl_alert_code_t sl_alert_from_diag(sl_diag_code_t diag) {
    switch (diag) {
        case SL_DIAG_VERSION_MISMATCH:    return SL_ALERT_PROTOCOL_VERSION;
        case SL_DIAG_CIPHER_MISMATCH:     return SL_ALERT_HANDSHAKE_FAILURE;
        case SL_DIAG_BAD_RECORD:          return SL_ALERT_BAD_RECORD_MAC;
        case SL_DIAG_UNEXPECTED_MESSAGE:  return SL_ALERT_UNEXPECTED_RECORD;
        case SL_DIAG_BAD_EXTENSION:       return SL_ALERT_HANDSHAKE_FAILURE;
        case SL_DIAG_OVERSIZE:            return SL_ALERT_RECORD_OVERFLOW;
        case SL_DIAG_BAD_MAC:             return SL_ALERT_BAD_RECORD_MAC;
        case SL_DIAG_DECRYPT_FAIL:        return SL_ALERT_DECRYPT_ERROR;
        case SL_DIAG_BAD_SIGNATURE:       return SL_ALERT_BAD_CERTIFICATE;
        case SL_DIAG_BAD_ECDH:            return SL_ALERT_HANDSHAKE_FAILURE;
        case SL_DIAG_RATE_LIMITED:        return SL_ALERT_RATE_LIMITED;
        case SL_DIAG_REPLAY:              return SL_ALERT_REPLAY;
        case SL_DIAG_QUARANTINED:         return SL_ALERT_QUARANTINED;
        case SL_DIAG_PIN_MISMATCH:        return SL_ALERT_BAD_CERTIFICATE;
        default:                          return SL_ALERT_INTERNAL_ERROR;
    }
}
