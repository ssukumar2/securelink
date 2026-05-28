#ifndef SECURELINK_SL_ALERT_H
#define SECURELINK_SL_ALERT_H

/* Alert records — fixed 2-byte payload sent in SL_REC_ALERT records.
 *
 *   u8 level     (1=warning, 2=fatal)
 *   u8 code      (sl_alert_code_t)
 *
 * On fatal alerts both peers MUST close the connection immediately.
 * On warning alerts the connection may continue. */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_ALERT_PAYLOAD_LEN 2U
#define SL_ALERT_LEVEL_WARNING 1U
#define SL_ALERT_LEVEL_FATAL   2U

typedef enum {
    SL_ALERT_CLOSE_NOTIFY          = 0,
    SL_ALERT_UNEXPECTED_RECORD     = 10,
    SL_ALERT_BAD_RECORD_MAC        = 20,
    SL_ALERT_RECORD_OVERFLOW       = 22,
    SL_ALERT_HANDSHAKE_FAILURE     = 40,
    SL_ALERT_BAD_CERTIFICATE       = 42,
    SL_ALERT_DECRYPT_ERROR         = 51,
    SL_ALERT_PROTOCOL_VERSION      = 70,
    SL_ALERT_INTERNAL_ERROR        = 80,
    SL_ALERT_USER_CANCELED         = 90,
    SL_ALERT_RATE_LIMITED          = 100,
    SL_ALERT_REPLAY                = 101,
    SL_ALERT_QUARANTINED           = 102,
} sl_alert_code_t;

int sl_alert_pack(uint8_t level, sl_alert_code_t code,
                  uint8_t out[SL_ALERT_PAYLOAD_LEN]);

int sl_alert_unpack(const uint8_t in[SL_ALERT_PAYLOAD_LEN],
                    uint8_t *level_out, sl_alert_code_t *code_out);

const char *sl_alert_code_name(sl_alert_code_t c);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_ALERT_H */
