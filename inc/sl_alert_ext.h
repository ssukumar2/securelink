#ifndef SECURELINK_SL_ALERT_EXT_H
#define SECURELINK_SL_ALERT_EXT_H

/* Extended alert payload: the standard 2-byte alert plus a 16-bit
 * structured diagnostic code, so logs and clients see the same precise
 * reason a connection was dropped.
 *
 *   u8  level         (1=warning, 2=fatal)
 *   u8  legacy_code   (sl_alert_code_t, for cross-compat)
 *   u16 diag_code     (sl_diag_code_t)
 *
 * Carried inside SL_REC_ALERT records, alongside or instead of the
 * basic 2-byte alert. The receiver MUST tolerate both lengths (2 or 4). */

#include <stddef.h>
#include <stdint.h>

#include "sl_alert.h"
#include "sl_diag_code.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SL_ALERT_EXT_LEN 4U

int sl_alert_ext_pack(uint8_t level, sl_alert_code_t legacy,
                      sl_diag_code_t diag,
                      uint8_t out[SL_ALERT_EXT_LEN]);

int sl_alert_ext_unpack(const uint8_t in[SL_ALERT_EXT_LEN],
                        uint8_t *level_out,
                        sl_alert_code_t *legacy_out,
                        sl_diag_code_t *diag_out);

/* Map a diag code to the closest legacy alert code, for peers that only
 * understand the 2-byte form. */
sl_alert_code_t sl_alert_from_diag(sl_diag_code_t diag);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_ALERT_EXT_H */
