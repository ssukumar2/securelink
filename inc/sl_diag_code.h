#ifndef SECURELINK_SL_DIAG_CODE_H
#define SECURELINK_SL_DIAG_CODE_H

/* Structured diagnostic codes for errors that travel both on the wire
 * (inside alerts) and in logs.
 *
 * The space is partitioned by leading hex digit so the source category
 * is visible at a glance:
 *
 *   0x1xxx  protocol (version, framing, parse)
 *   0x2xxx  crypto    (AEAD, signature, KDF)
 *   0x3xxx  policy    (rate limit, lockout, quarantine)
 *   0x4xxx  identity  (cert, pinning, ticket)
 *   0x5xxx  resource  (memory, fd exhaustion)
 *   0x9xxx  internal  (assertion, programming bug) */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SL_DIAG_OK                       = 0x0000,

    /* 0x1xxx — protocol */
    SL_DIAG_VERSION_MISMATCH         = 0x1001,
    SL_DIAG_CIPHER_MISMATCH          = 0x1002,
    SL_DIAG_BAD_RECORD               = 0x1003,
    SL_DIAG_UNEXPECTED_MESSAGE       = 0x1004,
    SL_DIAG_BAD_EXTENSION            = 0x1005,
    SL_DIAG_OVERSIZE                 = 0x1006,

    /* 0x2xxx — crypto */
    SL_DIAG_BAD_MAC                  = 0x2001,
    SL_DIAG_DECRYPT_FAIL             = 0x2002,
    SL_DIAG_BAD_SIGNATURE            = 0x2003,
    SL_DIAG_BAD_ECDH                 = 0x2004,
    SL_DIAG_KDF_FAIL                 = 0x2005,
    SL_DIAG_RNG_FAIL                 = 0x2006,

    /* 0x3xxx — policy */
    SL_DIAG_RATE_LIMITED             = 0x3001,
    SL_DIAG_LOCKED_OUT               = 0x3002,
    SL_DIAG_QUARANTINED              = 0x3003,
    SL_DIAG_REPLAY                   = 0x3004,
    SL_DIAG_CLOCK_SKEW               = 0x3005,

    /* 0x4xxx — identity */
    SL_DIAG_PEER_UNKNOWN             = 0x4001,
    SL_DIAG_PIN_MISMATCH             = 0x4002,
    SL_DIAG_TICKET_EXPIRED           = 0x4003,
    SL_DIAG_TICKET_INVALID           = 0x4004,

    /* 0x5xxx — resource */
    SL_DIAG_OUT_OF_MEMORY            = 0x5001,
    SL_DIAG_TOO_MANY_CONNECTIONS     = 0x5002,
    SL_DIAG_IO_ERROR                 = 0x5003,
    SL_DIAG_TIMEOUT                  = 0x5004,

    /* 0x9xxx — internal */
    SL_DIAG_INTERNAL                 = 0x9001,
    SL_DIAG_NOT_IMPLEMENTED          = 0x9002,
} sl_diag_code_t;

const char *sl_diag_code_name(sl_diag_code_t c);
const char *sl_diag_category (sl_diag_code_t c);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_DIAG_CODE_H */
