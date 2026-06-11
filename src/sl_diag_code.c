#include "sl_diag_code.h"

const char *sl_diag_code_name(sl_diag_code_t c) {
    switch (c) {
        case SL_DIAG_OK:                      return "ok";
        case SL_DIAG_VERSION_MISMATCH:        return "version_mismatch";
        case SL_DIAG_CIPHER_MISMATCH:         return "cipher_mismatch";
        case SL_DIAG_BAD_RECORD:              return "bad_record";
        case SL_DIAG_UNEXPECTED_MESSAGE:      return "unexpected_message";
        case SL_DIAG_BAD_EXTENSION:           return "bad_extension";
        case SL_DIAG_OVERSIZE:                return "oversize";
        case SL_DIAG_BAD_MAC:                 return "bad_mac";
        case SL_DIAG_DECRYPT_FAIL:            return "decrypt_fail";
        case SL_DIAG_BAD_SIGNATURE:           return "bad_signature";
        case SL_DIAG_BAD_ECDH:                return "bad_ecdh";
        case SL_DIAG_KDF_FAIL:                return "kdf_fail";
        case SL_DIAG_RNG_FAIL:                return "rng_fail";
        case SL_DIAG_RATE_LIMITED:            return "rate_limited";
        case SL_DIAG_LOCKED_OUT:              return "locked_out";
        case SL_DIAG_QUARANTINED:             return "quarantined";
        case SL_DIAG_REPLAY:                  return "replay";
        case SL_DIAG_CLOCK_SKEW:              return "clock_skew";
        case SL_DIAG_PEER_UNKNOWN:            return "peer_unknown";
        case SL_DIAG_PIN_MISMATCH:            return "pin_mismatch";
        case SL_DIAG_TICKET_EXPIRED:          return "ticket_expired";
        case SL_DIAG_TICKET_INVALID:          return "ticket_invalid";
        case SL_DIAG_OUT_OF_MEMORY:           return "out_of_memory";
        case SL_DIAG_TOO_MANY_CONNECTIONS:    return "too_many_connections";
        case SL_DIAG_IO_ERROR:                return "io_error";
        case SL_DIAG_TIMEOUT:                 return "timeout";
        case SL_DIAG_INTERNAL:                return "internal";
        case SL_DIAG_NOT_IMPLEMENTED:         return "not_implemented";
    }
    return "unknown";
}

const char *sl_diag_category(sl_diag_code_t c) {
    const uint16_t x = (uint16_t)c & 0xF000U;
    switch (x) {
        case 0x0000: return "ok";
        case 0x1000: return "protocol";
        case 0x2000: return "crypto";
        case 0x3000: return "policy";
        case 0x4000: return "identity";
        case 0x5000: return "resource";
        case 0x9000: return "internal";
        default:     return "unknown";
    }
}
