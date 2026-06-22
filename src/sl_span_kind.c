#include "sl_span_kind.h"

const char *sl_span_kind_name(sl_span_kind_t k) {
    switch (k) {
        case SL_SPAN_INTERNAL: return "internal";
        case SL_SPAN_SERVER:   return "server";
        case SL_SPAN_CLIENT:   return "client";
        case SL_SPAN_PRODUCER: return "producer";
        case SL_SPAN_CONSUMER: return "consumer";
    }
    return "?";
}

const char *sl_span_status_name(sl_span_status_t s) {
    switch (s) {
        case SL_SPAN_STATUS_UNSET: return "unset";
        case SL_SPAN_STATUS_OK:    return "ok";
        case SL_SPAN_STATUS_ERROR: return "error";
    }
    return "?";
}
