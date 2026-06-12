#include "sl_priority.h"

const char *sl_priority_name(sl_priority_t p) {
    switch (p) {
        case SL_PRIO_URGENT:     return "urgent";
        case SL_PRIO_HIGH:       return "high";
        case SL_PRIO_NORMAL:     return "normal";
        case SL_PRIO_LOW:        return "low";
        case SL_PRIO_BACKGROUND: return "background";
    }
    return "?";
}

sl_priority_t sl_priority_default_for(uint32_t stream_id) {
    if (stream_id == 0) return SL_PRIO_URGENT;
    return SL_PRIO_NORMAL;
}

uint8_t sl_priority_to_byte(sl_priority_t p) {
    if ((int)p < 0 || (int)p >= SL_PRIORITY_COUNT) return (uint8_t)SL_PRIO_NORMAL;
    return (uint8_t)p;
}

sl_priority_t sl_priority_from_byte(uint8_t b) {
    if (b >= SL_PRIORITY_COUNT) return SL_PRIO_NORMAL;
    return (sl_priority_t)b;
}
