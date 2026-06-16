#include "sl_topic.h"

#include <ctype.h>
#include <string.h>

static bool seg_char_ok(unsigned char c) {
    return isalnum(c) || c == '_' || c == '-';
}

static bool common_structure_ok(const char *s, size_t len) {
    if (!s || len == 0 || len > SL_TOPIC_MAX_LEN) return false;
    if (s[0] == '/' || s[len - 1] == '/') return false;
    size_t segs = 1;
    for (size_t i = 0; i < len; ++i) {
        if (s[i] == '/') ++segs;
    }
    return segs <= SL_TOPIC_MAX_SEGMENTS;
}

bool sl_topic_is_valid_publish(const char *topic, size_t len) {
    if (!common_structure_ok(topic, len)) return false;
    size_t seg_len = 0;
    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = (unsigned char)topic[i];
        if (c == '/') {
            if (seg_len == 0) return false;
            seg_len = 0;
            continue;
        }
        if (!seg_char_ok(c)) return false;
        ++seg_len;
    }
    return seg_len > 0;
}

bool sl_topic_is_valid_filter(const char *filter, size_t len) {
    if (!common_structure_ok(filter, len)) return false;
    /* Walk segment-by-segment. */
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && filter[j] != '/') ++j;
        const size_t seg_len = j - i;
        if (seg_len == 0) return false;

        /* Allowed shapes for one segment: "+", "#", or seg_char_ok+ */
        if (seg_len == 1 && filter[i] == '+') {
            /* fine */
        } else if (seg_len == 1 && filter[i] == '#') {
            /* must be the final segment */
            if (j != len) return false;
        } else {
            for (size_t k = i; k < j; ++k) {
                if (!seg_char_ok((unsigned char)filter[k])) return false;
            }
        }
        i = (j < len) ? j + 1 : j;
    }
    return true;
}

bool sl_topic_matches(const char *topic,  size_t topic_len,
                      const char *filter, size_t filter_len) {
    if (!sl_topic_is_valid_publish(topic, topic_len)) return false;
    if (!sl_topic_is_valid_filter(filter, filter_len)) return false;

    size_t ti = 0, fi = 0;
    while (ti < topic_len && fi < filter_len) {
        /* Locate end of next filter segment. */
        size_t fj = fi;
        while (fj < filter_len && filter[fj] != '/') ++fj;
        const size_t flen = fj - fi;

        if (flen == 1 && filter[fi] == '#') return true;  /* greedy tail */

        /* Locate end of next topic segment. */
        size_t tj = ti;
        while (tj < topic_len && topic[tj] != '/') ++tj;
        const size_t tlen = tj - ti;

        if (flen == 1 && filter[fi] == '+') {
            /* matches any single segment */
        } else if (flen != tlen ||
                   memcmp(filter + fi, topic + ti, flen) != 0) {
            return false;
        }

        ti = (tj < topic_len) ? tj + 1 : tj;
        fi = (fj < filter_len) ? fj + 1 : fj;
    }
    return ti == topic_len && fi == filter_len;
}
