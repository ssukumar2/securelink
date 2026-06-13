#include "sl_rpc_method.h"

#include <ctype.h>
#include <string.h>

bool sl_rpc_method_is_valid(const char *method, size_t len) {
    if (!method || len == 0 || len > SL_RPC_METHOD_NAME_MAX) return false;
    if (method[0] == '.' || method[len - 1] == '.') return false;

    size_t segment_len = 0;
    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = (unsigned char)method[i];
        if (c == '.') {
            if (segment_len == 0) return false;
            segment_len = 0;
            continue;
        }
        if (!(isalnum(c) || c == '_')) return false;
        ++segment_len;
    }
    return segment_len > 0;
}

int sl_rpc_method_split(const char *method, size_t len,
                        char *ns_out, char *leaf_out) {
    if (!sl_rpc_method_is_valid(method, len) || !ns_out || !leaf_out) return -1;

    const char *last_dot = NULL;
    for (size_t i = 0; i < len; ++i) {
        if (method[i] == '.') last_dot = method + i;
    }

    if (last_dot == NULL) {
        ns_out[0] = '\0';
        memcpy(leaf_out, method, len);
        leaf_out[len] = '\0';
        return 0;
    }

    const size_t ns_len   = (size_t)(last_dot - method);
    const size_t leaf_len = len - ns_len - 1;
    memcpy(ns_out, method, ns_len);
    ns_out[ns_len] = '\0';
    memcpy(leaf_out, last_dot + 1, leaf_len);
    leaf_out[leaf_len] = '\0';
    return 0;
}
