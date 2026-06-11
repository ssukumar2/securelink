#include "sl_server_name.h"

#include <ctype.h>
#include <string.h>

bool sl_server_name_is_valid_host(const char *host, size_t len) {
    if (!host || len == 0 || len > SL_SERVER_NAME_MAX_LEN) return false;
    if (host[0] == '.' || host[len - 1] == '.') return false;

    size_t label_len = 0;
    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = (unsigned char)host[i];
        if (c == '.') {
            if (label_len == 0 || label_len > 63) return false;
            label_len = 0;
            continue;
        }
        const bool ok = isalnum(c) || c == '-';
        if (!ok) return false;
        if (c == '-' && (label_len == 0)) return false; /* no leading hyphen */
        ++label_len;
    }
    return label_len > 0 && label_len <= 63;
}

int sl_server_name_pack(const sl_server_name_t *sn,
                        uint8_t *out, size_t out_cap) {
    if (!sn || !out) return -1;
    if (!sl_server_name_is_valid_host(sn->host, sn->host_len)) return -1;
    const size_t need = 1 + 2 + sn->host_len;
    if (out_cap < need) return -1;

    out[0] = sn->name_type;
    out[1] = (uint8_t)(sn->host_len >> 8);  /* always 0 since len<=253 */
    out[2] = (uint8_t)(sn->host_len & 0xFF);
    memcpy(out + 3, sn->host, sn->host_len);
    return (int)need;
}

int sl_server_name_unpack(const uint8_t *in, size_t in_len,
                          sl_server_name_t *out) {
    if (!in || !out) return -1;
    if (in_len < 3) return -1;

    memset(out, 0, sizeof(*out));
    out->name_type = in[0];
    const uint16_t hl = ((uint16_t)in[1] << 8) | (uint16_t)in[2];
    if (hl > SL_SERVER_NAME_MAX_LEN) return -1;
    if (in_len < (size_t)3 + hl) return -1;

    memcpy(out->host, in + 3, hl);
    out->host[hl] = '\0';
    out->host_len = (uint8_t)hl;

    if (!sl_server_name_is_valid_host(out->host, out->host_len)) return -1;
    return 0;
}
