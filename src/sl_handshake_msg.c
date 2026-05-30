#include "sl_handshake_msg.h"

#include <string.h>

int sl_hs_pack_header(uint8_t out[SL_HS_HEADER_LEN],
                      sl_hs_type_t type, uint32_t payload_len) {
    if (!out) return -1;
    if (payload_len > 0xFFFFFFu) return -1;
    out[0] = (uint8_t)type;
    out[1] = (uint8_t)((payload_len >> 16) & 0xFF);
    out[2] = (uint8_t)((payload_len >>  8) & 0xFF);
    out[3] = (uint8_t)( payload_len        & 0xFF);
    return 0;
}

int sl_hs_unpack_header(const uint8_t in[SL_HS_HEADER_LEN],
                        sl_hs_type_t *type_out, uint32_t *payload_len_out) {
    if (!in || !type_out || !payload_len_out) return -1;
    *type_out = (sl_hs_type_t)in[0];
    *payload_len_out = ((uint32_t)in[1] << 16) |
                       ((uint32_t)in[2] <<  8) |
                        (uint32_t)in[3];
    if (*payload_len_out > SL_HS_MAX_PAYLOAD) return -1;
    return 0;
}

int sl_hs_pack_hello(const sl_hs_hello_t *h, uint8_t *out, size_t cap) {
    if (!h || !out) return -1;
    if (cap < SL_HS_HELLO_BODY_LEN) return -1;

    size_t off = 0;
    memcpy(out + off, h->random,   SL_HS_RANDOM_LEN);    off += SL_HS_RANDOM_LEN;
    memcpy(out + off, h->ecdh_pub, SL_ECDH_PUBKEY_LEN);  off += SL_ECDH_PUBKEY_LEN;
    out[off++] = (uint8_t)(h->cipher >> 8);
    out[off++] = (uint8_t)(h->cipher & 0xFF);
    return (int)off;
}

int sl_hs_unpack_hello(const uint8_t *in, size_t len, sl_hs_hello_t *out) {
    if (!in || !out) return -1;
    if (len != SL_HS_HELLO_BODY_LEN) return -1;

    size_t off = 0;
    memcpy(out->random,   in + off, SL_HS_RANDOM_LEN);    off += SL_HS_RANDOM_LEN;
    memcpy(out->ecdh_pub, in + off, SL_ECDH_PUBKEY_LEN);  off += SL_ECDH_PUBKEY_LEN;
    out->cipher = ((uint16_t)in[off] << 8) | (uint16_t)in[off + 1];
    return 0;
}

const char *sl_hs_type_name(sl_hs_type_t t) {
    switch (t) {
        case SL_HS_INVALID:      return "invalid";
        case SL_HS_CLIENT_HELLO: return "client_hello";
        case SL_HS_SERVER_HELLO: return "server_hello";
        case SL_HS_CERTIFICATE:  return "certificate";
        case SL_HS_CERT_VERIFY:  return "certificate_verify";
        case SL_HS_FINISHED:     return "finished";
    }
    return "?";
}
