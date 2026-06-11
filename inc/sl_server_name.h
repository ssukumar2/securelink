#ifndef SECURELINK_SL_SERVER_NAME_H
#define SECURELINK_SL_SERVER_NAME_H

/* Server Name Indication — lets a client tell the server which logical
 * service it intends to connect to, so one server can host multiple
 * identities (different Ed25519 keys per name).
 *
 * Wire format for the extension body:
 *
 *   u8  name_type    (0 = DNS hostname; everything else reserved)
 *   u16 name_length
 *   ... ASCII hostname (no NUL terminator)
 *
 * Hostnames are validated as a conservative subset of RFC 1123 plus
 * dots: letters, digits, '-', '.'. Length is bounded at 253 to fit
 * the standard FQDN limit. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_SERVER_NAME_MAX_LEN 253

typedef struct {
    uint8_t name_type;
    char    host[SL_SERVER_NAME_MAX_LEN + 1];
    uint8_t host_len;
} sl_server_name_t;

bool sl_server_name_is_valid_host(const char *host, size_t len);

int  sl_server_name_pack(const sl_server_name_t *sn,
                         uint8_t *out, size_t out_cap);

int  sl_server_name_unpack(const uint8_t *in, size_t in_len,
                           sl_server_name_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_SERVER_NAME_H */
