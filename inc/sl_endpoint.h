#ifndef SECURELINK_SL_ENDPOINT_H
#define SECURELINK_SL_ENDPOINT_H

/* Endpoint = (host, port) parsed from a single string.
 *
 * Accepted forms:
 *   host:port              "example.com:4443"
 *   [v6addr]:port          "[::1]:4443"
 *   v6addr.port            "::1.4443"     (legacy, not supported)
 *
 * Port range is enforced (1..65535). Host is copied into a caller buffer. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_ENDPOINT_HOST_MAX 256

typedef struct {
    char     host[SL_ENDPOINT_HOST_MAX];
    uint16_t port;
} sl_endpoint_t;

int sl_endpoint_parse (const char *s, sl_endpoint_t *out);
int sl_endpoint_format(const sl_endpoint_t *ep, char *buf, size_t cap);

bool sl_endpoint_is_loopback(const sl_endpoint_t *ep);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_ENDPOINT_H */
