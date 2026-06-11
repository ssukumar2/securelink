#ifndef SECURELINK_SL_EXTENSIONS_H
#define SECURELINK_SL_EXTENSIONS_H

/* TLV extension framework, mirroring TLS extensions.
 *
 * Each extension on the wire:
 *
 *   u16  type
 *   u16  length
 *   ...  body (length bytes)
 *
 * Multiple extensions are concatenated in a length-prefixed block:
 *
 *   u16  total_extensions_length
 *   ...  extension_1 || extension_2 || ...
 *
 * Unknown extensions are skipped without error (graceful evolution).
 * The codebase parses into a small array; over-the-limit lists fail. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_EXT_MAX_COUNT   16
#define SL_EXT_MAX_BODY   512

typedef enum {
    SL_EXT_VERSIONS         = 0x0001,   /* supported_versions */
    SL_EXT_CIPHERS          = 0x0002,   /* supported_ciphers  */
    SL_EXT_SERVER_NAME      = 0x0003,   /* SNI-like */
    SL_EXT_RESUMPTION       = 0x0004,   /* session ticket on wire */
    SL_EXT_EARLY_DATA       = 0x0005,   /* reserved */
    SL_EXT_HEARTBEAT        = 0x0006,   /* enable beacon heartbeats */
} sl_ext_type_t;

typedef struct {
    uint16_t type;
    uint16_t len;
    uint8_t  body[SL_EXT_MAX_BODY];
} sl_extension_t;

typedef struct {
    sl_extension_t items[SL_EXT_MAX_COUNT];
    uint8_t        count;
} sl_extensions_t;

void sl_extensions_init(sl_extensions_t *e);

int  sl_extensions_add (sl_extensions_t *e,
                        sl_ext_type_t type,
                        const uint8_t *body, size_t body_len);

const sl_extension_t *sl_extensions_find(const sl_extensions_t *e,
                                         sl_ext_type_t type);

int sl_extensions_encode(const sl_extensions_t *e,
                         uint8_t *out, size_t out_cap);

int sl_extensions_decode(const uint8_t *in, size_t in_len,
                         sl_extensions_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_EXTENSIONS_H */
