#ifndef SECURELINK_SL_VERSION_H
#define SECURELINK_SL_VERSION_H

/* Protocol version negotiation.
 *
 * Each release of securelink declares a (major, minor) pair. The client
 * advertises a list of supported versions in its hello; the server picks
 * the highest version it also supports and echoes it back. If no overlap,
 * the server sends a protocol_version alert and closes.
 *
 * On wire each version is a u16: (major << 8) | minor.
 * Current version: 1.0 -> 0x0100. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_VERSION_1_0  0x0100U
#define SL_VERSION_CURRENT SL_VERSION_1_0

typedef struct {
    uint16_t versions[8];
    uint8_t  count;
} sl_version_list_t;

void sl_version_list_init(sl_version_list_t *l);
int  sl_version_list_add (sl_version_list_t *l, uint16_t version);
bool sl_version_list_has (const sl_version_list_t *l, uint16_t version);

/* Encode the list as: u8 count || u16[count] (big-endian).
 * Returns bytes written, or -1 if `out_cap` is too small. */
int sl_version_list_encode(const sl_version_list_t *l,
                           uint8_t *out, size_t out_cap);

int sl_version_list_decode(const uint8_t *in, size_t in_len,
                           sl_version_list_t *out);

/* Pick the highest version present in BOTH lists. Returns 0 if no overlap. */
uint16_t sl_version_choose(const sl_version_list_t *a,
                           const sl_version_list_t *b);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_VERSION_H */
