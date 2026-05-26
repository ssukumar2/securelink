#ifndef SECURELINK_SL_CONFIG_H
#define SECURELINK_SL_CONFIG_H

/* Minimal INI-style configuration loader.
 *
 *   # comment
 *   ; also comment
 *   [section]
 *   key = value
 *   key2=value with spaces
 *
 * Keys are looked up as "section.key" — flat namespace. No quoting,
 * no escape sequences, no nested sections. Values are stripped of
 * surrounding whitespace. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sl_config sl_config_t;

sl_config_t *sl_config_new(void);
void         sl_config_free(sl_config_t *c);

int          sl_config_load_file(sl_config_t *c, const char *path);
int          sl_config_set(sl_config_t *c, const char *key, const char *value);

const char  *sl_config_get_str (const sl_config_t *c, const char *key,
                                const char *fallback);
int          sl_config_get_int (const sl_config_t *c, const char *key, int fallback);
uint32_t     sl_config_get_u32 (const sl_config_t *c, const char *key, uint32_t fb);
uint64_t     sl_config_get_u64 (const sl_config_t *c, const char *key, uint64_t fb);
bool         sl_config_get_bool(const sl_config_t *c, const char *key, bool fb);

size_t       sl_config_size(const sl_config_t *c);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_CONFIG_H */
