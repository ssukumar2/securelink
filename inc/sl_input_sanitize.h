#ifndef SECURELINK_SL_INPUT_SANITIZE_H
#define SECURELINK_SL_INPUT_SANITIZE_H

/* Defensive input-validation helpers for untrusted protocol fields.
 *
 * The goal is to reject malformed/hostile input cheaply *before* it reaches
 * any allocator, parser, or crypto code path. Each check is branch-light
 * and constant-bounded so it can run on every frame.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* True if `len` lies in [min, max] inclusive without integer overflow. */
bool sl_in_range_size(size_t len, size_t min, size_t max);

/* True if `buf` of length `len` contains only printable ASCII (0x20-0x7E).
 * Reject control characters and high bytes outright. */
bool sl_is_printable_ascii(const uint8_t *buf, size_t len);

/* True if `buf` looks like valid UTF-8. Rejects overlong forms, surrogates,
 * and code points > U+10FFFF. */
bool sl_is_valid_utf8(const uint8_t *buf, size_t len);

/* Reject classic shell/SQL/log-injection metacharacters.
 * NOT a substitute for parameterized queries — use only for labels/IDs. */
bool sl_has_metachars(const uint8_t *buf, size_t len);

/* Verify that `a + b` does not overflow size_t. */
bool sl_size_add_safe(size_t a, size_t b, size_t *out);

/* Verify that `a * b` does not overflow size_t. */
bool sl_size_mul_safe(size_t a, size_t b, size_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_INPUT_SANITIZE_H */
