#ifndef SECURELINK_SL_LOG_REDACT_H
#define SECURELINK_SL_LOG_REDACT_H

/* Redact sensitive substrings from log output. Run any user-influenced
 * string through these before passing it to sl_log_emit().
 *
 * The functions write into a caller-supplied buffer and never allocate. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Mask any 32-char-or-longer hex run as a likely key/digest:
 *   "abc 0123456789abcdef0123456789abcdef end" ->
 *   "abc <REDACTED-HEX-32> end"
 * Returns bytes written (excluding NUL), or -1 on overflow. */
int sl_log_redact_hex(const char *in, char *out, size_t out_cap);

/* Replace anything that looks like an email address with "<email>". */
int sl_log_redact_email(const char *in, char *out, size_t out_cap);

/* Replace IPv4 dotted-quads with "<ip>". Useful for shipping logs offsite
 * while still letting on-host operators see real addresses. */
int sl_log_redact_ipv4(const char *in, char *out, size_t out_cap);

/* Apply all redactions in sequence. */
int sl_log_redact_all(const char *in, char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_LOG_REDACT_H */
