#ifndef SECURELINK_SL_LOG_H
#define SECURELINK_SL_LOG_H

/* Lightweight leveled structured logger for the C side.
 *
 * Output format (logfmt-style, one line per event):
 *   ts=2026-05-08T13:30:11.412Z level=INFO module=crypto msg="key rotated" peer=1.2.3.4
 *
 * Thread-safe. Lock-free fast path for the level filter check so disabled
 * lines cost only a load + branch. */

#include <stdarg.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SL_LOG_TRACE = 0,
    SL_LOG_DEBUG = 1,
    SL_LOG_INFO  = 2,
    SL_LOG_WARN  = 3,
    SL_LOG_ERROR = 4,
    SL_LOG_FATAL = 5,
} sl_log_level_t;

/* Configure global sink. If `fp` is NULL, defaults to stderr. */
void sl_log_init(FILE *fp, sl_log_level_t level);

/* Runtime level changes (e.g. on SIGUSR2). */
void           sl_log_set_level(sl_log_level_t level);
sl_log_level_t sl_log_get_level(void);

/* Core printf-style entry point. `module` is a short tag (e.g. "crypto"). */
void sl_log_emit(sl_log_level_t lvl, const char *module,
                 const char *fmt, ...);

/* Macros for the common levels. */
#define SL_LOG_T(mod, ...) sl_log_emit(SL_LOG_TRACE, (mod), __VA_ARGS__)
#define SL_LOG_D(mod, ...) sl_log_emit(SL_LOG_DEBUG, (mod), __VA_ARGS__)
#define SL_LOG_I(mod, ...) sl_log_emit(SL_LOG_INFO,  (mod), __VA_ARGS__)
#define SL_LOG_W(mod, ...) sl_log_emit(SL_LOG_WARN,  (mod), __VA_ARGS__)
#define SL_LOG_E(mod, ...) sl_log_emit(SL_LOG_ERROR, (mod), __VA_ARGS__)
#define SL_LOG_F(mod, ...) sl_log_emit(SL_LOG_FATAL, (mod), __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_LOG_H */
