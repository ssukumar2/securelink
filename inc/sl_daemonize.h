#ifndef SECURELINK_SL_DAEMONIZE_H
#define SECURELINK_SL_DAEMONIZE_H

/* Daemonize the current process via the classic double-fork pattern.
 *
 *   - fork() twice to detach from the controlling terminal
 *   - setsid() to start a new session
 *   - chdir("/") to avoid blocking unmount of the cwd
 *   - redirect stdin/stdout/stderr to /dev/null or a file
 *
 * Modern systemd-style supervision usually doesn't need this — set
 * Type=simple and run in the foreground. Provided here for environments
 * where the daemon is launched manually. */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *chdir_to;        /* default "/" */
    const char *stdout_redirect; /* path; NULL -> /dev/null */
    const char *stderr_redirect; /* path; NULL -> /dev/null */
    bool        close_all_fds;   /* close 3..NOFILE before returning */
} sl_daemonize_opts_t;

/* Returns 0 in the daemon child, -1 on error. The original parent exits. */
int sl_daemonize(const sl_daemonize_opts_t *opts);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_DAEMONIZE_H */
