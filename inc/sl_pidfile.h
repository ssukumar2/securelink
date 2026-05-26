#ifndef SECURELINK_SL_PIDFILE_H
#define SECURELINK_SL_PIDFILE_H

/* PID-file utilities for daemons.
 *
 *  - sl_pidfile_write(): atomically write the current PID, locking the file
 *    so a second instance can't start with the same pidfile.
 *  - sl_pidfile_check_stale(): tell whether an existing pidfile points at a
 *    process that's actually still running.
 *  - sl_pidfile_remove(): clean up at shutdown. */

#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 0 on success, -1 if another instance already holds the file. */
int  sl_pidfile_write(const char *path);

bool sl_pidfile_check_stale(const char *path);
pid_t sl_pidfile_read(const char *path);

void sl_pidfile_remove(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_PIDFILE_H */
