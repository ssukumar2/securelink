#ifndef SECURELINK_SL_SIGNALS_H
#define SECURELINK_SL_SIGNALS_H

/* Signal handling utilities.
 *
 *  - sl_signals_install_shutdown(): catch SIGINT/SIGTERM and set a flag.
 *  - sl_signals_install_reload(): catch SIGHUP and set a separate flag.
 *  - sl_signals_install_loglevel(): SIGUSR1 -> verbose, SIGUSR2 -> quieter.
 *
 * Use sig_atomic_t flags so the main loop can poll them without races. */

#include <signal.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void sl_signals_install_shutdown(void);
void sl_signals_install_reload  (void);
void sl_signals_install_loglevel(void);

bool sl_signals_shutdown_requested(void);
bool sl_signals_reload_requested  (void);

/* Clears the reload flag — call after acting on a reload signal. */
void sl_signals_clear_reload(void);

/* Block SIGPIPE process-wide. Recommended for any network daemon. */
void sl_signals_block_sigpipe(void);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_SIGNALS_H */
