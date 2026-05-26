#include "sl_signals.h"

#include <signal.h>
#include <string.h>

#include "sl_log.h"

static volatile sig_atomic_t g_shutdown = 0;
static volatile sig_atomic_t g_reload   = 0;

static void on_shutdown(int sig) {
    (void)sig;
    g_shutdown = 1;
}

static void on_reload(int sig) {
    (void)sig;
    g_reload = 1;
}

static void on_verbose(int sig) {
    (void)sig;
    sl_log_level_t cur = sl_log_get_level();
    if ((int)cur > 0) sl_log_set_level((sl_log_level_t)((int)cur - 1));
}

static void on_quieter(int sig) {
    (void)sig;
    sl_log_level_t cur = sl_log_get_level();
    if ((int)cur < SL_LOG_FATAL) sl_log_set_level((sl_log_level_t)((int)cur + 1));
}

static void install(int sig, void (*handler)(int)) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
}

void sl_signals_install_shutdown(void) {
    install(SIGINT,  on_shutdown);
    install(SIGTERM, on_shutdown);
}

void sl_signals_install_reload(void) {
    install(SIGHUP, on_reload);
}

void sl_signals_install_loglevel(void) {
    install(SIGUSR1, on_verbose);
    install(SIGUSR2, on_quieter);
}

bool sl_signals_shutdown_requested(void) { return g_shutdown != 0; }
bool sl_signals_reload_requested  (void) { return g_reload   != 0; }
void sl_signals_clear_reload(void)       { g_reload = 0;            }

void sl_signals_block_sigpipe(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}
