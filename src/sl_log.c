#include "sl_log.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static FILE              *g_fp    = NULL;
static _Atomic int        g_level = SL_LOG_INFO;
static pthread_mutex_t    g_mu    = PTHREAD_MUTEX_INITIALIZER;

static const char *level_str(sl_log_level_t l) {
    switch (l) {
        case SL_LOG_TRACE: return "TRACE";
        case SL_LOG_DEBUG: return "DEBUG";
        case SL_LOG_INFO:  return "INFO";
        case SL_LOG_WARN:  return "WARN";
        case SL_LOG_ERROR: return "ERROR";
        case SL_LOG_FATAL: return "FATAL";
    }
    return "?";
}

void sl_log_init(FILE *fp, sl_log_level_t level) {
    pthread_mutex_lock(&g_mu);
    g_fp = fp ? fp : stderr;
    atomic_store_explicit(&g_level, (int)level, memory_order_release);
    pthread_mutex_unlock(&g_mu);
}

void sl_log_set_level(sl_log_level_t level) {
    atomic_store_explicit(&g_level, (int)level, memory_order_release);
}

sl_log_level_t sl_log_get_level(void) {
    return (sl_log_level_t)atomic_load_explicit(&g_level, memory_order_acquire);
}

static void emit_timestamp(char *out, size_t n) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_utc;
    gmtime_r(&ts.tv_sec, &tm_utc);
    snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
             tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec,
             ts.tv_nsec / 1000000L);
}

void sl_log_emit(sl_log_level_t lvl, const char *module,
                 const char *fmt, ...) {
    if ((int)lvl < atomic_load_explicit(&g_level, memory_order_acquire)) return;

    char ts[40];
    emit_timestamp(ts, sizeof(ts));

    pthread_mutex_lock(&g_mu);
    FILE *fp = g_fp ? g_fp : stderr;
    fprintf(fp, "ts=%s level=%s module=%s msg=\"",
            ts, level_str(lvl), module ? module : "-");

    va_list ap;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);

    fputs("\"\n", fp);
    fflush(fp);
    pthread_mutex_unlock(&g_mu);
}
