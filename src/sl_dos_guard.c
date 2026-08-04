/* strdup is POSIX (POSIX.1-2008), not standard C11 — glibc hides it under
 * strict -std=c11 unless this feature-test macro is defined first. */
#define _POSIX_C_SOURCE 200809L

#include "sl_dos_guard.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SL_DOS_BUCKETS 1024U

typedef struct ip_entry {
    char           *ip;
    uint32_t        half_open;
    uint32_t        established;
    uint64_t        oldest_half_open_ms;
    struct ip_entry *next;
} ip_entry_t;

struct sl_dos_guard {
    uint32_t    max_per_ip;
    uint32_t    max_global;
    uint32_t    half_open_timeout_ms;
    uint32_t    global_half_open;
    uint32_t    global_established;
    ip_entry_t *buckets[SL_DOS_BUCKETS];
};

static uint64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint8_t)(*s++); h *= 16777619u; }
    return h;
}

static ip_entry_t *find_or_create(sl_dos_guard_t *g, const char *ip, bool create) {
    const uint32_t b = fnv1a(ip) % SL_DOS_BUCKETS;
    for (ip_entry_t *e = g->buckets[b]; e; e = e->next) {
        if (strcmp(e->ip, ip) == 0) return e;
    }
    if (!create) return NULL;
    ip_entry_t *ne = (ip_entry_t *)calloc(1, sizeof(*ne));
    if (!ne) return NULL;
    ne->ip = strdup(ip);
    if (!ne->ip) { free(ne); return NULL; }
    ne->next = g->buckets[b];
    g->buckets[b] = ne;
    return ne;
}

sl_dos_guard_t *sl_dos_guard_new(uint32_t max_per_ip,
                                 uint32_t max_global,
                                 uint32_t half_open_timeout_ms) {
    if (max_per_ip == 0 || max_global == 0 || half_open_timeout_ms == 0) {
        return NULL;
    }
    sl_dos_guard_t *g = (sl_dos_guard_t *)calloc(1, sizeof(*g));
    if (!g) return NULL;
    g->max_per_ip           = max_per_ip;
    g->max_global           = max_global;
    g->half_open_timeout_ms = half_open_timeout_ms;
    return g;
}

void sl_dos_guard_free(sl_dos_guard_t *g) {
    if (!g) return;
    for (size_t i = 0; i < SL_DOS_BUCKETS; ++i) {
        ip_entry_t *e = g->buckets[i];
        while (e) {
            ip_entry_t *n = e->next;
            free(e->ip);
            free(e);
            e = n;
        }
    }
    free(g);
}

bool sl_dos_guard_admit(sl_dos_guard_t *g, const char *peer_ip) {
    if (!g || !peer_ip) return false;
    if (g->global_half_open + g->global_established >= g->max_global) {
        return false;
    }
    ip_entry_t *e = find_or_create(g, peer_ip, true);
    if (!e) return false;
    if (e->half_open + e->established >= g->max_per_ip) return false;

    if (e->half_open == 0) e->oldest_half_open_ms = now_ms();
    ++e->half_open;
    ++g->global_half_open;
    return true;
}

void sl_dos_guard_promote(sl_dos_guard_t *g, const char *peer_ip) {
    if (!g || !peer_ip) return;
    ip_entry_t *e = find_or_create(g, peer_ip, false);
    if (!e || e->half_open == 0) return;
    --e->half_open;
    ++e->established;
    --g->global_half_open;
    ++g->global_established;
}

void sl_dos_guard_release(sl_dos_guard_t *g, const char *peer_ip) {
    if (!g || !peer_ip) return;
    ip_entry_t *e = find_or_create(g, peer_ip, false);
    if (!e) return;
    if (e->established > 0) {
        --e->established;
        --g->global_established;
    } else if (e->half_open > 0) {
        --e->half_open;
        --g->global_half_open;
    }
}

size_t sl_dos_guard_sweep(sl_dos_guard_t *g) {
    if (!g) return 0;
    const uint64_t cutoff = now_ms();
    size_t reaped = 0;
    for (size_t i = 0; i < SL_DOS_BUCKETS; ++i) {
        for (ip_entry_t *e = g->buckets[i]; e; e = e->next) {
            if (e->half_open == 0) continue;
            if (cutoff - e->oldest_half_open_ms > g->half_open_timeout_ms) {
                /* Treat all stale half-opens for this IP as abandoned. */
                if (e->half_open > g->global_half_open) {
                    g->global_half_open = 0;
                } else {
                    g->global_half_open -= e->half_open;
                }
                reaped += e->half_open;
                e->half_open = 0;
            }
        }
    }
    return reaped;
}

uint32_t sl_dos_guard_global_inflight(const sl_dos_guard_t *g) {
    if (!g) return 0;
    return g->global_half_open + g->global_established;
}

uint32_t sl_dos_guard_per_ip(const sl_dos_guard_t *g, const char *peer_ip) {
    if (!g || !peer_ip) return 0;
    /* find_or_create needs a non-const guard; this read path is harmless. */
    sl_dos_guard_t *gm = (sl_dos_guard_t *)g;
    ip_entry_t *e = find_or_create(gm, peer_ip, false);
    if (!e) return 0;
    return e->half_open + e->established;
}
