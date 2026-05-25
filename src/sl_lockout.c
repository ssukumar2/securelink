#include "sl_lockout.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SL_LOCKOUT_BUCKETS 1024U

typedef struct entry {
    char            *key;
    uint32_t         fails;
    uint64_t         locked_until_ms;
    struct entry    *next;
} entry_t;

struct sl_lockout {
    uint32_t base_lockout_ms;
    uint32_t cap_lockout_ms;
    uint32_t fail_threshold;
    entry_t *buckets[SL_LOCKOUT_BUCKETS];
    size_t   count;
};

static uint64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= (uint8_t)(*s++);
        h *= 16777619u;
    }
    return h;
}

static entry_t *find_or_create(sl_lockout_t *L, const char *key, bool create) {
    const uint32_t b = fnv1a(key) % SL_LOCKOUT_BUCKETS;
    for (entry_t *e = L->buckets[b]; e; e = e->next) {
        if (strcmp(e->key, key) == 0) return e;
    }
    if (!create) return NULL;
    entry_t *ne = (entry_t *)calloc(1, sizeof(*ne));
    if (!ne) return NULL;
    ne->key = strdup(key);
    if (!ne->key) { free(ne); return NULL; }
    ne->next = L->buckets[b];
    L->buckets[b] = ne;
    ++L->count;
    return ne;
}

sl_lockout_t *sl_lockout_new(uint32_t base_lockout_ms,
                             uint32_t cap_lockout_ms,
                             uint32_t fail_threshold) {
    if (base_lockout_ms == 0 || cap_lockout_ms < base_lockout_ms ||
        fail_threshold == 0) {
        return NULL;
    }
    sl_lockout_t *L = (sl_lockout_t *)calloc(1, sizeof(*L));
    if (!L) return NULL;
    L->base_lockout_ms = base_lockout_ms;
    L->cap_lockout_ms  = cap_lockout_ms;
    L->fail_threshold  = fail_threshold;
    return L;
}

void sl_lockout_free(sl_lockout_t *L) {
    if (!L) return;
    for (size_t i = 0; i < SL_LOCKOUT_BUCKETS; ++i) {
        entry_t *e = L->buckets[i];
        while (e) {
            entry_t *n = e->next;
            free(e->key);
            free(e);
            e = n;
        }
    }
    free(L);
}

sl_lockout_status_t sl_lockout_check(sl_lockout_t *L, const char *key) {
    if (!L || !key) return SL_LOCKOUT_BLOCKED;
    entry_t *e = find_or_create(L, key, false);
    if (!e) return SL_LOCKOUT_ALLOW;
    return (now_ms() < e->locked_until_ms) ? SL_LOCKOUT_BLOCKED : SL_LOCKOUT_ALLOW;
}

sl_lockout_status_t sl_lockout_fail(sl_lockout_t *L, const char *key) {
    if (!L || !key) return SL_LOCKOUT_BLOCKED;
    entry_t *e = find_or_create(L, key, true);
    if (!e) return SL_LOCKOUT_BLOCKED;

    ++e->fails;
    if (e->fails >= L->fail_threshold) {
        /* Each additional failure beyond threshold doubles the window. */
        const uint32_t over = e->fails - L->fail_threshold;
        uint64_t dur = (uint64_t)L->base_lockout_ms << (over < 16 ? over : 16);
        if (dur > L->cap_lockout_ms) dur = L->cap_lockout_ms;
        e->locked_until_ms = now_ms() + dur;
        return SL_LOCKOUT_BLOCKED;
    }
    return SL_LOCKOUT_ALLOW;
}

void sl_lockout_succeed(sl_lockout_t *L, const char *key) {
    if (!L || !key) return;
    entry_t *e = find_or_create(L, key, false);
    if (!e) return;
    e->fails = 0;
    e->locked_until_ms = 0;
}

size_t sl_lockout_size(const sl_lockout_t *L) {
    return L ? L->count : 0;
}
