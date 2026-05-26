#include "sl_config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SL_CFG_BUCKETS 256U

typedef struct entry {
    char *key;
    char *value;
    struct entry *next;
} entry_t;

struct sl_config {
    entry_t *buckets[SL_CFG_BUCKETS];
    size_t   count;
};

static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint8_t)(*s++); h *= 16777619u; }
    return h;
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) ++s;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

sl_config_t *sl_config_new(void) {
    return (sl_config_t *)calloc(1, sizeof(sl_config_t));
}

void sl_config_free(sl_config_t *c) {
    if (!c) return;
    for (size_t i = 0; i < SL_CFG_BUCKETS; ++i) {
        entry_t *e = c->buckets[i];
        while (e) {
            entry_t *n = e->next;
            free(e->key);
            free(e->value);
            free(e);
            e = n;
        }
    }
    free(c);
}

static entry_t *find(const sl_config_t *c, const char *key) {
    const uint32_t b = fnv1a(key) % SL_CFG_BUCKETS;
    for (entry_t *e = c->buckets[b]; e; e = e->next) {
        if (strcmp(e->key, key) == 0) return e;
    }
    return NULL;
}

int sl_config_set(sl_config_t *c, const char *key, const char *value) {
    if (!c || !key || !value) return -1;
    entry_t *e = find(c, key);
    if (e) {
        char *nv = strdup(value);
        if (!nv) return -1;
        free(e->value);
        e->value = nv;
        return 0;
    }
    entry_t *ne = (entry_t *)calloc(1, sizeof(*ne));
    if (!ne) return -1;
    ne->key = strdup(key);
    ne->value = strdup(value);
    if (!ne->key || !ne->value) {
        free(ne->key); free(ne->value); free(ne); return -1;
    }
    const uint32_t b = fnv1a(key) % SL_CFG_BUCKETS;
    ne->next = c->buckets[b];
    c->buckets[b] = ne;
    ++c->count;
    return 0;
}

int sl_config_load_file(sl_config_t *c, const char *path) {
    if (!c || !path) return -1;
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char  line[1024];
    char  section[128] = "";
    int   rc = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *p = trim(line);
        if (*p == '\0' || *p == '#' || *p == ';') continue;

        if (*p == '[') {
            char *end = strchr(p, ']');
            if (!end) { rc = -1; break; }
            *end = '\0';
            snprintf(section, sizeof(section), "%s", trim(p + 1));
            continue;
        }

        char *eq = strchr(p, '=');
        if (!eq) { rc = -1; break; }
        *eq = '\0';
        char *k = trim(p);
        char *v = trim(eq + 1);

        char full[256];
        if (section[0])
            snprintf(full, sizeof(full), "%s.%s", section, k);
        else
            snprintf(full, sizeof(full), "%s", k);

        if (sl_config_set(c, full, v) != 0) { rc = -1; break; }
    }
    fclose(fp);
    return rc;
}

const char *sl_config_get_str(const sl_config_t *c, const char *key,
                              const char *fallback) {
    if (!c || !key) return fallback;
    entry_t *e = find(c, key);
    return e ? e->value : fallback;
}

int sl_config_get_int(const sl_config_t *c, const char *key, int fb) {
    const char *v = sl_config_get_str(c, key, NULL);
    if (!v) return fb;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (!end || *end != '\0') return fb;
    return (int)n;
}

uint32_t sl_config_get_u32(const sl_config_t *c, const char *key, uint32_t fb) {
    const char *v = sl_config_get_str(c, key, NULL);
    if (!v) return fb;
    char *end = NULL;
    unsigned long n = strtoul(v, &end, 10);
    if (!end || *end != '\0') return fb;
    return (uint32_t)n;
}

uint64_t sl_config_get_u64(const sl_config_t *c, const char *key, uint64_t fb) {
    const char *v = sl_config_get_str(c, key, NULL);
    if (!v) return fb;
    char *end = NULL;
    unsigned long long n = strtoull(v, &end, 10);
    if (!end || *end != '\0') return fb;
    return (uint64_t)n;
}

bool sl_config_get_bool(const sl_config_t *c, const char *key, bool fb) {
    const char *v = sl_config_get_str(c, key, NULL);
    if (!v) return fb;
    if (strcasecmp(v, "true") == 0 || strcasecmp(v, "yes") == 0 ||
        strcasecmp(v, "on")   == 0 || strcmp(v, "1") == 0) return true;
    if (strcasecmp(v, "false") == 0 || strcasecmp(v, "no") == 0 ||
        strcasecmp(v, "off")   == 0 || strcmp(v, "0") == 0) return false;
    return fb;
}

size_t sl_config_size(const sl_config_t *c) {
    return c ? c->count : 0;
}
