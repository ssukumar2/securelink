#include "sl_endpoint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_port(const char *s, uint16_t *out) {
    if (!s || !*s) return -1;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (!end || *end != '\0') return -1;
    if (v < 1 || v > 65535) return -1;
    *out = (uint16_t)v;
    return 0;
}

int sl_endpoint_parse(const char *s, sl_endpoint_t *out) {
    if (!s || !out) return -1;
    memset(out, 0, sizeof(*out));

    if (s[0] == '[') {
        const char *rb = strchr(s, ']');
        if (!rb || rb[1] != ':') return -1;
        const size_t hlen = (size_t)(rb - s - 1);
        if (hlen == 0 || hlen >= sizeof(out->host)) return -1;
        memcpy(out->host, s + 1, hlen);
        out->host[hlen] = '\0';
        return parse_port(rb + 2, &out->port);
    }

    const char *colon = strrchr(s, ':');
    if (!colon || colon == s) return -1;
    const size_t hlen = (size_t)(colon - s);
    if (hlen == 0 || hlen >= sizeof(out->host)) return -1;
    memcpy(out->host, s, hlen);
    out->host[hlen] = '\0';
    return parse_port(colon + 1, &out->port);
}

int sl_endpoint_format(const sl_endpoint_t *ep, char *buf, size_t cap) {
    if (!ep || !buf) return -1;
    const bool has_colon = strchr(ep->host, ':') != NULL;
    int n = has_colon
        ? snprintf(buf, cap, "[%s]:%u", ep->host, (unsigned)ep->port)
        : snprintf(buf, cap, "%s:%u",   ep->host, (unsigned)ep->port);
    return (n > 0 && (size_t)n < cap) ? n : -1;
}

bool sl_endpoint_is_loopback(const sl_endpoint_t *ep) {
    if (!ep) return false;
    if (strcmp(ep->host, "127.0.0.1") == 0) return true;
    if (strcmp(ep->host, "::1")       == 0) return true;
    if (strcmp(ep->host, "localhost") == 0) return true;
    return false;
}
