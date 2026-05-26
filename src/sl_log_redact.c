#include "sl_log_redact.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static int is_hex(int c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static int append(char *out, size_t cap, size_t *pos, const char *s) {
    while (*s) {
        if (*pos + 1 >= cap) return -1;
        out[(*pos)++] = *s++;
    }
    return 0;
}

static int append_ch(char *out, size_t cap, size_t *pos, char c) {
    if (*pos + 1 >= cap) return -1;
    out[(*pos)++] = c;
    return 0;
}

int sl_log_redact_hex(const char *in, char *out, size_t out_cap) {
    if (!in || !out || out_cap == 0) return -1;
    size_t pos = 0;
    size_t i = 0;
    while (in[i] != '\0') {
        size_t j = i;
        while (in[j] && is_hex((unsigned char)in[j])) ++j;
        if (j - i >= 32) {
            if (append(out, out_cap, &pos, "<REDACTED-HEX-") != 0) return -1;
            char num[16];
            snprintf(num, sizeof(num), "%zu>", j - i);
            if (append(out, out_cap, &pos, num) != 0) return -1;
            i = j;
        } else {
            for (size_t k = i; k < j; ++k) {
                if (append_ch(out, out_cap, &pos, in[k]) != 0) return -1;
            }
            i = j;
            if (in[i] != '\0') {
                if (append_ch(out, out_cap, &pos, in[i]) != 0) return -1;
                ++i;
            }
        }
    }
    if (pos >= out_cap) return -1;
    out[pos] = '\0';
    return (int)pos;
}

int sl_log_redact_email(const char *in, char *out, size_t out_cap) {
    if (!in || !out || out_cap == 0) return -1;
    size_t pos = 0;
    size_t i = 0;
    while (in[i] != '\0') {
        /* Detect a run of word chars followed by '@' then domain-ish chars. */
        size_t start = i;
        size_t at = (size_t)-1;
        while (in[i] && (isalnum((unsigned char)in[i]) ||
                         in[i] == '.' || in[i] == '_' || in[i] == '+' ||
                         in[i] == '-' || in[i] == '@')) {
            if (in[i] == '@' && at == (size_t)-1) at = i;
            ++i;
        }
        const size_t end = i;
        if (at != (size_t)-1 && at > start && end > at + 1) {
            if (append(out, out_cap, &pos, "<email>") != 0) return -1;
        } else {
            for (size_t k = start; k < end; ++k) {
                if (append_ch(out, out_cap, &pos, in[k]) != 0) return -1;
            }
        }
        if (in[i] != '\0') {
            if (append_ch(out, out_cap, &pos, in[i]) != 0) return -1;
            ++i;
        }
    }
    if (pos >= out_cap) return -1;
    out[pos] = '\0';
    return (int)pos;
}

int sl_log_redact_ipv4(const char *in, char *out, size_t out_cap) {
    if (!in || !out || out_cap == 0) return -1;
    size_t pos = 0;
    size_t i = 0;
    while (in[i] != '\0') {
        /* Try to match d{1,3}.d{1,3}.d{1,3}.d{1,3} */
        size_t j = i;
        int    dots = 0;
        int    digits_in_segment = 0;
        int    looks_like_ipv4 = 1;
        for (int seg = 0; seg < 4 && looks_like_ipv4; ++seg) {
            digits_in_segment = 0;
            while (in[j] >= '0' && in[j] <= '9' && digits_in_segment < 3) {
                ++j; ++digits_in_segment;
            }
            if (digits_in_segment == 0) { looks_like_ipv4 = 0; break; }
            if (seg < 3) {
                if (in[j] != '.') { looks_like_ipv4 = 0; break; }
                ++j; ++dots;
            }
        }
        if (looks_like_ipv4 && dots == 3) {
            if (append(out, out_cap, &pos, "<ip>") != 0) return -1;
            i = j;
        } else {
            if (append_ch(out, out_cap, &pos, in[i]) != 0) return -1;
            ++i;
        }
    }
    if (pos >= out_cap) return -1;
    out[pos] = '\0';
    return (int)pos;
}

int sl_log_redact_all(const char *in, char *out, size_t out_cap) {
    char tmp1[1024], tmp2[1024];
    if (sl_log_redact_hex(in, tmp1, sizeof(tmp1)) < 0) return -1;
    if (sl_log_redact_email(tmp1, tmp2, sizeof(tmp2)) < 0) return -1;
    return sl_log_redact_ipv4(tmp2, out, out_cap);
}
