/* Tests for sl_log_redact.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_log_redact.c src/sl_log_redact.c \
 *       -o test_sl_log_redact
 */

#include <stdio.h>
#include <string.h>

#include "sl_log_redact.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_hex_redact(void) {
    char out[256];
    /* 64-char hex run -> redacted. */
    const char *in =
        "key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef done";
    CHECK(sl_log_redact_hex(in, out, sizeof(out)) > 0);
    CHECK(strstr(out, "<REDACTED-HEX-64>") != NULL);
    CHECK(strstr(out, "0123456789") == NULL);

    /* Short hex runs are kept. */
    const char *in2 = "code=abcd status=ok";
    CHECK(sl_log_redact_hex(in2, out, sizeof(out)) > 0);
    CHECK(strstr(out, "abcd") != NULL);
    return 0;
}

static int test_email_redact(void) {
    char out[256];
    CHECK(sl_log_redact_email("user=alice@example.com action=login",
                              out, sizeof(out)) > 0);
    CHECK(strstr(out, "<email>") != NULL);
    CHECK(strstr(out, "alice@example.com") == NULL);
    return 0;
}

static int test_ipv4_redact(void) {
    char out[256];
    CHECK(sl_log_redact_ipv4("peer=192.168.1.42 port=4443",
                             out, sizeof(out)) > 0);
    CHECK(strstr(out, "<ip>") != NULL);
    CHECK(strstr(out, "192.168.1.42") == NULL);

    /* Non-IP digit runs are preserved. */
    CHECK(sl_log_redact_ipv4("count=12345 ratio=1.5",
                             out, sizeof(out)) > 0);
    CHECK(strstr(out, "12345") != NULL);
    return 0;
}

static int test_redact_all_chain(void) {
    char out[512];
    const char *in =
        "peer=10.0.0.1 user=bob@example.com key=abcdef0123456789abcdef0123456789abcdef0123456789 ok";
    CHECK(sl_log_redact_all(in, out, sizeof(out)) > 0);
    CHECK(strstr(out, "<ip>")              != NULL);
    CHECK(strstr(out, "<email>")           != NULL);
    CHECK(strstr(out, "<REDACTED-HEX-")    != NULL);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_hex_redact();
    rc |= test_email_redact();
    rc |= test_ipv4_redact();
    rc |= test_redact_all_chain();
    if (rc == 0) puts("test_sl_log_redact: OK");
    return rc;
}
