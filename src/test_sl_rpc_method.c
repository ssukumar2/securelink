/* Tests for sl_rpc_method.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_rpc_method.c src/sl_rpc_method.c \
 *       -o test_sl_rpc_method
 */

#include <stdio.h>
#include <string.h>

#include "sl_rpc_method.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_valid_names_accepted(void) {
    CHECK(sl_rpc_method_is_valid("echo", 4));
    CHECK(sl_rpc_method_is_valid("fs.read_file", 12));
    CHECK(sl_rpc_method_is_valid("a.b.c.d.e", 9));
    CHECK(sl_rpc_method_is_valid("_underscore", 11));
    CHECK(sl_rpc_method_is_valid("Method1", 7));
    return 0;
}

static int test_invalid_names_rejected(void) {
    CHECK(!sl_rpc_method_is_valid("", 0));
    CHECK(!sl_rpc_method_is_valid(".leading", 8));
    CHECK(!sl_rpc_method_is_valid("trailing.", 9));
    CHECK(!sl_rpc_method_is_valid("two..dots", 9));
    CHECK(!sl_rpc_method_is_valid("has space", 9));
    CHECK(!sl_rpc_method_is_valid("dash-bad", 8));
    CHECK(!sl_rpc_method_is_valid("slash/bad", 9));
    return 0;
}

static int test_length_cap(void) {
    char too_long[SL_RPC_METHOD_NAME_MAX + 2];
    memset(too_long, 'a', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';
    CHECK(!sl_rpc_method_is_valid(too_long, SL_RPC_METHOD_NAME_MAX + 1));

    char at_max[SL_RPC_METHOD_NAME_MAX + 1];
    memset(at_max, 'b', SL_RPC_METHOD_NAME_MAX);
    at_max[SL_RPC_METHOD_NAME_MAX] = '\0';
    CHECK(sl_rpc_method_is_valid(at_max, SL_RPC_METHOD_NAME_MAX));
    return 0;
}

static int test_split_dotted(void) {
    char ns[SL_RPC_METHOD_NAME_MAX + 1];
    char leaf[SL_RPC_METHOD_NAME_MAX + 1];
    CHECK(sl_rpc_method_split("fs.read_file", 12, ns, leaf) == 0);
    CHECK(strcmp(ns, "fs") == 0);
    CHECK(strcmp(leaf, "read_file") == 0);

    CHECK(sl_rpc_method_split("auth.identity.fingerprint", 25, ns, leaf) == 0);
    CHECK(strcmp(ns, "auth.identity") == 0);
    CHECK(strcmp(leaf, "fingerprint") == 0);
    return 0;
}

static int test_split_bare(void) {
    char ns[SL_RPC_METHOD_NAME_MAX + 1];
    char leaf[SL_RPC_METHOD_NAME_MAX + 1];
    CHECK(sl_rpc_method_split("ping", 4, ns, leaf) == 0);
    CHECK(strcmp(ns, "") == 0);
    CHECK(strcmp(leaf, "ping") == 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_valid_names_accepted();
    rc |= test_invalid_names_rejected();
    rc |= test_length_cap();
    rc |= test_split_dotted();
    rc |= test_split_bare();
    if (rc == 0) puts("test_sl_rpc_method: OK");
    return rc;
}
