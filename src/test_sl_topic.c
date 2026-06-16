/* Tests for sl_topic.
 *
 * Build:
 *   gcc -std=c11 -Iinc src/test_sl_topic.c src/sl_topic.c -o test_sl_topic
 */

#include <stdio.h>
#include <string.h>

#include "sl_topic.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static bool match(const char *t, const char *f) {
    return sl_topic_matches(t, strlen(t), f, strlen(f));
}

static int test_publish_valid_rejects_wildcards(void) {
    CHECK(sl_topic_is_valid_publish("a/b/c", 5));
    CHECK(sl_topic_is_valid_publish("sensors/temp/kitchen-1", 22));
    CHECK(!sl_topic_is_valid_publish("a/+/c", 5));
    CHECK(!sl_topic_is_valid_publish("a/#", 3));
    CHECK(!sl_topic_is_valid_publish("/leading", 8));
    CHECK(!sl_topic_is_valid_publish("trailing/", 9));
    CHECK(!sl_topic_is_valid_publish("dou//ble", 8));
    return 0;
}

static int test_filter_accepts_wildcards(void) {
    CHECK(sl_topic_is_valid_filter("a/+/c", 5));
    CHECK(sl_topic_is_valid_filter("a/#", 3));
    CHECK(sl_topic_is_valid_filter("+", 1));
    CHECK(sl_topic_is_valid_filter("#", 1));
    CHECK(sl_topic_is_valid_filter("sensors/+/temp", 14));
    CHECK(!sl_topic_is_valid_filter("a/#/b", 5));     /* # not last */
    CHECK(!sl_topic_is_valid_filter("ab+", 3));        /* + must be whole seg */
    return 0;
}

static int test_match_exact(void) {
    CHECK(match("a/b/c", "a/b/c"));
    CHECK(!match("a/b/c", "a/b/d"));
    CHECK(!match("a/b",   "a/b/c"));
    CHECK(!match("a/b/c", "a/b"));
    return 0;
}

static int test_match_plus(void) {
    CHECK(match("a/b/c", "a/+/c"));
    CHECK(match("a/X/c", "a/+/c"));
    CHECK(!match("a/c",   "a/+/c"));
    CHECK(!match("a/b/c/d", "a/+/c"));
    CHECK(match("x/y/z", "+/+/+"));
    return 0;
}

static int test_match_hash(void) {
    CHECK(match("a/b/c",       "a/#"));
    CHECK(match("a/b/c/d/e",   "a/#"));
    CHECK(match("a",           "#"));
    CHECK(!match("b/c",        "a/#"));
    CHECK(match("a/b",         "a/b/#"));     /* # matches zero segments */
    return 0;
}

static int test_match_combined(void) {
    CHECK(match("sensors/A/temp/now",  "sensors/+/temp/#"));
    CHECK(match("sensors/B/temp",      "sensors/+/temp/#"));
    CHECK(!match("sensors/A/humid",    "sensors/+/temp/#"));
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_publish_valid_rejects_wildcards();
    rc |= test_filter_accepts_wildcards();
    rc |= test_match_exact();
    rc |= test_match_plus();
    rc |= test_match_hash();
    rc |= test_match_combined();
    if (rc == 0) puts("test_sl_topic: OK");
    return rc;
}
