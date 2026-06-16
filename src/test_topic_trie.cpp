// Tests for TopicTrie.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_topic_trie.cpp src/topic_trie.cpp \
//       -lpthread -o test_topic_trie

#include <algorithm>
#include <cstdio>

#include "topic_trie.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static bool contains(const std::vector<SubscriberId>& v, SubscriberId x) {
    return std::find(v.begin(), v.end(), x) != v.end();
}

static int test_exact_match(void) {
    TopicTrie t;
    CHECK(t.subscribe("a/b/c", 1));
    CHECK(t.subscribe("a/b/c", 2));
    CHECK(!t.subscribe("a/b/c", 1));   /* dedupe */

    auto m = t.match("a/b/c");
    CHECK(m.size() == 2);
    CHECK(contains(m, 1));
    CHECK(contains(m, 2));

    auto m2 = t.match("a/b/d");
    CHECK(m2.empty());
    return 0;
}

static int test_plus_match(void) {
    TopicTrie t;
    t.subscribe("a/+/c", 10);
    auto m = t.match("a/X/c");
    CHECK(contains(m, 10));
    CHECK(t.match("a/c").empty());
    CHECK(t.match("a/X/Y/c").empty());
    return 0;
}

static int test_hash_match(void) {
    TopicTrie t;
    t.subscribe("a/#", 20);
    CHECK(contains(t.match("a"),         20));
    CHECK(contains(t.match("a/b"),       20));
    CHECK(contains(t.match("a/b/c/d"),   20));
    CHECK(t.match("b/c").empty());
    return 0;
}

static int test_multiple_subscribers_per_topic(void) {
    TopicTrie t;
    t.subscribe("sensors/+/temp", 1);
    t.subscribe("sensors/#",       2);
    t.subscribe("sensors/A/temp",  3);

    auto m = t.match("sensors/A/temp");
    CHECK(m.size() == 3);
    CHECK(contains(m, 1));
    CHECK(contains(m, 2));
    CHECK(contains(m, 3));
    return 0;
}

static int test_unsubscribe(void) {
    TopicTrie t;
    t.subscribe("a/b", 1);
    t.subscribe("a/b", 2);
    CHECK(t.unsubscribe("a/b", 1));
    auto m = t.match("a/b");
    CHECK(m.size() == 1);
    CHECK(contains(m, 2));
    CHECK(!t.unsubscribe("a/b", 1));
    return 0;
}

static int test_unsubscribe_all(void) {
    TopicTrie t;
    t.subscribe("a/b",   42);
    t.subscribe("a/+/c", 42);
    t.subscribe("#",     42);
    t.subscribe("other", 99);

    CHECK(t.unsubscribe_all(42) == 3);
    CHECK(t.match("a/b").empty());
    CHECK(t.match("a/X/c").empty());
    CHECK(contains(t.match("other"), 99));
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_exact_match();
    rc |= test_plus_match();
    rc |= test_hash_match();
    rc |= test_multiple_subscribers_per_topic();
    rc |= test_unsubscribe();
    rc |= test_unsubscribe_all();
    if (rc == 0) std::puts("test_topic_trie: OK");
    return rc;
}
