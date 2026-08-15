// Tests for BeaconRegistry.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_beacon_registry.cpp src/beacon_registry.cpp \
//       -lpthread -o test_beacon_registry

#include <cstdio>

#include "beacon_registry.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static ClientEntry make_entry(std::uint64_t id, const char* label,
                              std::uint8_t key_seed) {
    ClientEntry e;
    e.client_id = id;
    e.label     = label;
    for (auto& b : e.key)       b = key_seed;
    for (auto& b : e.static_iv) b = static_cast<std::uint8_t>(key_seed + 1);
    e.enabled   = true;
    return e;
}

static int test_upsert_and_lookup(void) {
    BeaconRegistry r;
    CHECK(r.size() == 0);
    CHECK(r.upsert(make_entry(1, "alpha", 0x10)) == true);
    CHECK(r.upsert(make_entry(2, "beta",  0x20)) == true);
    CHECK(r.size() == 2);

    auto e1 = r.lookup(1);
    CHECK(e1.has_value());
    CHECK(e1->label == "alpha");
    CHECK(e1->enabled);
    CHECK(e1->key[0] == 0x10);

    auto missing = r.lookup(999);
    CHECK(!missing.has_value());
    return 0;
}

static int test_upsert_replaces(void) {
    BeaconRegistry r;
    r.upsert(make_entry(7, "old", 0x01));
    CHECK(r.upsert(make_entry(7, "new", 0x02)) == false);  /* not newly inserted */
    auto e = r.lookup(7);
    CHECK(e.has_value());
    CHECK(e->label == "new");
    CHECK(e->key[0] == 0x02);
    return 0;
}

static int test_set_enabled(void) {
    BeaconRegistry r;
    r.upsert(make_entry(3, "gamma", 0x30));
    CHECK(r.set_enabled(3, false));
    auto e1 = r.lookup(3);
    CHECK(e1.has_value());
    CHECK(e1->enabled == false);
    CHECK(r.set_enabled(3, true));
    auto e2 = r.lookup(3);
    CHECK(e2.has_value());
    CHECK(e2->enabled == true);
    CHECK(!r.set_enabled(999, false));
    return 0;
}

static int test_remove(void) {
    BeaconRegistry r;
    r.upsert(make_entry(11, "x", 0x11));
    CHECK(r.remove(11) == true);
    CHECK(r.remove(11) == false);
    CHECK(!r.lookup(11).has_value());
    return 0;
}

static int test_for_each(void) {
    BeaconRegistry r;
    r.upsert(make_entry(1, "a", 1));
    r.upsert(make_entry(2, "b", 2));
    r.upsert(make_entry(3, "c", 3));

    std::size_t count = 0;
    std::uint64_t id_sum = 0;
    r.for_each([&](const ClientEntry& e) {
        ++count;
        id_sum += e.client_id;
    });
    CHECK(count == 3);
    CHECK(id_sum == 6);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_upsert_and_lookup();
    rc |= test_upsert_replaces();
    rc |= test_set_enabled();
    rc |= test_remove();
    rc |= test_for_each();
    if (rc == 0) std::puts("test_beacon_registry: OK");
    return rc;
}
