// Tests for ReplayGuard sliding-window anti-replay logic.
//
// Build:
//   g++ -std=c++17 -Iinc src/test_replay_guard.cpp -o test_replay_guard

#include <cstdint>
#include <cstdio>

#include "replay_guard.hpp"

using namespace securelink;

#define CHECK(cond) do {                                         \
    if (!(cond)) {                                               \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                 \
                     __FILE__, __LINE__, #cond);                 \
        return 1;                                                \
    }                                                            \
} while (0)

static int test_seq_zero_rejected() {
    ReplayGuard<> g;
    CHECK(!g.check_and_update(0));
    CHECK(g.highest() == 0);
    return 0;
}

static int test_monotonic_accept() {
    ReplayGuard<> g;
    for (std::uint64_t i = 1; i <= 100; ++i) {
        CHECK(g.check_and_update(i));
    }
    CHECK(g.highest() == 100);
    CHECK(g.accepted_count() == 100);
    CHECK(g.replay_count() == 0);
    return 0;
}

static int test_immediate_replay_rejected() {
    ReplayGuard<> g;
    CHECK(g.check_and_update(42));
    CHECK(!g.check_and_update(42));
    CHECK(g.replay_count() == 1);
    return 0;
}

static int test_out_of_order_within_window() {
    ReplayGuard<> g;
    CHECK(g.check_and_update(50));
    CHECK(g.check_and_update(48));   // older, but within window
    CHECK(g.check_and_update(49));
    CHECK(!g.check_and_update(48));  // replay
    CHECK(g.replay_count() == 1);
    return 0;
}

static int test_too_old_rejected() {
    ReplayGuard<1024> g;
    CHECK(g.check_and_update(2000));
    // 2000 - 1024 = 976; anything <= 976 is outside the window.
    CHECK(!g.check_and_update(500));
    CHECK(!g.check_and_update(976));
    CHECK(g.check_and_update(977));
    CHECK(g.too_old_count() == 2);
    return 0;
}

static int test_large_jump_clears_window() {
    ReplayGuard<1024> g;
    CHECK(g.check_and_update(10));
    CHECK(g.check_and_update(20));
    // Big jump beyond window — window resets, old entries forgotten.
    CHECK(g.check_and_update(1'000'000));
    // 10 and 20 are now far out of window; treated as too-old.
    CHECK(!g.check_and_update(10));
    CHECK(!g.check_and_update(20));
    return 0;
}

static int test_would_accept_does_not_mutate() {
    ReplayGuard<> g;
    CHECK(g.check_and_update(100));
    CHECK(g.would_accept(101));
    CHECK(g.would_accept(101));   // still acceptable, no state change
    CHECK(!g.would_accept(100));
    CHECK(g.highest() == 100);
    CHECK(g.accepted_count() == 1);
    return 0;
}

static int test_reset() {
    ReplayGuard<> g;
    CHECK(g.check_and_update(5));
    CHECK(g.check_and_update(6));
    g.reset();
    CHECK(g.highest() == 0);
    CHECK(g.accepted_count() == 0);
    CHECK(g.check_and_update(1));
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_seq_zero_rejected();
    rc |= test_monotonic_accept();
    rc |= test_immediate_replay_rejected();
    rc |= test_out_of_order_within_window();
    rc |= test_too_old_rejected();
    rc |= test_large_jump_clears_window();
    rc |= test_would_accept_does_not_mutate();
    rc |= test_reset();
    if (rc == 0) std::puts("test_replay_guard: OK");
    return rc;
}
