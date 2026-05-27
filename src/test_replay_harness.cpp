// Tests for ReplayHarness using in-memory event vectors.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_replay_harness.cpp src/replay_harness.cpp \
//       src/sl_event_log.c src/sl_varint.c src/sl_crc32.c \
//       -lpthread -o test_replay_harness

#include <atomic>
#include <cstdio>
#include <vector>

#include "replay_harness.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static std::vector<ReplayEvent> make_events() {
    std::vector<ReplayEvent> v;
    for (int i = 0; i < 5; ++i) {
        ReplayEvent e;
        e.seq          = static_cast<std::uint64_t>(i + 1);
        e.timestamp_ns = static_cast<std::uint64_t>(i + 1) * 1'000'000ULL;
        e.type         = (i % 2 == 0) ? SL_EV_BEACON_OK : SL_EV_BEACON_REJECT;
        v.push_back(std::move(e));
    }
    return v;
}

static int test_handlers_dispatch(void) {
    ReplayHarness h;
    std::atomic<int> ok{0};
    std::atomic<int> rej{0};

    h.on(SL_EV_BEACON_OK,     [&](const ReplayEvent&) { ++ok; });
    h.on(SL_EV_BEACON_REJECT, [&](const ReplayEvent&) { ++rej; });

    auto events = make_events();
    auto st = h.run_events(events);

    CHECK(ok.load() == 3);
    CHECK(rej.load() == 2);
    CHECK(st.events_seen == 5);
    CHECK(st.events_dispatched == 5);
    CHECK(st.events_skipped == 0);
    return 0;
}

static int test_default_handler(void) {
    ReplayHarness h;
    std::atomic<int> total{0};
    h.on_default([&](const ReplayEvent&) { ++total; });

    auto st = h.run_events(make_events());
    CHECK(total.load() == 5);
    CHECK(st.events_dispatched == 5);
    return 0;
}

static int test_skips_unhandled(void) {
    ReplayHarness h;
    std::atomic<int> ok{0};
    h.on(SL_EV_BEACON_OK, [&](const ReplayEvent&) { ++ok; });

    auto st = h.run_events(make_events());
    CHECK(ok.load() == 3);
    CHECK(st.events_dispatched == 3);
    CHECK(st.events_skipped == 2);
    return 0;
}

static int test_payload_visible(void) {
    ReplayHarness h;
    std::vector<std::uint8_t> seen;
    h.on(SL_EV_INTERNAL, [&](const ReplayEvent& e) { seen = e.payload; });

    std::vector<ReplayEvent> events;
    ReplayEvent e;
    e.seq = 1;
    e.timestamp_ns = 1000;
    e.type = SL_EV_INTERNAL;
    e.payload = {0x01, 0x02, 0x03, 0x04};
    events.push_back(std::move(e));

    h.run_events(events);
    CHECK(seen.size() == 4);
    CHECK(seen[0] == 0x01 && seen[3] == 0x04);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_handlers_dispatch();
    rc |= test_default_handler();
    rc |= test_skips_unhandled();
    rc |= test_payload_visible();
    if (rc == 0) std::puts("test_replay_harness: OK");
    return rc;
}
