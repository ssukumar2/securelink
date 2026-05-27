// Tests for TimeSeries.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_timeseries.cpp src/timeseries.cpp \
//       -lpthread -o test_timeseries

#include <cstdio>

#include "timeseries.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_basic_push(void) {
    TimeSeries ts(4);
    CHECK(ts.size() == 0);
    ts.push(1, 10.0);
    ts.push(2, 20.0);
    ts.push(3, 30.0);
    CHECK(ts.size() == 3);

    auto samples = ts.samples();
    CHECK(samples.size() == 3);
    CHECK(samples[0].value == 10.0);
    CHECK(samples[2].value == 30.0);
    return 0;
}

static int test_ring_eviction(void) {
    TimeSeries ts(3);
    ts.push(1, 1.0);
    ts.push(2, 2.0);
    ts.push(3, 3.0);
    ts.push(4, 4.0);   // evicts (1,1)
    ts.push(5, 5.0);   // evicts (2,2)

    auto s = ts.samples();
    CHECK(s.size() == 3);
    CHECK(s[0].value == 3.0);
    CHECK(s[1].value == 4.0);
    CHECK(s[2].value == 5.0);
    return 0;
}

static int test_stats(void) {
    TimeSeries ts(10);
    for (int i = 1; i <= 10; ++i) ts.push((std::uint64_t)i, (double)i);

    auto st = ts.stats();
    CHECK(st.has_value());
    CHECK(st->count == 10);
    CHECK(st->min == 1.0);
    CHECK(st->max == 10.0);
    CHECK(st->mean > 5.4 && st->mean < 5.6);
    CHECK(st->p50  > 5.0 && st->p50  < 6.0);
    CHECK(st->p95  > 9.0 && st->p95  <= 10.0);
    return 0;
}

static int test_empty_stats(void) {
    TimeSeries ts(10);
    CHECK(!ts.stats().has_value());
    return 0;
}

static int test_clear(void) {
    TimeSeries ts(4);
    ts.push(1, 1.0);
    ts.push(2, 2.0);
    CHECK(ts.size() == 2);
    ts.clear();
    CHECK(ts.size() == 0);
    CHECK(!ts.stats().has_value());
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_basic_push();
    rc |= test_ring_eviction();
    rc |= test_stats();
    rc |= test_empty_stats();
    rc |= test_clear();
    if (rc == 0) std::puts("test_timeseries: OK");
    return rc;
}
