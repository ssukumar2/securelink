// Tests for MetricsRegistry.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_metrics_registry.cpp src/metrics_registry.cpp \
//       -lpthread -o test_metrics_registry

#include <cstdio>

#include "metrics_registry.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_counter_increments(void) {
    MetricsRegistry r;
    auto& c = r.counter("requests_total", {{"path", "/healthz"}});
    c.inc();
    c.inc(4);
    CHECK(c.value() == 5);

    /* Same name+labels returns same series. */
    auto& c2 = r.counter("requests_total", {{"path", "/healthz"}});
    CHECK(c2.value() == 5);

    /* Different labels => different series. */
    auto& c3 = r.counter("requests_total", {{"path", "/metrics"}});
    CHECK(c3.value() == 0);
    return 0;
}

static int test_gauge_set_inc_dec(void) {
    MetricsRegistry r;
    auto& g = r.gauge("inflight_connections");
    g.set(10.0);
    g.inc(5.0);
    g.dec(2.5);
    CHECK(g.value() == 12.5);
    return 0;
}

static int test_render_contains_series(void) {
    MetricsRegistry r;
    r.counter("frames_accepted_total").inc(7);
    r.gauge  ("inflight_connections").set(3.0);
    const std::string out = r.render_string();
    CHECK(out.find("frames_accepted_total") != std::string::npos);
    CHECK(out.find("inflight_connections")  != std::string::npos);
    CHECK(out.find("# TYPE frames_accepted_total counter") != std::string::npos);
    CHECK(out.find("# TYPE inflight_connections gauge") != std::string::npos);
    return 0;
}

static int test_label_isolation(void) {
    MetricsRegistry r;
    r.counter("c", {{"k", "a"}}).inc(1);
    r.counter("c", {{"k", "b"}}).inc(2);
    r.counter("c", {{"k", "a"}}).inc(10);
    CHECK(r.counter("c", {{"k", "a"}}).value() == 11);
    CHECK(r.counter("c", {{"k", "b"}}).value() == 2);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_counter_increments();
    rc |= test_gauge_set_inc_dec();
    rc |= test_render_contains_series();
    rc |= test_label_isolation();
    if (rc == 0) std::puts("test_metrics_registry: OK");
    return rc;
}
