// Tests for HealthCheck aggregation and probe behavior.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_health_check.cpp src/health_check.cpp \
//       -lpthread -o test_health_check

#include <cstdio>
#include <stdexcept>

#include "health_check.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_empty_is_healthy(void) {
    HealthCheck h;
    h.run_all();
    CHECK(h.aggregate() == HealthStatus::kHealthy);
    return 0;
}

static int test_all_healthy(void) {
    HealthCheck h;
    h.register_probe("a", []() {
        ProbeResult r;
        r.status = HealthStatus::kHealthy;
        return r;
    });
    h.register_probe("b", []() {
        ProbeResult r;
        r.status = HealthStatus::kHealthy;
        return r;
    });
    h.run_all();
    CHECK(h.aggregate() == HealthStatus::kHealthy);
    return 0;
}

static int test_worst_status_wins(void) {
    HealthCheck h;
    h.register_probe("ok",   []() { ProbeResult r; r.status = HealthStatus::kHealthy;   return r; });
    h.register_probe("warn", []() { ProbeResult r; r.status = HealthStatus::kDegraded;  return r; });
    h.run_all();
    CHECK(h.aggregate() == HealthStatus::kDegraded);

    h.register_probe("bad", []() { ProbeResult r; r.status = HealthStatus::kUnhealthy; return r; });
    h.run_all();
    CHECK(h.aggregate() == HealthStatus::kUnhealthy);
    return 0;
}

static int test_throwing_probe_marks_unhealthy(void) {
    HealthCheck h;
    h.register_probe("oops", []() -> ProbeResult {
        throw std::runtime_error("boom");
    });
    h.run_all();
    CHECK(h.aggregate() == HealthStatus::kUnhealthy);
    const auto json = h.render_string();
    CHECK(json.find("boom") != std::string::npos);
    return 0;
}

static int test_unregister(void) {
    HealthCheck h;
    h.register_probe("bad", []() { ProbeResult r; r.status = HealthStatus::kUnhealthy; return r; });
    h.run_all();
    CHECK(h.aggregate() == HealthStatus::kUnhealthy);

    h.unregister_probe("bad");
    h.run_all();
    CHECK(h.aggregate() == HealthStatus::kHealthy);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_empty_is_healthy();
    rc |= test_all_healthy();
    rc |= test_worst_status_wins();
    rc |= test_throwing_probe_marks_unhealthy();
    rc |= test_unregister();
    if (rc == 0) std::puts("test_health_check: OK");
    return rc;
}
