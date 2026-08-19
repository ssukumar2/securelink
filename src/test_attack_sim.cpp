// Tests for AttackSim itself, so we trust the harness used by attack_*.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_attack_sim.cpp src/attack_sim.cpp \
//       -lpthread -o test_attack_sim

#include <cstdio>
#include <stdexcept>
#include <thread>

#include "attack_sim.hpp"

using namespace securelink::attacks;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_all_blocked_returns_zero(void) {
    AttackSim sim;
    sim.add("a", []() { return blocked ("a", "ok"); });
    sim.add("b", []() { return detected("b", "warned"); });
    CHECK(sim.run_all(false) == 0);
    CHECK(sim.outcomes().size() == 2);
    CHECK(sim.outcomes()[0].result == AttackResult::kBlocked);
    CHECK(sim.outcomes()[1].result == AttackResult::kDetected);
    return 0;
}

static int test_one_allowed_returns_nonzero(void) {
    AttackSim sim;
    sim.add("good", []() { return blocked("good", ""); });
    sim.add("bad",  []() { return allowed("bad",  ""); });
    CHECK(sim.run_all(false) == 1);
    return 0;
}

static int test_throwing_scenario_is_inconclusive(void) {
    AttackSim sim;
    sim.add("oops", []() -> ScenarioOutcome {
        throw std::runtime_error("boom");
    });
    CHECK(sim.run_all(false) == 1);
    CHECK(sim.outcomes()[0].result == AttackResult::kInconclusive);
    CHECK(sim.outcomes()[0].evidence.find("boom") != std::string::npos);
    return 0;
}

static int test_outcome_helpers_set_fields(void) {
    auto b = blocked ("x", "evidence-x");
    auto a = allowed ("y", "evidence-y");
    CHECK(b.name == "x" && b.evidence == "evidence-x");
    CHECK(b.result == AttackResult::kBlocked);
    CHECK(a.result == AttackResult::kAllowed);
    return 0;
}

static int test_duration_is_recorded(void) {
    AttackSim sim;
    sim.add("slow", []() {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        return blocked("slow", "");
    });
    sim.run_all(false);
    CHECK(sim.outcomes()[0].duration_us >= 1000);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_all_blocked_returns_zero();
    rc |= test_one_allowed_returns_nonzero();
    rc |= test_throwing_scenario_is_inconclusive();
    rc |= test_outcome_helpers_set_fields();
    rc |= test_duration_is_recorded();
    if (rc == 0) std::puts("test_attack_sim: OK");
    return rc;
}
