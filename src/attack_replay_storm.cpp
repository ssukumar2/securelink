// Attack: replay storm.
// Attacker captures a legitimate sequence of records and replays them
// in a tight loop, hoping the receiver misses the duplicates.
//
// Defense: ReplayGuard sliding-window bitmap (inc/replay_guard.hpp).
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/attack_replay_storm.cpp src/attack_sim.cpp \
//       -lpthread -o attack_replay_storm

#include <cstdio>
#include <string>

#include "attack_sim.hpp"
#include "replay_guard.hpp"

using namespace securelink;
using namespace securelink::attacks;

static ScenarioOutcome scenario_pure_replay() {
    ReplayGuard<> g;
    // Legitimate burst.
    for (std::uint64_t i = 1; i <= 1000; ++i) {
        if (!g.check_and_update(i)) return allowed("pure_replay",
            "first-pass rejection at seq=" + std::to_string(i));
    }

    // Attacker replays the same 1000 seqs.
    std::uint64_t accepted_replays = 0;
    for (std::uint64_t i = 1; i <= 1000; ++i) {
        if (g.check_and_update(i)) ++accepted_replays;
    }

    if (accepted_replays == 0) {
        return blocked("pure_replay",
            "0/1000 replays accepted; window correctly rejected all");
    }
    return allowed("pure_replay",
        std::to_string(accepted_replays) + " replays slipped through");
}

static ScenarioOutcome scenario_interleaved_replay() {
    ReplayGuard<> g;
    // Build a mixed stream where attacker re-injects an old seq between
    // legitimate ones.
    std::uint64_t seq = 1;
    for (int i = 0; i < 500; ++i) {
        if (!g.check_and_update(seq++))
            return allowed("interleaved_replay", "legit reject");
    }
    const auto replayed = g.check_and_update(42);
    if (replayed) {
        return allowed("interleaved_replay",
            "guard accepted seq=42 after already seeing it");
    }
    return blocked("interleaved_replay",
        "interleaved replay of seq=42 rejected as expected");
}

static ScenarioOutcome scenario_window_underflow_attack() {
    ReplayGuard<1024> g;
    // Establish high-water at 10000.
    g.check_and_update(10000);
    // Attacker injects an ancient seq that's outside the window.
    const auto leaked = g.check_and_update(5);
    if (leaked) {
        return allowed("ancient_outside_window",
            "guard accepted seq=5 with high_water=10000");
    }
    if (g.too_old_count() != 1) {
        return detected("ancient_outside_window",
            "rejected but counter not bumped");
    }
    return blocked("ancient_outside_window",
        "ancient replay rejected and counter bumped");
}

int main() {
    AttackSim sim;
    sim.add("pure_replay",            scenario_pure_replay);
    sim.add("interleaved_replay",     scenario_interleaved_replay);
    sim.add("ancient_outside_window", scenario_window_underflow_attack);

    const int failures = sim.run_all(true);
    if (failures == 0) {
        std::puts("attack_replay_storm: ALL DEFENSES HELD");
        return 0;
    }
    std::fprintf(stderr, "attack_replay_storm: %d defense failure(s)\n", failures);
    return 1;
}
