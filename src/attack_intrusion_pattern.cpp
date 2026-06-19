// Attack: stealthy compromised client. The attacker behaves "almost"
// normally but periodically misbehaves — a few replays, an auth failure,
// occasional timing anomaly. Any single defense wouldn't block, but the
// IntrusionMonitor should accumulate score and quarantine.
//
// Defense: ThreatScore + AnomalyDetector wired through IntrusionMonitor.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/attack_intrusion_pattern.cpp src/attack_sim.cpp \
//       src/intrusion_monitor.cpp src/threat_score.cpp \
//       src/anomaly_detector.cpp \
//       -lpthread -o attack_intrusion_pattern

#include <cstdio>

#include "attack_sim.hpp"
#include "intrusion_monitor.hpp"

using namespace securelink;
using namespace securelink::attacks;

static ScenarioOutcome scenario_slow_burn() {
    IntrusionPolicy p;
    p.threat.block_threshold = 20.0;
    p.anomaly_warmup = 5;
    p.anomaly_z_threshold = 3.0;
    IntrusionMonitor mon(p);

    const std::string peer = "203.0.113.42";

    // Mostly normal beacon timing.
    for (int i = 0; i < 40; ++i) {
        mon.observe_beacon_timing(peer, 5000.0 + (i % 7));
    }

    // Sprinkle in low-severity signals.
    mon.report_clock_skew(peer);
    mon.report_rate_limited(peer);
    mon.report_clock_skew(peer);
    auto d_lo = mon.decision_for(peer);
    if (d_lo.block) {
        return detected("slow_burn",
            "blocked too eagerly on low-severity signals");
    }

    // Real attack moves: replay + auth failure + malformed.
    mon.report_replay(peer);
    mon.report_auth_failure(peer);
    auto d_mid = mon.report_malformed(peer);

    if (!d_mid.block) {
        return allowed("slow_burn",
            "accumulated score did not trip block threshold");
    }
    return blocked("slow_burn",
        "accumulated multi-signal score crossed threshold");
}

static ScenarioOutcome scenario_volume_spike() {
    IntrusionPolicy p;
    p.anomaly_warmup = 10;
    p.anomaly_z_threshold = 3.0;
    IntrusionMonitor mon(p);
    const std::string peer = "198.51.100.1";

    for (int i = 0; i < 40; ++i) mon.observe_volume(peer, 256.0 + (i % 3));
    auto d = mon.observe_volume(peer, 65000.0);
    if (!d.anomaly_volume) {
        return allowed("volume_spike",
            "volume anomaly missed");
    }
    return detected("volume_spike",
        "volume anomaly detected; threat score updated");
}

static ScenarioOutcome scenario_decay_recovers() {
    ThreatPolicy tp;
    tp.half_life_seconds = 0.05;
    tp.block_threshold = 5.0;
    IntrusionPolicy ip; ip.threat = tp;
    IntrusionMonitor mon(ip);
    const std::string peer = "p";

    mon.report_replay(peer);
    mon.report_replay(peer);
    if (!mon.decision_for(peer).block) {
        return inconclusive("decay_recovers",
            "expected to be blocked after two replays");
    }
    // Sleep long enough for the score to decay past the threshold.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    if (mon.decision_for(peer).block) {
        return allowed("decay_recovers",
            "score did not decay below threshold");
    }
    return blocked("decay_recovers",
        "score decayed and peer returned to allowed state");
}

int main() {
    AttackSim sim;
    sim.add("slow_burn_escalation", scenario_slow_burn);
    sim.add("volume_spike",         scenario_volume_spike);
    sim.add("decay_recovers",       scenario_decay_recovers);

    const int failures = sim.run_all(true);
    if (failures == 0) {
        std::puts("attack_intrusion_pattern: ALL DEFENSES HELD");
        return 0;
    }
    return 1;
}
