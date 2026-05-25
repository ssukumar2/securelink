// Tests for AnomalyDetector, ThreatScore, IntrusionMonitor.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_intrusion_monitor.cpp \
//       src/anomaly_detector.cpp src/threat_score.cpp \
//       src/intrusion_monitor.cpp \
//       -lpthread -o test_intrusion_monitor

#include <cstdio>
#include <thread>

#include "anomaly_detector.hpp"
#include "intrusion_monitor.hpp"
#include "threat_score.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_anomaly_detects_spike(void) {
    AnomalyDetector det(0.1, 3.0, 10);

    // Feed steady stream around 1000.
    for (int i = 0; i < 50; ++i) {
        bool a = det.observe(1000.0 + (i % 5));
        CHECK(!a);
    }
    // Inject a spike well outside the established distribution.
    bool a = det.observe(50000.0);
    CHECK(a);
    CHECK(det.anomalies() == 1);
    return 0;
}

static int test_anomaly_no_alarm_during_warmup(void) {
    AnomalyDetector det(0.1, 3.0, /*warmup=*/100);
    for (int i = 0; i < 50; ++i) det.observe(1.0);
    // Big jump during warmup must NOT trigger.
    bool a = det.observe(1e9);
    CHECK(!a);
    return 0;
}

static int test_threat_score_accumulates_and_decays(void) {
    ThreatPolicy p;
    p.half_life_seconds = 0.1;   // very fast decay for the test
    p.block_threshold   = 10.0;
    ThreatScore ts(p);

    ts.signal("attacker", ThreatSignal::kAuthFailure);
    ts.signal("attacker", ThreatSignal::kAuthFailure);
    CHECK(ts.score("attacker") > 0);
    CHECK(!ts.is_blocked("attacker"));     // not yet over threshold

    ts.signal("attacker", ThreatSignal::kMalformedFrame);
    // 8 + 8 + 6 = 22 (approx; decay tiny). Should now be blocked.
    CHECK(ts.is_blocked("attacker"));

    // Sleep long enough that decay drops below threshold.
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    CHECK(!ts.is_blocked("attacker"));
    return 0;
}

static int test_threat_score_clear(void) {
    ThreatScore ts;
    ts.signal("x", ThreatSignal::kAuthFailure);
    CHECK(ts.score("x") > 0);
    ts.clear("x");
    CHECK(ts.score("x") == 0.0);
    return 0;
}

static int test_intrusion_blocks_attacker(void) {
    IntrusionPolicy p;
    p.threat.block_threshold = 10.0;
    IntrusionMonitor mon(p);

    auto d1 = mon.report_auth_failure("evil");
    auto d2 = mon.report_replay("evil");
    auto d3 = mon.report_malformed("evil");
    (void)d1; (void)d2;
    CHECK(d3.block);
    CHECK(d3.score >= 10.0);

    // Unrelated peer is untouched.
    auto good = mon.decision_for("nice");
    CHECK(!good.block);
    CHECK(good.score == 0.0);
    return 0;
}

static int test_intrusion_timing_anomaly(void) {
    IntrusionPolicy p;
    p.anomaly_warmup = 10;
    p.anomaly_z_threshold = 3.0;
    IntrusionMonitor mon(p);

    for (int i = 0; i < 40; ++i) {
        auto d = mon.observe_beacon_timing("c", 5000.0 + (i % 3));
        CHECK(!d.anomaly_timing);
    }
    auto spike = mon.observe_beacon_timing("c", 200000.0);
    CHECK(spike.anomaly_timing);
    CHECK(spike.score > 0.0);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_anomaly_detects_spike();
    rc |= test_anomaly_no_alarm_during_warmup();
    rc |= test_threat_score_accumulates_and_decays();
    rc |= test_threat_score_clear();
    rc |= test_intrusion_blocks_attacker();
    rc |= test_intrusion_timing_anomaly();
    if (rc == 0) std::puts("test_intrusion_monitor: OK");
    return rc;
}
