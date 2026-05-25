#pragma once
// IntrusionMonitor — orchestrator that wires AnomalyDetector + ThreatScore
// together. Receives raw security signals, runs them through anomaly
// detection where applicable, and updates per-peer threat scores.
//
// This is the single seam the rest of the codebase calls when something
// suspicious happens. Keeps decision logic out of the protocol layer.

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

#include "anomaly_detector.hpp"
#include "threat_score.hpp"

namespace securelink {

struct IntrusionPolicy {
    // Anomaly detection tuning.
    double anomaly_alpha       = 0.1;
    double anomaly_z_threshold = 3.5;
    std::uint64_t anomaly_warmup = 30;

    // Threat scoring.
    ThreatPolicy threat;
};

struct IntrusionDecision {
    bool   block = false;           // peer should be quarantined
    double score = 0.0;             // current threat score
    bool   anomaly_timing = false;  // last timing observation was anomalous
    bool   anomaly_volume = false;  // last volume observation was anomalous
};

class IntrusionMonitor {
public:
    explicit IntrusionMonitor(IntrusionPolicy policy = {});

    // Raw security events from the protocol code path.
    IntrusionDecision report_auth_failure(const std::string& peer);
    IntrusionDecision report_replay(const std::string& peer);
    IntrusionDecision report_malformed(const std::string& peer);
    IntrusionDecision report_clock_skew(const std::string& peer);
    IntrusionDecision report_rate_limited(const std::string& peer);
    IntrusionDecision report_unknown_id(const std::string& peer);
    IntrusionDecision report_handshake_abort(const std::string& peer);

    // Behavioral observations — feed continuous metrics here.
    // `interval_ms` is the inter-arrival time of beacons.
    IntrusionDecision observe_beacon_timing(const std::string& peer,
                                            double interval_ms);
    // `bytes` is the size of an incoming frame.
    IntrusionDecision observe_volume(const std::string& peer, double bytes);

    // Manual queries.
    IntrusionDecision decision_for(const std::string& peer) const;
    void              clear(const std::string& peer);

private:
    AnomalyDetector& detector_for_timing(const std::string& peer);
    AnomalyDetector& detector_for_volume(const std::string& peer);
    IntrusionDecision build_decision(const std::string& peer) const;

    IntrusionPolicy policy_;
    ThreatScore     score_;

    mutable std::mutex mu_;
    std::unordered_map<std::string, AnomalyDetector> timing_;
    std::unordered_map<std::string, AnomalyDetector> volume_;
};

}  // namespace securelink
