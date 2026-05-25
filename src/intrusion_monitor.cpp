#include "intrusion_monitor.hpp"

namespace securelink {

IntrusionMonitor::IntrusionMonitor(IntrusionPolicy policy)
    : policy_(policy), score_(policy.threat) {}

AnomalyDetector& IntrusionMonitor::detector_for_timing(const std::string& peer) {
    auto it = timing_.find(peer);
    if (it == timing_.end()) {
        it = timing_.emplace(peer,
                AnomalyDetector(policy_.anomaly_alpha,
                                policy_.anomaly_z_threshold,
                                policy_.anomaly_warmup)).first;
    }
    return it->second;
}

AnomalyDetector& IntrusionMonitor::detector_for_volume(const std::string& peer) {
    auto it = volume_.find(peer);
    if (it == volume_.end()) {
        it = volume_.emplace(peer,
                AnomalyDetector(policy_.anomaly_alpha,
                                policy_.anomaly_z_threshold,
                                policy_.anomaly_warmup)).first;
    }
    return it->second;
}

IntrusionDecision IntrusionMonitor::build_decision(const std::string& peer) const {
    IntrusionDecision d;
    d.score = score_.score(peer);
    d.block = score_.is_blocked(peer);
    return d;
}

IntrusionDecision IntrusionMonitor::report_auth_failure(const std::string& peer) {
    score_.signal(peer, ThreatSignal::kAuthFailure);
    return build_decision(peer);
}
IntrusionDecision IntrusionMonitor::report_replay(const std::string& peer) {
    score_.signal(peer, ThreatSignal::kReplayDetected);
    return build_decision(peer);
}
IntrusionDecision IntrusionMonitor::report_malformed(const std::string& peer) {
    score_.signal(peer, ThreatSignal::kMalformedFrame);
    return build_decision(peer);
}
IntrusionDecision IntrusionMonitor::report_clock_skew(const std::string& peer) {
    score_.signal(peer, ThreatSignal::kClockSkew);
    return build_decision(peer);
}
IntrusionDecision IntrusionMonitor::report_rate_limited(const std::string& peer) {
    score_.signal(peer, ThreatSignal::kRateLimited);
    return build_decision(peer);
}
IntrusionDecision IntrusionMonitor::report_unknown_id(const std::string& peer) {
    score_.signal(peer, ThreatSignal::kUnknownClientId);
    return build_decision(peer);
}
IntrusionDecision IntrusionMonitor::report_handshake_abort(const std::string& peer) {
    score_.signal(peer, ThreatSignal::kHandshakeAbort);
    return build_decision(peer);
}

IntrusionDecision IntrusionMonitor::observe_beacon_timing(const std::string& peer,
                                                          double interval_ms) {
    bool anom = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        anom = detector_for_timing(peer).observe(interval_ms);
    }
    if (anom) score_.signal(peer, ThreatSignal::kAnomalousTiming);

    auto d = build_decision(peer);
    d.anomaly_timing = anom;
    return d;
}

IntrusionDecision IntrusionMonitor::observe_volume(const std::string& peer,
                                                   double bytes) {
    bool anom = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        anom = detector_for_volume(peer).observe(bytes);
    }
    if (anom) score_.signal(peer, ThreatSignal::kAnomalousVolume);

    auto d = build_decision(peer);
    d.anomaly_volume = anom;
    return d;
}

IntrusionDecision IntrusionMonitor::decision_for(const std::string& peer) const {
    return build_decision(peer);
}

void IntrusionMonitor::clear(const std::string& peer) {
    score_.clear(peer);
    std::lock_guard<std::mutex> lock(mu_);
    timing_.erase(peer);
    volume_.erase(peer);
}

}  // namespace securelink
