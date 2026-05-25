#include "threat_score.hpp"

#include <cmath>

namespace securelink {

ThreatScore::ThreatScore(ThreatPolicy policy)
    : policy_(policy),
      decay_rate_(std::log(2.0) /
                  (policy_.half_life_seconds > 0 ? policy_.half_life_seconds : 1.0)) {}

double ThreatScore::weight_for(ThreatSignal sig) const {
    switch (sig) {
        case ThreatSignal::kAuthFailure:     return policy_.weight_auth_failure;
        case ThreatSignal::kReplayDetected:  return policy_.weight_replay;
        case ThreatSignal::kMalformedFrame:  return policy_.weight_malformed;
        case ThreatSignal::kClockSkew:       return policy_.weight_skew;
        case ThreatSignal::kRateLimited:     return policy_.weight_rate_limited;
        case ThreatSignal::kAnomalousTiming: return policy_.weight_anomaly_timing;
        case ThreatSignal::kAnomalousVolume: return policy_.weight_anomaly_volume;
        case ThreatSignal::kUnknownClientId: return policy_.weight_unknown_id;
        case ThreatSignal::kHandshakeAbort:  return policy_.weight_handshake_abort;
    }
    return 0.0;
}

double ThreatScore::decayed(const Entry& e, Clock::time_point now) const {
    const auto dt = std::chrono::duration<double>(now - e.last_updated).count();
    if (dt <= 0.0) return e.score;
    return e.score * std::exp(-decay_rate_ * dt);
}

double ThreatScore::signal(const std::string& peer, ThreatSignal sig) {
    const auto now = Clock::now();
    std::lock_guard<std::mutex> lock(mu_);
    auto& e = peers_[peer];
    if (e.last_updated == Clock::time_point{}) {
        e.last_updated = now;
    }
    e.score = decayed(e, now) + weight_for(sig);
    e.last_updated = now;
    ++e.signals;
    return e.score;
}

double ThreatScore::score(const std::string& peer) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = peers_.find(peer);
    if (it == peers_.end()) return 0.0;
    return decayed(it->second, Clock::now());
}

bool ThreatScore::is_blocked(const std::string& peer) const {
    return score(peer) >= policy_.block_threshold;
}

void ThreatScore::clear(const std::string& peer) {
    std::lock_guard<std::mutex> lock(mu_);
    peers_.erase(peer);
}

std::vector<std::string> ThreatScore::blocked_peers() const {
    std::lock_guard<std::mutex> lock(mu_);
    const auto now = Clock::now();
    std::vector<std::string> out;
    for (const auto& [peer, e] : peers_) {
        if (decayed(e, now) >= policy_.block_threshold) {
            out.push_back(peer);
        }
    }
    return out;
}

std::size_t ThreatScore::tracked_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return peers_.size();
}

}  // namespace securelink
