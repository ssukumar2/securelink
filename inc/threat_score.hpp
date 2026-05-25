#pragma once
// ThreatScore — per-peer rolling risk score driven by observed signals.
//
// Each "signal" (auth failure, replay, malformed frame, anomalous timing,
// rate-limit hit, etc.) adds weighted points. Points decay exponentially
// with wall time. When the score crosses a threshold, the peer is
// considered high-risk and the caller can drop or quarantine it.
//
// This is the boring, auditable cousin of "ML-based threat detection":
// every input and weight is explicit, decisions are reproducible, and
// reviewers can argue about the numbers.

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace securelink {

enum class ThreatSignal {
    kAuthFailure,
    kReplayDetected,
    kMalformedFrame,
    kClockSkew,
    kRateLimited,
    kAnomalousTiming,
    kAnomalousVolume,
    kUnknownClientId,
    kHandshakeAbort,
};

struct ThreatPolicy {
    // Points added per signal type.
    double weight_auth_failure   = 8.0;
    double weight_replay         = 5.0;
    double weight_malformed      = 6.0;
    double weight_skew           = 2.0;
    double weight_rate_limited   = 1.0;
    double weight_anomaly_timing = 4.0;
    double weight_anomaly_volume = 4.0;
    double weight_unknown_id     = 3.0;
    double weight_handshake_abort = 5.0;

    // Half-life of accumulated score, in seconds.
    double half_life_seconds = 300.0;

    // Score >= block_threshold means quarantine recommended.
    double block_threshold = 20.0;
};

class ThreatScore {
public:
    explicit ThreatScore(ThreatPolicy policy = {});

    // Record a signal for `peer`. Returns the resulting score.
    double signal(const std::string& peer, ThreatSignal sig);

    // Current score for a peer (after applying time decay). 0 if unknown.
    double score(const std::string& peer) const;

    // True iff score >= block_threshold.
    bool   is_blocked(const std::string& peer) const;

    // Force-clear all state for a peer (e.g. on successful re-auth).
    void   clear(const std::string& peer);

    // Peers currently above threshold.
    std::vector<std::string> blocked_peers() const;

    std::size_t tracked_count() const;

private:
    using Clock = std::chrono::steady_clock;

    struct Entry {
        double                score = 0.0;
        Clock::time_point     last_updated;
        std::uint64_t         signals = 0;
    };

    double weight_for(ThreatSignal sig) const;
    double decayed(const Entry& e, Clock::time_point now) const;

    ThreatPolicy policy_;
    double       decay_rate_;  // ln(2)/half_life
    mutable std::mutex mu_;
    std::unordered_map<std::string, Entry> peers_;
};

}  // namespace securelink
