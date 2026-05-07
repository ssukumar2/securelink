#pragma once
// Token-bucket rate limiter keyed by peer identifier (typically an IP string
// or numeric address). Each bucket refills at `tokens_per_sec` up to `burst`.
//
// Designed for connection-establishment and frame-arrival pacing. Cheap
// enough to call on every packet. Not thread-safe; wrap externally if needed.

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "constants.hpp"

namespace securelink {

class RateLimiter {
public:
    using Clock     = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    RateLimiter(std::uint32_t tokens_per_sec = constants::RL_TOKENS_PER_SEC,
                std::uint32_t burst          = constants::RL_BURST)
        : refill_per_sec_(tokens_per_sec),
          burst_(burst) {}

    // Try to consume `cost` tokens for `key`. Returns true on success.
    bool allow(const std::string& key, std::uint32_t cost = 1) {
        const auto now = Clock::now();
        auto& b = buckets_[key];
        if (b.last == TimePoint{}) {
            b.tokens = burst_;
            b.last   = now;
        } else {
            refill(b, now);
        }
        if (b.tokens >= cost) {
            b.tokens -= cost;
            return true;
        }
        ++b.dropped;
        return false;
    }

    // Inspect current token count without consuming. Useful for tests.
    std::uint32_t tokens(const std::string& key) {
        const auto now = Clock::now();
        auto it = buckets_.find(key);
        if (it == buckets_.end()) return burst_;
        refill(it->second, now);
        return it->second.tokens;
    }

    std::uint64_t dropped(const std::string& key) const {
        auto it = buckets_.find(key);
        return (it == buckets_.end()) ? 0 : it->second.dropped;
    }

    // Evict idle buckets older than `max_age`. Call periodically.
    std::size_t evict_idle(std::chrono::seconds max_age) {
        const auto now    = Clock::now();
        const auto cutoff = now - max_age;
        std::size_t removed = 0;
        for (auto it = buckets_.begin(); it != buckets_.end(); ) {
            if (it->second.last < cutoff) {
                it = buckets_.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }
        return removed;
    }

    std::size_t bucket_count() const noexcept { return buckets_.size(); }

    void reset() noexcept { buckets_.clear(); }

private:
    struct Bucket {
        std::uint32_t tokens  = 0;
        std::uint64_t dropped = 0;
        TimePoint     last{};
    };

    void refill(Bucket& b, TimePoint now) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 now - b.last).count();
        if (elapsed <= 0) return;
        const std::uint64_t add = (static_cast<std::uint64_t>(refill_per_sec_) *
                                   static_cast<std::uint64_t>(elapsed)) / 1000ULL;
        if (add > 0) {
            const std::uint64_t sum = static_cast<std::uint64_t>(b.tokens) + add;
            b.tokens = static_cast<std::uint32_t>(
                           sum > burst_ ? burst_ : sum);
            b.last   = now;
        }
    }

    std::uint32_t refill_per_sec_;
    std::uint32_t burst_;
    std::unordered_map<std::string, Bucket> buckets_;
};

}  // namespace securelink
