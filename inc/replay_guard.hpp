#pragma once
#include <chrono>
#include <cstdint>
#include <mutex>
#include <set>
#include <string>

class ReplayGuard {
public:
    explicit ReplayGuard(int max_age_sec = 30, size_t max_nonces = 10000)
        : max_age_sec_(max_age_sec), max_nonces_(max_nonces) {}

    bool check_and_record(const std::string& nonce, uint64_t timestamp_ms) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        int64_t age_ms = static_cast<int64_t>(now) - static_cast<int64_t>(timestamp_ms);
        if (age_ms < 0 || age_ms > max_age_sec_ * 1000) {
            return false;
        }

        if (seen_nonces_.count(nonce) > 0) {
            return false;
        }

        seen_nonces_.insert(nonce);
        if (seen_nonces_.size() > max_nonces_) {
            // Evict oldest half
            auto it = seen_nonces_.begin();
            size_t to_remove = max_nonces_ / 2;
            for (size_t i = 0; i < to_remove && it != seen_nonces_.end(); ++i) {
                it = seen_nonces_.erase(it);
            }
        }

        return true;
    }

    size_t nonce_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return seen_nonces_.size();
    }

private:
    int max_age_sec_;
    size_t max_nonces_;
    mutable std::mutex mutex_;
    std::set<std::string> seen_nonces_;
};
