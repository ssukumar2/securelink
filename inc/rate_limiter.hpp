#pragma once
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class RateLimiter {
public:
    explicit RateLimiter(int max_per_minute = 10)
        : max_per_minute_(max_per_minute) {}

    bool allow(const std::string& client_ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();
        auto& timestamps = clients_[client_ip];

        // Remove entries older than 60 seconds
        auto cutoff = now - std::chrono::seconds(60);
        timestamps.erase(
            std::remove_if(timestamps.begin(), timestamps.end(),
                           [cutoff](auto& t) { return t < cutoff; }),
            timestamps.end());

        if (static_cast<int>(timestamps.size()) >= max_per_minute_) {
            return false;
        }

        timestamps.push_back(now);
        return true;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        clients_.clear();
    }

private:
    int max_per_minute_;
    std::mutex mutex_;
    std::unordered_map<std::string,
        std::vector<std::chrono::steady_clock::time_point>> clients_;
};
