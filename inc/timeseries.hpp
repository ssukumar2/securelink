#pragma once
// TimeSeries — fixed-capacity ring of (timestamp, value) samples for
// short-window metric history. Used to feed dashboards, anomaly checks
// over recent windows, and the admin HTTP endpoint.
//
// Memory usage is O(capacity); each sample is 16 bytes. Capacity is
// chosen at construction; oldest samples are evicted FIFO once full.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <vector>

namespace securelink {

struct TsSample {
    std::uint64_t timestamp_ms = 0;
    double        value        = 0.0;
};

struct TsStats {
    double        min   = 0.0;
    double        max   = 0.0;
    double        mean  = 0.0;
    double        p50   = 0.0;
    double        p95   = 0.0;
    double        p99   = 0.0;
    std::size_t   count = 0;
};

class TimeSeries {
public:
    explicit TimeSeries(std::size_t capacity);

    void push(double value);
    void push(std::uint64_t ts_ms, double value);

    void clear();

    std::size_t size()     const;
    std::size_t capacity() const { return cap_; }

    // Copy of all current samples in chronological order.
    std::vector<TsSample> samples() const;

    // Stats over the full ring. nullopt if empty.
    std::optional<TsStats> stats() const;

    // Stats over the last `window_ms` of wall-clock time.
    std::optional<TsStats> stats_window(std::uint64_t window_ms) const;

private:
    static std::uint64_t now_ms();
    static TsStats compute_stats(std::vector<double> values);

    std::size_t cap_;
    mutable std::mutex mu_;
    std::vector<TsSample> ring_;
    std::size_t head_ = 0;
    std::size_t used_ = 0;
};

}  // namespace securelink
