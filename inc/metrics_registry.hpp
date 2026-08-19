#pragma once
// Prometheus-style metrics registry with counters and gauges.
#include <cstring>
//
// Designed for low-overhead in-process accounting:
//   - Counters: monotonically increasing; cheap fetch_add.
//   - Gauges:   point-in-time values; set/inc/dec.
//   - Labels:   sorted map<string,string>; used for series identity.
//
// Render produces text in Prometheus exposition format, suitable for
// serving on /metrics from a tiny HTTP handler.

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <ostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace securelink {

using LabelSet = std::map<std::string, std::string>;

class Counter {
public:
    void inc(std::uint64_t by = 1) noexcept {
        v_.fetch_add(by, std::memory_order_relaxed);
    }
    std::uint64_t value() const noexcept {
        return v_.load(std::memory_order_relaxed);
    }
private:
    std::atomic<std::uint64_t> v_{0};
};

class Gauge {
public:
    void set(double v) noexcept {
        // double atomic stored via uint64 reinterpret keeps it lock-free.
        std::uint64_t bits;
        std::memcpy(&bits, &v, sizeof(bits));
        v_.store(bits, std::memory_order_relaxed);
    }
    void inc(double d) noexcept { set(value() + d); }
    void dec(double d) noexcept { set(value() - d); }
    double value() const noexcept {
        const std::uint64_t bits = v_.load(std::memory_order_relaxed);
        double v;
        std::memcpy(&v, &bits, sizeof(v));
        return v;
    }
private:
    std::atomic<std::uint64_t> v_{0};
};

class MetricsRegistry {
public:
    Counter& counter(const std::string& name, const LabelSet& labels = {});
    Gauge&   gauge  (const std::string& name, const LabelSet& labels = {});

    // Emit Prometheus exposition format.
    void render(std::ostream& os) const;
    std::string render_string() const;

    std::size_t series_count() const;

private:
    struct Series {
        std::string name;
        LabelSet    labels;
        std::shared_ptr<Counter> counter;
        std::shared_ptr<Gauge>   gauge;
    };

    std::string make_key(const std::string& name, const LabelSet& labels) const;

    mutable std::mutex mu_;
    std::unordered_map<std::string, Series> series_;
};

}  // namespace securelink
