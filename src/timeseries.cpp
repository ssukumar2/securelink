#include "timeseries.hpp"

#include <algorithm>
#include <chrono>
#include <numeric>

namespace securelink {

TimeSeries::TimeSeries(std::size_t capacity)
    : cap_(capacity > 0 ? capacity : 1),
      ring_(cap_) {}

std::uint64_t TimeSeries::now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void TimeSeries::push(double value) {
    push(now_ms(), value);
}

void TimeSeries::push(std::uint64_t ts_ms, double value) {
    std::lock_guard<std::mutex> lock(mu_);
    ring_[head_] = TsSample{ts_ms, value};
    head_ = (head_ + 1) % cap_;
    if (used_ < cap_) ++used_;
}

void TimeSeries::clear() {
    std::lock_guard<std::mutex> lock(mu_);
    head_ = 0;
    used_ = 0;
}

std::size_t TimeSeries::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return used_;
}

std::vector<TsSample> TimeSeries::samples() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<TsSample> out;
    out.reserve(used_);
    if (used_ < cap_) {
        for (std::size_t i = 0; i < used_; ++i) out.push_back(ring_[i]);
    } else {
        for (std::size_t i = 0; i < cap_; ++i) {
            out.push_back(ring_[(head_ + i) % cap_]);
        }
    }
    return out;
}

TsStats TimeSeries::compute_stats(std::vector<double> values) {
    TsStats s;
    s.count = values.size();
    if (values.empty()) return s;

    s.min = *std::min_element(values.begin(), values.end());
    s.max = *std::max_element(values.begin(), values.end());
    s.mean = std::accumulate(values.begin(), values.end(), 0.0) /
             static_cast<double>(values.size());
    std::sort(values.begin(), values.end());
    auto pct = [&](double q) -> double {
        const double idx = q * (values.size() - 1);
        const std::size_t lo = static_cast<std::size_t>(idx);
        const std::size_t hi = std::min(lo + 1, values.size() - 1);
        const double frac = idx - static_cast<double>(lo);
        return values[lo] * (1.0 - frac) + values[hi] * frac;
    };
    s.p50 = pct(0.50);
    s.p95 = pct(0.95);
    s.p99 = pct(0.99);
    return s;
}

std::optional<TsStats> TimeSeries::stats() const {
    const auto sm = samples();
    if (sm.empty()) return std::nullopt;
    std::vector<double> vals;
    vals.reserve(sm.size());
    for (const auto& s : sm) vals.push_back(s.value);
    return compute_stats(std::move(vals));
}

std::optional<TsStats> TimeSeries::stats_window(std::uint64_t window_ms) const {
    const auto sm = samples();
    if (sm.empty()) return std::nullopt;
    const std::uint64_t cutoff =
        (now_ms() > window_ms) ? (now_ms() - window_ms) : 0;
    std::vector<double> vals;
    for (const auto& s : sm) {
        if (s.timestamp_ms >= cutoff) vals.push_back(s.value);
    }
    if (vals.empty()) return std::nullopt;
    return compute_stats(std::move(vals));
}

}  // namespace securelink
