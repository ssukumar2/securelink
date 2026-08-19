#include "health_check.hpp"

#include <chrono>
#include <sstream>

namespace securelink {

const char* HealthCheck::to_string(HealthStatus s) {
    switch (s) {
        case HealthStatus::kHealthy:   return "healthy";
        case HealthStatus::kDegraded:  return "degraded";
        case HealthStatus::kUnhealthy: return "unhealthy";
    }
    return "unknown";
}

void HealthCheck::register_probe(const std::string& name, ProbeFn fn) {
    std::lock_guard<std::mutex> lock(mu_);
    probes_[name] = std::move(fn);
}

void HealthCheck::unregister_probe(const std::string& name) {
    std::lock_guard<std::mutex> lock(mu_);
    probes_.erase(name);
    last_.erase(name);
}

void HealthCheck::run_all() {
    // Snapshot the probes to avoid holding the lock during user callbacks.
    std::vector<std::pair<std::string, ProbeFn>> snapshot;
    {
        std::lock_guard<std::mutex> lock(mu_);
        snapshot.reserve(probes_.size());
        for (const auto& [n, fn] : probes_) snapshot.emplace_back(n, fn);
    }

    std::unordered_map<std::string, ProbeResult> results;
    const auto now = std::chrono::steady_clock::now();
    for (const auto& [name, fn] : snapshot) {
        ProbeResult r;
        try {
            r = fn();
        } catch (const std::exception& e) {
            r.status = HealthStatus::kUnhealthy;
            r.detail = std::string("probe threw: ") + e.what();
        } catch (...) {
            r.status = HealthStatus::kUnhealthy;
            r.detail = "probe threw unknown exception";
        }
        r.checked_at = now;
        results[name] = std::move(r);
    }

    std::lock_guard<std::mutex> lock(mu_);
    last_ = std::move(results);
}

HealthStatus HealthCheck::aggregate() const {
    std::lock_guard<std::mutex> lock(mu_);
    return aggregate_locked();
}

HealthStatus HealthCheck::aggregate_locked() const {
    HealthStatus worst = HealthStatus::kHealthy;
    for (const auto& [_, r] : last_) {
        if (static_cast<int>(r.status) > static_cast<int>(worst)) worst = r.status;
    }
    return worst;
}

void HealthCheck::render(std::ostream& os) const {
    std::lock_guard<std::mutex> lock(mu_);
    os << "{\n";
    // aggregate_locked(), not aggregate() -- this function already holds
    // mu_, and aggregate() taking the same non-recursive mutex again on
    // this thread would deadlock forever rather than return.
    os << "  \"status\": \"" << to_string(aggregate_locked()) << "\",\n";
    os << "  \"probes\": [\n";
    bool first = true;
    for (const auto& [name, r] : last_) {
        if (!first) os << ",\n";
        os << "    {\"name\":\"" << name << "\","
           << "\"status\":\"" << to_string(r.status) << "\","
           << "\"detail\":\"" << r.detail << "\"}";
        first = false;
    }
    os << "\n  ]\n";
    os << "}\n";
}

std::string HealthCheck::render_string() const {
    std::ostringstream oss;
    render(oss);
    return oss.str();
}

std::size_t HealthCheck::probe_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return probes_.size();
}

}  // namespace securelink
