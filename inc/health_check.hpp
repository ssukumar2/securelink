#pragma once
// HealthCheck — composite liveness/readiness reporting for the daemon.
//
// Register named probes that each return a status. The aggregator reports
// the worst status across all probes. Designed to be cheap to poll from
// an HTTP handler at /healthz or /readyz.

#include <chrono>
#include <functional>
#include <mutex>
#include <ostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace securelink {

enum class HealthStatus {
    kHealthy   = 0,
    kDegraded  = 1,
    kUnhealthy = 2,
};

struct ProbeResult {
    HealthStatus  status = HealthStatus::kHealthy;
    std::string   detail;
    std::chrono::steady_clock::time_point checked_at;
};

using ProbeFn = std::function<ProbeResult()>;

class HealthCheck {
public:
    // Register a probe. Overwrites a probe with the same name.
    void register_probe(const std::string& name, ProbeFn fn);
    void unregister_probe(const std::string& name);

    // Re-run every registered probe and cache the results.
    void run_all();

    // Aggregate status across most-recent results. Empty -> kHealthy.
    HealthStatus aggregate() const;

    // Render results as a JSON-ish payload (no external dep). Keys are stable.
    void render(std::ostream& os) const;
    std::string render_string() const;

    std::size_t probe_count() const;

    static const char* to_string(HealthStatus s);

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, ProbeFn>     probes_;
    std::unordered_map<std::string, ProbeResult> last_;
};

}  // namespace securelink
