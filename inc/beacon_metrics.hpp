#pragma once
// BeaconMetrics — aggregate counters for the beacon subsystem.
//
// All counters are std::atomic so they can be read and incremented from
// multiple threads without locking. The snapshot() method takes a
// consistent point-in-time copy that's safe to format/log.

#include <atomic>
#include <cstdint>
#include <ostream>

namespace securelink {

struct BeaconMetricsSnapshot {
    std::uint64_t beacons_accepted   = 0;
    std::uint64_t beacons_replayed   = 0;
    std::uint64_t beacons_auth_fail  = 0;
    std::uint64_t beacons_skew       = 0;
    std::uint64_t beacons_malformed  = 0;
    std::uint64_t acks_sent          = 0;
    std::uint64_t acks_failed        = 0;
    std::uint64_t clients_known      = 0;
    std::uint64_t clients_alive      = 0;
    std::uint64_t reaper_runs        = 0;
};

class BeaconMetrics {
public:
    void inc_accepted()   { beacons_accepted_.fetch_add(1, std::memory_order_relaxed); }
    void inc_replay()     { beacons_replayed_.fetch_add(1, std::memory_order_relaxed); }
    void inc_auth_fail()  { beacons_auth_fail_.fetch_add(1, std::memory_order_relaxed); }
    void inc_skew()       { beacons_skew_.fetch_add(1, std::memory_order_relaxed); }
    void inc_malformed()  { beacons_malformed_.fetch_add(1, std::memory_order_relaxed); }
    void inc_ack_sent()   { acks_sent_.fetch_add(1, std::memory_order_relaxed); }
    void inc_ack_failed() { acks_failed_.fetch_add(1, std::memory_order_relaxed); }
    void inc_reaper_run() { reaper_runs_.fetch_add(1, std::memory_order_relaxed); }

    void set_clients_known(std::uint64_t v) {
        clients_known_.store(v, std::memory_order_relaxed);
    }
    void set_clients_alive(std::uint64_t v) {
        clients_alive_.store(v, std::memory_order_relaxed);
    }

    BeaconMetricsSnapshot snapshot() const {
        BeaconMetricsSnapshot s;
        s.beacons_accepted  = beacons_accepted_.load(std::memory_order_relaxed);
        s.beacons_replayed  = beacons_replayed_.load(std::memory_order_relaxed);
        s.beacons_auth_fail = beacons_auth_fail_.load(std::memory_order_relaxed);
        s.beacons_skew      = beacons_skew_.load(std::memory_order_relaxed);
        s.beacons_malformed = beacons_malformed_.load(std::memory_order_relaxed);
        s.acks_sent         = acks_sent_.load(std::memory_order_relaxed);
        s.acks_failed       = acks_failed_.load(std::memory_order_relaxed);
        s.clients_known     = clients_known_.load(std::memory_order_relaxed);
        s.clients_alive     = clients_alive_.load(std::memory_order_relaxed);
        s.reaper_runs       = reaper_runs_.load(std::memory_order_relaxed);
        return s;
    }

    // Render counters in a single line, Prometheus-ish: key=value pairs.
    void render(std::ostream& os) const {
        const auto s = snapshot();
        os << "beacons_accepted="   << s.beacons_accepted
           << " beacons_replayed="  << s.beacons_replayed
           << " beacons_auth_fail=" << s.beacons_auth_fail
           << " beacons_skew="      << s.beacons_skew
           << " beacons_malformed=" << s.beacons_malformed
           << " acks_sent="         << s.acks_sent
           << " acks_failed="       << s.acks_failed
           << " clients_known="     << s.clients_known
           << " clients_alive="     << s.clients_alive
           << " reaper_runs="       << s.reaper_runs;
    }

private:
    std::atomic<std::uint64_t> beacons_accepted_{0};
    std::atomic<std::uint64_t> beacons_replayed_{0};
    std::atomic<std::uint64_t> beacons_auth_fail_{0};
    std::atomic<std::uint64_t> beacons_skew_{0};
    std::atomic<std::uint64_t> beacons_malformed_{0};
    std::atomic<std::uint64_t> acks_sent_{0};
    std::atomic<std::uint64_t> acks_failed_{0};
    std::atomic<std::uint64_t> clients_known_{0};
    std::atomic<std::uint64_t> clients_alive_{0};
    std::atomic<std::uint64_t> reaper_runs_{0};
};

}  // namespace securelink
