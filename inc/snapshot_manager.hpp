#pragma once
// SnapshotManager — orchestrates periodic snapshots of an in-memory
// component. Callers register a serializer/deserializer pair; the
// manager triggers serialize on a timer and writes via sl_snapshot.
//
// Designed for state that doesn't fit naturally into the KV store —
// e.g. anomaly detector statistics, time series, threat scores.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace securelink {

using SerializeFn   = std::function<std::vector<std::uint8_t>()>;
using DeserializeFn = std::function<bool(const std::vector<std::uint8_t>&)>;

struct SnapshotManagerConfig {
    std::string   path;
    std::uint32_t interval_ms = 60'000;   // snapshot every minute
    bool          fsync_on_save = true;
};

struct SnapshotManagerStats {
    std::uint64_t saves_ok      = 0;
    std::uint64_t saves_failed  = 0;
    std::uint64_t loads_ok      = 0;
    std::uint64_t loads_failed  = 0;
    std::uint64_t last_size_bytes = 0;
};

class SnapshotManager {
public:
    SnapshotManager(SnapshotManagerConfig cfg,
                    SerializeFn serializer,
                    DeserializeFn deserializer);
    ~SnapshotManager();

    // Restore from disk if a snapshot exists. Returns true on success
    // (or true with no snapshot present — nothing to restore).
    bool restore();

    // Take one snapshot synchronously.
    bool save_now();

    // Background timer thread.
    void start();
    void stop();
    bool running() const { return running_.load(); }

    SnapshotManagerStats stats() const;

private:
    void loop();

    SnapshotManagerConfig cfg_;
    SerializeFn   serialize_;
    DeserializeFn deserialize_;

    std::atomic<bool>       running_{false};
    std::thread             thread_;
    mutable std::mutex      mu_;
    std::condition_variable cv_;
    SnapshotManagerStats    stats_;
};

}  // namespace securelink
