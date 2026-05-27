#include "snapshot_manager.hpp"

#include <cstring>

#include "sl_snapshot.h"

namespace securelink {

SnapshotManager::SnapshotManager(SnapshotManagerConfig cfg,
                                 SerializeFn serializer,
                                 DeserializeFn deserializer)
    : cfg_(std::move(cfg)),
      serialize_(std::move(serializer)),
      deserialize_(std::move(deserializer)) {}

SnapshotManager::~SnapshotManager() { stop(); }

bool SnapshotManager::restore() {
    if (!deserialize_) return false;

    // First pass: discover size.
    std::size_t size = 0;
    int rc = sl_snapshot_load(cfg_.path.c_str(), nullptr, 0, &size);
    if (rc == -1) {
        // Missing or unreadable; treat as no-op success.
        return true;
    }
    std::vector<std::uint8_t> buf(size);
    rc = sl_snapshot_load(cfg_.path.c_str(), buf.data(), buf.size(), &size);
    if (rc != 0) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.loads_failed;
        return false;
    }
    buf.resize(size);
    if (!deserialize_(buf)) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.loads_failed;
        return false;
    }
    std::lock_guard<std::mutex> lock(mu_);
    ++stats_.loads_ok;
    stats_.last_size_bytes = buf.size();
    return true;
}

bool SnapshotManager::save_now() {
    if (!serialize_) return false;
    const auto payload = serialize_();
    int rc = sl_snapshot_save(cfg_.path.c_str(),
                              payload.data(), payload.size());
    std::lock_guard<std::mutex> lock(mu_);
    if (rc == 0) {
        ++stats_.saves_ok;
        stats_.last_size_bytes = payload.size();
        return true;
    }
    ++stats_.saves_failed;
    return false;
}

void SnapshotManager::start() {
    if (running_.exchange(true)) return;
    thread_ = std::thread([this] { loop(); });
}

void SnapshotManager::stop() {
    if (!running_.exchange(false)) return;
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void SnapshotManager::loop() {
    std::unique_lock<std::mutex> lock(mu_);
    while (running_.load()) {
        cv_.wait_for(lock, std::chrono::milliseconds(cfg_.interval_ms),
                     [this] { return !running_.load(); });
        if (!running_.load()) break;
        lock.unlock();
        save_now();
        lock.lock();
    }
}

SnapshotManagerStats SnapshotManager::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    return stats_;
}

}  // namespace securelink
