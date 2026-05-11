#pragma once
// Beacon server side: tracks per-client state for received beacons.
// Validates AEAD, enforces replay protection, detects liveness loss.

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "replay_guard.hpp"
#include "sl_aead.h"

namespace securelink {

struct BeaconServerConfig {
    // How long since the last beacon before a client is considered dead.
    std::uint32_t liveness_timeout_ms = 15000;

    // Maximum allowed clock skew between client timestamp and server now.
    std::uint32_t max_skew_ms = 30000;

    // Pre-shared key/IV registry could be added; for now a single shared one.
    std::uint8_t key[SL_AEAD_KEY_LEN]      = {};
    std::uint8_t static_iv[SL_AEAD_IV_LEN] = {};
};

struct ClientState {
    std::uint64_t client_id          = 0;
    std::uint64_t beacons_received   = 0;
    std::uint64_t replays_rejected   = 0;
    std::uint64_t auth_failures      = 0;
    std::uint64_t skew_rejections    = 0;
    std::uint64_t last_seq           = 0;
    std::uint64_t last_seen_mono_ms  = 0;
    std::uint64_t last_seen_wall_ms  = 0;
    bool          alive              = false;
    ReplayGuard<> replay;
};

enum class BeaconResult {
    kAccepted,
    kAuthFailed,
    kReplay,
    kClockSkew,
    kMalformed,
};

class BeaconServer {
public:
    explicit BeaconServer(BeaconServerConfig cfg);

    // Process one received beacon wire frame from `client_id`. Updates state.
    BeaconResult on_beacon(const std::uint8_t* wire, std::size_t wire_len);

    // Scan all tracked clients, mark any whose last_seen exceeded the
    // liveness timeout as not alive. Returns number that transitioned.
    std::size_t reap_stale();

    // Read-only snapshot of one client's state. nullopt if unknown.
    std::optional<ClientState> snapshot(std::uint64_t client_id) const;

    std::size_t client_count() const;

private:
    BeaconServerConfig cfg_;
    mutable std::mutex mu_;
    std::unordered_map<std::uint64_t, ClientState> clients_;
};

}  // namespace securelink
