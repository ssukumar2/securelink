#pragma once
// Beacon client — periodically sends authenticated beacons to a server.
//
// Lifecycle:
//   BeaconClient c(cfg);
//   if (!c.connect()) { ... }
//   c.run();           // blocks; sends until stop() or fatal error
//
// Thread-safety: stop() is safe to call from another thread.

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "sl_aead.h"

namespace securelink {

struct BeaconClientConfig {
    std::string host          = "127.0.0.1";
    std::uint16_t port        = 4443;
    std::uint64_t client_id   = 0;
    std::uint32_t interval_ms = 5000;    // beacon period
    std::uint32_t jitter_ms   = 500;     // +/- random jitter applied per beacon
    std::uint32_t connect_timeout_ms = 5000;
    std::uint32_t io_timeout_ms      = 3000;
    bool          request_ack        = true;
    std::vector<std::uint8_t> static_payload;  // optional metadata sent each tick

    // Pre-shared symmetric session material. In a fuller integration these
    // would come out of the handshake; for the beacon path we accept them
    // directly so the module is independently testable.
    std::uint8_t key[SL_AEAD_KEY_LEN]      = {};
    std::uint8_t static_iv[SL_AEAD_IV_LEN] = {};
};

struct BeaconClientStats {
    std::uint64_t beacons_sent     = 0;
    std::uint64_t acks_received    = 0;
    std::uint64_t send_failures    = 0;
    std::uint64_t reconnects       = 0;
    std::uint64_t last_rtt_ms      = 0;
};

class BeaconClient {
public:
    explicit BeaconClient(BeaconClientConfig cfg);
    ~BeaconClient();

    BeaconClient(const BeaconClient&)            = delete;
    BeaconClient& operator=(const BeaconClient&) = delete;

    // Establish TCP connection. Returns true on success.
    bool connect();

    // Blocking send loop. Returns when stop() is called or a fatal error
    // is hit (the latter still returns; check stats for context).
    void run();

    // Signal the run loop to exit. Safe to call from another thread.
    void stop();

    // Send one beacon now, outside the periodic loop. Returns true on success.
    bool send_one();

    const BeaconClientStats& stats() const { return stats_; }

private:
    bool send_beacon_locked(std::uint16_t flags);
    bool wait_for_ack(std::uint32_t timeout_ms);
    bool reconnect_with_backoff();
    std::uint32_t next_delay_ms() const;

    BeaconClientConfig cfg_;
    int  fd_       = -1;
    std::uint64_t seq_ = 1;        // beacon sequence number
    std::atomic<bool> running_{false};
    BeaconClientStats stats_;
};

}  // namespace securelink
