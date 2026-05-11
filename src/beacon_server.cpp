#include "beacon_server.hpp"

#include <cstring>

#include "sl_beacon.h"
#include "sl_beacon_codec.h"
#include "sl_clock.h"

namespace securelink {

BeaconServer::BeaconServer(BeaconServerConfig cfg) : cfg_(std::move(cfg)) {}

BeaconResult BeaconServer::on_beacon(const std::uint8_t* wire,
                                     std::size_t wire_len) {
    if (wire == nullptr || wire_len < SL_BEACON_HEADER_LEN + SL_AEAD_TAG_LEN) {
        return BeaconResult::kMalformed;
    }

    // Peek at header to know which client this beacon claims to be from.
    sl_beacon_t peek{};
    if (sl_beacon_unpack_header(wire, &peek) != 0) {
        return BeaconResult::kMalformed;
    }
    if (sl_beacon_validate(&peek) != 0) {
        return BeaconResult::kMalformed;
    }

    std::lock_guard<std::mutex> lock(mu_);
    auto& cs = clients_[peek.client_id];
    if (cs.client_id == 0) {
        cs.client_id = peek.client_id;
    }

    // Replay check uses sequence; must happen before authentication so a
    // replayed message doesn't waste an AEAD verify. (Authentication still
    // runs — replay only short-circuits the success path.)
    if (!cs.replay.would_accept(peek.sequence)) {
        ++cs.replays_rejected;
        return BeaconResult::kReplay;
    }

    // Authenticate + decrypt using the peer's sequence as the nonce input.
    sl_beacon_t opened{};
    if (sl_beacon_open(wire, wire_len, cfg_.key, cfg_.static_iv,
                       peek.sequence, &opened) != 0) {
        ++cs.auth_failures;
        return BeaconResult::kAuthFailed;
    }

    // Clock-skew check after authentication, on trusted fields.
    const std::uint64_t now_wall = sl_clock_wall_ms();
    const std::uint64_t skew = (opened.timestamp_ms > now_wall)
                                   ? (opened.timestamp_ms - now_wall)
                                   : (now_wall - opened.timestamp_ms);
    if (skew > cfg_.max_skew_ms) {
        ++cs.skew_rejections;
        return BeaconResult::kClockSkew;
    }

    // Commit replay window update only after full success.
    if (!cs.replay.check_and_update(opened.sequence)) {
        ++cs.replays_rejected;
        return BeaconResult::kReplay;
    }

    ++cs.beacons_received;
    cs.last_seq          = opened.sequence;
    cs.last_seen_mono_ms = sl_clock_mono_ms();
    cs.last_seen_wall_ms = opened.timestamp_ms;
    cs.alive             = true;
    return BeaconResult::kAccepted;
}

std::size_t BeaconServer::reap_stale() {
    const std::uint64_t now = sl_clock_mono_ms();
    std::lock_guard<std::mutex> lock(mu_);
    std::size_t transitioned = 0;
    for (auto& [id, cs] : clients_) {
        if (!cs.alive) continue;
        if (now - cs.last_seen_mono_ms > cfg_.liveness_timeout_ms) {
            cs.alive = false;
            ++transitioned;
        }
    }
    return transitioned;
}

std::optional<ClientState> BeaconServer::snapshot(std::uint64_t client_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = clients_.find(client_id);
    if (it == clients_.end()) return std::nullopt;
    return it->second;
}

std::size_t BeaconServer::client_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return clients_.size();
}

}  // namespace securelink
