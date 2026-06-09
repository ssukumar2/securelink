#pragma once
// SessionManager — tracks active securelink sessions, schedules rekeys,
// issues and consumes resumption tickets.
//
// One SessionManager per server. Each accepted connection registers a
// Session with it; the manager keeps weak references and reaps closed
// sessions during periodic sweeps.

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "sl_session_ticket.h"

namespace securelink {

struct SessionStats {
    std::uint64_t bytes_sent      = 0;
    std::uint64_t bytes_received  = 0;
    std::uint64_t records_sent    = 0;
    std::uint64_t records_received = 0;
    std::uint32_t rekeys_local    = 0;
    std::uint32_t rekeys_peer     = 0;
};

struct Session {
    std::uint64_t                                       id = 0;
    std::string                                         peer_label;
    std::array<std::uint8_t, 32>                        peer_identity{};
    std::chrono::steady_clock::time_point               opened_at;
    std::chrono::steady_clock::time_point               last_activity;
    SessionStats                                        stats;
    bool                                                authenticated = false;
};

struct SessionManagerConfig {
    // Rotate when either limit is hit.
    std::uint64_t rekey_after_bytes   = 1ULL << 30;   // 1 GiB
    std::uint32_t rekey_after_seconds = 3600;         // 1 hour
    // Tickets remain valid this long after issuance.
    std::uint32_t ticket_lifetime_seconds = 6 * 3600;
    // Inactive sessions reaped after this long.
    std::uint32_t idle_timeout_seconds = 600;
};

class SessionManager {
public:
    explicit SessionManager(SessionManagerConfig cfg);

    // Register a freshly-authenticated session. Returns the session id.
    std::uint64_t register_session(std::string peer_label,
                                   std::array<std::uint8_t, 32> peer_identity);

    // Mark traffic, update activity counters, and report whether a rekey
    // is recommended now. Idempotent and cheap.
    bool record_traffic(std::uint64_t id,
                        std::uint64_t bytes_sent,
                        std::uint64_t bytes_received);

    // Record that a rekey just completed (locally-initiated or peer-driven).
    void note_rekey_local(std::uint64_t id);
    void note_rekey_peer (std::uint64_t id);

    // Issue a ticket bound to the session's identity and a caller-provided
    // resumption secret. Returns the sealed wire bytes.
    std::vector<std::uint8_t> issue_ticket(
        std::uint64_t id,
        const std::array<std::uint8_t, 32>& stk,
        const std::array<std::uint8_t, 32>& resumption_secret);

    // Try to resume from a ticket. Returns nullopt if invalid/expired.
    std::optional<sl_ticket_body_t> consume_ticket(
        const std::array<std::uint8_t, 32>& stk,
        const std::vector<std::uint8_t>&    ticket_bytes);

    void close_session(std::uint64_t id);

    std::optional<Session> snapshot(std::uint64_t id) const;
    std::size_t            active_count() const;

    // Reap idle/closed sessions. Returns number removed.
    std::size_t sweep();

private:
    SessionManagerConfig cfg_;
    mutable std::mutex   mu_;
    std::unordered_map<std::uint64_t, Session> sessions_;
    std::uint64_t                              next_id_ = 1;
};

}  // namespace securelink
