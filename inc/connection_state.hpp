#pragma once
// ConnectionState — per-connection lifecycle state machine.
//
// States:
//   kFresh        : socket accepted, nothing read yet
//   kHandshaking  : reading/writing handshake messages
//   kAuthenticated: handshake done, exchanging application records
//   kClosing      : graceful close-notify in flight
//   kClosed       : socket closed; connection eligible for cleanup
//
// Transitions are explicit — only certain (from, event) pairs are valid.
// The state machine guards the protocol layer from doing illegal things
// like sending app data before the handshake completes.

#include <chrono>
#include <cstdint>
#include <string>

namespace securelink {

enum class ConnState {
    kFresh,
    kHandshaking,
    kAuthenticated,
    kClosing,
    kClosed,
};

enum class ConnEvent {
    kStartHandshake,
    kHandshakeDone,
    kHandshakeFailed,
    kRecvAppRecord,
    kSendAppRecord,
    kBeginClose,
    kPeerClosed,
    kIoError,
    kTimeout,
};

class ConnectionState {
public:
    ConnectionState();

    // Apply an event. Returns true if the transition was valid.
    // On invalid transitions the state moves to kClosed.
    bool on_event(ConnEvent ev);

    ConnState        state() const { return state_; }
    const char*      state_name() const;
    bool             is_terminal() const { return state_ == ConnState::kClosed; }
    bool             can_send_app() const { return state_ == ConnState::kAuthenticated; }

    std::uint64_t    events_handled()    const { return events_; }
    std::uint64_t    invalid_transitions() const { return invalids_; }

    std::chrono::milliseconds time_in_state() const;

    // Set or override the close reason (for logging/audit).
    void set_close_reason(std::string r) { close_reason_ = std::move(r); }
    const std::string& close_reason() const { return close_reason_; }

private:
    void transition_to(ConnState s);

    ConnState  state_;
    std::chrono::steady_clock::time_point entered_;
    std::uint64_t events_   = 0;
    std::uint64_t invalids_ = 0;
    std::string   close_reason_;
};

}  // namespace securelink
