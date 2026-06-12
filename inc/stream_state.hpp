#pragma once
// StreamState — lifecycle FSM for one multiplexed stream.
//
// States follow the HTTP/2 pattern:
//   idle                — never opened
//   open                — both sides may send
//   half_closed_local   — we sent FIN; can still receive
//   half_closed_remote  — peer sent FIN; can still send
//   closed              — terminal
//
// Reset is a separate fast-path to closed used for abnormal teardown.

#include <chrono>
#include <cstdint>
#include <string>

#include "sl_stream_frame.h"

namespace securelink {

enum class StreamPhase {
    kIdle,
    kOpen,
    kHalfClosedLocal,
    kHalfClosedRemote,
    kClosed,
};

class StreamState {
public:
    explicit StreamState(std::uint32_t id);

    bool open();
    bool on_sent_fin();
    bool on_recv_fin();
    void reset(std::string reason);

    bool can_send() const;
    bool can_recv() const;
    bool is_closed() const { return phase_ == StreamPhase::kClosed; }

    StreamPhase phase()      const { return phase_; }
    const char* phase_name() const;
    std::uint32_t id()       const { return id_; }
    const std::string& reset_reason() const { return reset_reason_; }

    std::chrono::milliseconds age() const;

private:
    void transition_to(StreamPhase p);

    std::uint32_t                          id_;
    StreamPhase                            phase_;
    std::chrono::steady_clock::time_point  opened_at_;
    std::string                            reset_reason_;
};

}  // namespace securelink
