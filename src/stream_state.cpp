#include "stream_state.hpp"

namespace securelink {

StreamState::StreamState(std::uint32_t id)
    : id_(id),
      phase_(StreamPhase::kIdle),
      opened_at_(std::chrono::steady_clock::now()) {}

const char* StreamState::phase_name() const {
    switch (phase_) {
        case StreamPhase::kIdle:               return "idle";
        case StreamPhase::kOpen:               return "open";
        case StreamPhase::kHalfClosedLocal:    return "half_closed_local";
        case StreamPhase::kHalfClosedRemote:   return "half_closed_remote";
        case StreamPhase::kClosed:             return "closed";
    }
    return "?";
}

void StreamState::transition_to(StreamPhase p) {
    phase_ = p;
}

bool StreamState::open() {
    if (phase_ != StreamPhase::kIdle) return false;
    transition_to(StreamPhase::kOpen);
    opened_at_ = std::chrono::steady_clock::now();
    return true;
}

bool StreamState::on_sent_fin() {
    switch (phase_) {
        case StreamPhase::kOpen:
            transition_to(StreamPhase::kHalfClosedLocal);
            return true;
        case StreamPhase::kHalfClosedRemote:
            transition_to(StreamPhase::kClosed);
            return true;
        default:
            return false;
    }
}

bool StreamState::on_recv_fin() {
    switch (phase_) {
        case StreamPhase::kOpen:
            transition_to(StreamPhase::kHalfClosedRemote);
            return true;
        case StreamPhase::kHalfClosedLocal:
            transition_to(StreamPhase::kClosed);
            return true;
        default:
            return false;
    }
}

void StreamState::reset(std::string reason) {
    reset_reason_ = std::move(reason);
    transition_to(StreamPhase::kClosed);
}

bool StreamState::can_send() const {
    return phase_ == StreamPhase::kOpen ||
           phase_ == StreamPhase::kHalfClosedRemote;
}

bool StreamState::can_recv() const {
    return phase_ == StreamPhase::kOpen ||
           phase_ == StreamPhase::kHalfClosedLocal;
}

std::chrono::milliseconds StreamState::age() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - opened_at_);
}

}  // namespace securelink
