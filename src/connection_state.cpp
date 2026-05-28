#include "connection_state.hpp"

namespace securelink {

ConnectionState::ConnectionState()
    : state_(ConnState::kFresh),
      entered_(std::chrono::steady_clock::now()) {}

void ConnectionState::transition_to(ConnState s) {
    state_   = s;
    entered_ = std::chrono::steady_clock::now();
}

const char* ConnectionState::state_name() const {
    switch (state_) {
        case ConnState::kFresh:         return "fresh";
        case ConnState::kHandshaking:   return "handshaking";
        case ConnState::kAuthenticated: return "authenticated";
        case ConnState::kClosing:       return "closing";
        case ConnState::kClosed:        return "closed";
    }
    return "?";
}

bool ConnectionState::on_event(ConnEvent ev) {
    ++events_;
    const ConnState from = state_;

    auto invalid = [&] {
        ++invalids_;
        transition_to(ConnState::kClosed);
        if (close_reason_.empty()) close_reason_ = "invalid_transition";
        return false;
    };

    switch (from) {
    case ConnState::kFresh:
        switch (ev) {
            case ConnEvent::kStartHandshake: transition_to(ConnState::kHandshaking); return true;
            case ConnEvent::kPeerClosed:
            case ConnEvent::kIoError:
            case ConnEvent::kTimeout:        transition_to(ConnState::kClosed);     return true;
            default: return invalid();
        }
    case ConnState::kHandshaking:
        switch (ev) {
            case ConnEvent::kHandshakeDone:   transition_to(ConnState::kAuthenticated); return true;
            case ConnEvent::kHandshakeFailed: transition_to(ConnState::kClosed);        return true;
            case ConnEvent::kPeerClosed:
            case ConnEvent::kIoError:
            case ConnEvent::kTimeout:         transition_to(ConnState::kClosed);        return true;
            default: return invalid();
        }
    case ConnState::kAuthenticated:
        switch (ev) {
            case ConnEvent::kRecvAppRecord:
            case ConnEvent::kSendAppRecord:   return true;   /* stay */
            case ConnEvent::kBeginClose:      transition_to(ConnState::kClosing); return true;
            case ConnEvent::kPeerClosed:
            case ConnEvent::kIoError:
            case ConnEvent::kTimeout:         transition_to(ConnState::kClosed); return true;
            default: return invalid();
        }
    case ConnState::kClosing:
        switch (ev) {
            case ConnEvent::kPeerClosed:
            case ConnEvent::kIoError:
            case ConnEvent::kTimeout:         transition_to(ConnState::kClosed); return true;
            case ConnEvent::kRecvAppRecord:   return true; /* drain inbound during close */
            default: return invalid();
        }
    case ConnState::kClosed:
        /* Once closed, only repeated terminal events are accepted as no-ops. */
        if (ev == ConnEvent::kPeerClosed || ev == ConnEvent::kIoError ||
            ev == ConnEvent::kTimeout) {
            return true;
        }
        return invalid();
    }
    return invalid();
}

std::chrono::milliseconds ConnectionState::time_in_state() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - entered_);
}

}  // namespace securelink
