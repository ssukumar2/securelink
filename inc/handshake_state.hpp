#pragma once
// HandshakeState — message-level state machine for the securelink handshake.
//
// Tracks which message we expect next, on the client and server sides. Used
// in conjunction with HandshakeEngine which performs the actual crypto.
// Keeping the FSM separate from the crypto makes it easy to unit-test the
// allowed orderings without setting up real keys.
//
// Client flow:
//   start -> send ClientHello       -> kWaitServerHello
//   recv ServerHello                -> kWaitCertificate
//   recv Certificate                -> kWaitCertVerify
//   recv CertVerify                 -> kWaitServerFinished
//   recv Finished                   -> send Finished -> kDone
//
// Server flow:
//   start                           -> kWaitClientHello
//   recv ClientHello                -> send ServerHello+Cert+CertVerify+Finished
//                                   -> kWaitClientFinished
//   recv Finished                   -> kDone
//
// On any unexpected message: kFailed. From kFailed/kDone no further events.

#include <cstdint>

#include "sl_handshake_msg.h"

namespace securelink {

enum class HsState {
    kInit,
    kWaitClientHello,
    kWaitServerHello,
    kWaitCertificate,
    kWaitCertVerify,
    kWaitServerFinished,
    kWaitClientFinished,
    kDone,
    kFailed,
};

enum class HsRole { kClient, kServer };

class HandshakeState {
public:
    explicit HandshakeState(HsRole role);

    HsRole role()  const { return role_; }
    HsState state() const { return state_; }
    const char* state_name() const;
    bool is_terminal() const { return state_ == HsState::kDone ||
                                      state_ == HsState::kFailed; }

    // Begin the handshake. Returns true if the transition was valid.
    bool start();

    // Record that we have just sent a message of `type`. Updates state.
    bool on_sent(sl_hs_type_t type);

    // Record that we have just received a message of `type`. Updates state.
    bool on_received(sl_hs_type_t type);

    // Force failure (e.g. after a crypto failure detected elsewhere).
    void fail(const char* reason);
    const char* failure_reason() const { return failure_reason_; }

    std::uint32_t messages_sent()     const { return sent_; }
    std::uint32_t messages_received() const { return recv_; }

private:
    HsRole       role_;
    HsState      state_;
    std::uint32_t sent_ = 0;
    std::uint32_t recv_ = 0;
    const char*  failure_reason_ = "";
};

}  // namespace securelink
