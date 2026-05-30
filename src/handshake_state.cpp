#include "handshake_state.hpp"

namespace securelink {

HandshakeState::HandshakeState(HsRole role)
    : role_(role), state_(HsState::kInit) {}

const char* HandshakeState::state_name() const {
    switch (state_) {
        case HsState::kInit:                return "init";
        case HsState::kWaitClientHello:     return "wait_client_hello";
        case HsState::kWaitServerHello:     return "wait_server_hello";
        case HsState::kWaitCertificate:     return "wait_certificate";
        case HsState::kWaitCertVerify:      return "wait_cert_verify";
        case HsState::kWaitServerFinished:  return "wait_server_finished";
        case HsState::kWaitClientFinished:  return "wait_client_finished";
        case HsState::kDone:                return "done";
        case HsState::kFailed:              return "failed";
    }
    return "?";
}

bool HandshakeState::start() {
    if (state_ != HsState::kInit) {
        fail("start_in_non_init");
        return false;
    }
    state_ = (role_ == HsRole::kClient)
                ? HsState::kWaitServerHello   /* client will send Hello next */
                : HsState::kWaitClientHello;
    return true;
}

bool HandshakeState::on_sent(sl_hs_type_t type) {
    if (is_terminal()) { fail("send_after_terminal"); return false; }
    ++sent_;

    if (role_ == HsRole::kClient) {
        switch (type) {
            case SL_HS_CLIENT_HELLO:
                if (state_ != HsState::kWaitServerHello) break; /* sending hello in init->wait */
                return true;
            case SL_HS_FINISHED:
                if (state_ != HsState::kWaitServerFinished &&
                    state_ != HsState::kDone) break;
                state_ = HsState::kDone;
                return true;
            default: break;
        }
        fail("unexpected_client_send");
        return false;
    }

    /* Server */
    switch (type) {
        case SL_HS_SERVER_HELLO:
        case SL_HS_CERTIFICATE:
        case SL_HS_CERT_VERIFY:
            if (state_ != HsState::kWaitClientFinished &&
                state_ != HsState::kWaitClientHello) break;
            state_ = HsState::kWaitClientFinished;
            return true;
        case SL_HS_FINISHED:
            /* Server sends Finished as part of its flight before waiting for client. */
            if (state_ != HsState::kWaitClientFinished) break;
            return true;
        default: break;
    }
    fail("unexpected_server_send");
    return false;
}

bool HandshakeState::on_received(sl_hs_type_t type) {
    if (is_terminal()) { fail("recv_after_terminal"); return false; }
    ++recv_;

    if (role_ == HsRole::kClient) {
        switch (type) {
            case SL_HS_SERVER_HELLO:
                if (state_ != HsState::kWaitServerHello) break;
                state_ = HsState::kWaitCertificate;
                return true;
            case SL_HS_CERTIFICATE:
                if (state_ != HsState::kWaitCertificate) break;
                state_ = HsState::kWaitCertVerify;
                return true;
            case SL_HS_CERT_VERIFY:
                if (state_ != HsState::kWaitCertVerify) break;
                state_ = HsState::kWaitServerFinished;
                return true;
            case SL_HS_FINISHED:
                if (state_ != HsState::kWaitServerFinished) break;
                /* After receiving server Finished, client must send its own. */
                return true;
            default: break;
        }
        fail("unexpected_client_recv");
        return false;
    }

    /* Server */
    switch (type) {
        case SL_HS_CLIENT_HELLO:
            if (state_ != HsState::kWaitClientHello) break;
            return true;
        case SL_HS_FINISHED:
            if (state_ != HsState::kWaitClientFinished) break;
            state_ = HsState::kDone;
            return true;
        default: break;
    }
    fail("unexpected_server_recv");
    return false;
}

void HandshakeState::fail(const char* reason) {
    state_ = HsState::kFailed;
    failure_reason_ = reason ? reason : "unknown";
}

}  // namespace securelink
