#pragma once
// HandshakeEngine — drives the cryptographic handshake by combining:
//   sl_ecdh           (key exchange)
//   sl_ed25519        (identity signature)
//   sl_transcript     (running SHA-256 of all handshake messages)
//   sl_finished       (handshake-completion MAC)
//   HandshakeState    (allowed-message ordering)
//
// The engine is single-step: feed it inbound bytes, get outbound bytes
// to send. It performs no I/O itself — that's the caller's job.

#include <array>
#include <cstdint>
#include <vector>

#include "handshake_state.hpp"
#include "sl_ed25519.h"
#include "sl_handshake_secret.h"

namespace securelink {

struct HandshakeConfig {
    HsRole role = HsRole::kClient;
    std::array<std::uint8_t, SL_ED25519_PRIVKEY_LEN> identity_priv{};
    std::array<std::uint8_t, SL_ED25519_PUBKEY_LEN>  identity_pub{};
    // Peer identity is optional. If empty the handshake accepts any signed
    // identity (TOFU mode); if set it must match the certificate received.
    std::array<std::uint8_t, SL_ED25519_PUBKEY_LEN>  expected_peer_pub{};
    bool pin_peer_identity = false;
};

enum class HsAction {
    kNeedMore,        // engine needs more inbound bytes to progress
    kSendBytes,       // engine produced bytes to send (in `out_bytes`)
    kHandshakeDone,   // session keys ready; pull via session_keys()
    kError,
};

struct HsStepResult {
    HsAction               action = HsAction::kNeedMore;
    std::vector<std::uint8_t> out_bytes;
    std::string            error;
};

class HandshakeEngine {
public:
    explicit HandshakeEngine(HandshakeConfig cfg);
    ~HandshakeEngine();

    HandshakeEngine(const HandshakeEngine&)            = delete;
    HandshakeEngine& operator=(const HandshakeEngine&) = delete;

    // Begin the handshake. For the client this immediately produces the
    // ClientHello bytes; for the server this just transitions state.
    HsStepResult start();

    // Feed inbound bytes from the wire. Engine may return any of the
    // HsAction values. Caller dispatches accordingly.
    HsStepResult on_bytes(const std::uint8_t* data, std::size_t len);

    // After kHandshakeDone, retrieve the negotiated session keys.
    const sl_session_keys_t* session_keys() const;

    // Diagnostic accessors.
    HsState        state() const;
    const char*    state_name() const;
    bool           is_terminal() const;

private:
    struct Impl;
    Impl* impl_;
};

}  // namespace securelink
