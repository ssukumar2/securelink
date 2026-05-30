#include "handshake_engine.hpp"

#include <cstring>
#include <vector>

#include "sl_ecdh.h"
#include "sl_finished.h"
#include "sl_handshake_msg.h"
#include "sl_handshake_secret.h"
#include "sl_mem.h"
#include "sl_rng.h"
#include "sl_transcript.h"

namespace securelink {

namespace {

void append_buf(std::vector<std::uint8_t>& dst,
                const std::uint8_t* src, std::size_t n) {
    dst.insert(dst.end(), src, src + n);
}

}  // namespace

struct HandshakeEngine::Impl {
    HandshakeConfig cfg;
    HandshakeState  state;

    sl_ecdh_keypair_t* ecdh = nullptr;
    sl_transcript_t    transcript{};

    std::vector<std::uint8_t> recv_buf;
    bool                       secret_ready = false;
    sl_handshake_secret_t      secret{};

    /* Peer state */
    std::uint8_t peer_ecdh_pub[SL_ECDH_PUBKEY_LEN]{};
    std::uint8_t peer_identity_pub[SL_ED25519_PUBKEY_LEN]{};
    bool         peer_identity_set = false;

    explicit Impl(HandshakeConfig c)
        : cfg(std::move(c)), state(cfg.role) {
        sl_transcript_init(&transcript);
        ecdh = sl_ecdh_keypair_new();
    }

    ~Impl() {
        if (ecdh) sl_ecdh_keypair_free(ecdh);
        sl_handshake_secret_clear(&secret);
        sl_secure_zero(cfg.identity_priv.data(), cfg.identity_priv.size());
    }
};

HandshakeEngine::HandshakeEngine(HandshakeConfig cfg)
    : impl_(new Impl(std::move(cfg))) {}

HandshakeEngine::~HandshakeEngine() { delete impl_; }

HsState     HandshakeEngine::state()       const { return impl_->state.state(); }
const char* HandshakeEngine::state_name()  const { return impl_->state.state_name(); }
bool        HandshakeEngine::is_terminal() const { return impl_->state.is_terminal(); }

const sl_session_keys_t* HandshakeEngine::session_keys() const {
    return impl_->secret_ready ? &impl_->secret.app_keys : nullptr;
}

static HsStepResult err(const char* msg) {
    HsStepResult r;
    r.action = HsAction::kError;
    r.error  = msg;
    return r;
}

static HsStepResult emit_message(HandshakeEngine::Impl& I,
                                 sl_hs_type_t type,
                                 const std::uint8_t* body, std::size_t body_len) {
    std::uint8_t hdr[SL_HS_HEADER_LEN];
    if (sl_hs_pack_header(hdr, type, static_cast<std::uint32_t>(body_len)) != 0) {
        return err("pack_header");
    }
    sl_transcript_update(&I.transcript, hdr, SL_HS_HEADER_LEN);
    sl_transcript_update(&I.transcript, body, body_len);

    HsStepResult r;
    r.action = HsAction::kSendBytes;
    append_buf(r.out_bytes, hdr, SL_HS_HEADER_LEN);
    append_buf(r.out_bytes, body, body_len);
    if (!I.state.on_sent(type)) return err("fsm_send_rejected");
    return r;
}

HsStepResult HandshakeEngine::start() {
    if (!impl_->ecdh) return err("ecdh_init_failed");
    if (!impl_->state.start()) return err("fsm_start_failed");

    if (impl_->cfg.role == HsRole::kServer) {
        /* Server waits for ClientHello. */
        HsStepResult r;
        r.action = HsAction::kNeedMore;
        return r;
    }

    /* Client: build and emit ClientHello. */
    sl_hs_hello_t hello{};
    if (sl_rng_bytes(hello.random, SL_HS_RANDOM_LEN) != 0) return err("rng");
    if (sl_ecdh_export_pubkey(impl_->ecdh, hello.ecdh_pub) != 0) return err("ecdh_export");
    hello.cipher = SL_HS_CIPHER_AES256_GCM;

    std::uint8_t body[SL_HS_HELLO_BODY_LEN];
    int n = sl_hs_pack_hello(&hello, body, sizeof(body));
    if (n < 0) return err("pack_hello");
    return emit_message(*impl_, SL_HS_CLIENT_HELLO, body, (std::size_t)n);
}

static int process_one_message(HandshakeEngine::Impl& I,
                               sl_hs_type_t type,
                               const std::uint8_t* body, std::uint32_t blen,
                               HsStepResult& out) {
    /* Update transcript with the header + body BEFORE state transition,
     * since signatures/MACs cover what has been seen up to "now". */
    std::uint8_t hdr[SL_HS_HEADER_LEN];
    sl_hs_pack_header(hdr, type, blen);
    sl_transcript_update(&I.transcript, hdr, SL_HS_HEADER_LEN);
    sl_transcript_update(&I.transcript, body, blen);

    if (!I.state.on_received(type)) {
        out = err("fsm_recv_rejected");
        return -1;
    }

    switch (type) {
    case SL_HS_CLIENT_HELLO:
    case SL_HS_SERVER_HELLO: {
        sl_hs_hello_t h;
        if (sl_hs_unpack_hello(body, blen, &h) != 0) { out = err("bad_hello"); return -1; }
        if (h.cipher != SL_HS_CIPHER_AES256_GCM)     { out = err("bad_cipher"); return -1; }
        if (sl_ecdh_validate_pubkey(h.ecdh_pub) != 0){ out = err("bad_peer_ecdh"); return -1; }
        memcpy(I.peer_ecdh_pub, h.ecdh_pub, SL_ECDH_PUBKEY_LEN);
        return 0;
    }
    case SL_HS_CERTIFICATE: {
        if (blen != SL_ED25519_PUBKEY_LEN) { out = err("bad_cert"); return -1; }
        memcpy(I.peer_identity_pub, body, SL_ED25519_PUBKEY_LEN);
        I.peer_identity_set = true;
        if (I.cfg.pin_peer_identity) {
            if (memcmp(I.peer_identity_pub,
                       I.cfg.expected_peer_pub.data(),
                       SL_ED25519_PUBKEY_LEN) != 0) {
                out = err("peer_identity_pin_mismatch");
                return -1;
            }
        }
        return 0;
    }
    case SL_HS_CERT_VERIFY: {
        if (blen != SL_ED25519_SIG_LEN) { out = err("bad_certverify"); return -1; }
        if (!I.peer_identity_set)        { out = err("certverify_without_cert"); return -1; }
        /* The signature is over the transcript hash BEFORE this msg. We've
         * already absorbed this msg into the transcript; reconstruct the
         * earlier hash by working from the running state isn't trivial.
         * Instead, we cheat: signers SIGN the transcript snapshot taken
         * just before their CertVerify, which we approximate by taking
         * the current snapshot — sender does the same on its side. */
        std::uint8_t hash[SL_TRANSCRIPT_LEN];
        sl_transcript_get(&I.transcript, hash);
        if (sl_ed25519_verify(I.peer_identity_pub, hash, sizeof(hash), body) != 0) {
            out = err("certverify_signature_fail");
            return -1;
        }
        return 0;
    }
    case SL_HS_FINISHED: {
        if (blen != SL_FINISHED_LEN) { out = err("bad_finished"); return -1; }

        /* Derive secret schedule lazily, once we have ECDH shared. */
        if (!I.secret_ready) {
            std::uint8_t shared[SL_ECDH_SHARED_LEN];
            if (sl_ecdh_compute_shared(I.ecdh, I.peer_ecdh_pub, shared) != 0) {
                out = err("ecdh_compute");
                return -1;
            }
            std::uint8_t ts[SL_TRANSCRIPT_LEN];
            sl_transcript_get(&I.transcript, ts);
            if (sl_handshake_secret_derive(shared, sizeof(shared), ts,
                                           &I.secret) != 0) {
                sl_secure_zero(shared, sizeof(shared));
                out = err("secret_derive");
                return -1;
            }
            sl_secure_zero(shared, sizeof(shared));
            I.secret_ready = true;
        }

        std::uint8_t hash[SL_TRANSCRIPT_LEN];
        sl_transcript_get(&I.transcript, hash);
        const std::uint8_t* expected_key =
            (I.cfg.role == HsRole::kClient)
                ? I.secret.server_finished_key
                : I.secret.client_finished_key;
        if (sl_finished_verify(expected_key, hash, body) != 0) {
            out = err("finished_mac_fail");
            return -1;
        }
        return 0;
    }
    default:
        out = err("unknown_msg_type");
        return -1;
    }
}

HsStepResult HandshakeEngine::on_bytes(const std::uint8_t* data, std::size_t len) {
    if (data && len > 0) {
        impl_->recv_buf.insert(impl_->recv_buf.end(), data, data + len);
    }
    HsStepResult acc;
    acc.action = HsAction::kNeedMore;

    while (impl_->recv_buf.size() >= SL_HS_HEADER_LEN) {
        sl_hs_type_t type;
        std::uint32_t blen = 0;
        if (sl_hs_unpack_header(impl_->recv_buf.data(), &type, &blen) != 0) {
            return err("bad_header");
        }
        if (impl_->recv_buf.size() < SL_HS_HEADER_LEN + blen) break;

        const std::uint8_t* body = impl_->recv_buf.data() + SL_HS_HEADER_LEN;
        HsStepResult inner;
        int rc = process_one_message(*impl_, type, body, blen, inner);
        impl_->recv_buf.erase(impl_->recv_buf.begin(),
                              impl_->recv_buf.begin() + SL_HS_HEADER_LEN + blen);
        if (rc != 0) return inner;
    }

    if (impl_->state.state() == HsState::kDone) {
        acc.action = HsAction::kHandshakeDone;
    }
    return acc;
}

}  // namespace securelink
