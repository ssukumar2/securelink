// Tests for HandshakeState transitions on client and server sides.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_handshake_state.cpp src/handshake_state.cpp \
//       -o test_handshake_state

#include <cstdio>
#include <string>

#include "handshake_state.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_client_happy_path(void) {
    HandshakeState c(HsRole::kClient);
    CHECK(c.start());
    CHECK(c.on_sent    (SL_HS_CLIENT_HELLO));
    CHECK(c.on_received(SL_HS_SERVER_HELLO));
    CHECK(c.on_received(SL_HS_CERTIFICATE));
    CHECK(c.on_received(SL_HS_CERT_VERIFY));
    CHECK(c.on_received(SL_HS_FINISHED));
    CHECK(c.on_sent    (SL_HS_FINISHED));
    CHECK(c.state() == HsState::kDone);
    CHECK(c.is_terminal());
    return 0;
}

static int test_server_happy_path(void) {
    HandshakeState s(HsRole::kServer);
    CHECK(s.start());
    CHECK(s.on_received(SL_HS_CLIENT_HELLO));
    CHECK(s.on_sent    (SL_HS_SERVER_HELLO));
    CHECK(s.on_sent    (SL_HS_CERTIFICATE));
    CHECK(s.on_sent    (SL_HS_CERT_VERIFY));
    CHECK(s.on_sent    (SL_HS_FINISHED));
    CHECK(s.on_received(SL_HS_FINISHED));
    CHECK(s.state() == HsState::kDone);
    return 0;
}

static int test_client_rejects_out_of_order(void) {
    HandshakeState c(HsRole::kClient);
    c.start();
    c.on_sent(SL_HS_CLIENT_HELLO);
    /* Expect ServerHello next; sending CERT_VERIFY first must fail. */
    CHECK(!c.on_received(SL_HS_CERT_VERIFY));
    CHECK(c.state() == HsState::kFailed);
    return 0;
}

static int test_server_rejects_unexpected_first(void) {
    HandshakeState s(HsRole::kServer);
    s.start();
    CHECK(!s.on_received(SL_HS_FINISHED));
    CHECK(s.state() == HsState::kFailed);
    return 0;
}

static int test_no_events_after_terminal(void) {
    HandshakeState s(HsRole::kServer);
    s.start();
    s.on_received(SL_HS_CLIENT_HELLO);
    s.on_sent    (SL_HS_SERVER_HELLO);
    s.on_sent    (SL_HS_CERTIFICATE);
    s.on_sent    (SL_HS_CERT_VERIFY);
    s.on_sent    (SL_HS_FINISHED);
    s.on_received(SL_HS_FINISHED);
    CHECK(s.is_terminal());
    CHECK(!s.on_received(SL_HS_CLIENT_HELLO));
    return 0;
}

static int test_fail_is_sticky(void) {
    HandshakeState c(HsRole::kClient);
    c.start();
    c.fail("test_reason");
    CHECK(c.state() == HsState::kFailed);
    CHECK(c.failure_reason() == std::string("test_reason"));
    CHECK(!c.on_sent(SL_HS_CLIENT_HELLO));
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_client_happy_path();
    rc |= test_server_happy_path();
    rc |= test_client_rejects_out_of_order();
    rc |= test_server_rejects_unexpected_first();
    rc |= test_no_events_after_terminal();
    rc |= test_fail_is_sticky();
    if (rc == 0) std::puts("test_handshake_state: OK");
    return rc;
}
