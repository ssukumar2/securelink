// Tests for ConnectionState transitions.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_connection_state.cpp src/connection_state.cpp \
//       -o test_connection_state

#include <cstdio>

#include "connection_state.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_happy_path(void) {
    ConnectionState c;
    CHECK(c.state() == ConnState::kFresh);
    CHECK(c.on_event(ConnEvent::kStartHandshake));
    CHECK(c.state() == ConnState::kHandshaking);
    CHECK(c.on_event(ConnEvent::kHandshakeDone));
    CHECK(c.state() == ConnState::kAuthenticated);
    CHECK(c.can_send_app());

    CHECK(c.on_event(ConnEvent::kRecvAppRecord));
    CHECK(c.on_event(ConnEvent::kSendAppRecord));
    CHECK(c.state() == ConnState::kAuthenticated);

    CHECK(c.on_event(ConnEvent::kBeginClose));
    CHECK(c.state() == ConnState::kClosing);
    CHECK(c.on_event(ConnEvent::kPeerClosed));
    CHECK(c.state() == ConnState::kClosed);
    CHECK(c.is_terminal());
    return 0;
}

static int test_handshake_failure(void) {
    ConnectionState c;
    c.on_event(ConnEvent::kStartHandshake);
    CHECK(c.on_event(ConnEvent::kHandshakeFailed));
    CHECK(c.state() == ConnState::kClosed);
    CHECK(!c.can_send_app());
    return 0;
}

static int test_app_before_handshake_invalid(void) {
    ConnectionState c;
    CHECK(!c.on_event(ConnEvent::kRecvAppRecord));   // illegal: fresh -> kClosed
    CHECK(c.state() == ConnState::kClosed);
    CHECK(c.invalid_transitions() == 1);
    return 0;
}

static int test_closed_is_terminal(void) {
    ConnectionState c;
    c.on_event(ConnEvent::kPeerClosed);
    CHECK(c.state() == ConnState::kClosed);
    CHECK(c.on_event(ConnEvent::kPeerClosed));       // no-op, valid
    CHECK(!c.on_event(ConnEvent::kStartHandshake));  // illegal once closed
    return 0;
}

static int test_io_error_closes(void) {
    ConnectionState c;
    c.on_event(ConnEvent::kStartHandshake);
    c.on_event(ConnEvent::kHandshakeDone);
    c.set_close_reason("read error");
    CHECK(c.on_event(ConnEvent::kIoError));
    CHECK(c.state() == ConnState::kClosed);
    CHECK(c.close_reason() == "read error");
    return 0;
}

static int test_drain_during_closing(void) {
    ConnectionState c;
    c.on_event(ConnEvent::kStartHandshake);
    c.on_event(ConnEvent::kHandshakeDone);
    c.on_event(ConnEvent::kBeginClose);
    CHECK(c.state() == ConnState::kClosing);
    CHECK(c.on_event(ConnEvent::kRecvAppRecord));   // drain inbound is OK
    CHECK(c.state() == ConnState::kClosing);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_happy_path();
    rc |= test_handshake_failure();
    rc |= test_app_before_handshake_invalid();
    rc |= test_closed_is_terminal();
    rc |= test_io_error_closes();
    rc |= test_drain_during_closing();
    if (rc == 0) std::puts("test_connection_state: OK");
    return rc;
}
