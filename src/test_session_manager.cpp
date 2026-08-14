// Tests for SessionManager.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_session_manager.cpp src/session_manager.cpp \
//       src/sl_session_ticket.c src/sl_aead.c src/sl_mem.c src/sl_rng.c \
//       -lcrypto -lpthread -o test_session_manager

#include <array>
#include <chrono>
#include <cstdio>
#include <thread>

#include "session_manager.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static std::array<std::uint8_t, 32> make_identity(std::uint8_t seed) {
    std::array<std::uint8_t, 32> a{};
    for (auto& b : a) b = seed;
    return a;
}

static int test_register_and_snapshot(void) {
    SessionManagerConfig c;
    SessionManager mgr(c);
    auto id = mgr.register_session("alice", make_identity(1));
    CHECK(id > 0);
    CHECK(mgr.active_count() == 1);

    auto snap = mgr.snapshot(id);
    CHECK(snap.has_value());
    CHECK(snap->peer_label == "alice");
    CHECK(snap->authenticated);
    return 0;
}

static int test_rekey_trigger_by_bytes(void) {
    SessionManagerConfig c;
    c.rekey_after_bytes = 100;
    SessionManager mgr(c);
    auto id = mgr.register_session("bob", make_identity(2));

    CHECK(mgr.record_traffic(id, 40, 0) == false);
    CHECK(mgr.record_traffic(id, 30, 0) == false);
    CHECK(mgr.record_traffic(id, 50, 0) == true);   /* 120 >= 100 */
    return 0;
}

static int test_rekey_counters(void) {
    SessionManager mgr(SessionManagerConfig{});
    auto id = mgr.register_session("c", make_identity(3));
    mgr.note_rekey_local(id);
    mgr.note_rekey_local(id);
    mgr.note_rekey_peer(id);
    auto s = mgr.snapshot(id);
    CHECK(s->stats.rekeys_local == 2);
    CHECK(s->stats.rekeys_peer  == 1);
    return 0;
}

static int test_ticket_roundtrip(void) {
    SessionManager mgr(SessionManagerConfig{});
    auto id = mgr.register_session("d", make_identity(4));

    SessionManager::SessionTicketKey stk{}; stk.bytes[0] = 0xAA;
    SessionManager::ResumptionSecret rs{};  for (int i = 0; i < 32; ++i) rs.bytes[i] = (uint8_t)i;

    auto wire = mgr.issue_ticket(id, stk, rs);
    CHECK(!wire.empty());
    CHECK(wire.size() == SL_TICKET_TOTAL_LEN);

    auto opened = mgr.consume_ticket(stk, wire);
    CHECK(opened.has_value());
    return 0;
}

static int test_sweep_idle(void) {
    SessionManagerConfig c;
    c.idle_timeout_seconds = 0;   // immediate
    SessionManager mgr(c);
    mgr.register_session("e", make_identity(5));
    mgr.register_session("f", make_identity(6));
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK(mgr.sweep() == 2);
    CHECK(mgr.active_count() == 0);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_register_and_snapshot();
    rc |= test_rekey_trigger_by_bytes();
    rc |= test_rekey_counters();
    rc |= test_ticket_roundtrip();
    rc |= test_sweep_idle();
    if (rc == 0) std::puts("test_session_manager: OK");
    return rc;
}
