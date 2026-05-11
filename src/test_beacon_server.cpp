// Tests for BeaconServer: acceptance, replay rejection, auth failure,
// liveness reaping.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_beacon_server.cpp src/beacon_server.cpp \
//       src/sl_beacon.c src/sl_beacon_codec.c src/sl_aead.c \
//       src/sl_mem.c src/sl_nonce.c src/sl_rng.c src/sl_clock.c \
//       -lcrypto -lpthread -o test_beacon_server

#include <cstdio>
#include <cstring>
#include <vector>

#include "beacon_server.hpp"
#include "sl_beacon.h"
#include "sl_beacon_codec.h"
#include "sl_clock.h"
#include "sl_rng.h"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static std::vector<std::uint8_t> make_wire(const std::uint8_t* key,
                                           const std::uint8_t* iv,
                                           std::uint64_t client_id,
                                           std::uint64_t seq,
                                           std::uint64_t ts_ms) {
    sl_beacon_t b{};
    b.client_id    = client_id;
    b.sequence     = seq;
    b.timestamp_ms = ts_ms;
    b.interval_ms  = 1000;
    b.flags        = 0;
    b.payload_len  = 0;

    std::vector<std::uint8_t> wire(sl_beacon_wire_size(&b));
    std::size_t wire_len = 0;
    if (sl_beacon_seal(&b, key, iv, seq, wire.data(), &wire_len) != 0) {
        return {};
    }
    wire.resize(wire_len);
    return wire;
}

static int test_accept_and_replay(void) {
    BeaconServerConfig cfg;
    cfg.max_skew_ms = 60000;
    sl_rng_init();
    sl_rng_bytes(cfg.key, sizeof(cfg.key));
    sl_rng_bytes(cfg.static_iv, sizeof(cfg.static_iv));

    BeaconServer srv(cfg);

    const std::uint64_t now = sl_clock_wall_ms();
    auto w1 = make_wire(cfg.key, cfg.static_iv, 100, 1, now);
    CHECK(!w1.empty());
    CHECK(srv.on_beacon(w1.data(), w1.size()) == BeaconResult::kAccepted);

    auto w2 = make_wire(cfg.key, cfg.static_iv, 100, 2, now);
    CHECK(srv.on_beacon(w2.data(), w2.size()) == BeaconResult::kAccepted);

    // Replay seq=1
    CHECK(srv.on_beacon(w1.data(), w1.size()) == BeaconResult::kReplay);

    auto snap = srv.snapshot(100);
    CHECK(snap.has_value());
    CHECK(snap->beacons_received == 2);
    CHECK(snap->replays_rejected == 1);
    CHECK(snap->last_seq == 2);
    CHECK(snap->alive == true);
    return 0;
}

static int test_auth_failure(void) {
    BeaconServerConfig cfg;
    cfg.max_skew_ms = 60000;
    sl_rng_init();
    sl_rng_bytes(cfg.key, sizeof(cfg.key));
    sl_rng_bytes(cfg.static_iv, sizeof(cfg.static_iv));

    BeaconServer srv(cfg);
    auto w = make_wire(cfg.key, cfg.static_iv, 7, 1, sl_clock_wall_ms());
    CHECK(!w.empty());
    // Corrupt the ciphertext/tag region.
    w[w.size() - 1] ^= 0x01;
    CHECK(srv.on_beacon(w.data(), w.size()) == BeaconResult::kAuthFailed);

    auto snap = srv.snapshot(7);
    CHECK(snap.has_value());
    CHECK(snap->auth_failures == 1);
    CHECK(snap->beacons_received == 0);
    return 0;
}

static int test_clock_skew_rejected(void) {
    BeaconServerConfig cfg;
    cfg.max_skew_ms = 1000;  // 1 second window
    sl_rng_init();
    sl_rng_bytes(cfg.key, sizeof(cfg.key));
    sl_rng_bytes(cfg.static_iv, sizeof(cfg.static_iv));

    BeaconServer srv(cfg);
    const std::uint64_t way_off = sl_clock_wall_ms() + 10ULL * 60ULL * 1000ULL;
    auto w = make_wire(cfg.key, cfg.static_iv, 9, 1, way_off);
    CHECK(srv.on_beacon(w.data(), w.size()) == BeaconResult::kClockSkew);
    return 0;
}

static int test_liveness_reap(void) {
    BeaconServerConfig cfg;
    cfg.liveness_timeout_ms = 1;  // 1 ms — anything goes stale immediately
    cfg.max_skew_ms = 60000;
    sl_rng_init();
    sl_rng_bytes(cfg.key, sizeof(cfg.key));
    sl_rng_bytes(cfg.static_iv, sizeof(cfg.static_iv));

    BeaconServer srv(cfg);
    auto w = make_wire(cfg.key, cfg.static_iv, 200, 1, sl_clock_wall_ms());
    CHECK(srv.on_beacon(w.data(), w.size()) == BeaconResult::kAccepted);
    sl_clock_sleep_ms(10);

    CHECK(srv.reap_stale() == 1);
    auto snap = srv.snapshot(200);
    CHECK(snap.has_value());
    CHECK(snap->alive == false);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_accept_and_replay();
    rc |= test_auth_failure();
    rc |= test_clock_skew_rejected();
    rc |= test_liveness_reap();
    if (rc == 0) std::puts("test_beacon_server: OK");
    return rc;
}
