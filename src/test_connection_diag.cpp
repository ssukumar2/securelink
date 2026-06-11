// Tests for ConnectionDiag.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_connection_diag.cpp src/connection_diag.cpp \
//       src/sl_diag_code.c \
//       -lpthread -o test_connection_diag

#include <cstdio>
#include <sstream>

#include "connection_diag.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_records_and_returns_last_code(void) {
    ConnectionDiag d(42, "10.0.0.1:4443");
    CHECK(d.last_code() == SL_DIAG_OK);
    CHECK(d.entry_count() == 0);

    d.record(SL_DIAG_BAD_MAC, "frame 12");
    d.record(SL_DIAG_DECRYPT_FAIL, "");
    CHECK(d.entry_count() == 2);
    CHECK(d.last_code() == SL_DIAG_DECRYPT_FAIL);
    return 0;
}

static int test_summary_contains_key_fields(void) {
    ConnectionDiag d(7, "peer-x");
    d.set_negotiated_version(0x0100);
    d.set_negotiated_cipher (0x0001);
    d.record(SL_DIAG_REPLAY, "seq=99");
    const auto s = d.summary();
    CHECK(s.find("conn=7")   != std::string::npos);
    CHECK(s.find("peer-x")   != std::string::npos);
    CHECK(s.find("version=0x100") != std::string::npos);
    CHECK(s.find("cipher=0x1")    != std::string::npos);
    CHECK(s.find("replay")    != std::string::npos);
    CHECK(s.find("seq=99")    != std::string::npos);
    return 0;
}

static int test_render_lists_entries(void) {
    ConnectionDiag d(1, "p");
    d.record(SL_DIAG_RATE_LIMITED, "ip exceeded");
    d.record(SL_DIAG_LOCKED_OUT,   "3 strikes");
    std::ostringstream oss;
    d.render(oss);
    const auto text = oss.str();
    CHECK(text.find("rate_limited") != std::string::npos);
    CHECK(text.find("locked_out")   != std::string::npos);
    CHECK(text.find("ip exceeded")  != std::string::npos);
    /* Category prefix should be present. */
    CHECK(text.find("policy/")      != std::string::npos);
    return 0;
}

static int test_peer_label_update(void) {
    ConnectionDiag d(1, "");
    d.set_peer_label("alice");
    const auto s = d.summary();
    CHECK(s.find("peer=alice") != std::string::npos);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_records_and_returns_last_code();
    rc |= test_summary_contains_key_fields();
    rc |= test_render_lists_entries();
    rc |= test_peer_label_update();
    if (rc == 0) std::puts("test_connection_diag: OK");
    return rc;
}
