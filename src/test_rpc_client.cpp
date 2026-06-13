// Tests for RpcClient.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_rpc_client.cpp src/rpc_client.cpp \
//       src/sl_rpc_msg.c src/sl_rpc_id.c src/sl_rpc_method.c \
//       src/sl_deadline.c \
//       -lpthread -o test_rpc_client

#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#include "rpc_client.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

/* Build a fake response wire matching a given request id. */
static std::vector<std::uint8_t> make_response(std::uint32_t id,
                                               sl_rpc_status_t status,
                                               const std::vector<std::uint8_t>& body) {
    sl_rpc_response_t r{};
    r.request_id = id;
    r.status     = status;
    r.body       = body.empty() ? nullptr : body.data();
    r.body_len   = (std::uint32_t)body.size();
    std::vector<std::uint8_t> out(12 + body.size());
    int n = sl_rpc_response_pack(&r, out.data(), out.size());
    out.resize((std::size_t)n);
    return out;
}

static int test_happy_path(void) {
    std::vector<std::uint8_t> last_sent;
    auto send = [&](const std::vector<std::uint8_t>& bytes) {
        last_sent = bytes;
        return true;
    };
    RpcClient client(send);

    auto fut = client.call("echo", {'h', 'i'}, 1000);
    CHECK(!last_sent.empty());

    /* Decode the request the client sent and respond with the same id. */
    sl_rpc_request_t req{};
    CHECK(sl_rpc_request_unpack(last_sent.data(), last_sent.size(), &req) == 0);
    auto resp = make_response(req.request_id, SL_RPC_OK,
                              std::vector<std::uint8_t>{'O', 'K'});
    CHECK(client.on_response(resp));

    auto reply = fut.get();
    CHECK(reply.status == SL_RPC_OK);
    CHECK(reply.body.size() == 2);
    CHECK(reply.body[0] == 'O' && reply.body[1] == 'K');
    CHECK(!reply.timed_out);
    return 0;
}

static int test_timeout_via_sweep(void) {
    auto send = [](const std::vector<std::uint8_t>&) { return true; };
    RpcClient client(send);

    auto fut = client.call("slow", {}, 1);          /* 1 ms timeout */
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK(client.sweep_timeouts() == 1);

    auto reply = fut.get();
    CHECK(reply.timed_out);
    CHECK(reply.status == SL_RPC_UNAVAILABLE);
    return 0;
}

static int test_send_failure_fails_immediately(void) {
    auto send = [](const std::vector<std::uint8_t>&) { return false; };
    RpcClient client(send);

    auto fut = client.call("nope", {}, 5000);
    auto reply = fut.get();
    CHECK(reply.status == SL_RPC_UNAVAILABLE);
    CHECK(!reply.timed_out);
    CHECK(client.stats().send_failures == 1);
    return 0;
}

static int test_invalid_method_rejected(void) {
    auto send = [](const std::vector<std::uint8_t>&) { return true; };
    RpcClient client(send);

    auto fut = client.call("bad method", {}, 5000);
    auto reply = fut.get();
    CHECK(reply.status == SL_RPC_BAD_REQUEST);
    /* No call should be in flight. */
    CHECK(client.pending_count() == 0);
    return 0;
}

static int test_unmatched_response_ignored(void) {
    auto send = [](const std::vector<std::uint8_t>&) { return true; };
    RpcClient client(send);

    auto bogus = make_response(9999, SL_RPC_OK, {});
    CHECK(!client.on_response(bogus));
    CHECK(client.stats().unmatched == 1);
    return 0;
}

static int test_cancel_all_resolves_pending(void) {
    auto send = [](const std::vector<std::uint8_t>&) { return true; };
    RpcClient client(send);

    auto f1 = client.call("a", {}, 60000);
    auto f2 = client.call("b", {}, 60000);
    CHECK(client.pending_count() == 2);

    client.cancel_all(SL_RPC_UNAVAILABLE);
    CHECK(client.pending_count() == 0);

    CHECK(f1.get().status == SL_RPC_UNAVAILABLE);
    CHECK(f2.get().status == SL_RPC_UNAVAILABLE);
    CHECK(client.stats().cancellations == 2);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_happy_path();
    rc |= test_timeout_via_sweep();
    rc |= test_send_failure_fails_immediately();
    rc |= test_invalid_method_rejected();
    rc |= test_unmatched_response_ignored();
    rc |= test_cancel_all_resolves_pending();
    if (rc == 0) std::puts("test_rpc_client: OK");
    return rc;
}
