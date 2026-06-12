// Tests for RpcDispatcher.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_rpc_dispatcher.cpp src/rpc_dispatcher.cpp \
//       src/sl_rpc_msg.c -lpthread -o test_rpc_dispatcher

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

#include "rpc_dispatcher.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static std::vector<std::uint8_t> make_request(std::uint32_t id,
                                              const std::string& method,
                                              const std::string& body) {
    sl_rpc_request_t r{};
    r.request_id = id;
    std::memcpy(r.method, method.data(), method.size());
    r.method_len = (std::uint16_t)method.size();
    r.body       = reinterpret_cast<const std::uint8_t*>(body.data());
    r.body_len   = (std::uint32_t)body.size();
    std::vector<std::uint8_t> out(12 + method.size() + body.size());
    int n = sl_rpc_request_pack(&r, out.data(), out.size());
    out.resize((std::size_t)n);
    return out;
}

static int test_dispatch_ok(void) {
    RpcDispatcher d;
    d.register_method("echo", [](const std::vector<std::uint8_t>& body) {
        RpcResponse r;
        r.status = SL_RPC_OK;
        r.body   = body;
        return r;
    });

    auto req = make_request(42, "echo", "hello");
    auto resp_bytes = d.handle(req);

    sl_rpc_response_t out{};
    CHECK(sl_rpc_response_unpack(resp_bytes.data(), resp_bytes.size(), &out) == 0);
    CHECK(out.request_id == 42);
    CHECK(out.status == SL_RPC_OK);
    CHECK(out.body_len == 5);
    CHECK(std::memcmp(out.body, "hello", 5) == 0);
    return 0;
}

static int test_unknown_method(void) {
    RpcDispatcher d;
    auto req = make_request(7, "nope", "");
    auto resp_bytes = d.handle(req);

    sl_rpc_response_t out{};
    sl_rpc_response_unpack(resp_bytes.data(), resp_bytes.size(), &out);
    CHECK(out.status == SL_RPC_NOT_FOUND);
    CHECK(out.request_id == 7);
    CHECK(d.stats().method_not_found == 1);
    return 0;
}

static int test_handler_exception_returns_internal(void) {
    RpcDispatcher d;
    d.register_method("boom", [](const std::vector<std::uint8_t>&) -> RpcResponse {
        throw std::runtime_error("kaboom");
    });
    auto req = make_request(9, "boom", "");
    auto resp_bytes = d.handle(req);

    sl_rpc_response_t out{};
    sl_rpc_response_unpack(resp_bytes.data(), resp_bytes.size(), &out);
    CHECK(out.status == SL_RPC_INTERNAL);
    CHECK(d.stats().handler_threw == 1);
    return 0;
}

static int test_malformed_request_returns_bad_request(void) {
    RpcDispatcher d;
    std::vector<std::uint8_t> garbage{0x00, 0x00, 0x01, 0x02};
    auto resp_bytes = d.handle(garbage);

    sl_rpc_response_t out{};
    sl_rpc_response_unpack(resp_bytes.data(), resp_bytes.size(), &out);
    CHECK(out.status == SL_RPC_BAD_REQUEST);
    return 0;
}

static int test_unregister(void) {
    RpcDispatcher d;
    d.register_method("ping", [](auto) {
        RpcResponse r; r.status = SL_RPC_OK; return r;
    });
    CHECK(d.method_count() == 1);
    d.unregister_method("ping");
    CHECK(d.method_count() == 0);

    auto resp = d.handle(make_request(1, "ping", ""));
    sl_rpc_response_t out{};
    sl_rpc_response_unpack(resp.data(), resp.size(), &out);
    CHECK(out.status == SL_RPC_NOT_FOUND);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_dispatch_ok();
    rc |= test_unknown_method();
    rc |= test_handler_exception_returns_internal();
    rc |= test_malformed_request_returns_bad_request();
    rc |= test_unregister();
    if (rc == 0) std::puts("test_rpc_dispatcher: OK");
    return rc;
}
