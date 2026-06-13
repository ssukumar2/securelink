#pragma once
// RpcClient — client-side companion to RpcDispatcher.
//
// Lifecycle:
//   RpcClient c(send_fn);             // caller supplies an outbound sink
//   auto fut = c.call("fs.read", body, timeout_ms);
//   c.on_response(wire_bytes);        // pump inbound bytes as they arrive
//   auto resp = fut.get();            // blocks until response or timeout
//
// Threading: call() and on_response() are safe from different threads.
// `send_fn` is invoked under the client's mutex; keep it non-blocking
// (e.g. push onto a queue that another thread drains).

#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "sl_rpc_id.h"
#include "sl_rpc_msg.h"

namespace securelink {

struct RpcReply {
    sl_rpc_status_t           status = SL_RPC_OK;
    std::vector<std::uint8_t> body;
    bool                      timed_out = false;
};

using RpcSendFn = std::function<bool(const std::vector<std::uint8_t>&)>;

class RpcClient {
public:
    explicit RpcClient(RpcSendFn send_fn);
    ~RpcClient();

    RpcClient(const RpcClient&)            = delete;
    RpcClient& operator=(const RpcClient&) = delete;

    // Initiate a call. Returns a future that resolves when a matching
    // response arrives or the timeout fires. timeout_ms == 0 disables
    // the timeout (caller must still cancel on shutdown).
    std::future<RpcReply> call(const std::string& method,
                               std::vector<std::uint8_t> body,
                               std::uint32_t timeout_ms = 5000);

    // Feed inbound wire bytes (one encoded response). Matches against
    // pending requests and resolves the corresponding future.
    bool on_response(const std::vector<std::uint8_t>& wire_bytes);

    // Sweep expired calls and resolve them with timed_out=true.
    // Returns number of calls resolved this way.
    std::size_t sweep_timeouts();

    // Cancel all pending calls (e.g. on session teardown).
    void cancel_all(sl_rpc_status_t status = SL_RPC_UNAVAILABLE);

    std::size_t pending_count() const;

    struct Stats {
        std::uint64_t calls_started     = 0;
        std::uint64_t responses_matched = 0;
        std::uint64_t timeouts          = 0;
        std::uint64_t cancellations     = 0;
        std::uint64_t send_failures     = 0;
        std::uint64_t unmatched         = 0;
    };
    Stats stats() const;

private:
    struct Pending {
        std::promise<RpcReply> promise;
        std::uint64_t          deadline_ms = 0;
    };

    RpcSendFn          send_fn_;
    sl_rpc_id_alloc_t  ids_{};
    mutable std::mutex mu_;
    std::unordered_map<std::uint32_t, Pending> pending_;
    Stats              stats_;
};

}  // namespace securelink
