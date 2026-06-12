#pragma once
// RpcDispatcher — server-side method table + handler invocation.
//
// Applications register named handlers; the dispatcher decodes incoming
// request bytes, calls the matching handler, and encodes the response.
// Unknown methods return SL_RPC_NOT_FOUND without invoking anything.

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "sl_rpc_msg.h"

namespace securelink {

struct RpcResponse {
    sl_rpc_status_t           status = SL_RPC_OK;
    std::vector<std::uint8_t> body;
};

using RpcHandler = std::function<RpcResponse(const std::vector<std::uint8_t>&)>;

class RpcDispatcher {
public:
    void register_method(const std::string& method, RpcHandler handler);
    void unregister_method(const std::string& method);

    // Decode `request_bytes`, dispatch, encode reply. Returns encoded
    // response bytes (always non-empty on success or error).
    std::vector<std::uint8_t> handle(const std::vector<std::uint8_t>& request_bytes);

    std::size_t method_count() const;

    struct Stats {
        std::uint64_t requests_total   = 0;
        std::uint64_t responses_ok     = 0;
        std::uint64_t responses_error  = 0;
        std::uint64_t method_not_found = 0;
        std::uint64_t handler_threw    = 0;
    };

    Stats stats() const;

private:
    std::vector<std::uint8_t> make_response(std::uint32_t req_id,
                                            const RpcResponse& r) const;

    mutable std::mutex                                mu_;
    std::unordered_map<std::string, RpcHandler>       methods_;
    Stats                                             stats_;
};

}  // namespace securelink
