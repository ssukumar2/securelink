#include "rpc_dispatcher.hpp"

#include <cstring>

namespace securelink {

void RpcDispatcher::register_method(const std::string& method, RpcHandler h) {
    std::lock_guard<std::mutex> lock(mu_);
    methods_[method] = std::move(h);
}

void RpcDispatcher::unregister_method(const std::string& method) {
    std::lock_guard<std::mutex> lock(mu_);
    methods_.erase(method);
}

std::size_t RpcDispatcher::method_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return methods_.size();
}

RpcDispatcher::Stats RpcDispatcher::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    return stats_;
}

std::vector<std::uint8_t> RpcDispatcher::make_response(
    std::uint32_t req_id, const RpcResponse& r) const {
    sl_rpc_response_t resp{};
    resp.request_id = req_id;
    resp.status     = r.status;
    resp.body       = r.body.empty() ? nullptr : r.body.data();
    resp.body_len   = (std::uint32_t)r.body.size();

    std::vector<std::uint8_t> out(12 + r.body.size());
    int n = sl_rpc_response_pack(&resp, out.data(), out.size());
    if (n < 0) {
        out.clear();
        return out;
    }
    out.resize((std::size_t)n);
    return out;
}

std::vector<std::uint8_t> RpcDispatcher::handle(
    const std::vector<std::uint8_t>& request_bytes) {
    sl_rpc_request_t req{};
    if (sl_rpc_request_unpack(request_bytes.data(), request_bytes.size(),
                              &req) != 0) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.requests_total;
        ++stats_.responses_error;
        RpcResponse r; r.status = SL_RPC_BAD_REQUEST;
        return make_response(0, r);
    }

    RpcHandler handler;
    {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.requests_total;
        auto it = methods_.find(req.method);
        if (it == methods_.end()) {
            ++stats_.method_not_found;
            ++stats_.responses_error;
            RpcResponse r; r.status = SL_RPC_NOT_FOUND;
            return make_response(req.request_id, r);
        }
        handler = it->second;
    }

    std::vector<std::uint8_t> body;
    if (req.body_len > 0) {
        body.assign(req.body, req.body + req.body_len);
    }

    RpcResponse result;
    try {
        result = handler(body);
    } catch (const std::exception&) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.handler_threw;
        ++stats_.responses_error;
        result.status = SL_RPC_INTERNAL;
        result.body.clear();
    } catch (...) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.handler_threw;
        ++stats_.responses_error;
        result.status = SL_RPC_INTERNAL;
        result.body.clear();
    }

    {
        std::lock_guard<std::mutex> lock(mu_);
        if (result.status == SL_RPC_OK) ++stats_.responses_ok;
        else                            ++stats_.responses_error;
    }
    return make_response(req.request_id, result);
}

}  // namespace securelink
