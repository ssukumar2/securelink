#include "rpc_client.hpp"

#include <cstring>

#include "sl_deadline.h"
#include "sl_rpc_method.h"

namespace securelink {

RpcClient::RpcClient(RpcSendFn send_fn) : send_fn_(std::move(send_fn)) {
    sl_rpc_id_init(&ids_);
}

RpcClient::~RpcClient() {
    cancel_all(SL_RPC_UNAVAILABLE);
}

std::future<RpcReply> RpcClient::call(const std::string& method,
                                      std::vector<std::uint8_t> body,
                                      std::uint32_t timeout_ms) {
    std::promise<RpcReply> p;
    auto fut = p.get_future();

    /* Validate method name before allocating an ID. */
    if (!sl_rpc_method_is_valid(method.c_str(), method.size())) {
        RpcReply r;
        r.status = SL_RPC_BAD_REQUEST;
        p.set_value(std::move(r));
        return fut;
    }
    if (body.size() > SL_RPC_BODY_MAX) {
        RpcReply r;
        r.status = SL_RPC_BAD_REQUEST;
        p.set_value(std::move(r));
        return fut;
    }

    std::uint32_t id = 0;
    std::vector<std::uint8_t> wire;
    {
        std::lock_guard<std::mutex> lock(mu_);
        id = sl_rpc_id_next(&ids_);
        if (id == SL_RPC_ID_RESERVED) {
            RpcReply r;
            r.status = SL_RPC_UNAVAILABLE;
            p.set_value(std::move(r));
            return fut;
        }

        sl_rpc_request_t req{};
        req.request_id = id;
        std::memcpy(req.method, method.data(), method.size());
        req.method_len = (std::uint16_t)method.size();
        req.body       = body.empty() ? nullptr : body.data();
        req.body_len   = (std::uint32_t)body.size();

        wire.resize(12 + method.size() + body.size());
        int n = sl_rpc_request_pack(&req, wire.data(), wire.size());
        if (n < 0) {
            RpcReply r;
            r.status = SL_RPC_BAD_REQUEST;
            p.set_value(std::move(r));
            return fut;
        }
        wire.resize((std::size_t)n);

        Pending pend;
        pend.promise     = std::move(p);
        pend.deadline_ms = (timeout_ms > 0) ? sl_deadline_in_ms(timeout_ms) : 0;
        pending_.emplace(id, std::move(pend));
        ++stats_.calls_started;
    }

    /* Drop the lock before the send so a slow send doesn't block matching. */
    const bool sent = send_fn_ ? send_fn_(wire) : false;
    if (!sent) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = pending_.find(id);
        if (it != pending_.end()) {
            RpcReply r;
            r.status = SL_RPC_UNAVAILABLE;
            it->second.promise.set_value(std::move(r));
            pending_.erase(it);
            ++stats_.send_failures;
        }
    }
    return fut;
}

bool RpcClient::on_response(const std::vector<std::uint8_t>& wire_bytes) {
    sl_rpc_response_t resp{};
    if (sl_rpc_response_unpack(wire_bytes.data(), wire_bytes.size(), &resp) != 0) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.unmatched;
        return false;
    }

    Pending p;
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = pending_.find(resp.request_id);
        if (it == pending_.end()) {
            ++stats_.unmatched;
            return false;
        }
        p = std::move(it->second);
        pending_.erase(it);
        ++stats_.responses_matched;
    }

    RpcReply r;
    r.status = resp.status;
    if (resp.body_len > 0) {
        r.body.assign(resp.body, resp.body + resp.body_len);
    }
    p.promise.set_value(std::move(r));
    return true;
}

std::size_t RpcClient::sweep_timeouts() {
    std::vector<Pending> expired;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto it = pending_.begin(); it != pending_.end(); ) {
            if (it->second.deadline_ms != 0 &&
                sl_deadline_expired(it->second.deadline_ms)) {
                expired.push_back(std::move(it->second));
                it = pending_.erase(it);
                ++stats_.timeouts;
            } else {
                ++it;
            }
        }
    }
    for (auto& p : expired) {
        RpcReply r;
        r.status = SL_RPC_UNAVAILABLE;
        r.timed_out = true;
        p.promise.set_value(std::move(r));
    }
    return expired.size();
}

void RpcClient::cancel_all(sl_rpc_status_t status) {
    std::vector<Pending> all;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& [_, p] : pending_) all.push_back(std::move(p));
        stats_.cancellations += pending_.size();
        pending_.clear();
    }
    for (auto& p : all) {
        RpcReply r;
        r.status = status;
        p.promise.set_value(std::move(r));
    }
}

std::size_t RpcClient::pending_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return pending_.size();
}

RpcClient::Stats RpcClient::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    return stats_;
}

}  // namespace securelink
