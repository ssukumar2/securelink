#include "pubsub_client.hpp"

#include <cstring>

#include "sl_pubsub_msg.h"
#include "sl_topic.h"

namespace securelink {

PubSubClient::PubSubClient(PubSubSendFn send) : send_(std::move(send)) {}

static std::vector<std::uint8_t> pack(const sl_pubsub_msg_t& m) {
    std::vector<std::uint8_t> out(SL_PUBSUB_HEADER_LEN +
                                  m.topic_len + m.payload_len);
    int n = sl_pubsub_pack(&m, out.data(), out.size());
    if (n < 0) return {};
    out.resize((std::size_t)n);
    return out;
}

bool PubSubClient::subscribe(const std::string& filter, PubSubHandler handler) {
    if (!sl_topic_is_valid_filter(filter.c_str(), filter.size())) return false;
    sl_pubsub_msg_t m{};
    m.type      = SL_PUBSUB_SUBSCRIBE;
    m.topic     = filter.c_str();
    m.topic_len = (std::uint16_t)filter.size();

    auto wire = pack(m);
    if (wire.empty() || !send_(wire)) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.send_failures;
        return false;
    }
    std::lock_guard<std::mutex> lock(mu_);
    handlers_[filter] = std::move(handler);
    ++stats_.subscribes_sent;
    return true;
}

bool PubSubClient::unsubscribe(const std::string& filter) {
    sl_pubsub_msg_t m{};
    m.type      = SL_PUBSUB_UNSUBSCRIBE;
    m.topic     = filter.c_str();
    m.topic_len = (std::uint16_t)filter.size();

    auto wire = pack(m);
    if (wire.empty() || !send_(wire)) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.send_failures;
        return false;
    }
    std::lock_guard<std::mutex> lock(mu_);
    handlers_.erase(filter);
    ++stats_.unsubscribes_sent;
    return true;
}

bool PubSubClient::publish(const std::string& topic,
                           const std::vector<std::uint8_t>& payload,
                           bool retain) {
    if (!sl_topic_is_valid_publish(topic.c_str(), topic.size())) return false;
    sl_pubsub_msg_t m{};
    m.type        = SL_PUBSUB_PUBLISH;
    m.flags       = retain ? SL_PUBSUB_FLAG_RETAIN : 0;
    m.topic       = topic.c_str();
    m.topic_len   = (std::uint16_t)topic.size();
    m.payload     = payload.empty() ? nullptr : payload.data();
    m.payload_len = (std::uint32_t)payload.size();

    auto wire = pack(m);
    if (wire.empty() || !send_(wire)) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.send_failures;
        return false;
    }
    std::lock_guard<std::mutex> lock(mu_);
    ++stats_.publishes_sent;
    return true;
}

bool PubSubClient::on_message(const std::vector<std::uint8_t>& wire_bytes) {
    sl_pubsub_msg_t m{};
    if (sl_pubsub_unpack(wire_bytes.data(), wire_bytes.size(), &m) != 0) {
        return false;
    }
    if (m.type != SL_PUBSUB_PUBLISH) {
        /* PUBACK/SUBACK delivery is the application's concern; ignored. */
        return true;
    }

    const std::string topic((const char*)m.topic, m.topic_len);
    std::vector<std::uint8_t> payload;
    if (m.payload_len > 0) {
        payload.assign(m.payload, m.payload + m.payload_len);
    }

    /* Dispatch to every matching handler. */
    std::vector<PubSubHandler> to_invoke;
    {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.publishes_received;
        for (const auto& [filter, h] : handlers_) {
            if (sl_topic_matches(topic.c_str(), topic.size(),
                                 filter.c_str(), filter.size())) {
                to_invoke.push_back(h);
            }
        }
        if (to_invoke.empty()) ++stats_.handler_misses;
    }
    for (auto& h : to_invoke) {
        try { h(topic, payload); } catch (...) {}
    }
    return true;
}

std::size_t PubSubClient::subscription_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return handlers_.size();
}

PubSubClient::Stats PubSubClient::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    return stats_;
}

}  // namespace securelink
