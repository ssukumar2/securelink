#include "pubsub_broker.hpp"

#include "sl_topic.h"

namespace securelink {

PubSubBroker::PubSubBroker(std::shared_ptr<TopicAcl> acl)
    : acl_(std::move(acl)) {}

std::vector<PubSubDelivery> PubSubBroker::publish(
    const TopicAcl::Fingerprint& publisher,
    const std::string&           topic,
    std::vector<std::uint8_t>    payload,
    bool                         retain) {
    if (!sl_topic_is_valid_publish(topic.c_str(), topic.size())) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.publishes_total;
        ++stats_.publishes_denied;
        return {};
    }
    if (acl_ && !acl_->check(publisher, TopicOp::kPublish, topic)) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.publishes_total;
        ++stats_.publishes_denied;
        return {};
    }

    const auto subs = trie_.match(topic);

    std::vector<PubSubDelivery> out;
    {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.publishes_total;
        if (retain) retained_[topic] = payload;
        if (subs.empty()) {
            ++stats_.publishes_no_match;
            return out;
        }
        out.reserve(subs.size());
        for (auto s : subs) {
            PubSubDelivery d;
            d.subscriber = s;
            d.topic      = topic;
            d.payload    = payload;        /* copy; caller may free arg */
            d.retained   = false;
            out.push_back(std::move(d));
            ++stats_.deliveries_queued;
        }
    }
    return out;
}

std::vector<PubSubDelivery> PubSubBroker::subscribe(
    const TopicAcl::Fingerprint& subscriber_fp,
    SubscriberId                 sub_id,
    const std::string&           filter) {
    if (!sl_topic_is_valid_filter(filter.c_str(), filter.size())) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.subscribes_total;
        ++stats_.subscribes_denied;
        return {};
    }
    if (acl_ && !acl_->check(subscriber_fp, TopicOp::kSubscribe, filter)) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.subscribes_total;
        ++stats_.subscribes_denied;
        return {};
    }

    trie_.subscribe(filter, sub_id);

    /* Replay retained messages matching this new subscription. */
    std::vector<PubSubDelivery> replays;
    {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.subscribes_total;
        for (const auto& [topic, payload] : retained_) {
            if (sl_topic_matches(topic.c_str(), topic.size(),
                                 filter.c_str(), filter.size())) {
                PubSubDelivery d;
                d.subscriber = sub_id;
                d.topic      = topic;
                d.payload    = payload;
                d.retained   = true;
                replays.push_back(std::move(d));
                ++stats_.retained_replays;
            }
        }
    }
    return replays;
}

bool PubSubBroker::unsubscribe(SubscriberId sub_id, const std::string& filter) {
    const bool ok = trie_.unsubscribe(filter, sub_id);
    if (ok) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.unsubscribes_total;
    }
    return ok;
}

std::size_t PubSubBroker::drop_subscriber(SubscriberId sub_id) {
    const auto n = trie_.unsubscribe_all(sub_id);
    if (n > 0) {
        std::lock_guard<std::mutex> lock(mu_);
        stats_.unsubscribes_total += n;
    }
    return n;
}

std::size_t PubSubBroker::subscription_count() const {
    return trie_.subscription_count();
}

std::size_t PubSubBroker::retained_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return retained_.size();
}

PubSubBrokerStats PubSubBroker::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    return stats_;
}

}  // namespace securelink
