#pragma once
// PubSubBroker — the server-side dispatcher for pub/sub traffic.
//
// One broker per server. Subscribers register their stream id; when a
// publish arrives, the broker looks up matching subscribers via TopicTrie
// and enqueues the message for delivery to each one.
//
// Retained messages: if a publish has SL_PUBSUB_FLAG_RETAIN set, the
// broker keeps the latest message per topic. New subscribers receive any
// retained message that matches their filter immediately on subscribe.

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "topic_acl.hpp"
#include "topic_trie.hpp"

namespace securelink {

struct PubSubDelivery {
    SubscriberId               subscriber;
    std::string                topic;
    std::vector<std::uint8_t>  payload;
    bool                       retained = false;
};

struct PubSubBrokerStats {
    std::uint64_t publishes_total      = 0;
    std::uint64_t publishes_denied     = 0;
    std::uint64_t publishes_no_match   = 0;
    std::uint64_t subscribes_total     = 0;
    std::uint64_t subscribes_denied    = 0;
    std::uint64_t unsubscribes_total   = 0;
    std::uint64_t deliveries_queued    = 0;
    std::uint64_t retained_replays     = 0;
};

class PubSubBroker {
public:
    explicit PubSubBroker(std::shared_ptr<TopicAcl> acl = nullptr);

    // Returns deliveries that should be sent out as a result of this publish.
    // Empty vector means no matching subscribers (or denied).
    std::vector<PubSubDelivery> publish(
        const TopicAcl::Fingerprint& publisher,
        const std::string&           topic,
        const std::vector<std::uint8_t>& payload,
        bool                         retain = false);

    // Subscribe `sub_id` (identified by `subscriber_fp`) to `filter`.
    // Returns retained messages that match the new subscription.
    std::vector<PubSubDelivery> subscribe(
        const TopicAcl::Fingerprint& subscriber_fp,
        SubscriberId                 sub_id,
        const std::string&           filter);

    bool unsubscribe(SubscriberId sub_id, const std::string& filter);

    // Remove every trace of a subscriber. Called when a session ends.
    std::size_t drop_subscriber(SubscriberId sub_id);

    std::size_t subscription_count() const;
    std::size_t retained_count()     const;

    PubSubBrokerStats stats() const;

private:
    std::shared_ptr<TopicAcl>                       acl_;
    TopicTrie                                       trie_;
    mutable std::mutex                              mu_;
    std::unordered_map<std::string, std::vector<std::uint8_t>> retained_;
    PubSubBrokerStats                               stats_;
};

}  // namespace securelink
