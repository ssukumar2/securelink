// Tests for PubSubBroker.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_pubsub_broker.cpp src/pubsub_broker.cpp \
//       src/topic_acl.cpp src/topic_trie.cpp src/sl_topic.c \
//       -lpthread -o test_pubsub_broker

#include <cstdio>
#include <memory>

#include "pubsub_broker.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static TopicAcl::Fingerprint fp(std::uint8_t seed) {
    TopicAcl::Fingerprint a{};
    for (auto& b : a) b = seed;
    return a;
}

static int test_publish_to_matching_subscribers(void) {
    PubSubBroker br;
    br.subscribe(fp(1), 100, "sensors/+/temp");
    br.subscribe(fp(2), 200, "sensors/#");
    br.subscribe(fp(3), 300, "other");

    auto deliveries = br.publish(fp(9), "sensors/kitchen/temp",
                                 {1, 2, 3}, false);
    CHECK(deliveries.size() == 2);
    bool saw100 = false, saw200 = false;
    for (const auto& d : deliveries) {
        if (d.subscriber == 100) saw100 = true;
        if (d.subscriber == 200) saw200 = true;
        CHECK(d.topic == "sensors/kitchen/temp");
        CHECK(d.payload.size() == 3);
    }
    CHECK(saw100 && saw200);
    return 0;
}

static int test_publish_invalid_topic_denied(void) {
    PubSubBroker br;
    br.subscribe(fp(1), 1, "#");
    auto d = br.publish(fp(9), "bad//topic", {}, false);
    CHECK(d.empty());
    CHECK(br.stats().publishes_denied == 1);
    return 0;
}

static int test_retained_replayed_on_subscribe(void) {
    PubSubBroker br;
    br.publish(fp(9), "alerts/critical", {0xAA, 0xBB}, /*retain=*/true);
    CHECK(br.retained_count() == 1);

    auto replays = br.subscribe(fp(1), 100, "alerts/#");
    CHECK(replays.size() == 1);
    CHECK(replays[0].topic == "alerts/critical");
    CHECK(replays[0].retained);
    CHECK(replays[0].payload.size() == 2);
    return 0;
}

static int test_acl_denies_publish(void) {
    auto acl = std::make_shared<TopicAcl>();
    acl->set_default_allow(true);                         /* default allow */
    acl->deny(fp(9), TopicOp::kPublish, "sensors/#");     /* but block sensors */

    PubSubBroker br(acl);
    br.subscribe(fp(1), 100, "sensors/#");

    auto d = br.publish(fp(9), "sensors/kitchen/temp", {}, false);
    CHECK(d.empty());
    CHECK(br.stats().publishes_denied == 1);

    auto ok = br.publish(fp(9), "alerts/critical", {}, false);
    /* No subscribers for alerts but publish was allowed. */
    CHECK(ok.empty());
    CHECK(br.stats().publishes_no_match == 1);
    return 0;
}

static int test_unsubscribe_and_drop_subscriber(void) {
    PubSubBroker br;
    br.subscribe(fp(1), 100, "a/+");
    br.subscribe(fp(1), 100, "b/#");
    br.subscribe(fp(2), 200, "a/+");
    CHECK(br.subscription_count() == 3);

    CHECK(br.unsubscribe(100, "a/+"));
    CHECK(br.subscription_count() == 2);

    CHECK(br.drop_subscriber(100) == 1);   /* "b/#" remaining for 100 */
    CHECK(br.subscription_count() == 1);

    auto d = br.publish(fp(9), "a/x", {}, false);
    CHECK(d.size() == 1);
    CHECK(d[0].subscriber == 200);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_publish_to_matching_subscribers();
    rc |= test_publish_invalid_topic_denied();
    rc |= test_retained_replayed_on_subscribe();
    rc |= test_acl_denies_publish();
    rc |= test_unsubscribe_and_drop_subscriber();
    if (rc == 0) std::puts("test_pubsub_broker: OK");
    return rc;
}
