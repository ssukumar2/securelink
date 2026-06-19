// Attack: topic ACL bypass.
//
// A subscriber tries to receive events from a topic it is not authorized
// to consume, using clever wildcard filters and path-traversal tricks.
//
// Defense: TopicAcl checks both publish and subscribe filters against
// per-identity rule lists, and the topic validator rejects malformed
// patterns up front.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/attack_topic_acl_bypass.cpp \
//       src/attack_sim.cpp \
//       src/topic_acl.cpp src/sl_topic.c \
//       -lpthread -o attack_topic_acl_bypass

#include <cstdio>

#include "attack_sim.hpp"
#include "topic_acl.hpp"

using namespace securelink;
using namespace securelink::attacks;

static TopicAcl::Fingerprint fp(std::uint8_t s) {
    TopicAcl::Fingerprint a{};
    for (auto& b : a) b = s;
    return a;
}

static ScenarioOutcome scenario_subscribe_outside_allowed() {
    TopicAcl acl;
    acl.allow(fp(1), TopicOp::kSubscribe, "sensors/kitchen/#");
    // Attacker tries to subscribe to ALL sensors.
    const bool allowed_eval = acl.check(fp(1), TopicOp::kSubscribe, "sensors/#");
    if (allowed_eval) {
        return allowed("subscribe_outside",
                       "wider filter accepted despite narrower allow");
    }
    return blocked("subscribe_outside",
                   "broader filter rejected; narrower allow held");
}

static ScenarioOutcome scenario_invalid_filter_rejected() {
    // The wildcard validator should refuse malformed patterns even before
    // ACL evaluation. This guards against authors typing the patterns
    // directly into config without validation.
    const bool ok = sl_topic_is_valid_filter("a/#/b", 5);
    if (ok) {
        return allowed("invalid_filter",
                       "validator accepted '#' not at end");
    }
    return blocked("invalid_filter",
                   "'#' must be terminal; validator rejected");
}

static ScenarioOutcome scenario_publish_to_others_namespace() {
    TopicAcl acl;
    acl.set_default_allow(false);
    acl.allow(fp(9), TopicOp::kPublish, "tenantA/#");
    // tenant 9 tries to publish into tenant B.
    if (acl.check(fp(9), TopicOp::kPublish, "tenantB/event") ) {
        return allowed("cross_tenant_publish",
                       "publish into foreign tenant succeeded");
    }
    return blocked("cross_tenant_publish",
                   "default-deny + scoped allow blocked the publish");
}

static ScenarioOutcome scenario_explicit_deny_overrides_default() {
    TopicAcl acl;
    acl.set_default_allow(true);
    acl.deny(fp(5), TopicOp::kSubscribe, "admin/#");
    if (acl.check(fp(5), TopicOp::kSubscribe, "admin/audit")) {
        return allowed("explicit_deny",
                       "explicit deny did not override default-allow");
    }
    return blocked("explicit_deny",
                   "explicit deny correctly overrode default-allow");
}

int main() {
    AttackSim sim;
    sim.add("subscribe_outside_allowed", scenario_subscribe_outside_allowed);
    sim.add("invalid_filter_rejected",   scenario_invalid_filter_rejected);
    sim.add("cross_tenant_publish",      scenario_publish_to_others_namespace);
    sim.add("explicit_deny_wins",        scenario_explicit_deny_overrides_default);

    const int failures = sim.run_all(true);
    if (failures == 0) {
        std::puts("attack_topic_acl_bypass: ALL DEFENSES HELD");
        return 0;
    }
    return 1;
}
