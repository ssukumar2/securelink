#pragma once
// TopicAcl — per-identity allow lists for publish and subscribe.
//
// Each Ed25519 identity fingerprint can be authorized to publish and/or
// subscribe to specific topic patterns. Patterns follow the same syntax
// as subscription filters (sl_topic) — '+' and '#' wildcards allowed.
//
// Lookup is O(rules) per check. Rule lists are kept small (per identity);
// for very large fleets, group rules by role and have one ACL per role.

#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace securelink {

enum class TopicOp {
    kPublish,
    kSubscribe,
};

struct TopicRule {
    std::string filter;   // e.g. "sensors/+/temp"
    bool        allow;    // true = grant, false = explicit deny
};

class TopicAcl {
public:
    using Fingerprint = std::array<std::uint8_t, 32>;

    void allow (const Fingerprint& fp, TopicOp op, const std::string& filter);
    void deny  (const Fingerprint& fp, TopicOp op, const std::string& filter);
    void clear (const Fingerprint& fp);

    // Default policy when no rule matches. Default: deny.
    void set_default_allow(bool allow) { default_allow_ = allow; }

    // Returns true if the operation is permitted.
    bool check(const Fingerprint& fp, TopicOp op,
               const std::string& topic_or_filter) const;

    std::size_t rule_count(const Fingerprint& fp) const;
    std::size_t identity_count() const;

private:
    struct Entry {
        std::vector<TopicRule> publish_rules;
        std::vector<TopicRule> subscribe_rules;
    };

    bool eval(const std::vector<TopicRule>& rules,
              const std::string& topic_or_filter) const;

    mutable std::mutex                                   mu_;
    std::unordered_map<std::string, Entry>               by_fp_;   // hex-encoded
    bool                                                 default_allow_ = false;

    static std::string fp_key(const Fingerprint& fp);
};

}  // namespace securelink
