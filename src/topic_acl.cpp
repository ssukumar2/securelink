#include "topic_acl.hpp"

#include <cstdio>

#include "sl_topic.h"

namespace securelink {

std::string TopicAcl::fp_key(const Fingerprint& fp) {
    static const char d[] = "0123456789abcdef";
    std::string s(fp.size() * 2, '\0');
    for (std::size_t i = 0; i < fp.size(); ++i) {
        s[2 * i]     = d[(fp[i] >> 4) & 0x0F];
        s[2 * i + 1] = d[fp[i] & 0x0F];
    }
    return s;
}

void TopicAcl::allow(const Fingerprint& fp, TopicOp op,
                     const std::string& filter) {
    std::lock_guard<std::mutex> lock(mu_);
    auto& e = by_fp_[fp_key(fp)];
    TopicRule r{filter, true};
    if (op == TopicOp::kPublish) e.publish_rules.push_back(std::move(r));
    else                          e.subscribe_rules.push_back(std::move(r));
}

void TopicAcl::deny(const Fingerprint& fp, TopicOp op,
                    const std::string& filter) {
    std::lock_guard<std::mutex> lock(mu_);
    auto& e = by_fp_[fp_key(fp)];
    TopicRule r{filter, false};
    if (op == TopicOp::kPublish) e.publish_rules.push_back(std::move(r));
    else                          e.subscribe_rules.push_back(std::move(r));
}

void TopicAcl::clear(const Fingerprint& fp) {
    std::lock_guard<std::mutex> lock(mu_);
    by_fp_.erase(fp_key(fp));
}

bool TopicAcl::eval(const std::vector<TopicRule>& rules,
                    const std::string& s) const {
    /* First rule (in insertion order) whose filter matches wins. */
    for (const auto& r : rules) {
        if (sl_topic_matches(s.c_str(), s.size(),
                             r.filter.c_str(), r.filter.size())) {
            return r.allow;
        }
    }
    return default_allow_;
}

bool TopicAcl::check(const Fingerprint& fp, TopicOp op,
                     const std::string& topic_or_filter) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = by_fp_.find(fp_key(fp));
    if (it == by_fp_.end()) return default_allow_;
    return eval(op == TopicOp::kPublish ? it->second.publish_rules
                                         : it->second.subscribe_rules,
                topic_or_filter);
}

std::size_t TopicAcl::rule_count(const Fingerprint& fp) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = by_fp_.find(fp_key(fp));
    if (it == by_fp_.end()) return 0;
    return it->second.publish_rules.size() + it->second.subscribe_rules.size();
}

std::size_t TopicAcl::identity_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return by_fp_.size();
}

}  // namespace securelink
