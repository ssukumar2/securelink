#include "topic_trie.hpp"

#include <algorithm>

namespace securelink {

std::vector<std::string_view> TopicTrie::split(const std::string& s) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == '/') {
            out.emplace_back(s.data() + start, i - start);
            start = i + 1;
        }
    }
    return out;
}

bool TopicTrie::subscribe(const std::string& filter, SubscriberId sub_id) {
    std::lock_guard<std::mutex> lock(mu_);
    const auto segs = split(filter);
    Node* node = &root_;

    for (std::size_t i = 0; i < segs.size(); ++i) {
        const auto seg = segs[i];
        if (seg == "#") {
            const bool inserted = node->hash_subs.insert(sub_id).second;
            if (inserted) ++total_subs_;
            return inserted;
        }
        if (seg == "+") {
            if (!node->plus) node->plus = std::make_unique<Node>();
            node = node->plus.get();
            continue;
        }
        const std::string key(seg);
        auto& child = node->children[key];
        if (!child) child = std::make_unique<Node>();
        node = child.get();
    }
    const bool inserted = node->exact_subs.insert(sub_id).second;
    if (inserted) ++total_subs_;
    return inserted;
}

bool TopicTrie::unsubscribe(const std::string& filter, SubscriberId sub_id) {
    std::lock_guard<std::mutex> lock(mu_);
    const auto segs = split(filter);
    Node* node = &root_;
    for (std::size_t i = 0; i < segs.size(); ++i) {
        const auto seg = segs[i];
        if (seg == "#") {
            const bool removed = node->hash_subs.erase(sub_id) > 0;
            if (removed) --total_subs_;
            return removed;
        }
        if (seg == "+") {
            if (!node->plus) return false;
            node = node->plus.get();
            continue;
        }
        const std::string key(seg);
        auto it = node->children.find(key);
        if (it == node->children.end()) return false;
        node = it->second.get();
    }
    const bool removed = node->exact_subs.erase(sub_id) > 0;
    if (removed) --total_subs_;
    return removed;
}

static std::size_t prune_node(TopicTrie* /*self*/) { return 0; } // placeholder

std::size_t TopicTrie::unsubscribe_all(SubscriberId sub_id) {
    std::lock_guard<std::mutex> lock(mu_);
    std::size_t removed = 0;

    /* Iterative DFS so we don't blow the stack on deep tries. */
    std::vector<Node*> stack{&root_};
    while (!stack.empty()) {
        Node* n = stack.back();
        stack.pop_back();
        if (n->exact_subs.erase(sub_id) > 0) { ++removed; --total_subs_; }
        if (n->hash_subs.erase (sub_id) > 0) { ++removed; --total_subs_; }
        if (n->plus) stack.push_back(n->plus.get());
        for (auto& kv : n->children) stack.push_back(kv.second.get());
    }
    return removed;
}

void TopicTrie::match_into(const Node* node,
                           const std::vector<std::string_view>& segs,
                           std::size_t depth,
                           std::unordered_set<SubscriberId>& out) const {
    /* '#' at this depth matches everything from here down. */
    for (auto s : node->hash_subs) out.insert(s);

    if (depth == segs.size()) {
        for (auto s : node->exact_subs) out.insert(s);
        return;
    }

    const auto seg = segs[depth];

    auto it = node->children.find(std::string(seg));
    if (it != node->children.end()) {
        match_into(it->second.get(), segs, depth + 1, out);
    }
    if (node->plus) {
        match_into(node->plus.get(), segs, depth + 1, out);
    }
}

std::vector<SubscriberId> TopicTrie::match(const std::string& topic) const {
    std::lock_guard<std::mutex> lock(mu_);
    const auto segs = split(topic);
    std::unordered_set<SubscriberId> set;
    match_into(&root_, segs, 0, set);
    return std::vector<SubscriberId>(set.begin(), set.end());
}

std::size_t TopicTrie::subscription_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return total_subs_;
}

}  // namespace securelink
