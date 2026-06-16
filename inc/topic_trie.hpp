#pragma once
// TopicTrie — efficient many-to-many lookup of subscribers by topic.
//
// A trie keyed by topic segments. Each leaf carries a set of subscriber
// IDs. Wildcards '+' and '#' are stored as special branches so a publish
// to "sensors/temp/kitchen" finds subscribers to "sensors/+/kitchen",
// "sensors/#", and exact matches in a single tree walk.
//
// Complexity: insertion O(segments), match O(segments * fanout).

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace securelink {

using SubscriberId = std::uint64_t;

class TopicTrie {
public:
    // Add `sub_id` as a subscriber of `filter`. Returns true if newly inserted.
    bool subscribe(const std::string& filter, SubscriberId sub_id);

    // Remove `sub_id` from `filter`. Returns true if it was present.
    bool unsubscribe(const std::string& filter, SubscriberId sub_id);

    // Remove `sub_id` from every filter it is subscribed to. Used when
    // a subscriber disconnects. Returns number of filters cleaned.
    std::size_t unsubscribe_all(SubscriberId sub_id);

    // Collect every subscriber whose filter matches `topic`.
    std::vector<SubscriberId> match(const std::string& topic) const;

    std::size_t subscription_count() const;

private:
    struct Node {
        std::unordered_map<std::string, std::unique_ptr<Node>> children;
        std::unique_ptr<Node>             plus;   // '+' branch
        std::unordered_set<SubscriberId> hash_subs;  // subs for '#'
        std::unordered_set<SubscriberId> exact_subs; // subs ending here
    };

    static std::vector<std::string_view> split(const std::string& s);
    void match_into(const Node* node,
                    const std::vector<std::string_view>& segs,
                    std::size_t depth,
                    std::unordered_set<SubscriberId>& out) const;

    mutable std::mutex mu_;
    Node               root_;
    std::size_t        total_subs_ = 0;
};

}  // namespace securelink
