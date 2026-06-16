#pragma once
// PubSubClient — client-side wrapper around the pubsub wire format.
//
// Applications register topic handlers; the client encodes subscribe /
// publish / unsubscribe frames and dispatches inbound publishes to the
// matching handler. Send is delegated via a caller-supplied callback,
// same pattern as RpcClient.

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace securelink {

using PubSubSendFn = std::function<bool(const std::vector<std::uint8_t>&)>;

using PubSubHandler =
    std::function<void(const std::string& topic,
                       const std::vector<std::uint8_t>& payload)>;

class PubSubClient {
public:
    explicit PubSubClient(PubSubSendFn send);

    bool subscribe  (const std::string& filter, PubSubHandler handler);
    bool unsubscribe(const std::string& filter);

    bool publish(const std::string& topic,
                 const std::vector<std::uint8_t>& payload,
                 bool retain = false);

    // Pump inbound wire bytes (one encoded message). Dispatches publishes
    // to handlers; returns false on malformed input.
    bool on_message(const std::vector<std::uint8_t>& wire_bytes);

    std::size_t subscription_count() const;

    struct Stats {
        std::uint64_t publishes_sent     = 0;
        std::uint64_t subscribes_sent    = 0;
        std::uint64_t unsubscribes_sent  = 0;
        std::uint64_t publishes_received = 0;
        std::uint64_t handler_misses     = 0;
        std::uint64_t send_failures      = 0;
    };
    Stats stats() const;

private:
    PubSubSendFn        send_;
    mutable std::mutex  mu_;
    std::unordered_map<std::string, PubSubHandler> handlers_;
    Stats               stats_;
};

}  // namespace securelink
