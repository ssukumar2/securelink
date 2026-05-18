#pragma once
// BeaconRegistry — server-side allow-list of known clients.
//
// Each client is registered with its symmetric key + IV (typically pinned
// out-of-band or established during handshake). The server uses the registry
// to look up the right key when processing an incoming beacon, instead of
// assuming a single global key for everyone.

#include <array>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "sl_aead.h"

namespace securelink {

struct ClientEntry {
    std::uint64_t client_id = 0;
    std::string   label;              // human-readable name, for logs
    std::array<std::uint8_t, SL_AEAD_KEY_LEN> key{};
    std::array<std::uint8_t, SL_AEAD_IV_LEN>  static_iv{};
    bool          enabled = true;
};

class BeaconRegistry {
public:
    // Insert or replace a client entry. Returns true if newly inserted.
    bool upsert(const ClientEntry& entry);

    // Disable a client without removing it (its beacons will be rejected).
    bool set_enabled(std::uint64_t client_id, bool enabled);

    // Remove a client entirely. Returns true if it existed.
    bool remove(std::uint64_t client_id);

    // Look up the key/IV/enabled state for a client.
    std::optional<ClientEntry> lookup(std::uint64_t client_id) const;

    std::size_t size() const;

    // Apply `fn` to every entry (read-only). The mutex is held during the
    // iteration — fn should be quick.
    template <typename F>
    void for_each(F&& fn) const {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& [id, entry] : entries_) {
            fn(entry);
        }
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<std::uint64_t, ClientEntry> entries_;
};

}  // namespace securelink
