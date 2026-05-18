#include "beacon_registry.hpp"

namespace securelink {

bool BeaconRegistry::upsert(const ClientEntry& entry) {
    std::lock_guard<std::mutex> lock(mu_);
    auto [it, inserted] = entries_.insert_or_assign(entry.client_id, entry);
    return inserted;
}

bool BeaconRegistry::set_enabled(std::uint64_t client_id, bool enabled) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = entries_.find(client_id);
    if (it == entries_.end()) return false;
    it->second.enabled = enabled;
    return true;
}

bool BeaconRegistry::remove(std::uint64_t client_id) {
    std::lock_guard<std::mutex> lock(mu_);
    return entries_.erase(client_id) > 0;
}

std::optional<ClientEntry> BeaconRegistry::lookup(std::uint64_t client_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = entries_.find(client_id);
    if (it == entries_.end()) return std::nullopt;
    return it->second;
}

std::size_t BeaconRegistry::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return entries_.size();
}

}  // namespace securelink
