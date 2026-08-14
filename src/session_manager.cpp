#include "session_manager.hpp"

#include <chrono>
#include <ctime>
#include <cstring>

namespace securelink {

SessionManager::SessionManager(SessionManagerConfig cfg) : cfg_(cfg) {}

std::uint64_t SessionManager::register_session(
    std::string peer_label,
    std::array<std::uint8_t, 32> peer_identity) {
    std::lock_guard<std::mutex> lock(mu_);
    Session s;
    s.id            = next_id_++;
    s.peer_label    = std::move(peer_label);
    s.peer_identity = peer_identity;
    s.opened_at     = std::chrono::steady_clock::now();
    s.last_activity = s.opened_at;
    s.authenticated = true;
    const auto id = s.id;
    sessions_.emplace(id, std::move(s));
    return id;
}

bool SessionManager::record_traffic(std::uint64_t id,
                                    std::uint64_t bytes_sent,
                                    std::uint64_t bytes_received) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = sessions_.find(id);
    if (it == sessions_.end()) return false;
    auto& s = it->second;
    s.stats.bytes_sent     += bytes_sent;
    s.stats.bytes_received += bytes_received;
    if (bytes_sent > 0)     ++s.stats.records_sent;
    if (bytes_received > 0) ++s.stats.records_received;
    s.last_activity = std::chrono::steady_clock::now();

    const std::uint64_t total = s.stats.bytes_sent + s.stats.bytes_received;
    const auto age_s = std::chrono::duration_cast<std::chrono::seconds>(
                           s.last_activity - s.opened_at).count();
    return (total >= cfg_.rekey_after_bytes) ||
           (age_s >= (long)cfg_.rekey_after_seconds);
}

void SessionManager::note_rekey_local(std::uint64_t id) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = sessions_.find(id);
    if (it != sessions_.end()) ++it->second.stats.rekeys_local;
}

void SessionManager::note_rekey_peer(std::uint64_t id) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = sessions_.find(id);
    if (it != sessions_.end()) ++it->second.stats.rekeys_peer;
}

std::vector<std::uint8_t> SessionManager::issue_ticket(
    std::uint64_t id,
    const SessionTicketKey& stk,
    const ResumptionSecret& resumption_secret) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = sessions_.find(id);
    if (it == sessions_.end()) return {};

    sl_ticket_body_t body{};
    body.issued_at_s = (uint32_t)std::time(nullptr);
    body.lifetime_s  = cfg_.ticket_lifetime_seconds;
    std::memcpy(body.resumption_secret, resumption_secret.data(), 32);
    std::memcpy(body.peer_identity_pub, it->second.peer_identity.data(), 32);

    std::vector<std::uint8_t> wire(SL_TICKET_TOTAL_LEN);
    if (sl_ticket_seal(stk.data(), &body, wire.data()) != 0) return {};
    return wire;
}

std::optional<sl_ticket_body_t> SessionManager::consume_ticket(
    const std::array<std::uint8_t, 32>& stk,
    const std::vector<std::uint8_t>&    ticket_bytes) {
    if (ticket_bytes.size() != SL_TICKET_TOTAL_LEN) return std::nullopt;
    sl_ticket_body_t body{};
    if (sl_ticket_open(stk.data(), ticket_bytes.data(), &body) != 0) {
        return std::nullopt;
    }
    if (!sl_ticket_is_fresh(&body, (uint32_t)std::time(nullptr))) {
        return std::nullopt;
    }
    return body;
}

void SessionManager::close_session(std::uint64_t id) {
    std::lock_guard<std::mutex> lock(mu_);
    sessions_.erase(id);
}

std::optional<Session> SessionManager::snapshot(std::uint64_t id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = sessions_.find(id);
    if (it == sessions_.end()) return std::nullopt;
    return it->second;
}

std::size_t SessionManager::active_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return sessions_.size();
}

std::size_t SessionManager::sweep() {
    std::lock_guard<std::mutex> lock(mu_);
    const auto now = std::chrono::steady_clock::now();
    std::size_t removed = 0;
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        const auto idle = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_activity).count();
        if (idle >= (long)cfg_.idle_timeout_seconds) {
            it = sessions_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

}  // namespace securelink
