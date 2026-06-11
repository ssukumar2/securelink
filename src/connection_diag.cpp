#include "connection_diag.hpp"

#include <sstream>

namespace securelink {

ConnectionDiag::ConnectionDiag(std::uint64_t conn_id, std::string peer)
    : conn_id_(conn_id),
      peer_(std::move(peer)),
      opened_at_(std::chrono::steady_clock::now()) {}

void ConnectionDiag::record(sl_diag_code_t code, std::string detail) {
    std::lock_guard<std::mutex> lock(mu_);
    DiagEntry e;
    e.at     = std::chrono::steady_clock::now();
    e.code   = code;
    e.detail = std::move(detail);
    entries_.push_back(std::move(e));
}

sl_diag_code_t ConnectionDiag::last_code() const {
    std::lock_guard<std::mutex> lock(mu_);
    return entries_.empty() ? SL_DIAG_OK : entries_.back().code;
}

std::string ConnectionDiag::summary() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::ostringstream oss;
    oss << "conn=" << conn_id_
        << " peer=" << peer_
        << " version=0x" << std::hex << version_
        << " cipher=0x"  << cipher_  << std::dec
        << " events=" << entries_.size();
    if (!entries_.empty()) {
        const auto& last = entries_.back();
        oss << " last=" << sl_diag_code_name(last.code);
        if (!last.detail.empty()) oss << "(" << last.detail << ")";
    }
    return oss.str();
}

void ConnectionDiag::render(std::ostream& os) const {
    std::lock_guard<std::mutex> lock(mu_);
    os << "conn_id="   << conn_id_ << "\n"
       << "peer="      << peer_    << "\n"
       << "version=0x" << std::hex << version_
       << " cipher=0x" << cipher_  << std::dec << "\n"
       << "events:\n";
    for (const auto& e : entries_) {
        const auto rel = std::chrono::duration_cast<std::chrono::milliseconds>(
            e.at - opened_at_).count();
        os << "  +" << rel << "ms  "
           << sl_diag_category(e.code) << "/" << sl_diag_code_name(e.code);
        if (!e.detail.empty()) os << "  -- " << e.detail;
        os << "\n";
    }
}

std::size_t ConnectionDiag::entry_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return entries_.size();
}

}  // namespace securelink
