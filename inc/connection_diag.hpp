#pragma once
// ConnectionDiag — per-connection diagnostic context.
//
// Each connection owns one of these to track what happened during its
// lifetime. Useful for incident analysis (look up a connection by id,
// see the chain of events that led to closure) and to surface a clean
// reason to the operator without scraping logs.

#include <chrono>
#include <cstdint>
#include <mutex>
#include <ostream>
#include <string>
#include <vector>

#include "sl_diag_code.h"

namespace securelink {

struct DiagEntry {
    std::chrono::steady_clock::time_point at;
    sl_diag_code_t                        code;
    std::string                           detail;
};

class ConnectionDiag {
public:
    explicit ConnectionDiag(std::uint64_t conn_id, std::string peer);

    void record(sl_diag_code_t code, std::string detail = "");

    void set_negotiated_version(std::uint16_t v) { version_ = v; }
    void set_negotiated_cipher (std::uint16_t s) { cipher_  = s; }
    void set_peer_label(std::string s) { peer_ = std::move(s); }

    std::uint64_t  connection_id() const { return conn_id_; }
    std::uint16_t  version()       const { return version_; }
    std::uint16_t  cipher()        const { return cipher_;  }
    const std::string& peer()      const { return peer_; }

    // Most recent recorded code; SL_DIAG_OK if none yet.
    sl_diag_code_t last_code() const;

    // Render as one-line summary for logs.
    std::string summary() const;

    // Render entries for verbose inspection (e.g. admin /diag endpoint).
    void render(std::ostream& os) const;

    std::size_t entry_count() const;

private:
    mutable std::mutex     mu_;
    std::uint64_t          conn_id_;
    std::string            peer_;
    std::uint16_t          version_ = 0;
    std::uint16_t          cipher_  = 0;
    std::vector<DiagEntry> entries_;
    std::chrono::steady_clock::time_point opened_at_;
};

}  // namespace securelink
