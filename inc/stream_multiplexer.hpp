#pragma once
// StreamMultiplexer — orchestrates many streams over one session.
//
// Owns: an ID allocator, per-stream state (StreamState + flow control +
// priority), and session-level flow control. The transport layer feeds
// it inbound stream frames; applications submit outbound stream frames.
//
// Scheduling is intentionally simple: priority bands picked in order,
// round-robin within a band. Replace with weighted/fair-queueing if
// needed later — the interface won't change.

#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>

#include "sl_flow_control.h"
#include "sl_priority.h"
#include "sl_stream_frame.h"
#include "sl_stream_id.h"
#include "stream_state.hpp"

namespace securelink {

struct StreamRecord {
    std::unique_ptr<StreamState> state;
    sl_flow_ctrl_t               flow{};
    sl_priority_t                priority = SL_PRIO_NORMAL;
    std::deque<std::vector<std::uint8_t>> outbound;  // queued DATA payloads
    std::vector<std::uint8_t>             inbound;   // assembled bytes
    bool                                  inbound_fin = false;
};

struct MuxStats {
    std::uint64_t streams_opened = 0;
    std::uint64_t streams_closed = 0;
    std::uint64_t frames_in      = 0;
    std::uint64_t frames_out     = 0;
    std::uint64_t bytes_in       = 0;
    std::uint64_t bytes_out      = 0;
    std::uint64_t flow_blocks    = 0;
    std::uint64_t resets         = 0;
};

class StreamMultiplexer {
public:
    explicit StreamMultiplexer(sl_stream_role_t role,
                               std::uint32_t initial_window = SL_FC_INITIAL_WINDOW);

    // Open a new locally-initiated stream. Returns its id.
    std::uint32_t open_stream(sl_priority_t prio = SL_PRIO_NORMAL);

    // Queue data on a stream. Returns false if the stream is closed/unknown
    // or if the data exceeds available send credit + session credit.
    bool send_data(std::uint32_t id, const std::uint8_t* data, std::size_t len,
                   bool fin = false);

    // Inbound frame from the transport. Updates state, buffers data.
    bool on_frame(const sl_stream_frame_t& f);

    // Pull the next outbound frame to send according to priority.
    // Returns std::nullopt if nothing to send right now.
    std::optional<sl_stream_frame_t> pop_outbound(
        std::vector<std::uint8_t>& storage);

    // Drain assembled inbound data from a stream into `out`.
    std::size_t read_inbound(std::uint32_t id,
                             std::vector<std::uint8_t>& out);

    bool reset_stream(std::uint32_t id, std::string reason);

    bool is_open(std::uint32_t id) const;
    std::size_t open_stream_count() const;
    MuxStats    stats() const;

private:
    StreamRecord* find_or_create(std::uint32_t id, bool peer_initiated);
    StreamRecord* find(std::uint32_t id);

    sl_stream_role_t                                       role_;
    std::uint32_t                                          initial_window_;
    sl_stream_id_alloc_t                                   id_alloc_{};
    sl_flow_ctrl_t                                         session_flow_{};
    mutable std::mutex                                     mu_;
    std::unordered_map<std::uint32_t, StreamRecord>        streams_;
    MuxStats                                               stats_{};
};

}  // namespace securelink
