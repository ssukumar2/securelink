#include "stream_multiplexer.hpp"

#include <algorithm>
#include <cstring>

namespace securelink {

StreamMultiplexer::StreamMultiplexer(sl_stream_role_t role,
                                     std::uint32_t initial_window)
    : role_(role), initial_window_(initial_window) {
    sl_stream_id_init(&id_alloc_, role);
    sl_flow_init_with(&session_flow_, initial_window);
}

StreamRecord* StreamMultiplexer::find(std::uint32_t id) {
    auto it = streams_.find(id);
    return (it == streams_.end()) ? nullptr : &it->second;
}

StreamRecord* StreamMultiplexer::find_or_create(std::uint32_t id,
                                                bool peer_initiated) {
    auto it = streams_.find(id);
    if (it != streams_.end()) return &it->second;

    StreamRecord rec;
    rec.state = std::make_unique<StreamState>(id);
    rec.priority = sl_priority_default_for(id);
    sl_flow_init_with(&rec.flow, initial_window_);
    auto [ins, _] = streams_.emplace(id, std::move(rec));
    ++stats_.streams_opened;
    ins->second.state->open();
    (void)peer_initiated;
    return &ins->second;
}

std::uint32_t StreamMultiplexer::open_stream(sl_priority_t prio) {
    std::lock_guard<std::mutex> lock(mu_);
    const auto id = sl_stream_id_next(&id_alloc_);
    if (id == 0) return 0;
    auto* rec = find_or_create(id, false);
    rec->priority = prio;
    return id;
}

bool StreamMultiplexer::send_data(std::uint32_t id,
                                  const std::uint8_t* data, std::size_t len,
                                  bool fin) {
    std::lock_guard<std::mutex> lock(mu_);
    auto* rec = find(id);
    if (!rec || !rec->state->can_send()) return false;
    if (len > SL_STREAM_FRAME_MAX_PAYLOAD) return false;

    if (len > 0) {
        if (!sl_flow_can_send(&rec->flow, (uint32_t)len) ||
            !sl_flow_can_send(&session_flow_, (uint32_t)len)) {
            ++stats_.flow_blocks;
            return false;
        }
        sl_flow_charge_send(&rec->flow,        (uint32_t)len);
        sl_flow_charge_send(&session_flow_,    (uint32_t)len);
        rec->outbound.emplace_back(data, data + len);
    }
    if (fin) {
        rec->state->on_sent_fin();
        if (rec->outbound.empty()) {
            // Push an empty marker so pop_outbound emits a FIN frame.
            rec->outbound.emplace_back();
        }
    }
    return true;
}

bool StreamMultiplexer::on_frame(const sl_stream_frame_t& f) {
    std::lock_guard<std::mutex> lock(mu_);
    ++stats_.frames_in;
    stats_.bytes_in += f.payload_len;

    if (f.stream_id == SL_STREAM_ID_CONTROL) {
        // Reserved for session-level control frames; ignore here.
        return true;
    }

    auto* rec = find(f.stream_id);
    if (!rec) {
        if (!sl_stream_id_belongs_to_peer(f.stream_id, role_)) return false;
        rec = find_or_create(f.stream_id, true);
    }

    switch (f.type) {
    case SL_STREAM_FRAME_DATA: {
        if (!rec->state->can_recv()) return false;
        if (f.payload_len > 0) {
            if (sl_flow_charge_recv(&rec->flow, f.payload_len) != 0) return false;
            if (sl_flow_charge_recv(&session_flow_, f.payload_len) != 0) return false;
            rec->inbound.insert(rec->inbound.end(),
                                f.payload, f.payload + f.payload_len);
        }
        if (f.flags & SL_STREAM_FLAG_FIN) {
            rec->state->on_recv_fin();
            rec->inbound_fin = true;
        }
        return true;
    }
    case SL_STREAM_FRAME_WINDOW: {
        if (f.payload_len < 4) return false;
        const std::uint32_t delta =
            ((std::uint32_t)f.payload[0] << 24) |
            ((std::uint32_t)f.payload[1] << 16) |
            ((std::uint32_t)f.payload[2] <<  8) |
             (std::uint32_t)f.payload[3];
        sl_flow_grant_send(&rec->flow, delta);
        return true;
    }
    case SL_STREAM_FRAME_RESET: {
        rec->state->reset("peer_reset");
        ++stats_.resets;
        return true;
    }
    default:
        return true;   /* PING/PONG handled at higher layer */
    }
}

std::optional<sl_stream_frame_t> StreamMultiplexer::pop_outbound(
    std::vector<std::uint8_t>& storage) {
    std::lock_guard<std::mutex> lock(mu_);

    /* Priority scan: URGENT first, then HIGH, etc. */
    for (int band = 0; band < SL_PRIORITY_COUNT; ++band) {
        for (auto& [id, rec] : streams_) {
            if ((int)rec.priority != band) continue;
            if (rec.outbound.empty())      continue;

            auto chunk = std::move(rec.outbound.front());
            rec.outbound.pop_front();

            sl_stream_frame_t f{};
            f.type        = SL_STREAM_FRAME_DATA;
            f.stream_id   = id;
            f.flags       = 0;
            if (rec.outbound.empty() &&
                rec.state->phase() == StreamPhase::kHalfClosedLocal) {
                f.flags |= SL_STREAM_FLAG_FIN;
            }
            storage = std::move(chunk);
            f.payload     = storage.empty() ? nullptr : storage.data();
            f.payload_len = (std::uint16_t)storage.size();
            ++stats_.frames_out;
            stats_.bytes_out += f.payload_len;
            return f;
        }
    }
    return std::nullopt;
}

std::size_t StreamMultiplexer::read_inbound(std::uint32_t id,
                                            std::vector<std::uint8_t>& out) {
    std::lock_guard<std::mutex> lock(mu_);
    auto* rec = find(id);
    if (!rec) return 0;
    out.insert(out.end(), rec->inbound.begin(), rec->inbound.end());
    const auto n = rec->inbound.size();
    rec->inbound.clear();
    /* Replenish recv window for the bytes we just consumed. */
    sl_flow_grant_recv(&rec->flow,     (uint32_t)n);
    sl_flow_grant_recv(&session_flow_, (uint32_t)n);
    if (rec->inbound_fin && rec->state->phase() == StreamPhase::kHalfClosedLocal) {
        ++stats_.streams_closed;
    }
    return n;
}

bool StreamMultiplexer::reset_stream(std::uint32_t id, std::string reason) {
    std::lock_guard<std::mutex> lock(mu_);
    auto* rec = find(id);
    if (!rec) return false;
    rec->state->reset(std::move(reason));
    ++stats_.resets;
    return true;
}

bool StreamMultiplexer::is_open(std::uint32_t id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = streams_.find(id);
    return it != streams_.end() && !it->second.state->is_closed();
}

std::size_t StreamMultiplexer::open_stream_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::size_t n = 0;
    for (auto& [_, rec] : streams_) {
        if (!rec.state->is_closed()) ++n;
    }
    return n;
}

MuxStats StreamMultiplexer::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    return stats_;
}

}  // namespace securelink
