#include "replay_harness.hpp"

#include <chrono>
#include <thread>

namespace securelink {

void ReplayHarness::on(sl_event_type_t type, ReplayHandler handler) {
    handlers_[static_cast<int>(type)] = std::move(handler);
}

void ReplayHarness::on_default(ReplayHandler handler) {
    default_handler_ = std::move(handler);
}

void ReplayHarness::dispatch(const ReplayEvent& ev) {
    auto it = handlers_.find(static_cast<int>(ev.type));
    if (it != handlers_.end()) {
        it->second(ev);
    } else if (default_handler_) {
        default_handler_(ev);
    }
}

int ReplayHarness::visitor_thunk(const sl_event_record_t* rec, void* user) {
    auto* ctx = static_cast<RunCtx*>(user);
    ++ctx->stats.events_seen;

    ReplayEvent ev;
    ev.seq          = rec->seq;
    ev.timestamp_ns = rec->timestamp_ns;
    ev.type         = rec->type;
    if (rec->payload_len > 0 && rec->payload != nullptr) {
        ev.payload.assign(rec->payload, rec->payload + rec->payload_len);
    }

    if (ctx->respect_timing && ctx->prev_ts_ns != 0 &&
        ev.timestamp_ns > ctx->prev_ts_ns) {
        std::uint64_t delta_ms =
            (ev.timestamp_ns - ctx->prev_ts_ns) / 1000000ULL;
        if (delta_ms > ctx->max_sleep_ms) delta_ms = ctx->max_sleep_ms;
        if (delta_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delta_ms));
        }
    }
    ctx->prev_ts_ns = ev.timestamp_ns;

    const auto handler_present =
        ctx->self->handlers_.find(static_cast<int>(ev.type)) !=
        ctx->self->handlers_.end();
    if (handler_present || ctx->self->default_handler_) {
        ctx->self->dispatch(ev);
        ++ctx->stats.events_dispatched;
    } else {
        ++ctx->stats.events_skipped;
    }
    return 0;
}

ReplayStats ReplayHarness::run_file(const std::string& path,
                                    bool respect_timing,
                                    std::uint32_t max_sleep_ms) {
    RunCtx ctx;
    ctx.self           = this;
    ctx.respect_timing = respect_timing;
    ctx.max_sleep_ms   = max_sleep_ms;
    ctx.prev_ts_ns     = 0;

    const auto t0 = std::chrono::steady_clock::now();
    sl_event_log_iterate(path.c_str(), &ReplayHarness::visitor_thunk, &ctx);
    const auto t1 = std::chrono::steady_clock::now();
    ctx.stats.elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        t1 - t0).count();
    return ctx.stats;
}

ReplayStats ReplayHarness::run_events(const std::vector<ReplayEvent>& events,
                                      bool respect_timing,
                                      std::uint32_t max_sleep_ms) {
    ReplayStats stats;
    std::uint64_t prev_ts = 0;
    const auto t0 = std::chrono::steady_clock::now();

    for (const auto& ev : events) {
        ++stats.events_seen;
        if (respect_timing && prev_ts != 0 && ev.timestamp_ns > prev_ts) {
            std::uint64_t delta_ms = (ev.timestamp_ns - prev_ts) / 1000000ULL;
            if (delta_ms > max_sleep_ms) delta_ms = max_sleep_ms;
            if (delta_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(delta_ms));
            }
        }
        prev_ts = ev.timestamp_ns;

        const auto handler_present =
            handlers_.find(static_cast<int>(ev.type)) != handlers_.end();
        if (handler_present || default_handler_) {
            dispatch(ev);
            ++stats.events_dispatched;
        } else {
            ++stats.events_skipped;
        }
    }

    const auto t1 = std::chrono::steady_clock::now();
    stats.elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        t1 - t0).count();
    return stats;
}

}  // namespace securelink
