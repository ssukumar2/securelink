#pragma once
// ReplayHarness — drives a captured event log back into a stateful
// system for deterministic regression testing or post-mortem analysis.
//
// Loaders register handlers per event type. The harness iterates the
// log in order, dispatching each record. Optional `respect_timing`
// preserves inter-event delays (useful for stress/timing tests); when
// false events fire as fast as possible.

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "sl_event_log.h"

namespace securelink {

struct ReplayEvent {
    std::uint64_t   seq          = 0;
    std::uint64_t   timestamp_ns = 0;
    sl_event_type_t type         = SL_EV_INTERNAL;
    std::vector<std::uint8_t> payload;
};

using ReplayHandler = std::function<void(const ReplayEvent&)>;

struct ReplayStats {
    std::uint64_t events_seen      = 0;
    std::uint64_t events_dispatched = 0;
    std::uint64_t events_skipped   = 0;
    std::uint64_t elapsed_ns       = 0;
};

class ReplayHarness {
public:
    void on(sl_event_type_t type, ReplayHandler handler);

    // Set a global fallback handler invoked for events with no specific
    // handler. nullptr (default) skips such events silently.
    void on_default(ReplayHandler handler);

    // Run all events from a file. respect_timing pauses between events
    // according to the captured timestamps (capped at max_sleep_ms).
    ReplayStats run_file(const std::string& path,
                         bool respect_timing = false,
                         std::uint32_t max_sleep_ms = 200);

    // Run a single in-memory event vector. Useful in tests.
    ReplayStats run_events(const std::vector<ReplayEvent>& events,
                           bool respect_timing = false,
                           std::uint32_t max_sleep_ms = 200);

private:
    static int visitor_thunk(const sl_event_record_t* rec, void* user);

    struct RunCtx {
        ReplayHarness*           self;
        ReplayStats              stats;
        bool                     respect_timing;
        std::uint32_t            max_sleep_ms;
        std::uint64_t            prev_ts_ns;
    };

    void dispatch(const ReplayEvent& ev);

    std::unordered_map<int, ReplayHandler> handlers_;
    ReplayHandler default_handler_;
};

}  // namespace securelink
