#pragma once
// Span — one unit of work in a trace.
//
// A span has a name, kind, start/end timestamps, status, attributes (key
// → string value pairs), and events (timestamped notes). Spans are
// finalized via end() and handed to a Tracer's exporter.
//
// Spans are NOT thread-safe — they belong to the work being measured.
// Each piece of work should own its own span; spawn child spans for
// parallel sub-operations.

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "sl_span_kind.h"
#include "sl_trace_context.h"

namespace securelink {

struct SpanAttribute {
    std::string key;
    std::string value;
};

struct SpanEvent {
    std::chrono::system_clock::time_point at;
    std::string                            name;
    std::vector<SpanAttribute>             attributes;
};

class Span {
public:
    Span(sl_trace_ctx_t ctx,
         sl_trace_ctx_t parent,
         std::string name,
         sl_span_kind_t kind);

    void set_attribute(std::string key, std::string value);
    void add_event    (std::string name);
    void add_event    (std::string name, std::vector<SpanAttribute> attrs);
    void set_status   (sl_span_status_t status, std::string description = "");

    void end();
    bool is_ended() const { return ended_; }

    const sl_trace_ctx_t&            context()      const { return ctx_; }
    const sl_trace_ctx_t&            parent_ctx()   const { return parent_; }
    const std::string&               name()         const { return name_; }
    sl_span_kind_t                   kind()         const { return kind_; }
    sl_span_status_t                 status()       const { return status_; }
    const std::string&               status_desc()  const { return status_desc_; }
    const std::vector<SpanAttribute>& attributes()  const { return attrs_; }
    const std::vector<SpanEvent>&     events()      const { return events_; }
    std::chrono::system_clock::time_point start_time() const { return start_; }
    std::chrono::system_clock::time_point end_time()   const { return end_;   }

    std::chrono::microseconds duration() const;

private:
    sl_trace_ctx_t     ctx_{};
    sl_trace_ctx_t     parent_{};
    std::string        name_;
    sl_span_kind_t     kind_;
    sl_span_status_t   status_       = SL_SPAN_STATUS_UNSET;
    std::string        status_desc_;
    std::vector<SpanAttribute> attrs_;
    std::vector<SpanEvent>     events_;
    std::chrono::system_clock::time_point start_;
    std::chrono::system_clock::time_point end_;
    bool                ended_       = false;
};

}  // namespace securelink
