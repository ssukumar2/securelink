#pragma once
// Tracer — factory for spans. Holds the sampling decision policy and
// the exporter sink.
//
// Each service constructs one Tracer at startup, sharing it across
// request handlers. start_span() returns a Span you fill in and then
// end() — when the span is ended, the tracer routes it through the
// exporter if sampled.

#include <memory>
#include <mutex>
#include <string>

#include "span.hpp"
#include "span_exporter.hpp"
#include "sl_trace_sampler.h"

namespace securelink {

struct TracerConfig {
    std::string service_name = "securelink";
    double      sample_ratio = 1.0;
};

class Tracer {
public:
    Tracer(TracerConfig cfg, std::shared_ptr<SpanExporter> exporter);

    // Start a root span (no parent).
    Span start_root_span(const std::string& name,
                         sl_span_kind_t kind = SL_SPAN_INTERNAL);

    // Start a child span under an existing context. If `parent_ctx`
    // is zero, behaves like start_root_span.
    Span start_span(const sl_trace_ctx_t& parent_ctx,
                    const std::string& name,
                    sl_span_kind_t kind);

    // Called by Span on end(); applies sampling and forwards to exporter.
    void finish(const Span& span);

    const TracerConfig& config() const { return cfg_; }

    struct Stats {
        std::uint64_t spans_started   = 0;
        std::uint64_t spans_exported  = 0;
        std::uint64_t spans_dropped   = 0;
    };
    Stats stats() const;

private:
    TracerConfig                   cfg_;
    sl_trace_sampler_t             sampler_{};
    std::shared_ptr<SpanExporter>  exporter_;
    mutable std::mutex             mu_;
    Stats                          stats_;
};

// RAII helper that calls end() on scope exit and routes through tracer.
class ScopedSpan {
public:
    ScopedSpan(Tracer& tracer, Span span);
    ~ScopedSpan();

    ScopedSpan(const ScopedSpan&) = delete;
    ScopedSpan& operator=(const ScopedSpan&) = delete;

    Span& span() { return span_; }
    const Span& span() const { return span_; }

private:
    Tracer& tracer_;
    Span    span_;
};

}  // namespace securelink
