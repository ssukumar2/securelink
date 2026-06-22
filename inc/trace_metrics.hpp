#pragma once
// TraceMetrics — wires the tracer into the metrics_registry so
// dashboards see counts and durations alongside the spans themselves.
//
// Registered counters:
//   securelink_spans_started
//   securelink_spans_exported
//   securelink_spans_dropped
// Histogram-style summary (running min / max / p50-ish via reservoir):
//   securelink_span_duration_us
//
// This is a thin adapter; the tracer remains the source of truth.

#include <memory>

#include "metrics_registry.hpp"
#include "span.hpp"
#include "span_exporter.hpp"

namespace securelink {

class TraceMetrics : public SpanExporter {
public:
    TraceMetrics(std::shared_ptr<SpanExporter> downstream,
                 std::shared_ptr<MetricsRegistry> metrics);

    void export_span(const Span& span) override;
    void flush() override;

    void note_started();
    void note_dropped();

private:
    void ensure_registered();

    std::shared_ptr<SpanExporter>    downstream_;
    std::shared_ptr<MetricsRegistry> metrics_;
    bool                             registered_ = false;
};

}  // namespace securelink
