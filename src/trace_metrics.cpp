#include "trace_metrics.hpp"

namespace securelink {

TraceMetrics::TraceMetrics(std::shared_ptr<SpanExporter> downstream,
                           std::shared_ptr<MetricsRegistry> metrics)
    : downstream_(std::move(downstream)), metrics_(std::move(metrics)) {
    ensure_registered();
}

void TraceMetrics::ensure_registered() {
    if (registered_ || !metrics_) return;
    metrics_->register_counter("securelink_spans_started",
                               "Total spans started by the tracer.");
    metrics_->register_counter("securelink_spans_exported",
                               "Total spans exported by the tracer.");
    metrics_->register_counter("securelink_spans_dropped",
                               "Total spans dropped (unsampled).");
    metrics_->register_gauge  ("securelink_span_duration_us_last",
                               "Microseconds of the most recently exported span.");
    registered_ = true;
}

void TraceMetrics::export_span(const Span& span) {
    if (metrics_) {
        metrics_->inc_counter("securelink_spans_exported");
        metrics_->set_gauge  ("securelink_span_duration_us_last",
                              (double)span.duration().count());
    }
    if (downstream_) downstream_->export_span(span);
}

void TraceMetrics::flush() {
    if (downstream_) downstream_->flush();
}

void TraceMetrics::note_started() {
    if (metrics_) metrics_->inc_counter("securelink_spans_started");
}

void TraceMetrics::note_dropped() {
    if (metrics_) metrics_->inc_counter("securelink_spans_dropped");
}

}  // namespace securelink
