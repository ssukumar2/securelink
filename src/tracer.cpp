#include "tracer.hpp"

namespace securelink {

Tracer::Tracer(TracerConfig cfg, std::shared_ptr<SpanExporter> exporter)
    : cfg_(std::move(cfg)), exporter_(std::move(exporter)) {
    sl_trace_sampler_init(&sampler_, cfg_.sample_ratio);
}

Span Tracer::start_root_span(const std::string& name, sl_span_kind_t kind) {
    sl_trace_ctx_t ctx{};
    sl_trace_ctx_root(&ctx);

    /* Apply sampler eagerly so children inherit the decision. */
    if (sl_trace_sampler_should_sample(&sampler_, &ctx)) {
        ctx.flags = sl_trace_flags_with(ctx.flags, SL_TRACE_FLAG_SAMPLED);
    }
    sl_trace_ctx_t no_parent{};
    {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.spans_started;
    }
    return Span(ctx, no_parent, name, kind);
}

Span Tracer::start_span(const sl_trace_ctx_t& parent_ctx,
                        const std::string& name,
                        sl_span_kind_t kind) {
    if (sl_trace_ctx_is_zero(&parent_ctx)) {
        return start_root_span(name, kind);
    }
    sl_trace_ctx_t child{};
    sl_trace_ctx_child(&parent_ctx, &child);
    {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.spans_started;
    }
    return Span(child, parent_ctx, name, kind);
}

void Tracer::finish(const Span& span) {
    const bool sampled = sl_trace_flag_is_set(span.context().flags,
                                              SL_TRACE_FLAG_SAMPLED);
    if (sampled && exporter_) {
        exporter_->export_span(span);
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.spans_exported;
    } else {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.spans_dropped;
    }
}

Tracer::Stats Tracer::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    return stats_;
}

ScopedSpan::ScopedSpan(Tracer& tracer, Span span)
    : tracer_(tracer), span_(std::move(span)) {}

ScopedSpan::~ScopedSpan() {
    if (!span_.is_ended()) span_.end();
    tracer_.finish(span_);
}

}  // namespace securelink
