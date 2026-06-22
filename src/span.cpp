#include "span.hpp"

namespace securelink {

Span::Span(sl_trace_ctx_t ctx,
           sl_trace_ctx_t parent,
           std::string name,
           sl_span_kind_t kind)
    : ctx_(ctx),
      parent_(parent),
      name_(std::move(name)),
      kind_(kind),
      start_(std::chrono::system_clock::now()) {}

void Span::set_attribute(std::string key, std::string value) {
    if (ended_) return;
    attrs_.push_back({std::move(key), std::move(value)});
}

void Span::add_event(std::string name) {
    add_event(std::move(name), {});
}

void Span::add_event(std::string name, std::vector<SpanAttribute> attrs) {
    if (ended_) return;
    events_.push_back({std::chrono::system_clock::now(),
                       std::move(name), std::move(attrs)});
}

void Span::set_status(sl_span_status_t status, std::string description) {
    if (ended_) return;
    status_      = status;
    status_desc_ = std::move(description);
}

void Span::end() {
    if (ended_) return;
    end_   = std::chrono::system_clock::now();
    ended_ = true;
}

std::chrono::microseconds Span::duration() const {
    const auto stop = ended_ ? end_ : std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(stop - start_);
}

}  // namespace securelink
