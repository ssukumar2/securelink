#pragma once
// SpanExporter — sink for finished spans.
//
// Two built-in implementations:
//   InMemorySpanExporter — buffers spans for inspection (tests, /debug).
//   JsonStdoutSpanExporter — writes one JSON object per line to stderr,
//       easy to pipe into anything that reads JSON lines.
//
// The interface is intentionally narrow; production deployments would
// add an OtlpSpanExporter that ships over gRPC or HTTP.

#include <memory>
#include <mutex>
#include <ostream>
#include <string>
#include <vector>

#include "span.hpp"

namespace securelink {

class SpanExporter {
public:
    virtual ~SpanExporter() = default;
    virtual void export_span(const Span& span) = 0;
    virtual void flush() {}
};

class InMemorySpanExporter : public SpanExporter {
public:
    void export_span(const Span& span) override;
    std::vector<Span> drain();
    std::size_t       size() const;

private:
    mutable std::mutex mu_;
    std::vector<Span>  spans_;
};

class JsonStdoutSpanExporter : public SpanExporter {
public:
    explicit JsonStdoutSpanExporter(std::ostream& os);
    void export_span(const Span& span) override;
    void flush() override;
private:
    std::ostream&      os_;
    mutable std::mutex mu_;
};

// Helpers exposed for testing.
std::string span_to_json(const Span& span);

}  // namespace securelink
