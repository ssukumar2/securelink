// Tests for InMemorySpanExporter and span_to_json.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_span_exporter.cpp \
//       src/span.cpp src/span_exporter.cpp \
//       src/sl_trace_context.c src/sl_trace_id.c src/sl_trace_flags.c \
//       src/sl_span_kind.c src/sl_rng.c \
//       -lpthread -lcrypto -o test_span_exporter

#include <cstdio>
#include <sstream>

#include "span_exporter.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static Span make_span(const std::string& name) {
    sl_trace_ctx_t ctx{};
    sl_trace_ctx_root(&ctx);
    sl_trace_ctx_t no_parent{};
    Span s(ctx, no_parent, name, SL_SPAN_INTERNAL);
    s.set_attribute("k", "v");
    s.add_event("started");
    s.set_status(SL_SPAN_STATUS_OK);
    s.end();
    return s;
}

static int test_in_memory_collects_then_drains(void) {
    InMemorySpanExporter ex;
    ex.export_span(make_span("a"));
    ex.export_span(make_span("b"));
    CHECK(ex.size() == 2);

    auto drained = ex.drain();
    CHECK(drained.size() == 2);
    CHECK(drained[0].name() == "a");
    CHECK(drained[1].name() == "b");
    CHECK(ex.size() == 0);
    return 0;
}

static int test_json_contains_expected_fields(void) {
    Span s = make_span("rpc.echo");
    const auto json = span_to_json(s);
    CHECK(json.find("\"name\":\"rpc.echo\"") != std::string::npos);
    CHECK(json.find("\"kind\":\"internal\"") != std::string::npos);
    CHECK(json.find("\"status\":\"ok\"")     != std::string::npos);
    CHECK(json.find("\"k\":\"v\"")           != std::string::npos);
    CHECK(json.find("\"trace_id\":")         != std::string::npos);
    CHECK(json.find("\"span_id\":")          != std::string::npos);
    return 0;
}

static int test_json_escapes_special_chars(void) {
    sl_trace_ctx_t ctx{}; sl_trace_ctx_root(&ctx);
    sl_trace_ctx_t no_parent{};
    Span s(ctx, no_parent, "needs\nquote\"and\\slash", SL_SPAN_INTERNAL);
    s.end();
    const auto json = span_to_json(s);
    CHECK(json.find("\\n")  != std::string::npos);
    CHECK(json.find("\\\"") != std::string::npos);
    CHECK(json.find("\\\\") != std::string::npos);
    return 0;
}

static int test_json_stdout_writes_lines(void) {
    std::ostringstream oss;
    JsonStdoutSpanExporter ex(oss);
    ex.export_span(make_span("first"));
    ex.export_span(make_span("second"));
    ex.flush();
    const auto out = oss.str();
    CHECK(out.find("\"name\":\"first\"")  != std::string::npos);
    CHECK(out.find("\"name\":\"second\"") != std::string::npos);
    CHECK(out.find('\n') != std::string::npos);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_in_memory_collects_then_drains();
    rc |= test_json_contains_expected_fields();
    rc |= test_json_escapes_special_chars();
    rc |= test_json_stdout_writes_lines();
    if (rc == 0) std::puts("test_span_exporter: OK");
    return rc;
}
