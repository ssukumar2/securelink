// Tests for Tracer and ScopedSpan.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_tracer.cpp \
//       src/tracer.cpp src/span.cpp src/span_exporter.cpp \
//       src/sl_trace_sampler.c src/sl_trace_context.c \
//       src/sl_trace_id.c src/sl_trace_flags.c \
//       src/sl_span_kind.c src/sl_rng.c \
//       -lpthread -lcrypto -o test_tracer

#include <cstdio>
#include <cstring>
#include <memory>

#include "tracer.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_always_sample_exports_every_span(void) {
    auto ex = std::make_shared<InMemorySpanExporter>();
    TracerConfig cfg; cfg.sample_ratio = 1.0;
    Tracer t(cfg, ex);

    {
        ScopedSpan ss(t, t.start_root_span("op", SL_SPAN_SERVER));
        ss.span().set_attribute("k", "v");
    }
    CHECK(ex->size() == 1);
    auto spans = ex->drain();
    CHECK(spans[0].name() == "op");
    CHECK(spans[0].kind() == SL_SPAN_SERVER);
    return 0;
}

static int test_never_sample_drops(void) {
    auto ex = std::make_shared<InMemorySpanExporter>();
    TracerConfig cfg; cfg.sample_ratio = 0.0;
    Tracer t(cfg, ex);

    {
        ScopedSpan ss(t, t.start_root_span("op", SL_SPAN_INTERNAL));
    }
    CHECK(ex->size() == 0);
    CHECK(t.stats().spans_dropped == 1);
    CHECK(t.stats().spans_exported == 0);
    return 0;
}

static int test_child_inherits_trace_id(void) {
    auto ex = std::make_shared<InMemorySpanExporter>();
    TracerConfig cfg; cfg.sample_ratio = 1.0;
    Tracer t(cfg, ex);

    Span parent = t.start_root_span("parent", SL_SPAN_INTERNAL);
    Span child  = t.start_span(parent.context(), "child", SL_SPAN_CLIENT);

    CHECK(std::memcmp(&parent.context().trace_id,
                      &child.context().trace_id,
                      sizeof(parent.context().trace_id)) == 0);
    CHECK(std::memcmp(&parent.context().span_id,
                      &child.context().span_id,
                      sizeof(parent.context().span_id)) != 0);
    CHECK(std::memcmp(&parent.context().span_id,
                      &child.parent_ctx().span_id,
                      sizeof(parent.context().span_id)) == 0);

    child.end();  t.finish(child);
    parent.end(); t.finish(parent);
    return 0;
}

static int test_scoped_span_ends_on_destruct(void) {
    auto ex = std::make_shared<InMemorySpanExporter>();
    TracerConfig cfg; cfg.sample_ratio = 1.0;
    Tracer t(cfg, ex);

    {
        ScopedSpan ss(t, t.start_root_span("scoped", SL_SPAN_INTERNAL));
        CHECK(!ss.span().is_ended());
    }
    CHECK(ex->size() == 1);
    auto s = ex->drain();
    CHECK(s[0].duration().count() >= 0);
    return 0;
}

static int test_stats_count_started(void) {
    auto ex = std::make_shared<InMemorySpanExporter>();
    TracerConfig cfg; cfg.sample_ratio = 1.0;
    Tracer t(cfg, ex);

    {
        ScopedSpan a(t, t.start_root_span("a", SL_SPAN_INTERNAL));
        ScopedSpan b(t, t.start_span(a.span().context(), "b", SL_SPAN_INTERNAL));
        ScopedSpan c(t, t.start_span(b.span().context(), "c", SL_SPAN_INTERNAL));
        (void)a; (void)b; (void)c;
    }
    CHECK(t.stats().spans_started == 3);
    CHECK(t.stats().spans_exported == 3);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_always_sample_exports_every_span();
    rc |= test_never_sample_drops();
    rc |= test_child_inherits_trace_id();
    rc |= test_scoped_span_ends_on_destruct();
    rc |= test_stats_count_started();
    if (rc == 0) std::puts("test_tracer: OK");
    return rc;
}
