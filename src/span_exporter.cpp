#include "span_exporter.hpp"

#include <chrono>
#include <iomanip>
#include <sstream>

namespace securelink {

void InMemorySpanExporter::export_span(const Span& span) {
    std::lock_guard<std::mutex> lock(mu_);
    spans_.push_back(span);
}

std::vector<Span> InMemorySpanExporter::drain() {
    std::lock_guard<std::mutex> lock(mu_);
    auto out = std::move(spans_);
    spans_.clear();
    return out;
}

std::size_t InMemorySpanExporter::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return spans_.size();
}

JsonStdoutSpanExporter::JsonStdoutSpanExporter(std::ostream& os) : os_(os) {}

void JsonStdoutSpanExporter::export_span(const Span& span) {
    std::lock_guard<std::mutex> lock(mu_);
    os_ << span_to_json(span) << '\n';
}

void JsonStdoutSpanExporter::flush() {
    std::lock_guard<std::mutex> lock(mu_);
    os_.flush();
}

static void escape_json(std::ostream& os, const std::string& s) {
    os << '"';
    for (char c : s) {
        switch (c) {
            case '"':  os << "\\\""; break;
            case '\\': os << "\\\\"; break;
            case '\n': os << "\\n";  break;
            case '\r': os << "\\r";  break;
            case '\t': os << "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) {
                    os << "\\u" << std::hex << std::setw(4)
                       << std::setfill('0') << (int)(unsigned char)c
                       << std::dec << std::setw(0);
                } else {
                    os << c;
                }
        }
    }
    os << '"';
}

static std::uint64_t time_us(std::chrono::system_clock::time_point t) {
    return (std::uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
               t.time_since_epoch()).count();
}

std::string span_to_json(const Span& span) {
    char tid[SL_TRACE_ID_HEX_LEN + 1];
    char sid[SL_SPAN_ID_HEX_LEN  + 1];
    sl_trace_id_to_hex(&span.context().trace_id, tid, sizeof(tid));
    sl_span_id_to_hex (&span.context().span_id,  sid, sizeof(sid));

    char psid[SL_SPAN_ID_HEX_LEN + 1] = "";
    if (!sl_span_id_is_zero(&span.parent_ctx().span_id)) {
        sl_span_id_to_hex(&span.parent_ctx().span_id, psid, sizeof(psid));
    }

    std::ostringstream os;
    os << '{';
    os << "\"trace_id\":\""  << tid << "\",";
    os << "\"span_id\":\""   << sid << "\",";
    if (psid[0]) os << "\"parent_id\":\"" << psid << "\",";
    os << "\"name\":";       escape_json(os, span.name());            os << ',';
    os << "\"kind\":\""      << sl_span_kind_name(span.kind())   << "\",";
    os << "\"status\":\""    << sl_span_status_name(span.status()) << "\",";
    if (!span.status_desc().empty()) {
        os << "\"status_desc\":";
        escape_json(os, span.status_desc());
        os << ',';
    }
    os << "\"start_us\":"    << time_us(span.start_time()) << ',';
    os << "\"end_us\":"      << time_us(span.end_time())   << ',';
    os << "\"duration_us\":" << span.duration().count();

    if (!span.attributes().empty()) {
        os << ",\"attributes\":{";
        bool first = true;
        for (const auto& a : span.attributes()) {
            if (!first) os << ',';
            first = false;
            escape_json(os, a.key); os << ':'; escape_json(os, a.value);
        }
        os << '}';
    }

    if (!span.events().empty()) {
        os << ",\"events\":[";
        bool first = true;
        for (const auto& e : span.events()) {
            if (!first) os << ',';
            first = false;
            os << "{\"at_us\":" << time_us(e.at) << ',';
            os << "\"name\":";  escape_json(os, e.name);
            if (!e.attributes.empty()) {
                os << ",\"attributes\":{";
                bool inner_first = true;
                for (const auto& a : e.attributes) {
                    if (!inner_first) os << ',';
                    inner_first = false;
                    escape_json(os, a.key); os << ':'; escape_json(os, a.value);
                }
                os << '}';
            }
            os << '}';
        }
        os << ']';
    }
    os << '}';
    return os.str();
}

}  // namespace securelink
