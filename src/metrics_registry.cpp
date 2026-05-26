#include "metrics_registry.hpp"

#include <cstring>
#include <sstream>

namespace securelink {

std::string MetricsRegistry::make_key(const std::string& name,
                                      const LabelSet& labels) const {
    std::string k = name;
    k.push_back('{');
    bool first = true;
    for (const auto& [lk, lv] : labels) {
        if (!first) k.push_back(',');
        k += lk;
        k.push_back('=');
        k += lv;
        first = false;
    }
    k.push_back('}');
    return k;
}

Counter& MetricsRegistry::counter(const std::string& name,
                                  const LabelSet& labels) {
    std::lock_guard<std::mutex> lock(mu_);
    const auto key = make_key(name, labels);
    auto it = series_.find(key);
    if (it == series_.end()) {
        Series s;
        s.name    = name;
        s.labels  = labels;
        s.counter = std::make_shared<Counter>();
        it = series_.emplace(key, std::move(s)).first;
    }
    if (!it->second.counter) {
        it->second.counter = std::make_shared<Counter>();
    }
    return *it->second.counter;
}

Gauge& MetricsRegistry::gauge(const std::string& name,
                              const LabelSet& labels) {
    std::lock_guard<std::mutex> lock(mu_);
    const auto key = make_key(name, labels);
    auto it = series_.find(key);
    if (it == series_.end()) {
        Series s;
        s.name   = name;
        s.labels = labels;
        s.gauge  = std::make_shared<Gauge>();
        it = series_.emplace(key, std::move(s)).first;
    }
    if (!it->second.gauge) {
        it->second.gauge = std::make_shared<Gauge>();
    }
    return *it->second.gauge;
}

static void render_labels(std::ostream& os, const LabelSet& labels) {
    if (labels.empty()) return;
    os << "{";
    bool first = true;
    for (const auto& [k, v] : labels) {
        if (!first) os << ",";
        os << k << "=\"" << v << "\"";
        first = false;
    }
    os << "}";
}

void MetricsRegistry::render(std::ostream& os) const {
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto& [_, s] : series_) {
        if (s.counter) {
            os << "# TYPE " << s.name << " counter\n";
            os << s.name;
            render_labels(os, s.labels);
            os << " " << s.counter->value() << "\n";
        }
        if (s.gauge) {
            os << "# TYPE " << s.name << " gauge\n";
            os << s.name;
            render_labels(os, s.labels);
            os << " " << s.gauge->value() << "\n";
        }
    }
}

std::string MetricsRegistry::render_string() const {
    std::ostringstream oss;
    render(oss);
    return oss.str();
}

std::size_t MetricsRegistry::series_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return series_.size();
}

}  // namespace securelink
