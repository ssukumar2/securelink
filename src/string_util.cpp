#include "string_util.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>

namespace securelink::str {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    return s;
}

bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool contains(std::string_view s, std::string_view needle) {
    return s.find(needle) != std::string_view::npos;
}

bool ieq(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

std::string_view trim_left(std::string_view s) {
    std::size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    return s.substr(i);
}

std::string_view trim_right(std::string_view s) {
    std::size_t n = s.size();
    while (n > 0 && std::isspace(static_cast<unsigned char>(s[n - 1]))) --n;
    return s.substr(0, n);
}

std::string_view trim(std::string_view s) { return trim_left(trim_right(s)); }

std::vector<std::string> split(std::string_view s, char sep, bool keep_empty) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == sep) {
            const auto part = s.substr(start, i - start);
            if (keep_empty || !part.empty()) out.emplace_back(part);
            start = i + 1;
        }
    }
    return out;
}

std::string join(const std::vector<std::string>& parts, std::string_view sep) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) out.append(sep);
        out.append(parts[i]);
    }
    return out;
}

std::string replace_all(std::string s, std::string_view from,
                        std::string_view to) {
    if (from.empty()) return s;
    std::size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
    return s;
}

std::string human_bytes(std::uint64_t n) {
    static constexpr std::array<const char*, 6> units = {
        "B", "KiB", "MiB", "GiB", "TiB", "PiB"};
    double v = static_cast<double>(n);
    std::size_t u = 0;
    while (v >= 1024.0 && u + 1 < units.size()) { v /= 1024.0; ++u; }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f %s", v, units[u]);
    return std::string(buf);
}

std::string human_duration_ms(std::uint64_t ms) {
    const std::uint64_t sec = ms / 1000;
    const std::uint64_t h   = sec / 3600;
    const std::uint64_t m   = (sec % 3600) / 60;
    const std::uint64_t s   = sec % 60;
    char buf[32];
    if (h > 0)      std::snprintf(buf, sizeof(buf), "%lluh%02llum",
                                  (unsigned long long)h, (unsigned long long)m);
    else if (m > 0) std::snprintf(buf, sizeof(buf), "%llum%02llus",
                                  (unsigned long long)m, (unsigned long long)s);
    else            std::snprintf(buf, sizeof(buf), "%llu.%03llus",
                                  (unsigned long long)s,
                                  (unsigned long long)(ms % 1000));
    return std::string(buf);
}

}  // namespace securelink::str
