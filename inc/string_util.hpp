#pragma once
// Small string utilities used across the C++ side. Header-only would be
// fine for most of these, but keeping the .cpp avoids inline-bloat in
// every translation unit that includes string-handling code.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace securelink::str {

std::string  to_lower(std::string s);
std::string  to_upper(std::string s);

bool starts_with(std::string_view s, std::string_view prefix);
bool ends_with  (std::string_view s, std::string_view suffix);
bool contains   (std::string_view s, std::string_view needle);
bool ieq        (std::string_view a, std::string_view b);

std::string_view trim_left (std::string_view s);
std::string_view trim_right(std::string_view s);
std::string_view trim      (std::string_view s);

std::vector<std::string> split(std::string_view s, char sep,
                               bool keep_empty = false);

std::string join(const std::vector<std::string>& parts, std::string_view sep);

std::string replace_all(std::string s, std::string_view from,
                        std::string_view to);

// "1.2 KiB", "3.4 MiB" — for log lines.
std::string human_bytes(std::uint64_t n);

// "1m12s", "3h04m" — durations from milliseconds.
std::string human_duration_ms(std::uint64_t ms);

}  // namespace securelink::str
