#pragma once
// Header-only hexdump utility for debugging crypto/protocol buffers.
//
// Output format (canonical xxd-style):
//   00000000  48 65 6c 6c 6f 20 77 6f  72 6c 64 21 0a 00 ff 7f  |Hello world!....|
//   00000010  ...
//
// Usage:
//   securelink::hexdump(std::cout, buf, len);
//   std::string s = securelink::hexdump_to_string(buf, len);
//   securelink::hexdump_log("handshake_msg", buf, len);   // -> logger

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>

#include "logger.hpp"

namespace securelink {

namespace detail {

inline char printable_or_dot(std::uint8_t b) {
    return (b >= 0x20 && b < 0x7f) ? static_cast<char>(b) : '.';
}

inline void write_offset(std::ostream& os, std::size_t off) {
    std::ios old_state(nullptr);
    old_state.copyfmt(os);
    os << std::hex << std::setw(8) << std::setfill('0') << off;
    os.copyfmt(old_state);
}

}  // namespace detail

// Width (bytes per row) is fixed at 16 for canonical output.
constexpr std::size_t HEXDUMP_ROW = 16;

inline void hexdump(std::ostream& os, const void* data, std::size_t len) {
    const auto* p = static_cast<const std::uint8_t*>(data);

    for (std::size_t row = 0; row < len; row += HEXDUMP_ROW) {
        detail::write_offset(os, row);
        os << "  ";

        // Hex columns
        for (std::size_t col = 0; col < HEXDUMP_ROW; ++col) {
            const std::size_t idx = row + col;
            if (idx < len) {
                std::ios old_state(nullptr);
                old_state.copyfmt(os);
                os << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<unsigned>(p[idx]);
                os.copyfmt(old_state);
            } else {
                os << "  ";
            }
            os << ((col == 7) ? "  " : " ");
        }

        // ASCII gutter
        os << " |";
        for (std::size_t col = 0; col < HEXDUMP_ROW; ++col) {
            const std::size_t idx = row + col;
            if (idx < len) {
                os << detail::printable_or_dot(p[idx]);
            } else {
                os << ' ';
            }
        }
        os << "|\n";
    }
}

inline std::string hexdump_to_string(const void* data, std::size_t len) {
    std::ostringstream oss;
    hexdump(oss, data, len);
    return oss.str();
}

// Compact one-line hex string, e.g. "48656c6c6f". Useful for log fields.
inline std::string to_hex(const void* data, std::size_t len) {
    static const char kDigits[] = "0123456789abcdef";
    const auto* p = static_cast<const std::uint8_t*>(data);
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i]     = kDigits[(p[i] >> 4) & 0x0F];
        out[2 * i + 1] = kDigits[p[i] & 0x0F];
    }
    return out;
}

// Log a labelled dump at debug level. No-op if logger is below debug.
inline void hexdump_log(std::string_view label, const void* data, std::size_t len) {
    Logger::debug() << "hexdump[" << label << "] " << len << " bytes\n"
                    << hexdump_to_string(data, len);
}

}  // namespace securelink
