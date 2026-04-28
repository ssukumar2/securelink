#pragma once
#include <cstdint>
#include <cstdio>
#include <string>
#include <sstream>
#include <iomanip>

inline std::string hexdump(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    for (size_t i = 0; i < len; i += 16) {
        ss << std::setw(4) << std::setfill('0') << std::hex << i << "  ";
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len)
                ss << std::setw(2) << std::setfill('0') << std::hex
                   << static_cast<int>(data[i + j]) << " ";
            else
                ss << "   ";
            if (j == 7) ss << " ";
        }
        ss << " |";
        for (size_t j = 0; j < 16 && i + j < len; ++j) {
            char c = static_cast<char>(data[i + j]);
            ss << (c >= 32 && c < 127 ? c : '.');
        }
        ss << "|\n";
    }
    return ss.str();
}

inline void print_hexdump(const char* label, const uint8_t* data, size_t len) {
    printf("--- %s (%zu bytes) ---\n%s", label, len, hexdump(data, len).c_str());
}
