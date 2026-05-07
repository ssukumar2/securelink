#pragma once
// Public-key fingerprint helpers. A fingerprint is a SHA-256 digest of the
// raw uncompressed EC public key bytes, formatted for human comparison.
//
// Two output styles:
//   hex_colon: "ab:cd:ef:01:..."   (full 32-byte digest)
//   short_id : "ABCD-EF01-2345"    (first 6 bytes, uppercase, dashed)
//
// Comparison is constant-time via secure_memory::ct_equal.

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

#include "secure_memory.hpp"

namespace securelink {

constexpr std::size_t kFingerprintBytes = 32;
using FingerprintBytes = std::array<std::uint8_t, kFingerprintBytes>;

// Format a digest as "ab:cd:ef:..." (lowercase, colon-separated).
inline std::string fingerprint_hex_colon(const FingerprintBytes& fp) {
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(kFingerprintBytes * 3 - 1);
    for (std::size_t i = 0; i < kFingerprintBytes; ++i) {
        if (i > 0) out.push_back(':');
        out.push_back(kDigits[(fp[i] >> 4) & 0x0F]);
        out.push_back(kDigits[fp[i] & 0x0F]);
    }
    return out;
}

// Short, human-friendly identifier from the first 6 bytes:
// "ABCD-EF01-2345" — useful for log lines and TOFU prompts.
inline std::string fingerprint_short_id(const FingerprintBytes& fp) {
    static const char kDigits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(14);
    for (std::size_t i = 0; i < 6; ++i) {
        if (i == 2 || i == 4) out.push_back('-');
        out.push_back(kDigits[(fp[i] >> 4) & 0x0F]);
        out.push_back(kDigits[fp[i] & 0x0F]);
    }
    return out;
}

// Constant-time fingerprint comparison.
inline bool fingerprint_equal(const FingerprintBytes& a,
                              const FingerprintBytes& b) noexcept {
    return ct_equal(a.data(), b.data(), kFingerprintBytes);
}

// Parse a colon-hex string back into bytes. Returns false on malformed input.
inline bool parse_fingerprint_hex_colon(const std::string& s,
                                        FingerprintBytes& out) noexcept {
    // Expected length: 32 bytes * 2 hex + 31 colons = 95.
    if (s.size() != 95) return false;
    auto hex_val = [](char c, std::uint8_t& v) -> bool {
        if (c >= '0' && c <= '9') { v = static_cast<std::uint8_t>(c - '0');      return true; }
        if (c >= 'a' && c <= 'f') { v = static_cast<std::uint8_t>(c - 'a' + 10); return true; }
        if (c >= 'A' && c <= 'F') { v = static_cast<std::uint8_t>(c - 'A' + 10); return true; }
        return false;
    };
    for (std::size_t i = 0; i < kFingerprintBytes; ++i) {
        const std::size_t off = i * 3;
        std::uint8_t hi, lo;
        if (!hex_val(s[off], hi) || !hex_val(s[off + 1], lo)) return false;
        if (i + 1 < kFingerprintBytes && s[off + 2] != ':')   return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

}  // namespace securelink
