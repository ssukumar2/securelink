#pragma once
// Portable host<->network byte order helpers for 16/32/64-bit values.
// Avoids pulling in <arpa/inet.h> at every call site and adds 64-bit support.

#include <cstdint>
#include <cstring>

namespace securelink::bo {

inline std::uint16_t hton16(std::uint16_t v) {
    return static_cast<std::uint16_t>((v << 8) | (v >> 8));
}

inline std::uint32_t hton32(std::uint32_t v) {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8)  | ((v & 0xFF000000u) >> 24);
}

inline std::uint64_t hton64(std::uint64_t v) {
    return (static_cast<std::uint64_t>(hton32(static_cast<std::uint32_t>(v))) << 32) |
           hton32(static_cast<std::uint32_t>(v >> 32));
}

inline std::uint16_t ntoh16(std::uint16_t v) { return hton16(v); }
inline std::uint32_t ntoh32(std::uint32_t v) { return hton32(v); }
inline std::uint64_t ntoh64(std::uint64_t v) { return hton64(v); }

// Safe pack/unpack into byte buffers (no aliasing UB).
inline void pack_u32_be(std::uint8_t* out, std::uint32_t v) {
    out[0] = static_cast<std::uint8_t>(v >> 24);
    out[1] = static_cast<std::uint8_t>(v >> 16);
    out[2] = static_cast<std::uint8_t>(v >> 8);
    out[3] = static_cast<std::uint8_t>(v);
}

inline std::uint32_t unpack_u32_be(const std::uint8_t* in) {
    return (static_cast<std::uint32_t>(in[0]) << 24) |
           (static_cast<std::uint32_t>(in[1]) << 16) |
           (static_cast<std::uint32_t>(in[2]) << 8)  |
            static_cast<std::uint32_t>(in[3]);
}

inline void pack_u64_be(std::uint8_t* out, std::uint64_t v) {
    pack_u32_be(out,     static_cast<std::uint32_t>(v >> 32));
    pack_u32_be(out + 4, static_cast<std::uint32_t>(v));
}

inline std::uint64_t unpack_u64_be(const std::uint8_t* in) {
    return (static_cast<std::uint64_t>(unpack_u32_be(in)) << 32) |
            static_cast<std::uint64_t>(unpack_u32_be(in + 4));
}

}  // namespace securelink::bo
