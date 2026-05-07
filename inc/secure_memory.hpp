#pragma once
// Secure memory utilities for handling key material and sensitive buffers.
//
// - secure_zero(): compiler-barrier-protected memset that won't be elided.
// - SecureBuffer<N>: fixed-size buffer that zeroes itself on destruction
//   and optionally locks pages with mlock() to prevent swapping.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>

namespace securelink {

// Volatile pointer trick prevents the compiler from optimizing the memset away.
inline void secure_zero(void* p, std::size_t n) noexcept {
    if (p == nullptr || n == 0) return;
    volatile std::uint8_t* vp = static_cast<volatile std::uint8_t*>(p);
    while (n--) {
        *vp++ = 0;
    }
}

// Constant-time comparison. Returns true if buffers match.
// Use for MAC tags, tokens, fingerprints — anything attacker-influenced.
inline bool ct_equal(const void* a, const void* b, std::size_t n) noexcept {
    const auto* pa = static_cast<const std::uint8_t*>(a);
    const auto* pb = static_cast<const std::uint8_t*>(b);
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < n; ++i) {
        diff |= pa[i] ^ pb[i];
    }
    return diff == 0;
}

template <std::size_t N>
class SecureBuffer {
public:
    SecureBuffer() noexcept { lock_pages(); }

    ~SecureBuffer() noexcept {
        secure_zero(data_.data(), N);
        if (locked_) {
            ::munlock(data_.data(), N);
        }
    }

    SecureBuffer(const SecureBuffer&)            = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&&)                 = delete;
    SecureBuffer& operator=(SecureBuffer&&)      = delete;

    std::uint8_t*       data() noexcept       { return data_.data(); }
    const std::uint8_t* data() const noexcept { return data_.data(); }
    constexpr std::size_t size() const noexcept { return N; }

    std::uint8_t&       operator[](std::size_t i) noexcept       { return data_[i]; }
    const std::uint8_t& operator[](std::size_t i) const noexcept { return data_[i]; }

    void clear() noexcept { secure_zero(data_.data(), N); }

    bool equals(const SecureBuffer& other) const noexcept {
        return ct_equal(data_.data(), other.data_.data(), N);
    }

private:
    void lock_pages() noexcept {
        // Best-effort; ignore failure (e.g. RLIMIT_MEMLOCK too low).
        locked_ = (::mlock(data_.data(), N) == 0);
    }

    alignas(16) std::array<std::uint8_t, N> data_{};
    bool locked_ = false;
};

}  // namespace securelink
