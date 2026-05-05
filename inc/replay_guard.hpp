#pragma once
// Sliding-window replay protection for monotonic 64-bit sequence numbers.
//
// Algorithm: RFC 4303 / RFC 6479 style bitmap window. The guard tracks the
// highest sequence number seen and a bitmap of the last N numbers below it.
// A sequence is rejected if:
//   - it has been seen before (bit set in window), or
//   - it is older than the trailing edge of the window.
// Window size is a power of two for fast modulo via mask.
//
// This class is NOT thread-safe by itself — wrap with a mutex if a single
// guard is shared across threads. In practice each connection has its own.

#include <array>
#include <cstdint>
#include <limits>

#include "constants.hpp"

namespace securelink {

template <std::uint32_t WindowSize = constants::REPLAY_WINDOW_SIZE>
class ReplayGuard {
    static_assert(WindowSize >= 64, "window must be at least 64");
    static_assert((WindowSize & (WindowSize - 1)) == 0,
                  "window size must be a power of two");

public:
    static constexpr std::uint32_t kWindow = WindowSize;
    static constexpr std::uint32_t kWords  = WindowSize / 64;

    ReplayGuard() = default;

    // Test+set. Returns true if `seq` is fresh and was accepted.
    // Returns false if `seq` is a replay or too old.
    bool check_and_update(std::uint64_t seq) noexcept {
        // Sequence 0 is reserved as "uninitialized". Reject it explicitly.
        if (seq == 0) {
            return false;
        }

        if (seq > highest_) {
            advance_to(seq);
            set_bit(seq);
            highest_ = seq;
            ++accepted_;
            return true;
        }

        // seq <= highest_: must be inside the window and not previously seen.
        const std::uint64_t diff = highest_ - seq;
        if (diff >= kWindow) {
            ++rejected_too_old_;
            return false;
        }
        if (test_bit(seq)) {
            ++rejected_replay_;
            return false;
        }
        set_bit(seq);
        ++accepted_;
        return true;
    }

    // Read-only test, useful for diagnostics. Does not mutate state.
    bool would_accept(std::uint64_t seq) const noexcept {
        if (seq == 0) return false;
        if (seq > highest_) return true;
        const std::uint64_t diff = highest_ - seq;
        if (diff >= kWindow) return false;
        return !test_bit(seq);
    }

    void reset() noexcept {
        bitmap_.fill(0);
        highest_ = 0;
        accepted_ = rejected_replay_ = rejected_too_old_ = 0;
    }

    std::uint64_t highest()           const noexcept { return highest_; }
    std::uint64_t accepted_count()    const noexcept { return accepted_; }
    std::uint64_t replay_count()      const noexcept { return rejected_replay_; }
    std::uint64_t too_old_count()     const noexcept { return rejected_too_old_; }

private:
    void advance_to(std::uint64_t new_high) noexcept {
        const std::uint64_t shift = new_high - highest_;
        if (shift >= kWindow) {
            bitmap_.fill(0);
            return;
        }
        // Shift bitmap left by `shift` positions, clearing low bits.
        const std::uint32_t word_shift = static_cast<std::uint32_t>(shift / 64);
        const std::uint32_t bit_shift  = static_cast<std::uint32_t>(shift % 64);

        if (word_shift > 0) {
            for (std::int32_t i = static_cast<std::int32_t>(kWords) - 1; i >= 0; --i) {
                const std::int32_t src = i - static_cast<std::int32_t>(word_shift);
                bitmap_[i] = (src >= 0) ? bitmap_[src] : 0;
            }
        }
        if (bit_shift > 0) {
            for (std::int32_t i = static_cast<std::int32_t>(kWords) - 1; i >= 0; --i) {
                std::uint64_t hi = bitmap_[i] << bit_shift;
                std::uint64_t lo = (i > 0) ? (bitmap_[i - 1] >> (64 - bit_shift)) : 0;
                bitmap_[i] = hi | lo;
            }
        }
    }

    std::uint32_t index_of(std::uint64_t seq) const noexcept {
        // Position relative to highest_, mapped into the bitmap.
        const std::uint64_t pos = (highest_ >= seq) ? (highest_ - seq)
                                                    : (kWindow - 1);
        return static_cast<std::uint32_t>(pos & (kWindow - 1));
    }

    bool test_bit(std::uint64_t seq) const noexcept {
        const std::uint32_t idx = index_of(seq);
        return (bitmap_[idx / 64] >> (idx % 64)) & 1ULL;
    }

    void set_bit(std::uint64_t seq) noexcept {
        const std::uint32_t idx = index_of(seq);
        bitmap_[idx / 64] |= (1ULL << (idx % 64));
    }

    std::array<std::uint64_t, kWords> bitmap_{};
    std::uint64_t highest_           = 0;
    std::uint64_t accepted_          = 0;
    std::uint64_t rejected_replay_   = 0;
    std::uint64_t rejected_too_old_  = 0;
};

}  // namespace securelink
