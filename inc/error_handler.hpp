#pragma once
// Error type and Result<T, E> for the securelink codebase.
// Avoids exceptions on hot paths; exceptions remain valid for truly
// unrecoverable failures (e.g. allocation).

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace securelink {

enum class ErrorCode : std::uint16_t {
    kOk = 0,

    // I/O
    kIoWouldBlock = 100,
    kIoClosed,
    kIoError,
    kIoTimeout,

    // Protocol
    kFrameOversize = 200,
    kFrameBadType,
    kFrameBadReserved,
    kFrameTruncated,
    kHandshakeFailed,
    kReplayDetected,
    kSequenceOutOfWindow,

    // Crypto
    kCryptoInit = 300,
    kCryptoKeyDerive,
    kCryptoEncrypt,
    kCryptoDecrypt,
    kCryptoBadTag,
    kCryptoRng,

    // Resource
    kRateLimited = 400,
    kTooManyConnections,
    kOutOfMemory,

    // Generic
    kInvalidArgument = 900,
    kNotImplemented,
    kInternal,
};

struct Error {
    ErrorCode   code = ErrorCode::kOk;
    std::string what;

    Error() = default;
    Error(ErrorCode c, std::string msg) : code(c), what(std::move(msg)) {}

    bool ok() const noexcept { return code == ErrorCode::kOk; }
};

inline std::string_view to_string(ErrorCode c) noexcept {
    switch (c) {
        case ErrorCode::kOk:                   return "ok";
        case ErrorCode::kIoWouldBlock:         return "io_would_block";
        case ErrorCode::kIoClosed:             return "io_closed";
        case ErrorCode::kIoError:              return "io_error";
        case ErrorCode::kIoTimeout:            return "io_timeout";
        case ErrorCode::kFrameOversize:        return "frame_oversize";
        case ErrorCode::kFrameBadType:         return "frame_bad_type";
        case ErrorCode::kFrameBadReserved:     return "frame_bad_reserved";
        case ErrorCode::kFrameTruncated:       return "frame_truncated";
        case ErrorCode::kHandshakeFailed:      return "handshake_failed";
        case ErrorCode::kReplayDetected:       return "replay_detected";
        case ErrorCode::kSequenceOutOfWindow:  return "sequence_out_of_window";
        case ErrorCode::kCryptoInit:           return "crypto_init";
        case ErrorCode::kCryptoKeyDerive:      return "crypto_key_derive";
        case ErrorCode::kCryptoEncrypt:        return "crypto_encrypt";
        case ErrorCode::kCryptoDecrypt:        return "crypto_decrypt";
        case ErrorCode::kCryptoBadTag:         return "crypto_bad_tag";
        case ErrorCode::kCryptoRng:            return "crypto_rng";
        case ErrorCode::kRateLimited:          return "rate_limited";
        case ErrorCode::kTooManyConnections:   return "too_many_connections";
        case ErrorCode::kOutOfMemory:          return "out_of_memory";
        case ErrorCode::kInvalidArgument:      return "invalid_argument";
        case ErrorCode::kNotImplemented:       return "not_implemented";
        case ErrorCode::kInternal:             return "internal";
    }
    return "unknown";
}

template <typename T>
class Result {
public:
    Result(T value)            : data_(std::move(value)) {}
    Result(Error err)          : data_(std::move(err))   {}

    bool ok() const noexcept { return std::holds_alternative<T>(data_); }
    explicit operator bool() const noexcept { return ok(); }

    T&       value()       { return std::get<T>(data_); }
    const T& value() const { return std::get<T>(data_); }

    const Error& error() const { return std::get<Error>(data_); }

    T value_or(T fallback) const {
        return ok() ? std::get<T>(data_) : std::move(fallback);
    }

private:
    std::variant<T, Error> data_;
};

// Specialization for Result<void>.
template <>
class Result<void> {
public:
    Result()                : err_() {}
    Result(Error err)       : err_(std::move(err)) {}

    bool ok() const noexcept { return err_.ok(); }
    explicit operator bool() const noexcept { return ok(); }
    const Error& error() const { return err_; }

private:
    Error err_;
};

}  // namespace securelink
