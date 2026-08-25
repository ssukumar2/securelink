#pragma once
// Wire framing for securelink. Frames are length-prefixed records:
//
//   offset  size  field
//   0       4     length     (big-endian, payload bytes only, excludes header)
//   4       1     type       (FrameType enum)
//   5       1     flags      (bitfield, reserved)
//   6       2     reserved   (must be zero on send, ignored on receive)
//   8       N     payload    (length bytes)
//
// FrameParser is a streaming consumer: feed it bytes as they arrive on the
// socket and it will yield complete frames or report errors.

#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

#include "byte_order.hpp"
#include "constants.hpp"

namespace securelink {

enum class FrameType : std::uint8_t {
    kInvalid       = 0,
    kHandshakeHi   = 1,   // client hello
    kHandshakeAck  = 2,   // server hello
    kHandshakeFin  = 3,   // handshake finished
    kData          = 4,   // encrypted application data
    kKeyUpdate     = 5,   // request/perform key rotation
    kCloseNotify   = 6,   // graceful shutdown
    kPing          = 7,
    kPong          = 8,
};

enum class ParseStatus {
    kNeedMore,    // not enough bytes yet, call again later
    kReady,       // a full frame is available via take_frame()
    kErrorOversize,
    kErrorBadType,
    kErrorBadReserved,
};

struct Frame {
    FrameType            type   = FrameType::kInvalid;
    std::uint8_t         flags  = 0;
    std::vector<std::uint8_t> payload;
};

class FrameParser {
public:
    explicit FrameParser(std::size_t max_frame = constants::MAX_FRAME_SIZE)
        : max_frame_(max_frame) {}

    // Append raw bytes from the socket.
    void feed(const std::uint8_t* data, std::size_t len) {
        buf_.insert(buf_.end(), data, data + len);
    }

    // Try to extract the next frame. Removes consumed bytes from the buffer.
    ParseStatus next(Frame& out) {
        if (buf_.size() < constants::FRAME_HEADER_SIZE) {
            return ParseStatus::kNeedMore;
        }

        const std::uint32_t length = bo::unpack_u32_be(buf_.data());
        const std::uint8_t  type   = buf_[4];
        const std::uint8_t  flags  = buf_[5];
        const std::uint16_t rsv    = static_cast<std::uint16_t>(buf_[6]) << 8 | buf_[7];

        if (rsv != 0) {
            return ParseStatus::kErrorBadReserved;
        }
        if (length > max_frame_) {
            return ParseStatus::kErrorOversize;
        }
        if (type == 0 || type > static_cast<std::uint8_t>(FrameType::kPong)) {
            return ParseStatus::kErrorBadType;
        }

        const std::size_t total = constants::FRAME_HEADER_SIZE + length;
        if (buf_.size() < total) {
            return ParseStatus::kNeedMore;
        }

        out.type  = static_cast<FrameType>(type);
        out.flags = flags;
        // Explicit cast, not an implicit narrowing conversion: `total` is
        // std::size_t (unsigned) but iterator arithmetic needs the
        // vector's signed difference_type. In practice `total` is always
        // small here -- length was already checked against max_frame_
        // above -- but max_frame_ is caller-configurable, so this makes
        // the conversion visible instead of silently implementation-
        // defined if someone ever configures an unreasonably large one.
        const auto total_offset =
            static_cast<std::vector<std::uint8_t>::difference_type>(total);
        out.payload.assign(buf_.begin() + constants::FRAME_HEADER_SIZE,
                           buf_.begin() + total_offset);
        buf_.erase(buf_.begin(), buf_.begin() + total_offset);
        return ParseStatus::kReady;
    }

    // Build a frame for transmission. Returns the encoded bytes.
    static std::vector<std::uint8_t> encode(FrameType type,
                                            std::uint8_t flags,
                                            const std::uint8_t* payload,
                                            std::size_t payload_len) {
        std::vector<std::uint8_t> out(constants::FRAME_HEADER_SIZE + payload_len);
        bo::pack_u32_be(out.data(), static_cast<std::uint32_t>(payload_len));
        out[4] = static_cast<std::uint8_t>(type);
        out[5] = flags;
        out[6] = 0;
        out[7] = 0;
        if (payload_len > 0) {
            std::memcpy(out.data() + constants::FRAME_HEADER_SIZE, payload, payload_len);
        }
        return out;
    }

    std::size_t buffered() const noexcept { return buf_.size(); }
    void        reset()          noexcept { buf_.clear(); }

private:
    std::vector<std::uint8_t> buf_;
    std::size_t               max_frame_;
};

}  // namespace securelink
