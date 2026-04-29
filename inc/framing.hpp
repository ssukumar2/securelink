#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <stdexcept>

namespace framing {

constexpr uint16_t MAGIC = 0x5E01;
constexpr size_t HEADER_SIZE = 5;
constexpr size_t CRC_SIZE = 1;

enum class MsgType : uint8_t {
    HANDSHAKE_INIT = 0x01,
    HANDSHAKE_RESP = 0x02,
    DATA           = 0x03,
    HEARTBEAT      = 0x04,
    ERROR_MSG      = 0xFF,
};

inline uint8_t crc8(const uint8_t* data, size_t len) {
    uint8_t crc = 0;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j)
            crc = (crc & 0x80) ? (crc << 1) ^ 0x07 : (crc << 1);
    }
    return crc;
}

inline std::vector<uint8_t> encode(MsgType type, const uint8_t* payload, uint16_t len) {
    std::vector<uint8_t> frame(HEADER_SIZE + len + CRC_SIZE);
    frame[0] = (MAGIC >> 8) & 0xFF;
    frame[1] = MAGIC & 0xFF;
    frame[2] = (len >> 8) & 0xFF;
    frame[3] = len & 0xFF;
    frame[4] = static_cast<uint8_t>(type);
    if (len > 0) std::memcpy(&frame[5], payload, len);
    frame[HEADER_SIZE + len] = crc8(frame.data(), HEADER_SIZE + len);
    return frame;
}

struct DecodedMsg {
    MsgType type;
    std::vector<uint8_t> payload;
};

inline DecodedMsg decode(const uint8_t* data, size_t len) {
    if (len < HEADER_SIZE + CRC_SIZE)
        throw std::runtime_error("frame too short");
    uint16_t magic = (data[0] << 8) | data[1];
    if (magic != MAGIC)
        throw std::runtime_error("bad magic");
    uint16_t payload_len = (data[2] << 8) | data[3];
    if (len < HEADER_SIZE + payload_len + CRC_SIZE)
        throw std::runtime_error("incomplete frame");
    uint8_t expected_crc = crc8(data, HEADER_SIZE + payload_len);
    if (data[HEADER_SIZE + payload_len] != expected_crc)
        throw std::runtime_error("crc mismatch");
    DecodedMsg msg;
    msg.type = static_cast<MsgType>(data[4]);
    msg.payload.assign(data + 5, data + 5 + payload_len);
    return msg;
}

} // namespace framing
