#pragma once
#include <cstddef>
#include <cstdint>

namespace securelink::constants {

// Network
constexpr std::size_t MAX_FRAME_SIZE      = 65536;   // 64 KiB hard cap per frame
constexpr std::size_t FRAME_HEADER_SIZE   = 8;       // length(4) + type(1) + flags(1) + reserved(2)
constexpr int         DEFAULT_PORT        = 4443;
constexpr int         LISTEN_BACKLOG      = 64;

// Crypto
constexpr std::size_t AES256_KEY_BYTES    = 32;
constexpr std::size_t AES_GCM_IV_BYTES    = 12;
constexpr std::size_t AES_GCM_TAG_BYTES   = 16;
constexpr std::size_t ECDH_PUBKEY_BYTES   = 65;      // uncompressed P-256
constexpr std::size_t HANDSHAKE_NONCE_LEN = 32;

// Session / rotation
constexpr std::uint64_t KEY_ROTATION_BYTES   = 1ULL << 30;  // rotate after 1 GiB
constexpr std::uint64_t KEY_ROTATION_SECONDS = 3600;        // or 1 hour
constexpr std::uint32_t REPLAY_WINDOW_SIZE   = 1024;

// Rate limiter
constexpr std::uint32_t RL_TOKENS_PER_SEC = 50;
constexpr std::uint32_t RL_BURST          = 100;

// Timeouts (milliseconds)
constexpr int HANDSHAKE_TIMEOUT_MS = 5000;
constexpr int IDLE_TIMEOUT_MS      = 30000;

}  // namespace securelink::constants
