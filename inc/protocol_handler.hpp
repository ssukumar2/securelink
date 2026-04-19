#pragma once

#include <cstdint>
#include <string>
#include <vector>

class ProtocolHandler
{
public:
    explicit ProtocolHandler(std::string secret_message);

    /// Process client handshake: receive pubkey, return server pubkey + ciphertext
    std::vector<uint8_t> handle_handshake(const std::vector<uint8_t>& client_pubkey);

private:
    std::string secret_message_;
};