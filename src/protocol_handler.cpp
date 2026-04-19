#include "protocol_handler.hpp"

extern "C" {
#include "crypto_engine.h"
}

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <utility>

ProtocolHandler::ProtocolHandler(std::string secret_message)
    : secret_message_(std::move(secret_message)) {}

std::vector<uint8_t> ProtocolHandler::handle_handshake(
    const std::vector<uint8_t>& client_pubkey)
{
    if (client_pubkey.size() != 64)
        throw std::runtime_error("expected 64 bytes, got " +
                                 std::to_string(client_pubkey.size()));

    ecc_keypair_t* kp = ecc_keypair_create();
    
    if (!kp) 
        throw std::runtime_error("keygen failed");

    uint8_t server_pub[64];
    if (ecc_get_public_key(kp, server_pub, sizeof(server_pub)) != 0)
    {
        ecc_keypair_free(kp);
        throw std::runtime_error("failed to get public key");
    }

    std::cout << "  generated server keypair" << std::endl;

    uint8_t shared_secret[32];

    int slen = ecc_derive_shared_secret(kp, client_pubkey.data(), client_pubkey.size(),
                                         shared_secret, sizeof(shared_secret));
    ecc_keypair_free(kp);

    if (slen < 0) 
        throw std::runtime_error("ecdh failed");

    std::cout << "  derived shared secret" << std::endl;

    uint8_t plaintext[16];
    std::memset(plaintext, 0, sizeof(plaintext));
    size_t msg_len = secret_message_.size();

    if (msg_len > 16) 
        msg_len = 16;

    std::memcpy(plaintext, secret_message_.data(), msg_len);

    uint8_t ciphertext[16];
    int enc = aes256_ecb_encrypt(shared_secret, plaintext, 16,
                                  ciphertext, sizeof(ciphertext));
    if (enc < 0) 
        throw std::runtime_error("aes encrypt failed");

    std::cout << "  encrypted message (" << enc << " bytes)" << std::endl;

    std::vector<uint8_t> response;

    response.reserve(80);
    response.insert(response.end(), server_pub, server_pub + 64);
    response.insert(response.end(), ciphertext, ciphertext + 16);

    return response;
}