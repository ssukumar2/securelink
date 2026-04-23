#pragma once

#include <iostream>
#include <string>

namespace securelink {

enum class ErrorCode
{
    OK = 0,
    SOCKET_ERROR,
    BIND_ERROR,
    LISTEN_ERROR,
    ACCEPT_ERROR,
    RECV_ERROR,
    SEND_ERROR,
    KEYGEN_ERROR,
    ECDH_ERROR,
    ENCRYPT_ERROR,
    DECRYPT_ERROR,
    INVALID_DATA,
};

inline const char* error_to_string(ErrorCode code)
{
    switch (code)
    {
        case ErrorCode::OK:            return "ok";
        case ErrorCode::SOCKET_ERROR:  return "socket creation failed";
        case ErrorCode::BIND_ERROR:    return "bind failed";
        case ErrorCode::LISTEN_ERROR:  return "listen failed";
        case ErrorCode::ACCEPT_ERROR:  return "accept failed";
        case ErrorCode::RECV_ERROR:    return "receive failed";
        case ErrorCode::SEND_ERROR:    return "send failed";
        case ErrorCode::KEYGEN_ERROR:  return "key generation failed";
        case ErrorCode::ECDH_ERROR:    return "ecdh derivation failed";
        case ErrorCode::ENCRYPT_ERROR: return "encryption failed";
        case ErrorCode::DECRYPT_ERROR: return "decryption failed";
        case ErrorCode::INVALID_DATA:  return "invalid data received";
    }
    return "unknown error";
}

inline void log_error(ErrorCode code, const std::string& context = "")
{
    std::cerr << "[ERROR] " << error_to_string(code);
    if (!context.empty())
        std::cerr << " (" << context << ")";
    std::cerr << std::endl;
}

} // namespace securelink