#include "protocol_handler.hpp"
#include "tcp_server.hpp"

#include <csignal>
#include <iostream>

namespace {
TcpServer* g_server = nullptr;

void handle_sigint(int) {
    // close() and setting an atomic flag are both async-signal-safe;
    // avoid doing anything else (like std::cout) directly in a handler.
    if (g_server) g_server->stop();
}
}  // namespace

int main()
{
    const uint16_t port = 1234; // arbitrary demo port, not a fixed protocol port
    const std::string secret = "U2VjbG91cyBHbWJI";  // used as raw plaintext bytes,
                                                       // not base64-decoded — the string
                                                       // just happens to look like base64

    std::cout << "securelink server" << std::endl;
    std::cout << "  port:   " << port << std::endl;
    std::cout << "  curve:  secp256r1" << std::endl;
    // Demo entry point only: uses ECB for a minimal handshake proof.
    // Real record encryption is AES-256-GCM in sl_aead.c.
    std::cout << "  cipher: AES-256-ECB" << std::endl;
    std::cout << std::endl;

    ProtocolHandler handler(secret);
    TcpServer server(port);

    g_server = &server;
    std::signal(SIGINT, handle_sigint);

    server.run([&](const std::vector<uint8_t>& client_data) {
        std::cout << "handshake started (" << client_data.size()
                  << " bytes)" << std::endl;
        auto response = handler.handle_handshake(client_data);
        std::cout << "handshake complete (" << response.size()
                  << " bytes)" << std::endl;
        return response;
    });

    std::cout << "server shut down cleanly" << std::endl;
    return 0;
}