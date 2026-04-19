#include "protocol_handler.hpp"
#include "tcp_server.hpp"

#include <iostream>

int main()
{
    const uint16_t port = 1234;
    const std::string secret = "U2VjbG91cyBHbWJI";

    std::cout << "securelink server" << std::endl;
    std::cout << "  port:   " << port << std::endl;
    std::cout << "  curve:  secp256r1" << std::endl;
    std::cout << "  cipher: AES-256-ECB" << std::endl;
    std::cout << std::endl;

    ProtocolHandler handler(secret);
    TcpServer server(port);

    server.run([&](const std::vector<uint8_t>& client_data) {
        std::cout << "handshake started (" << client_data.size()
                  << " bytes)" << std::endl;
        auto response = handler.handle_handshake(client_data);
        std::cout << "handshake complete (" << response.size()
                  << " bytes)" << std::endl;
        return response;
    });

    return 0;
}