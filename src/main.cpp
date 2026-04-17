#include "tcp_server.hpp"

#include <iostream>

int main() 
{
    std::cout << "securelink — echo mode (crypto not yet implemented)" << std::endl;

    TcpServer server(1234);

    server.run([](const std::vector<uint8_t>& data) {
        std::cout << "echoing " << data.size() << " bytes back to client" << std::endl;
        return data;
    });

    return 0;
}