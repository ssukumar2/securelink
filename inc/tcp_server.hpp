#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

class TcpServer 
{
public:
    using HandlerFn = std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)>;

    explicit TcpServer(uint16_t port);
    ~TcpServer();

    TcpServer(const TcpServer&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;

    void run(HandlerFn handler);
    void stop();

private:
    uint16_t port_;
    int server_fd_{-1};
    bool running_{false};
    
};