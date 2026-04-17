#include "tcp_server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <stdexcept>

TcpServer::TcpServer(uint16_t port) : port_(port) {}

TcpServer::~TcpServer() { stop(); }

void TcpServer::run(HandlerFn handler) 
{
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) throw std::runtime_error("socket creation failed");

    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);

    if (bind(server_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) 
    {
        close(server_fd_);
        throw std::runtime_error("bind failed on port " + std::to_string(port_));
    }

    if (listen(server_fd_, 5) < 0) 
    {
        close(server_fd_);
        throw std::runtime_error("listen failed");
    }

    running_ = true;
    std::cout << "server listening on port " << port_ << std::endl;

    while (running_) 
    {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd_, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        if (client_fd < 0) {
            if (!running_) break;
            std::cerr << "accept failed" << std::endl;
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        std::cout << "client connected from " << client_ip << std::endl;

        std::vector<uint8_t> buffer(1024);
        ssize_t bytes_read = recv(client_fd, buffer.data(), buffer.size(), 0);
        
        if (bytes_read <= 0) 
        {
            std::cerr << "failed to read from client" << std::endl;
            close(client_fd);
            continue;
        }

        buffer.resize(bytes_read);
        std::cout << "received " << bytes_read << " bytes" << std::endl;

        try 
        {
            std::vector<uint8_t> response = handler(buffer);
            send(client_fd, response.data(), response.size(), 0);
            std::cout << "sent " << response.size() << " bytes" << std::endl;
        } 
        catch (const std::exception& e) 
        {
            std::cerr << "handler error: " << e.what() << std::endl;
        }

        close(client_fd);
    }
}

void TcpServer::stop() 
{
    running_ = false;
    if (server_fd_ >= 0) 
    {
        close(server_fd_);
        server_fd_ = -1;
    }
}