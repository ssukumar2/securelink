#pragma once
// AdminHttpServer — minimal blocking HTTP/1.0 server for in-process admin
// endpoints (/metrics, /healthz, /readyz, custom handlers).
//
// Deliberately small: no keep-alive, no chunked encoding, no TLS.
// Bind to a loopback or unix-socket-only interface in production.

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>

namespace securelink {

struct AdminRequest {
    std::string method;
    std::string path;
    std::string body;
};

struct AdminResponse {
    int         status = 200;
    std::string content_type = "text/plain; charset=utf-8";
    std::string body;
};

using AdminHandler = std::function<AdminResponse(const AdminRequest&)>;

class AdminHttpServer {
public:
    AdminHttpServer(std::string bind_addr, std::uint16_t port);
    ~AdminHttpServer();

    void route(const std::string& path, AdminHandler handler);

    bool start();
    void stop();
    bool running() const { return running_.load(); }

    std::uint16_t port() const { return port_; }

private:
    void run();
    void handle_client(int fd);
    AdminResponse dispatch(const AdminRequest& req);

    std::string       bind_addr_;
    std::uint16_t     port_;
    int               listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread       thread_;
    std::unordered_map<std::string, AdminHandler> routes_;
};

}  // namespace securelink
