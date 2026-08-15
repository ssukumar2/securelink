#include "admin_http.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace securelink {

namespace {

std::string read_request(int fd) {
    std::string out;
    char buf[1024];
    for (int i = 0; i < 64; ++i) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, buf + n);
        if (out.find("\r\n\r\n") != std::string::npos) break;
        if (out.size() > std::size_t{64} * 1024) break;
    }
    return out;
}

AdminRequest parse_request(const std::string& raw) {
    AdminRequest req;
    const auto line_end = raw.find("\r\n");
    if (line_end == std::string::npos) return req;
    const std::string line = raw.substr(0, line_end);

    const auto sp1 = line.find(' ');
    if (sp1 == std::string::npos) return req;
    const auto sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return req;

    req.method = line.substr(0, sp1);
    req.path   = line.substr(sp1 + 1, sp2 - sp1 - 1);

    const auto body_pos = raw.find("\r\n\r\n");
    if (body_pos != std::string::npos) {
        req.body = raw.substr(body_pos + 4);
    }
    return req;
}

std::string format_response(const AdminResponse& r) {
    std::string out;
    out += "HTTP/1.0 " + std::to_string(r.status) + " OK\r\n";
    out += "Content-Type: " + r.content_type + "\r\n";
    out += "Content-Length: " + std::to_string(r.body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    out += r.body;
    return out;
}

}  // namespace

AdminHttpServer::AdminHttpServer(std::string bind_addr, std::uint16_t port)
    : bind_addr_(std::move(bind_addr)), port_(port) {}

AdminHttpServer::~AdminHttpServer() { stop(); }

void AdminHttpServer::route(const std::string& path, AdminHandler handler) {
    routes_[path] = std::move(handler);
}

bool AdminHttpServer::start() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) return false;

    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port_);
    if (::inet_pton(AF_INET, bind_addr_.c_str(), &addr.sin_addr) != 1) {
        ::close(listen_fd_); listen_fd_ = -1; return false;
    }

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(listen_fd_, 16) != 0) {
        ::close(listen_fd_); listen_fd_ = -1; return false;
    }

    running_.store(true);
    thread_ = std::thread([this] { run(); });
    return true;
}

void AdminHttpServer::stop() {
    if (!running_.exchange(false)) return;
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    if (thread_.joinable()) thread_.join();
}

void AdminHttpServer::run() {
    while (running_.load()) {
        sockaddr_in peer{};
        socklen_t   plen = sizeof(peer);
        int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&peer), &plen);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (!running_.load()) break;
            continue;
        }
        handle_client(fd);
    }
}

void AdminHttpServer::handle_client(int fd) {
    const std::string raw = read_request(fd);
    AdminRequest req = parse_request(raw);
    AdminResponse resp = dispatch(req);
    const std::string out = format_response(resp);
    ssize_t sent = 0;
    while (sent < static_cast<ssize_t>(out.size())) {
        ssize_t n = ::send(fd, out.data() + sent, out.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) break;
        sent += n;
    }
    ::close(fd);
}

AdminResponse AdminHttpServer::dispatch(const AdminRequest& req) {
    auto it = routes_.find(req.path);
    if (it == routes_.end()) {
        AdminResponse r;
        r.status = 404;
        r.body   = "not found\n";
        return r;
    }
    return it->second(req);
}

}  // namespace securelink
