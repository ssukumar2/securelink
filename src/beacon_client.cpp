#include "beacon_client.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "framing.hpp"
#include "logger.hpp"
#include "scope_guard.hpp"
#include "sl_beacon.h"
#include "sl_beacon_codec.h"
#include "sl_clock.h"
#include "sl_rng.h"

namespace securelink {

namespace {

bool set_nonblocking(int fd) {
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool write_all(int fd, const std::uint8_t* buf, std::size_t len,
               std::uint32_t timeout_ms) {
    std::size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd{fd, POLLOUT, 0};
            int pr = ::poll(&pfd, 1, static_cast<int>(timeout_ms));
            if (pr <= 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

}  // namespace

BeaconClient::BeaconClient(BeaconClientConfig cfg) : cfg_(std::move(cfg)) {
    sl_rng_init();
}

BeaconClient::~BeaconClient() {
    if (fd_ >= 0) ::close(fd_);
}

bool BeaconClient::connect() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    const std::string port_str = std::to_string(cfg_.port);
    int gai = ::getaddrinfo(cfg_.host.c_str(), port_str.c_str(), &hints, &res);
    if (gai != 0 || res == nullptr) return false;
    auto free_res = make_scope_guard([&] { ::freeaddrinfo(res); });

    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        int s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
        if (!set_nonblocking(s)) { ::close(s); continue; }

        int rc = ::connect(s, p->ai_addr, p->ai_addrlen);
        if (rc == 0) { fd_ = s; break; }
        if (errno != EINPROGRESS) { ::close(s); continue; }

        struct pollfd pfd{s, POLLOUT, 0};
        int pr = ::poll(&pfd, 1, static_cast<int>(cfg_.connect_timeout_ms));
        if (pr <= 0) { ::close(s); continue; }

        int err = 0;
        socklen_t elen = sizeof(err);
        if (::getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
            ::close(s);
            continue;
        }
        fd_ = s;
        break;
    }

    if (fd_ < 0) return false;

    int one = 1;
    ::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return true;
}

bool BeaconClient::send_beacon_locked(std::uint16_t flags) {
    sl_beacon_t b{};
    b.client_id    = cfg_.client_id;
    b.sequence     = seq_;
    b.timestamp_ms = sl_clock_wall_ms();
    b.interval_ms  = cfg_.interval_ms;
    b.flags        = flags;
    b.payload_len  = static_cast<std::uint16_t>(
                         std::min(cfg_.static_payload.size(),
                                  static_cast<std::size_t>(SL_BEACON_MAX_PAYLOAD)));
    if (b.payload_len > 0) {
        std::memcpy(b.payload, cfg_.static_payload.data(), b.payload_len);
    }

    std::vector<std::uint8_t> wire(sl_beacon_wire_size(&b));
    std::size_t wire_len = 0;
    if (sl_beacon_seal(&b, cfg_.key, cfg_.static_iv, seq_,
                       wire.data(), &wire_len) != 0) {
        return false;
    }

    auto frame = FrameParser::encode(FrameType::kData, 0,
                                     wire.data(), wire_len);
    if (!write_all(fd_, frame.data(), frame.size(), cfg_.io_timeout_ms)) {
        return false;
    }
    ++seq_;
    ++stats_.beacons_sent;
    return true;
}

bool BeaconClient::wait_for_ack(std::uint32_t timeout_ms) {
    struct pollfd pfd{fd_, POLLIN, 0};
    int pr = ::poll(&pfd, 1, static_cast<int>(timeout_ms));
    if (pr <= 0) return false;

    std::uint8_t buf[256];
    ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
    if (n <= 0) return false;
    ++stats_.acks_received;
    return true;
}

bool BeaconClient::reconnect_with_backoff() {
    static constexpr std::uint32_t kBaseMs = 500;
    static constexpr std::uint32_t kMaxMs  = 30000;
    std::uint32_t delay = kBaseMs;
    for (int attempt = 0; running_.load() && attempt < 8; ++attempt) {
        sl_clock_sleep_ms(delay);
        if (connect()) {
            ++stats_.reconnects;
            return true;
        }
        delay = std::min(delay * 2, kMaxMs);
    }
    return false;
}

std::uint32_t BeaconClient::next_delay_ms() const {
    if (cfg_.jitter_ms == 0) return cfg_.interval_ms;
    std::uint64_t j = 0;
    sl_rng_uniform(2 * cfg_.jitter_ms + 1, &j);
    const std::int64_t delta = static_cast<std::int64_t>(j) -
                               static_cast<std::int64_t>(cfg_.jitter_ms);
    const std::int64_t base  = static_cast<std::int64_t>(cfg_.interval_ms);
    const std::int64_t out   = base + delta;
    return out < 100 ? 100u : static_cast<std::uint32_t>(out);
}

bool BeaconClient::send_one() {
    const std::uint16_t flags = cfg_.request_ack ? SL_BEACON_FLAG_REQUEST_ACK
                                                 : SL_BEACON_FLAG_NONE;
    const std::uint64_t t0 = sl_clock_mono_ms();
    if (!send_beacon_locked(flags)) {
        ++stats_.send_failures;
        return false;
    }
    if (cfg_.request_ack) {
        if (!wait_for_ack(cfg_.io_timeout_ms)) {
            ++stats_.send_failures;
            return false;
        }
        stats_.last_rtt_ms = sl_clock_mono_ms() - t0;
    }
    return true;
}

void BeaconClient::run() {
    running_.store(true);
    while (running_.load()) {
        if (fd_ < 0 && !reconnect_with_backoff()) break;

        if (!send_one()) {
            ::close(fd_);
            fd_ = -1;
            continue;
        }
        sl_clock_sleep_ms(next_delay_ms());
    }
}

void BeaconClient::stop() {
    running_.store(false);
}

}  // namespace securelink
