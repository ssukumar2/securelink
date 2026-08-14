#include "event_loop.hpp"

#include <poll.h>
#include <vector>

namespace securelink {

EventLoop::EventLoop() = default;
EventLoop::~EventLoop() { stop(); }

bool EventLoop::add(int fd, std::uint32_t events, IoCallback cb) {
    if (fd < 0) return false;
    if (entries_.count(fd)) return false;
    entries_[fd] = Entry{events, std::move(cb)};
    return true;
}

bool EventLoop::modify(int fd, std::uint32_t events) {
    auto it = entries_.find(fd);
    if (it == entries_.end()) return false;
    it->second.events = events;
    return true;
}

bool EventLoop::remove(int fd) {
    return entries_.erase(fd) > 0;
}

int EventLoop::run_once(int timeout_ms) {
    drain_posted();
    if (entries_.empty()) return 0;

    std::vector<pollfd> pfds;
    std::vector<int>    fds;
    pfds.reserve(entries_.size());
    fds.reserve(entries_.size());
    for (const auto& [fd, e] : entries_) {
        pollfd p{};
        p.fd = fd;
        if (e.events & kEvRead)  p.events |= POLLIN;
        if (e.events & kEvWrite) p.events |= POLLOUT;
        pfds.push_back(p);
        fds.push_back(fd);
    }

    int n = ::poll(pfds.data(), pfds.size(), timeout_ms);
    if (n <= 0) return n;

    for (std::size_t i = 0; i < pfds.size(); ++i) {
        const auto& p = pfds[i];
        if (p.revents == 0) continue;

        std::uint32_t flags = 0;
        if (p.revents & (POLLIN  | POLLHUP | POLLERR)) flags |= kEvRead;
        if (p.revents & (POLLOUT))                     flags |= kEvWrite;

        auto it = entries_.find(fds[i]);
        if (it == entries_.end()) continue;
        // Copy the callback so handler can remove(fd) safely.
        IoCallback cb = it->second.cb;
        cb(fds[i], flags);
    }
    return n;
}

void EventLoop::run() {
    running_.store(true);
    while (running_.load()) {
        run_once(100);
    }
}

void EventLoop::stop() {
    running_.store(false);
}

void EventLoop::post(PostedTask task) {
    std::lock_guard<std::mutex> lock(post_mu_);
    posted_.emplace_back(std::move(task));
}

void EventLoop::drain_posted() {
    std::vector<PostedTask> local;
    {
        std::lock_guard<std::mutex> lock(post_mu_);
        local.swap(posted_);
    }
    for (auto& t : local) {
        try {
            t();
        } catch (...) {
            ++posted_task_exceptions_;
        }
    }
}

}  // namespace securelink
