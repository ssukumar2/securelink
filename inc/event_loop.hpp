#pragma once
// EventLoop — single-threaded poll(2) based reactor.
//
// Register fds with read/write interest and callbacks; run_once() polls
// once and dispatches. run() loops until stop(). Designed for the server
// accept loop and per-connection I/O on a single thread; offload heavy
// work to ThreadPool.
//
// Not thread-safe by itself — only the owning thread should call register/
// modify/run. Use post() from other threads to schedule work onto the loop.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace securelink {

enum EventFlag : std::uint32_t {
    kEvRead  = 1U << 0,
    kEvWrite = 1U << 1,
};

using IoCallback   = std::function<void(int fd, std::uint32_t events)>;
using PostedTask   = std::function<void()>;

class EventLoop {
public:
    EventLoop();
    ~EventLoop();

    // Add an fd with initial interest mask. Returns false if fd already present.
    bool add(int fd, std::uint32_t events, IoCallback cb);

    // Replace the interest mask. Callback stays the same.
    bool modify(int fd, std::uint32_t events);

    bool remove(int fd);

    // Run one poll iteration (blocks up to `timeout_ms`). Returns # ready.
    int  run_once(int timeout_ms);

    // Loop until stop() is called.
    void run();
    void stop();

    // Schedule a callable to run on the next iteration (thread-safe).
    void post(PostedTask task);

    bool running() const { return running_.load(); }
    std::size_t fd_count() const { return entries_.size(); }

private:
    struct Entry {
        std::uint32_t events;
        IoCallback    cb;
    };

    void drain_posted();

    std::atomic<bool> running_{false};
    std::unordered_map<int, Entry> entries_;
    std::mutex                     post_mu_;
    std::vector<PostedTask>        posted_;
};

}  // namespace securelink
