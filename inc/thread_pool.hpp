#pragma once
// Fixed-size thread pool with bounded task queue.
//
//   - Workers pull from a single std::deque guarded by a mutex + cv.
//   - submit() drops the task and returns false when the queue is full
//     (back-pressure), preventing unbounded memory growth under overload.
//   - stop() drains the queue then joins workers.

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace securelink {

class ThreadPool {
public:
    using Task = std::function<void()>;

    ThreadPool(std::size_t worker_count, std::size_t queue_capacity);
    ~ThreadPool();

    ThreadPool(const ThreadPool&)            = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    // Returns false if the queue is full (back-pressure).
    bool submit(Task task);

    void stop();

    std::size_t workers()  const { return threads_.size(); }
    std::size_t queued()   const;
    std::size_t completed()const { return completed_.load(); }
    std::size_t dropped()  const { return dropped_.load(); }
    bool        stopped()  const { return stopped_.load(); }

private:
    void worker_loop();

    std::size_t queue_cap_;
    std::vector<std::thread>  threads_;
    mutable std::mutex        mu_;
    std::condition_variable   cv_;
    std::deque<Task>          q_;
    std::atomic<bool>         stopped_{false};
    std::atomic<std::size_t>  completed_{0};
    std::atomic<std::size_t>  dropped_{0};
};

}  // namespace securelink
