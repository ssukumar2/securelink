#include "thread_pool.hpp"

namespace securelink {

ThreadPool::ThreadPool(std::size_t worker_count, std::size_t queue_capacity)
    : queue_cap_(queue_capacity) {
    if (worker_count == 0) worker_count = 1;
    threads_.reserve(worker_count);
    for (std::size_t i = 0; i < worker_count; ++i) {
        threads_.emplace_back([this] { worker_loop(); });
    }
}

ThreadPool::~ThreadPool() { stop(); }

bool ThreadPool::submit(Task task) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (stopped_.load()) return false;
        if (q_.size() >= queue_cap_) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        q_.emplace_back(std::move(task));
    }
    cv_.notify_one();
    return true;
}

void ThreadPool::stop() {
    if (stopped_.exchange(true)) return;
    cv_.notify_all();
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
}

std::size_t ThreadPool::queued() const {
    std::lock_guard<std::mutex> lock(mu_);
    return q_.size();
}

void ThreadPool::worker_loop() {
    for (;;) {
        Task task;
        {
            std::unique_lock<std::mutex> lock(mu_);
            cv_.wait(lock, [this] { return stopped_.load() || !q_.empty(); });
            if (stopped_.load() && q_.empty()) return;
            task = std::move(q_.front());
            q_.pop_front();
        }
        try { task(); }
        catch (...) { /* swallow: pool must not die on a stray exception */ }
        completed_.fetch_add(1, std::memory_order_relaxed);
    }
}

}  // namespace securelink
