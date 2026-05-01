#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>

class KeyRotation {
public:
    using KeygenFunc = std::function<void(uint8_t* privkey, uint8_t* pubkey)>;

    explicit KeyRotation(KeygenFunc keygen, int rotation_interval_sec = 3600)
        : keygen_(std::move(keygen)),
          interval_(rotation_interval_sec) {
        rotate_now();
    }

    bool needs_rotation() const {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_rotation_).count();
        return elapsed >= interval_;
    }

    void rotate_if_needed() {
        if (needs_rotation()) {
            rotate_now();
        }
    }

    void rotate_now() {
        std::lock_guard<std::mutex> lock(mutex_);
        memcpy(prev_pubkey_, current_pubkey_, 64);
        keygen_(current_privkey_, current_pubkey_);
        last_rotation_ = std::chrono::steady_clock::now();
        rotation_count_++;
    }

    const uint8_t* current_public_key() const { return current_pubkey_; }
    const uint8_t* current_private_key() const { return current_privkey_; }
    const uint8_t* previous_public_key() const { return prev_pubkey_; }
    int rotation_count() const { return rotation_count_; }

private:
    KeygenFunc keygen_;
    int interval_;
    std::mutex mutex_;
    uint8_t current_privkey_[32] = {};
    uint8_t current_pubkey_[64] = {};
    uint8_t prev_pubkey_[64] = {};
    std::chrono::steady_clock::time_point last_rotation_;
    int rotation_count_ = 0;
};
