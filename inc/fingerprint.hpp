#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <vector>

class FingerprintValidator {
public:
    void add_trusted(const std::string& hex_fingerprint) {
        trusted_.push_back(normalize(hex_fingerprint));
    }

    bool is_trusted(const uint8_t* pubkey, size_t len) const {
        std::string fp = compute_sha256(pubkey, len);
        for (const auto& t : trusted_) {
            if (t == fp) return true;
        }
        return false;
    }

    static std::string compute_sha256(const uint8_t* data, size_t len) {
        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256(data, len, hash);
        std::ostringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            if (i > 0) ss << ":";
            ss << std::setw(2) << std::setfill('0') << std::hex
               << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

private:
    std::vector<std::string> trusted_;

    static std::string normalize(const std::string& s) {
        std::string result;
        for (char c : s) {
            if (c != ' ' && c != '\t') result += std::tolower(c);
        }
        return result;
    }
};
