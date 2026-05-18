#pragma once
// Minimal command-line arg parser. No dependency on getopt, no allocations
// beyond std::string. Supports long flags only:
//
//     --host=127.0.0.1
//     --port 4443
//     --verbose          (boolean flag, no value)
//
// Unknown flags are an error. Positional args are collected separately.

#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace securelink {

class CliArgs {
public:
    // boolean_flags: long names (without --) that take no value.
    CliArgs(int argc, char** argv,
            const std::unordered_set<std::string>& boolean_flags = {});

    // Returns the value of `--name=VALUE` or `--name VALUE`. nullopt if unset.
    std::optional<std::string> get(const std::string& name) const;

    // For boolean flags. true if the flag was present.
    bool flag(const std::string& name) const;

    // Typed accessors with defaults.
    std::string  get_string(const std::string& name, std::string fallback) const;
    int          get_int   (const std::string& name, int         fallback) const;
    std::uint32_t get_u32  (const std::string& name, std::uint32_t fallback) const;
    std::uint64_t get_u64  (const std::string& name, std::uint64_t fallback) const;

    const std::vector<std::string>& positionals() const { return positionals_; }
    const std::string& program_name() const { return program_; }

private:
    std::string program_;
    std::unordered_map<std::string, std::string> values_;
    std::unordered_set<std::string>              flags_;
    std::vector<std::string>                     positionals_;
};

class CliError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

}  // namespace securelink
