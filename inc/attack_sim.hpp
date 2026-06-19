#pragma once
// AttackSim — declarative harness for running an attack scenario and
// asserting the defense's response.
//
// Each scenario is structured as:
//   1. Setup    — build the defender(s)
//   2. Attack   — perform the malicious actions
//   3. Assert   — verify expected outcomes (block, alert, counter delta)
//
// The harness exists so all attack tests share the same vocabulary:
//   AttackResult: kBlocked / kAllowed / kDetected / kInconclusive
//
// Tests register a name + callable; main() runs them and prints a summary.

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace securelink::attacks {

enum class AttackResult {
    kBlocked        = 0,   // defense rejected the attack outright
    kDetected       = 1,   // defense flagged but did not (yet) block
    kAllowed        = 2,   // attack succeeded — TEST FAILURE
    kInconclusive   = 3,   // setup error; ignore in totals
};

struct ScenarioOutcome {
    std::string   name;
    AttackResult  result        = AttackResult::kInconclusive;
    std::string   evidence;     // human-readable summary
    std::uint64_t duration_us   = 0;
};

using ScenarioFn = std::function<ScenarioOutcome()>;

class AttackSim {
public:
    void add(const std::string& name, ScenarioFn fn);

    // Run every registered scenario. Returns the number that DID NOT
    // end in kBlocked or kDetected (i.e. count of allowed/failed/error).
    int run_all(bool verbose = true);

    const std::vector<ScenarioOutcome>& outcomes() const { return outcomes_; }

private:
    struct Reg { std::string name; ScenarioFn fn; };
    std::vector<Reg>             scenarios_;
    std::vector<ScenarioOutcome> outcomes_;
};

const char* attack_result_name(AttackResult r);

// Helpers for scenario authors.
ScenarioOutcome blocked  (std::string name, std::string evidence);
ScenarioOutcome detected (std::string name, std::string evidence);
ScenarioOutcome allowed  (std::string name, std::string evidence);
ScenarioOutcome incon    (std::string name, std::string evidence);

}  // namespace securelink::attacks
