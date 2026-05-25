#pragma once
// AnomalyDetector — online statistical anomaly detection for traffic
// patterns. Uses exponentially-weighted moving average and variance
// (Welford-style EWMA) plus z-score thresholding to flag values that
// fall outside expected behavior.
//
// This is the "AI" you can actually defend in a security review: simple,
// memory-bounded, no model file, no training pipeline. Suitable for:
//   - beacon inter-arrival time anomalies (compromised client / sync attack)
//   - request-rate spikes (DDoS, scanner)
//   - payload-size outliers (data exfiltration, command injection)
//
// All updates run in O(1). Detector is not thread-safe; wrap externally.

#include <cstddef>
#include <cstdint>

namespace securelink {

class AnomalyDetector {
public:
    // alpha: smoothing factor in (0, 1]. Smaller = longer memory.
    //   0.05 ~ several minutes of beacon-rate history
    //   0.30 ~ recent-burst-sensitive
    // z_threshold: how many EWMA-sigmas counts as anomalous. 3.0 is standard.
    explicit AnomalyDetector(double alpha = 0.1,
                             double z_threshold = 3.0,
                             std::uint64_t warmup_samples = 20);

    // Feed an observation. Returns true if this observation is anomalous
    // (i.e. abs(z-score) > z_threshold) AND the detector has seen enough
    // samples to be confident. False during the warmup period regardless.
    bool observe(double value);

    // Statistics
    double mean()        const { return mean_; }
    double variance()    const { return var_;  }
    double last_value()  const { return last_; }
    double last_zscore() const { return last_z_; }
    std::uint64_t samples()    const { return n_; }
    std::uint64_t anomalies()  const { return anomalies_; }

    void reset();

private:
    double alpha_;
    double z_threshold_;
    std::uint64_t warmup_;
    double mean_   = 0.0;
    double var_    = 0.0;
    double last_   = 0.0;
    double last_z_ = 0.0;
    std::uint64_t n_         = 0;
    std::uint64_t anomalies_ = 0;
};

}  // namespace securelink
