# Securelink Threat Model

## Scope
Securelink provides a TCP-based encrypted channel using ECDHE (P-256) for key
agreement and AES-256-GCM for record encryption. This document enumerates the
adversarial assumptions and the mitigations the protocol relies on.

## Assets
1. Confidentiality of application payloads in transit.
2. Integrity and authenticity of every record.
3. Forward secrecy across sessions and across key rotations.
4. Server availability under adversarial load.

## Adversary Model
- **Network attacker:** can read, drop, reorder, replay, and inject TCP segments.
- **Off-path attacker:** can guess sequence numbers but cannot observe traffic.
- **Compromised long-term key (future):** attacker who later obtains a static
  identity key must not be able to decrypt past recorded sessions.

Out of scope for v1: malicious endpoints, side-channel attacks on the host,
physical access, OS compromise.

## Mitigations
| Threat | Mitigation |
|---|---|
| Passive eavesdropping | AES-256-GCM with per-session keys derived via ECDHE |
| Active MITM during handshake | Transcript hash binding (planned: identity sigs) |
| Replay of captured records | Monotonic sequence numbers + replay window |
| Key compromise of long-term material | Ephemeral ECDHE keys per session |
| Long-lived session key wear | Time- and byte-based key rotation |
| Resource exhaustion | Per-IP token-bucket rate limiter, frame size cap |
| Truncation attacks | Explicit close-notify record (planned) |

## Open Items
- [ ] Mutual authentication via long-term Ed25519 identity keys.
- [ ] Pinned-fingerprint TOFU mode for clients.
- [ ] Formal verification of handshake transcript binding.
