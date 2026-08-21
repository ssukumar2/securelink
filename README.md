# securelink

A TCP server where two parties can talk privately and authentically. They do an ECDHE key exchange to agree on a shared secret, authenticate with Ed25519 identity keys, then encrypt every message with AES-256-GCM. Crypto is in C, the rest is C++. Built on OpenSSL.

I started this to actually understand how secure key exchange works — not just call a TLS library. Once the handshake worked I kept going and added more layers around it.

## How it works

The handshake is basically TLS 1.3 stripped down: ClientHello and ServerHello carry random nonces, ephemeral ECDH public keys, and a cipher choice. The server sends its Ed25519 identity, signs the transcript, and both sides exchange a Finished MAC. After that, HKDF gives directional AES-256-GCM keys and every record is sealed with the AEAD. Sequence numbers feed a sliding-window replay guard.

A session stays open and the app layer multiplexes many logical streams over it.

Note: `main.cpp` is a minimal handshake demo using AES-256-ECB to keep the
first end-to-end proof simple. The real sealed-record protocol used
throughout the rest of the project is AES-256-GCM, implemented in `sl_aead.c`.

## What's in here

- **Crypto and handshake** — ECDHE P-256, Ed25519 identity, SHA-256 transcript, HKDF key schedule, AES-256-GCM AEAD, HMAC Finished
- **Session lifecycle** — sealed records, replay guard, in-session rekey, encrypted resumption tickets, graceful close
- **Protocol negotiation** — version selection, cipher suite registry, TLV extensions, structured diagnostic codes
- **Streams** — many logical streams per session with flow control and priority scheduling
- **RPC** — server-side dispatcher and client with futures, deadlines, cancel-all
- **Pub/sub** — topic validator, wildcard subscriptions, per-identity ACLs, retained-message replay
- **File transfer** — chunked streaming with CRC-32C, SHA-256 verify, resume bitmap, throttling
- **Defenses** — replay guard, lockout, DoS caps, anomaly detector, threat score, intrusion monitor, audit log
- **Observability** — Prometheus-style metrics, health checks, distributed tracing with W3C-style context
- **Persistence** — append-only KV, atomic snapshots, event log, time series, replay harness
- **Adversarial tests** — red-team scenarios for each defense (replay storm, AEAD tamper, downgrade, brute force, flood, fuzz, ACL bypass, intrusion escalation)

## Architecture

C handles anything touching keys, nonces, or wire bytes — could theoretically run on an embedded target with no C++ dependency. C++ handles orchestration: handshake engine, stream mux, RPC, pub/sub, sessions, observability. They talk through `extern "C"`.

## Stack

- C11 for crypto and wire formats
- C++17 for orchestration
- OpenSSL 1.1+
- POSIX sockets
- CMake
- GitHub Actions CI

## Build and run
cmake -B build

cmake --build build

./build/securelink_server

Listens on port 1234. Ctrl+C for a clean shutdown (a real SIGINT handler,
not just an abrupt kill).

The server also retries `recv`/`accept` on `EINTR` instead of treating an
interrupted syscall as a hard error, and a client disconnecting mid-response
fails with `EPIPE` instead of being able to take the whole process down
with `SIGPIPE`.

## Tests

`ctest --output-on-failure` from the build directory runs everything in
one command: the core crypto correctness test, plus all 8 adversarial
attack programs — each one tries to break a specific defense and exits
non-zero if it succeeds.

```
cd build
ctest --output-on-failure
```

All 8 attacks and the crypto test currently pass:

- `attack_replay_storm` — replayed records get rejected by the sliding window
- `attack_aead_tamper` — any single-bit tamper of ciphertext, tag, or AAD fails to decrypt
- `attack_record_fuzz` — 2000 randomly-corrupted records, all rejected
- `attack_handshake_downgrade` — can't force a weaker version than both sides support
- `attack_brute_force` — lockout with backoff stops repeated credential guesses
- `attack_dos_flood` — per-source and global connection caps hold under a flood
- `attack_intrusion_pattern` — a slow, quiet attacker still gets caught by accumulated threat score
- `attack_topic_acl_bypass` — wildcard and path-traversal tricks can't bypass per-identity pub/sub rules

Each one is also wired into CI individually, so a regression in any single
defense shows up by name, not just as a generic test failure.

Beyond ctest, there are 21 more standalone test files (sessions, streams,
RPC, pub/sub, file transfer, tracing, health checks, and more) that each
document their own build command and can be run individually. All 21 now
also run automatically in CI via `python3 scripts/run_standalone_tests.py`,
which builds each one using its documented command (compiling every file
with the compiler that actually matches its language, not just whatever
the single documented command happens to invoke) and runs it under a
timeout, since a hang is a real failure mode here, not a hypothetical one
-- that'''s exactly how a real self-deadlock in `HealthCheck::render()` got
caught.

## License

MIT
