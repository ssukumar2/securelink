# securelink

A TCP server where two parties can talk privately and authentically. They do an ECDHE key exchange to agree on a shared secret, authenticate with Ed25519 identity keys, then encrypt every message with AES-256-GCM. Crypto is in C, the rest is C++. Built on OpenSSL.

I started this to actually understand how secure key exchange works — not just call a TLS library. Once the handshake worked I kept going and added more layers around it.

## How it works

The handshake is basically TLS 1.3 stripped down: ClientHello and ServerHello carry random nonces, ephemeral ECDH public keys, and a cipher choice. The server sends its Ed25519 identity, signs the transcript, and both sides exchange a Finished MAC. After that, HKDF gives directional AES-256-GCM keys and every record is sealed with the AEAD. Sequence numbers feed a sliding-window replay guard.

A session stays open and the app layer multiplexes many logical streams over it.

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

Listens on port 1234. Ctrl+C for a clean shutdown.

## Tests
Plus a lot more across protocol, streams, RPC, pub/sub, file transfer, observability — and a set of adversarial test binaries (`attack_replay_storm`, `attack_aead_tamper`, `attack_record_fuzz`, etc.) that each exit non-zero if a defense fails to hold.

## License

MIT
