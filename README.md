![Build and Test](https://github.com/ssukumar2/securelink/actions/workflows/c-cpp.yml/badge.svg)

# securelink

A TCP server that implements a secure handshake protocol using ECC key exchange and AES-256 encryption. The crypto layer is written in pure C for portability, the application layer is in C++. Built with OpenSSL.

I built this to explore how secure key exchange actually works at the protocol level — not just calling a TLS library, but implementing the handshake myself: key generation, ECDH shared secret derivation, and symmetric encryption of a message.

## How it works

When a client connects to the server on port 1234, it sends its ECC public key (64 bytes, using the secp256r1 curve). The server receives this key, generates its own ECC key pair, and uses both keys to derive a shared secret through ECDH. It then uses that shared secret as an AES-256-ECB key to encrypt a message. Finally, the server sends back its own public key along with the encrypted message. The client can then perform the same ECDH derivation on its side to get the same shared secret and decrypt the message.

The whole exchange happens in a single TCP round trip — the client sends 64 bytes, the server responds with 80 bytes (64 for its public key plus 16 for the ciphertext).

## Architecture

The project mixes C and C++ on purpose. In real embedded security work, crypto primitives are often written in C so they can run on any platform — microcontrollers, FreeRTOS, bare metal, Linux. The application layer uses C++ for cleaner abstractions.

The crypto engine is pure C and handles ECC key generation, ECDH shared secret derivation, and AES encrypt/decrypt through OpenSSL. It has no C++ dependencies and could theoretically run on an embedded target. The protocol handler is C++ and calls the C crypto API through extern "C" to implement the handshake logic. The TCP server is also C++ using POSIX sockets for handling client connections. A separate pure C test suite exercises the crypto engine independently.

## Security notes

The server uses secp256r1 (NIST P-256) for key exchange. AES-256-ECB is used for simplicity — production systems should use AES-GCM for authenticated encryption. New keys are generated per session so each handshake produces its own unique shared secret. There is no certificate validation in this implementation — a real system would add mutual authentication to prevent man-in-the-middle attacks.

## Stack

- C11 for crypto primitives
- C++17 for application layer
- OpenSSL (libssl, libcrypto)
- POSIX sockets
- CMake (mixed C/C++ build)

## Building

    cmake -B build
    cmake --build build

## Running

    ./build/securelink_server

Listens on port 1234. Press Ctrl+C to stop.

## Tests

    ./build/test_crypto

Ten tests covering key generation, ECDH shared secret derivation, AES encrypt/decrypt roundtrip, and key uniqueness.

## License

MIT