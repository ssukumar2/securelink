# securelink

Secure handshake protocol server — ECC key exchange with ECDH shared secret and AES-256 encryption. Crypto primitives written in C for portability, application layer in C++.

## Status

TCP server skeleton with echo handler. Crypto coming next.

## Stack

- C11 (crypto primitives — coming)
- C++17 (TCP server, protocol handler)
- OpenSSL (coming)
- POSIX sockets
- CMake (mixed C/C++)

## Building

    cmake -B build
    cmake --build build
    ./build/securelink_server

## License

MIT