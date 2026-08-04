cmake_minimum_required(VERSION 3.15)
project(securelink VERSION 0.1.0 DESCRIPTION "A minimal ECDHE + AES-256-GCM secure channel, written from scratch" LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)

# Server binary
add_executable(securelink_server
    src/main.cpp
    src/tcp_server.cpp
    src/crypto_engine.c
    src/protocol_handler.cpp
)

target_include_directories(securelink_server PRIVATE inc)

target_link_libraries(securelink_server PRIVATE
    ssl
    crypto
    pthread
)

# Test binary
add_executable(test_crypto
    src/test_crypto.c
    src/crypto_engine.c
)

target_include_directories(test_crypto PRIVATE inc)

target_link_libraries(test_crypto PRIVATE
    ssl
    crypto
)

# Test client
add_executable(test_client
    src/test_client.cpp
    src/crypto_engine.c
)

target_include_directories(test_client PRIVATE inc)

target_link_libraries(test_client PRIVATE
    ssl
    crypto
    pthread
)

# Adversarial test: replay storm
add_executable(attack_replay_storm
    src/attack_replay_storm.cpp
    src/attack_sim.cpp
)
target_include_directories(attack_replay_storm PRIVATE inc)
target_link_libraries(attack_replay_storm PRIVATE pthread)

# Adversarial test: credential brute force
add_executable(attack_brute_force
    src/attack_brute_force.c
    src/sl_lockout.c
)
target_include_directories(attack_brute_force PRIVATE inc)

# Adversarial test: connection flood / DoS
add_executable(attack_dos_flood
    src/attack_dos_flood.c
    src/sl_dos_guard.c
)
target_include_directories(attack_dos_flood PRIVATE inc)

# Adversarial test: handshake downgrade
add_executable(attack_handshake_downgrade
    src/attack_handshake_downgrade.c
    src/sl_version.c
)
target_include_directories(attack_handshake_downgrade PRIVATE inc)

# Adversarial test: random record corruption (fuzzing)
add_executable(attack_record_fuzz
    src/attack_record_fuzz.c
    src/sl_record.c
    src/sl_aead.c
    src/sl_nonce.c
    src/sl_mem.c
    src/sl_rng.c
    src/sl_packet_mutator.c
)
target_include_directories(attack_record_fuzz PRIVATE inc)
target_link_libraries(attack_record_fuzz PRIVATE crypto)

# Adversarial test: AEAD tampering
add_executable(attack_aead_tamper
    src/attack_aead_tamper.c
    src/sl_aead.c
    src/sl_packet_mutator.c
    src/sl_mem.c
    src/sl_rng.c
)

target_include_directories(attack_aead_tamper PRIVATE inc)

target_link_libraries(attack_aead_tamper PRIVATE
    crypto
)