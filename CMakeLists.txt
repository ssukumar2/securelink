cmake_minimum_required(VERSION 3.15)
project(securelink VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

# Server binary
add_executable(securelink_server
    src/main.cpp
    src/tcp_server.cpp
    src/crypto_engine.c
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