cmake_minimum_required(VERSION 3.15)
project(securelink VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(securelink_server
    src/main.cpp
    src/tcp_server.cpp
)

target_include_directories(securelink_server PRIVATE inc)
target_link_libraries(securelink_server PRIVATE pthread)