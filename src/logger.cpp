#include "logger.hpp"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

void log_info(const std::string& msg) 
{
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&t), "%H:%M:%S");
    std::cout << "[" << ss.str() << "] INFO  " << msg << std::endl;
}

void log_error(const std::string& msg) 
{
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&t), "%H:%M:%S");
    std::cerr << "[" << ss.str() << "] ERROR " << msg << std::endl;
}