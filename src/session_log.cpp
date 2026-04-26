#include "session_log.hpp"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <sstream>

static std::string now_iso() 
{
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void log_session(const std::string& client_ip, const std::string& event,
                 const std::string& detail) 
{
    std::string line = now_iso() + " [" + client_ip + "] " + event + ": " + detail;
    std::cout << line << std::endl;

    std::ofstream log("session.log", std::ios::app);
    
    if (log.is_open()) 
    {
        log << line << "\n";
    }
}