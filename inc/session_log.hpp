#pragma once
#include <string>

void log_session(const std::string& client_ip, const std::string& event,
                 const std::string& detail);