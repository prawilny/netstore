#ifndef NETSTORE_NETSTORE_H
#define NETSTORE_NETSTORE_H

#include <boost/program_options.hpp>
#include <iostream>
#include <regex>
#include <vector>
#include <string>
#include <filesystem>

static constexpr int DEFAULT_TIMEOUT = 5;
static constexpr int MAX_TIMEOUT = 300;
static constexpr int MAX_PORT = 65535;

std::string IPV4_REGEXP = "^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\\.(?!$)|$)){4}$";

#endif //NETSTORE_NETSTORE_H
