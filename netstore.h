#ifndef NETSTORE_NETSTORE_H
#define NETSTORE_NETSTORE_H

#include <boost/program_options.hpp>
#include <iostream>
#include <regex>
#include <vector>
#include <string>
#include <filesystem>
#include <algorithm>
#include <cassert>

static constexpr int DEFAULT_TIMEOUT = 5;
static constexpr int MAX_TIMEOUT = 300;
static constexpr int MAX_PORT = 65535;

std::string IPV4_REGEXP = "^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\\.(?!$)|$)){4}$";

static constexpr int UDP_DATA_SIZE = 65507;
static constexpr int CMD_LEN = 10;
static constexpr int SIMPL_CMD_DATA_SIZE = UDP_DATA_SIZE - CMD_LEN * sizeof(char) - sizeof(uint64_t);
static constexpr int CMPLX_CMD_DATA_SIZE = UDP_DATA_SIZE - CMD_LEN * sizeof(char) - sizeof(uint64_t) - sizeof(uint64_t);

static std::string MSG_HELLO = "HELLO\0\0\0\0\0";

struct SIMPL_CMD {
    char cmd[CMD_LEN];
    uint64_t cmd_seq;
    char data[SIMPL_CMD_DATA_SIZE];
};

struct CMPLX_CMD {
    char cmd[CMD_LEN];
    uint64_t cmd_seq;
    uint64_t param;
    char data[CMPLX_CMD_DATA_SIZE];
};

#endif //NETSTORE_NETSTORE_H
