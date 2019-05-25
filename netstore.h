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
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctime>

static constexpr int DEFAULT_TIMEOUT = 5;
static constexpr int MAX_TIMEOUT = 300;
static constexpr int MAX_PORT = 65535;

std::string IPV4_REGEXP = "^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\\.(?!$)|$)){4}$";

static constexpr int UDP_DATA_SIZE = 65507;
static constexpr int CMD_LEN = 10;
static constexpr int SIMPL_CMD_DATA_SIZE = UDP_DATA_SIZE - CMD_LEN * sizeof(char) - sizeof(uint64_t);
static constexpr int CMPLX_CMD_DATA_SIZE = UDP_DATA_SIZE - CMD_LEN * sizeof(char) - sizeof(uint64_t) - sizeof(uint64_t);
static constexpr int BUF_CMD_DATA_SIZE = UDP_DATA_SIZE - CMD_LEN * sizeof(char);

static constexpr const char *MSG_HEADER_HELLO = "HELLO\0\0\0\0\0";
static constexpr const char *MSG_HEADER_GOOD_DAY = "GOOD_DAY\0\0";


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

struct BUF_CMD{
    char cmd[CMD_LEN];
    char data[BUF_CMD_DATA_SIZE];
};

bool cmd_send(int socket, void *ptr, struct sockaddr_in *address) {
    return sendto(socket, ptr, UDP_DATA_SIZE, 0, (const sockaddr *) address, sizeof(*address)) == UDP_DATA_SIZE;
}

bool cmd_recvfrom_timed(int sock, void *buffer, struct sockaddr_in *from, struct timeval *timeout) {
    struct timeval start, end, diff, left;
    socklen_t from_size = sizeof(*from);

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &timeout, sizeof(*timeout)) == -1) {
        return false;
    }

    gettimeofday(&start, NULL);
    if (recvfrom(sock, buffer, UDP_DATA_SIZE, 0, (sockaddr *) from, &from_size) != UDP_DATA_SIZE) {
        return false;
    }
    gettimeofday(&end, NULL);

    timersub(&end, &start, &diff);
    timersub(timeout, &diff, &left);
    *timeout = left;

    return true;
}

#endif //NETSTORE_NETSTORE_H
