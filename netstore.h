#ifndef NETSTORE_NETSTORE_H
#define NETSTORE_NETSTORE_H

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <cassert>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctime>
#include <mutex>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <pthread.h>

static constexpr int UDP_DATA_SIZE = 65507;
static constexpr int TCP_BUFFER_SIZE = 524288;
static constexpr int CMD_LEN = 10;

static constexpr int SIMPL_CMD_DATA_SIZE = UDP_DATA_SIZE - CMD_LEN - sizeof(uint64_t);
static constexpr int CMPLX_CMD_DATA_SIZE = UDP_DATA_SIZE - CMD_LEN - sizeof(uint64_t) - sizeof(uint64_t);
static constexpr int BUF_CMD_DATA_SIZE = UDP_DATA_SIZE - CMD_LEN;

static constexpr int EMPTY_SIMPL_CMD_SIZE = UDP_DATA_SIZE - SIMPL_CMD_DATA_SIZE;
static constexpr int EMPTY_CMPLX_CMD_SIZE = UDP_DATA_SIZE - CMPLX_CMD_DATA_SIZE;

static constexpr const char *MSG_HEADER_HELLO = "HELLO\0\0\0\0\0";
static constexpr const char *MSG_HEADER_GOOD_DAY = "GOOD_DAY\0\0";
static constexpr const char *MSG_HEADER_DEL = "DEL\0\0\0\0\0\0\0";
static constexpr const char *MSG_HEADER_LIST = "LIST\0\0\0\0\0\0";
static constexpr const char *MSG_HEADER_MY_LIST = "MY_LIST\0\0\0";
static constexpr const char *MSG_HEADER_GET = "GET\0\0\0\0\0\0\0";
static constexpr const char *MSG_HEADER_ADD = "ADD\0\0\0\0\0\0\0";
static constexpr const char *MSG_HEADER_CONNECT_ME = "CONNECT_ME";
static constexpr const char *MSG_HEADER_CAN_ADD = "CAN_ADD\0\0\0";
static constexpr const char *MSG_HEADER_NO_WAY = "NO_WAY\0\0\0\0";

static constexpr const char *msg_pckg_error = "[PCKG ERROR] Skipping invalid package from %s:%d.%s\n";

struct SIMPL_CMD {
    char cmd[CMD_LEN];
    uint64_t cmd_seq;
    char data[SIMPL_CMD_DATA_SIZE];
} __attribute__((packed));

struct CMPLX_CMD {
    char cmd[CMD_LEN];
    uint64_t cmd_seq;
    uint64_t param;
    char data[CMPLX_CMD_DATA_SIZE];
}__attribute__((packed));

struct BUF_CMD {
    char cmd[CMD_LEN];
    char data[BUF_CMD_DATA_SIZE];
}__attribute__((packed));

bool cmd_send(int socket, void *cmd, size_t msg_len, struct sockaddr_in *address);

ssize_t cmd_recvfrom(int sock, void *buffer, struct sockaddr_in *from);

ssize_t cmd_recvfrom_timed(int sock, void *buffer, struct sockaddr_in *from, struct timeval *timeout);

ssize_t writen(int fd, const void *vptr, size_t n);

ssize_t readn(int fd, void *vptr, size_t n);

int fdncpy(int dest, int source, size_t len, char *buffer, size_t buffer_size);

#endif //NETSTORE_NETSTORE_H
