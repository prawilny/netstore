#include "netstore.h"

static_assert(sizeof(SIMPL_CMD) == UDP_DATA_SIZE);
static_assert(sizeof(CMPLX_CMD) == UDP_DATA_SIZE);
static_assert(sizeof(BUF_CMD) == UDP_DATA_SIZE);

bool cmd_send(int socket, void *cmd, size_t msg_len, struct sockaddr_in *address) {
    return sendto(socket, cmd, msg_len, 0, (const sockaddr *) address, sizeof(*address)) == msg_len;
}

ssize_t cmd_recvfrom(int sock, void *buffer, struct sockaddr_in *from) {
    socklen_t from_size = sizeof(*from);
    return recvfrom(sock, buffer, UDP_DATA_SIZE, 0, (sockaddr *) from, &from_size);
}

ssize_t cmd_recvfrom_timed(int sock, void *buffer, struct sockaddr_in *from, struct timeval *timeout) {
    ssize_t result;
    struct timeval start, end, diff, left;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, timeout, sizeof(*timeout)) == -1) {
        return -1;
    }

    gettimeofday(&start, NULL);
    result = cmd_recvfrom(sock, buffer, from);
    gettimeofday(&end, NULL);

    timersub(&end, &start, &diff);
    timersub(timeout, &diff, &left);
    *timeout = left;

    return result;
}

void pckg_error(struct sockaddr_in *address) {
    std::cerr << "[PCKG ERROR]  Skipping invalid package from {" << inet_ntoa(address->sin_addr) << "}:{"
              << address->sin_port << "}." << std::endl;
}