#include "netstore.h"

static_assert(sizeof(SIMPL_CMD) == UDP_DATA_SIZE);
static_assert(sizeof(CMPLX_CMD) == UDP_DATA_SIZE);
static_assert(sizeof(BUF_CMD) == UDP_DATA_SIZE);

bool cmd_send(int socket, void *ptr, struct sockaddr_in *address) {
    ssize_t result = sendto(socket, ptr, UDP_DATA_SIZE, 0, (const sockaddr *) address, sizeof(*address));
    if (result != UDP_DATA_SIZE) {
        perror(NULL);
        return false;
    }
    return true;

    return sendto(socket, ptr, UDP_DATA_SIZE, 0, (const sockaddr *) address, sizeof(*address)) == UDP_DATA_SIZE;
}

bool cmd_recvfrom(int sock, void *buffer, struct sockaddr_in *from) {
    socklen_t from_size = sizeof(*from);
    return recvfrom(sock, buffer, UDP_DATA_SIZE, 0, (sockaddr *) from, &from_size) == UDP_DATA_SIZE;
}

bool cmd_recvfrom_timed(int sock, void *buffer, struct sockaddr_in *from, struct timeval *timeout) {
    struct timeval start, end, diff, left;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, timeout, sizeof(*timeout)) == -1) {
        return false;
    }

    gettimeofday(&start, NULL);
    if (!cmd_recvfrom(sock, buffer, from)) {
        return false;
    }
    gettimeofday(&end, NULL);

    timersub(&end, &start, &diff);
    timersub(timeout, &diff, &left);
    *timeout = left;

    return true;
}

void pckg_error(struct sockaddr_in *address) {
    std::cerr << "[PCKG ERROR]  Skipping invalid package from {" << address->sin_addr.s_addr << "}:{"
              << address->sin_port << "}." << std::endl;
}