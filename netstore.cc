#include "netstore.h"
#include <unistd.h>

namespace netstore {
    static_assert(sizeof(SIMPL_CMD) == UDP_DATA_SIZE);
    static_assert(sizeof(CMPLX_CMD) == UDP_DATA_SIZE);
    static_assert(sizeof(BUF_CMD) == UDP_DATA_SIZE);

    bool cmd_send(int socket, void *cmd, size_t msg_len, struct sockaddr_in *address) {
        return sendto(socket, cmd, msg_len, 0, (const sockaddr *) address, sizeof(*address)) == (ssize_t) msg_len;
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

    ssize_t readn(int fd, void *vptr, size_t n) {
        size_t nleft;
        ssize_t nread;
        char *ptr;

        ptr = (char *) vptr;
        nleft = n;
        while (nleft > 0) {
            if ((nread = read(fd, ptr, nleft)) < 0) {
                if (errno == EINTR) {
                    nread = 0;
                } else {
                    return -1;
                }
            } else if (nread == 0) {
                break;
            }
            nleft -= nread;
            ptr += nread;
        }
        return (n - nleft);
    }

    ssize_t writen(int fd, const void *vptr, size_t n) {
        size_t nleft;
        ssize_t nwritten;
        const char *ptr;

        ptr = (const char *) vptr;
        nleft = n;
        while (nleft > 0) {
            if ((nwritten = write(fd, ptr, nleft)) <= 0) {
                if (errno == EINTR) {
                    nwritten = 0;
                } else {
                    return -1;
                }
            }
            nleft -= nwritten;
            ptr += nwritten;
        }
        return n;
    }

    int fdncpy(int dest, int source, size_t len, char *buffer, size_t buffer_size) {
        for (size_t left = len; left != 0;) {
            ssize_t batch = readn(source, buffer, std::min(buffer_size, left));
            left -= batch;
            if (batch <= 0 || writen(dest, buffer, batch) != batch) {
                return -1;
            }
        }
        return 0;
    }
}